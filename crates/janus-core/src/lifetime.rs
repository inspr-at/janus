//! Value-free issuer material lifetime metadata and reporting.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusResult, PrincipalChain, SafeLabel,
    SecretDescriptor, SecretRef, Severity,
};

const DEFAULT_RENEWAL_WARNING: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MAX_PUBLIC_CERTIFICATE_BYTES: usize = 64 * 1024;

/// Stable, value-free material lifetime validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaterialLifetimeError {
    reason_code: &'static str,
}

impl MaterialLifetimeError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    /// Stable reason code. The rejected input is intentionally never retained.
    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for MaterialLifetimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code)
    }
}

impl std::error::Error for MaterialLifetimeError {}

/// Absolute UTC timestamp represented as Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaterialTimestamp(i64);

impl MaterialTimestamp {
    /// Build from Unix seconds.
    pub fn from_unix_seconds(unix_seconds: i64) -> Self {
        Self(unix_seconds)
    }

    /// Unix seconds for policy comparisons and value-free evidence.
    pub fn unix_seconds(self) -> i64 {
        self.0
    }

    /// Convert a clock value without losing pre-epoch timestamps.
    pub fn from_system_time(value: SystemTime) -> Self {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Self(i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)),
            Err(error) => {
                let seconds = i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX);
                Self(-seconds)
            }
        }
    }

    /// Parse strict second-precision RFC 3339 UTC text.
    pub fn parse_utc(value: &str) -> Result<Self, MaterialLifetimeError> {
        let bytes = value.as_bytes();
        if bytes.len() != 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'Z'
        {
            return Err(MaterialLifetimeError::new(
                "material_lifetime_date_malformed",
            ));
        }
        let year = parse_decimal(&bytes[0..4])? as i32;
        let month = parse_decimal(&bytes[5..7])? as u32;
        let day = parse_decimal(&bytes[8..10])? as u32;
        let hour = parse_decimal(&bytes[11..13])? as u32;
        let minute = parse_decimal(&bytes[14..16])? as u32;
        let second = parse_decimal(&bytes[17..19])? as u32;
        timestamp_from_components(year, month, day, hour, minute, second)
    }

    /// Canonical second-precision RFC 3339 UTC text.
    pub fn to_utc_string(self) -> String {
        let days = self.0.div_euclid(86_400);
        let seconds = self.0.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

/// How lifetime metadata entered the reviewed catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterialLifetimeProvenance {
    /// Parsed from public certificate material at import.
    ParsedAtImport,
    /// Supplied through the reviewed manual metadata overlay.
    ReviewedManual,
}

impl MaterialLifetimeProvenance {
    /// Stable metadata text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParsedAtImport => "parsed_at_import",
            Self::ReviewedManual => "reviewed_manual",
        }
    }

    /// Parse stable metadata text.
    pub fn parse(value: &str) -> Result<Self, MaterialLifetimeError> {
        match value {
            "parsed_at_import" => Ok(Self::ParsedAtImport),
            "reviewed_manual" => Ok(Self::ReviewedManual),
            _ => Err(MaterialLifetimeError::new(
                "material_lifetime_provenance_invalid",
            )),
        }
    }
}

/// Value-free lifetime of externally issued material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialLifetime {
    /// Issuance/not-before time when known.
    pub issued_at: Option<MaterialTimestamp>,
    /// Issuer-controlled expiry time.
    pub not_after: MaterialTimestamp,
    /// Opaque reviewed issuer label when known.
    pub issuer: Option<SafeLabel>,
    /// Source of this metadata when known.
    pub provenance: Option<MaterialLifetimeProvenance>,
}

impl MaterialLifetime {
    /// Construct validated material lifetime metadata.
    pub fn new(
        issued_at: Option<MaterialTimestamp>,
        not_after: MaterialTimestamp,
        issuer: Option<SafeLabel>,
        provenance: Option<MaterialLifetimeProvenance>,
    ) -> Result<Self, MaterialLifetimeError> {
        if issued_at.is_some_and(|issued_at| issued_at > not_after) {
            return Err(MaterialLifetimeError::new(
                "material_lifetime_range_invalid",
            ));
        }
        Ok(Self {
            issued_at,
            not_after,
            issuer,
            provenance,
        })
    }

    /// Parse lifetime metadata only from a public DER X.509 certificate.
    pub fn from_public_certificate_der(der: &[u8]) -> Result<Self, MaterialLifetimeError> {
        if der.is_empty() || der.len() > MAX_PUBLIC_CERTIFICATE_BYTES {
            return Err(MaterialLifetimeError::new(
                "public_certificate_size_invalid",
            ));
        }

        let certificate = read_tlv(der, 0)?;
        if certificate.tag != 0x30 || certificate.next != der.len() {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }
        let certificate_body = &der[certificate.content_start..certificate.content_end];
        let tbs = read_tlv(certificate_body, 0)?;
        if tbs.tag != 0x30 {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }
        let signature_algorithm = read_tlv(certificate_body, tbs.next)?;
        let signature_value = read_tlv(certificate_body, signature_algorithm.next)?;
        if signature_algorithm.tag != 0x30
            || signature_value.tag != 0x03
            || signature_value.next != certificate_body.len()
        {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }

        let tbs_body = &certificate_body[tbs.content_start..tbs.content_end];
        let mut offset = 0;
        let first = read_tlv(tbs_body, offset)?;
        if first.tag == 0xa0 {
            offset = first.next;
        }
        offset = expect_tag(tbs_body, offset, 0x02)?.next;
        offset = expect_tag(tbs_body, offset, 0x30)?.next;
        let issuer = expect_tag(tbs_body, offset, 0x30)?;
        offset = issuer.next;
        let validity = expect_tag(tbs_body, offset, 0x30)?;
        offset = validity.next;
        offset = expect_tag(tbs_body, offset, 0x30)?.next;
        let _subject_public_key = expect_tag(tbs_body, offset, 0x30)?;

        let validity_body = &tbs_body[validity.content_start..validity.content_end];
        let not_before = read_tlv(validity_body, 0)?;
        let not_after = read_tlv(validity_body, not_before.next)?;
        if not_after.next != validity_body.len() {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }
        let issued_at = parse_der_time(
            not_before.tag,
            &validity_body[not_before.content_start..not_before.content_end],
        )?;
        let not_after = parse_der_time(
            not_after.tag,
            &validity_body[not_after.content_start..not_after.content_end],
        )?;

        let mut hasher = Sha256::new();
        hasher.update(&tbs_body[issuer.full_start..issuer.next]);
        let digest = hasher.finalize();
        let issuer = SafeLabel::new(format!("issuer_{}", hex::encode(&digest[..12])))
            .map_err(|_| MaterialLifetimeError::new("public_certificate_malformed"))?;

        Self::new(
            Some(issued_at),
            not_after,
            Some(issuer),
            Some(MaterialLifetimeProvenance::ParsedAtImport),
        )
    }

    /// Parse lifetime metadata only from a PEM block labeled `CERTIFICATE`.
    pub fn from_public_certificate_pem(pem: &str) -> Result<Self, MaterialLifetimeError> {
        const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
        const END: &str = "-----END CERTIFICATE-----";
        let trimmed = pem.trim();
        let body = trimmed
            .strip_prefix(BEGIN)
            .and_then(|value| value.strip_suffix(END))
            .ok_or_else(|| MaterialLifetimeError::new("public_certificate_type_denied"))?;
        if body.contains("-----") {
            return Err(MaterialLifetimeError::new("public_certificate_type_denied"));
        }
        let der = decode_base64(body)?;
        Self::from_public_certificate_der(&der)
    }
}

/// Renewal warning policy for issuer-controlled material expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaterialLifetimePolicy {
    /// Lead time before expiry at which reviewed renewal is required.
    pub renewal_warning_before: Duration,
}

impl MaterialLifetimePolicy {
    /// Build a policy with an explicit renewal lead time.
    pub fn new(renewal_warning_before: Duration) -> Self {
        Self {
            renewal_warning_before,
        }
    }

    /// Classify one optional material lifetime at an explicit clock value.
    pub fn classify(
        self,
        lifetime: Option<&MaterialLifetime>,
        now: SystemTime,
    ) -> MaterialExpiryStatus {
        let Some(lifetime) = lifetime else {
            return MaterialExpiryStatus::NotTracked;
        };
        let now = MaterialTimestamp::from_system_time(now).unix_seconds();
        let not_after = lifetime.not_after.unix_seconds();
        if now >= not_after {
            return MaterialExpiryStatus::Expired;
        }
        let warning_seconds =
            i64::try_from(self.renewal_warning_before.as_secs()).unwrap_or(i64::MAX);
        if now >= not_after.saturating_sub(warning_seconds) {
            MaterialExpiryStatus::Warning
        } else {
            MaterialExpiryStatus::Valid
        }
    }
}

impl Default for MaterialLifetimePolicy {
    fn default() -> Self {
        Self::new(DEFAULT_RENEWAL_WARNING)
    }
}

/// Expiry status, intentionally separate from age-based stale status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterialExpiryStatus {
    /// No issuer expiry is known; existing age-based reporting remains authoritative.
    NotTracked,
    /// Known expiry is outside the renewal warning window.
    Valid,
    /// Known expiry is inside the policy warning window.
    Warning,
    /// The issuer expiry instant has been reached or passed.
    Expired,
}

impl MaterialExpiryStatus {
    /// Stable reporting text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotTracked => "not_tracked",
            Self::Valid => "valid",
            Self::Warning => "warning",
            Self::Expired => "expired",
        }
    }
}

/// Value-free material lifetime report row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialLifetimeReportRow {
    /// Opaque catalog reference.
    pub secret_ref: SecretRef,
    /// Separate issuer-expiry status.
    pub status: MaterialExpiryStatus,
    /// Stable reason code.
    pub reason_code: &'static str,
    /// Issuer expiry when known.
    pub not_after: Option<MaterialTimestamp>,
    /// Whether reviewed renewal action is required.
    pub action_required: bool,
    /// Stable value-free action hint.
    pub action: &'static str,
    /// Secret values are never returned by lifetime reporting.
    pub value_returned: bool,
}

/// Builds value-free, audited material lifetime reports.
pub struct MaterialLifetimeReporter {
    policy: MaterialLifetimePolicy,
}

impl MaterialLifetimeReporter {
    /// Construct a reporter from policy.
    pub fn new(policy: MaterialLifetimePolicy) -> Self {
        Self { policy }
    }

    /// Report issuer expiry independently from age-based staleness.
    pub fn report<A>(
        &self,
        descriptors: &[SecretDescriptor],
        now: SystemTime,
        principal: &PrincipalChain,
        audit: &mut A,
    ) -> JanusResult<Vec<MaterialLifetimeReportRow>>
    where
        A: AuditSink,
    {
        let mut rows = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            if descriptor.scope != principal.scope {
                continue;
            }
            let status = self
                .policy
                .classify(descriptor.material_lifetime.as_ref(), now);
            let (reason_code, action_required, action, severity) = match status {
                MaterialExpiryStatus::NotTracked => (
                    "material_lifetime_not_tracked",
                    false,
                    "none",
                    Severity::Info,
                ),
                MaterialExpiryStatus::Valid => {
                    ("material_lifetime_valid", false, "none", Severity::Info)
                }
                MaterialExpiryStatus::Warning => (
                    "material_lifetime_warning",
                    true,
                    "review_renewal_with_issuer",
                    Severity::Warning,
                ),
                MaterialExpiryStatus::Expired => (
                    "material_lifetime_expired",
                    true,
                    "renew_with_issuer_before_use",
                    Severity::Critical,
                ),
            };
            let row = MaterialLifetimeReportRow {
                secret_ref: descriptor.secret_ref.clone(),
                status,
                reason_code,
                not_after: descriptor
                    .material_lifetime
                    .as_ref()
                    .map(|lifetime| lifetime.not_after),
                action_required,
                action,
                value_returned: false,
            };
            audit.record(
                AuditEvent::new(
                    AuditAction::SecretStalenessReport,
                    AuditOutcome::Allowed,
                    row.reason_code,
                    severity,
                    Some(row.secret_ref.clone()),
                    principal,
                )
                .with_evidence(SafeLabel::new(row.status.as_str())?),
            )?;
            rows.push(row);
        }
        Ok(rows)
    }
}

#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    full_start: usize,
    content_start: usize,
    content_end: usize,
    next: usize,
}

fn read_tlv(input: &[u8], offset: usize) -> Result<Tlv, MaterialLifetimeError> {
    let tag = *input
        .get(offset)
        .ok_or_else(|| MaterialLifetimeError::new("public_certificate_malformed"))?;
    let length_first = *input
        .get(offset + 1)
        .ok_or_else(|| MaterialLifetimeError::new("public_certificate_malformed"))?;
    let (length, content_start) = if length_first & 0x80 == 0 {
        (usize::from(length_first), offset + 2)
    } else {
        let count = usize::from(length_first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }
        let length_bytes = input
            .get(offset + 2..offset + 2 + count)
            .ok_or_else(|| MaterialLifetimeError::new("public_certificate_malformed"))?;
        if length_bytes.first() == Some(&0) {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }
        let mut length = 0usize;
        for byte in length_bytes {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| MaterialLifetimeError::new("public_certificate_malformed"))?;
        }
        (length, offset + 2 + count)
    };
    let content_end = content_start
        .checked_add(length)
        .filter(|end| *end <= input.len())
        .ok_or_else(|| MaterialLifetimeError::new("public_certificate_malformed"))?;
    Ok(Tlv {
        tag,
        full_start: offset,
        content_start,
        content_end,
        next: content_end,
    })
}

fn expect_tag(input: &[u8], offset: usize, tag: u8) -> Result<Tlv, MaterialLifetimeError> {
    let value = read_tlv(input, offset)?;
    if value.tag != tag {
        return Err(MaterialLifetimeError::new("public_certificate_malformed"));
    }
    Ok(value)
}

fn parse_der_time(tag: u8, value: &[u8]) -> Result<MaterialTimestamp, MaterialLifetimeError> {
    match tag {
        0x17 if value.len() == 13 && value[12] == b'Z' => {
            let short_year = parse_decimal(&value[0..2])? as i32;
            let year = if short_year >= 50 {
                1900 + short_year
            } else {
                2000 + short_year
            };
            timestamp_from_compact(year, &value[2..12])
        }
        0x18 if value.len() == 15 && value[14] == b'Z' => {
            let year = parse_decimal(&value[0..4])? as i32;
            timestamp_from_compact(year, &value[4..14])
        }
        _ => Err(MaterialLifetimeError::new(
            "material_lifetime_date_malformed",
        )),
    }
}

fn timestamp_from_compact(
    year: i32,
    value: &[u8],
) -> Result<MaterialTimestamp, MaterialLifetimeError> {
    let month = parse_decimal(&value[0..2])? as u32;
    let day = parse_decimal(&value[2..4])? as u32;
    let hour = parse_decimal(&value[4..6])? as u32;
    let minute = parse_decimal(&value[6..8])? as u32;
    let second = parse_decimal(&value[8..10])? as u32;
    timestamp_from_components(year, month, day, hour, minute, second)
}

fn parse_decimal(value: &[u8]) -> Result<u64, MaterialLifetimeError> {
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(MaterialLifetimeError::new(
            "material_lifetime_date_malformed",
        ));
    }
    Ok(value
        .iter()
        .fold(0u64, |total, byte| total * 10 + u64::from(byte - b'0')))
}

fn timestamp_from_components(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<MaterialTimestamp, MaterialLifetimeError> {
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(MaterialLifetimeError::new(
            "material_lifetime_date_malformed",
        ));
    }
    let days = days_from_civil(year, month, day);
    let day_seconds = i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second);
    let unix_seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(day_seconds))
        .ok_or_else(|| MaterialLifetimeError::new("material_lifetime_date_malformed"))?;
    Ok(MaterialTimestamp(unix_seconds))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = i64::from(adjusted_year).div_euclid(400);
    let year_of_era = i64::from(adjusted_year) - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let zero_day = days + 719_468;
    let era = zero_day.div_euclid(146_097);
    let day_of_era = zero_day - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, MaterialLifetimeError> {
    let compact = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.is_empty() || compact.len() % 4 != 0 {
        return Err(MaterialLifetimeError::new("public_certificate_malformed"));
    }
    let mut output = Vec::with_capacity(compact.len() / 4 * 3);
    for (chunk_index, chunk) in compact.chunks_exact(4).enumerate() {
        let last = chunk_index + 1 == compact.len() / 4;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c_padding = chunk[2] == b'=';
        let d_padding = chunk[3] == b'=';
        if (c_padding && !d_padding) || (d_padding && !last) {
            return Err(MaterialLifetimeError::new("public_certificate_malformed"));
        }
        let c = if c_padding {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if d_padding {
            0
        } else {
            base64_value(chunk[3])?
        };
        output.push((a << 2) | (b >> 4));
        if !c_padding {
            output.push((b << 4) | (c >> 2));
        }
        if !d_padding {
            output.push((c << 6) | d);
        }
    }
    if output.len() > MAX_PUBLIC_CERTIFICATE_BYTES {
        return Err(MaterialLifetimeError::new(
            "public_certificate_size_invalid",
        ));
    }
    Ok(output)
}

fn base64_value(value: u8) -> Result<u8, MaterialLifetimeError> {
    match value {
        b'A'..=b'Z' => Ok(value - b'A'),
        b'a'..=b'z' => Ok(value - b'a' + 26),
        b'0'..=b'9' => Ok(value - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(MaterialLifetimeError::new("public_certificate_malformed")),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{
        AuditWrite, OwnerRef, Principal, PrincipalId, PrincipalKind, ProfileId, SecretClass,
        SecretLifecycle, SecretName, TrustLevel,
    };

    fn lifetime(not_after: i64) -> MaterialLifetime {
        MaterialLifetime::new(
            None,
            MaterialTimestamp::from_unix_seconds(not_after),
            Some(SafeLabel::new("issuer_fixture").unwrap()),
            Some(MaterialLifetimeProvenance::ReviewedManual),
        )
        .unwrap()
    }

    fn descriptor(lifetime: Option<MaterialLifetime>) -> SecretDescriptor {
        SecretDescriptor {
            name: SecretName::new("PUBLIC_CERT").unwrap(),
            secret_ref: SecretRef::new("sec_public_cert").unwrap(),
            label: SafeLabel::new("Public certificate material").unwrap(),
            scope: crate::test_scope("dev"),
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.cert").unwrap()],
            material_lifetime: lifetime,
            present: true,
        }
    }

    fn principal() -> PrincipalChain {
        PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("lifetime-reporter").unwrap(),
            ),
            crate::test_scope("dev"),
        )
    }

    #[test]
    fn lifetime_clock_boundaries_and_missing_dates_are_separate() {
        let policy = MaterialLifetimePolicy::new(Duration::from_secs(100));
        let expiry = lifetime(1_000);
        for (now, expected) in [
            (899, MaterialExpiryStatus::Valid),
            (900, MaterialExpiryStatus::Warning),
            (999, MaterialExpiryStatus::Warning),
            (1_000, MaterialExpiryStatus::Expired),
            (1_001, MaterialExpiryStatus::Expired),
        ] {
            assert_eq!(
                policy.classify(Some(&expiry), UNIX_EPOCH + Duration::from_secs(now as u64)),
                expected
            );
        }
        assert_eq!(
            policy.classify(None, UNIX_EPOCH + Duration::from_secs(1_001)),
            MaterialExpiryStatus::NotTracked
        );
        assert!(
            MaterialLifetimePolicy::default().renewal_warning_before
                >= Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[test]
    fn lifetime_report_is_value_free_and_fresh_age_can_still_warn() {
        let descriptor = descriptor(Some(lifetime(1_000)));
        let now = UNIX_EPOCH + Duration::from_secs(950);
        let mut audit = AuditWrite::accepting();
        let rows =
            MaterialLifetimeReporter::new(MaterialLifetimePolicy::new(Duration::from_secs(100)))
                .report(
                    std::slice::from_ref(&descriptor),
                    now,
                    &principal(),
                    &mut audit,
                )
                .unwrap();

        assert_eq!(rows[0].status, MaterialExpiryStatus::Warning);
        assert!(rows[0].action_required);
        assert!(!rows[0].value_returned);
        assert_eq!(audit.events()[0].reason_code, "material_lifetime_warning");
        assert!(!audit.events()[0].value_returned);

        let evidence = [(
            descriptor.secret_ref.clone(),
            crate::SecretAgeEvidence::new(descriptor.secret_ref.clone())
                .with_last_used_at(now - Duration::from_secs(10)),
        )]
        .into_iter()
        .collect();
        let mut stale_audit = AuditWrite::accepting();
        let stale = crate::StaleSecretReporter::new(crate::StaleSecretPolicy::new(
            Duration::from_secs(100),
            Duration::from_secs(50),
        ))
        .report(
            &[descriptor],
            &evidence,
            now,
            &principal(),
            &mut stale_audit,
        )
        .unwrap();
        assert_eq!(stale[0].status, crate::StaleSecretStatus::Fresh);
    }

    #[test]
    fn utc_dates_are_strict_and_value_free_on_error() {
        let leap = MaterialTimestamp::parse_utc("2028-02-29T12:34:56Z").unwrap();
        assert_eq!(leap.to_utc_string(), "2028-02-29T12:34:56Z");
        for malformed in [
            "2027-02-29T12:34:56Z",
            "2028-02-29T12:34:56+00:00",
            "not-a-date",
        ] {
            let error = MaterialTimestamp::parse_utc(malformed).unwrap_err();
            assert_eq!(error.reason_code(), "material_lifetime_date_malformed");
            assert!(!error.to_string().contains(malformed));
        }
    }

    #[test]
    fn public_certificate_parser_rejects_non_certificate_without_echoing_input() {
        let marker = "fixture_private_material_marker";
        let input = format!("-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----");
        let error = MaterialLifetime::from_public_certificate_pem(&input).unwrap_err();
        assert_eq!(error.reason_code(), "public_certificate_type_denied");
        assert!(!error.to_string().contains(marker));
    }

    #[test]
    fn public_certificate_import_populates_only_value_free_lifetime_metadata() {
        const PUBLIC_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIICFzCCAb4CCQCNayeGUS0jSjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9maXh0
dXJlLmludmFsaWQwHhcNMjYwODI3MDc0MjA5WhcNMzYwODI0MDc0MjA5WjAaMRgw
FgYDVQQDDA9maXh0dXJlLmludmFsaWQwggFLMIIBAwYHKoZIzj0CATCB9wIBATAs
BgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg
/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaY
hrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEQQRrF9Hy
4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNX
azFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVEC
AQEDQgAE1BsHmwcvSupYCqY+USAXtOgWfR+ZYFcmqs30U8J+NpDDMceTc+gddWTu
VsWSXyNnEsECMJPw+Dp1ZKgEe0SpGTAKBggqhkjOPQQDAgNHADBEAiAhhqtt43wv
Dw2sfdaOe4nPY6tiQUR9vRJ9Wsj1ELWd5AIgIdGTxh0U+PvpihCKCDV7BzvcZ2T+
D98oLWbMdRnzr0M=
-----END CERTIFICATE-----"#;

        let lifetime = MaterialLifetime::from_public_certificate_pem(PUBLIC_CERTIFICATE).unwrap();

        assert_eq!(
            lifetime.issued_at.unwrap().to_utc_string(),
            "2026-08-27T07:42:09Z"
        );
        assert_eq!(lifetime.not_after.to_utc_string(), "2036-08-24T07:42:09Z");
        assert_eq!(
            lifetime.provenance,
            Some(MaterialLifetimeProvenance::ParsedAtImport)
        );
        assert!(lifetime
            .issuer
            .as_ref()
            .is_some_and(|issuer| issuer.as_str().starts_with("issuer_")));
    }
}
