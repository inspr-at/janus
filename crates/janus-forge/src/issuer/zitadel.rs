//! Zitadel OIDC client-secret issuer connector.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use janus_core::{JanusError, JanusResult, SecretValue};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_HTTP_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_MACHINE_PROFILE_BYTES: usize = 32 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CLIENT_SECRET_BYTES: usize = 4 * 1024;
const MAX_ORIGIN_BYTES: usize = 512;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_TIMEOUT_SECONDS: u64 = 60;
const ASSERTION_TTL_SECONDS: u64 = 300;
const API_SCOPE: &str = "openid urn:zitadel:iam:org:project:id:zitadel:aud";

/// Exact public configuration for one reviewed Zitadel application.
#[derive(Clone, PartialEq, Eq)]
pub struct ZitadelOidcClientConfig {
    origin: String,
    project_id: String,
    application_id: String,
    timeout: Duration,
}

impl ZitadelOidcClientConfig {
    /// Validate a catalog entry without performing network or custody work.
    pub fn new(
        origin: &str,
        project_id: &str,
        application_id: &str,
        timeout_seconds: u64,
    ) -> JanusResult<Self> {
        let parsed = Url::parse(origin).map_err(|_| invalid_config())?;
        if origin.len() > MAX_ORIGIN_BYTES
            || parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
            || !numeric_id(project_id)
            || !numeric_id(application_id)
            || !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds)
        {
            return Err(invalid_config());
        }
        Ok(Self {
            origin: parsed.origin().ascii_serialization(),
            project_id: project_id.to_string(),
            application_id: application_id.to_string(),
            timeout: Duration::from_secs(timeout_seconds),
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.origin, path)
    }
}

fn numeric_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn invalid_config() -> JanusError {
    JanusError::InvalidManifest {
        detail: "Zitadel issuer connector configuration is invalid".to_string(),
    }
}

fn unavailable() -> JanusError {
    JanusError::StoreUnavailable {
        detail: "Zitadel issuer operation failed".to_string(),
    }
}

/// Clock boundary used to make the signed assertion deterministic in tests.
pub trait ZitadelIssuerClock: Send + Sync {
    /// Current Unix time in seconds.
    fn unix_seconds(&self) -> JanusResult<u64>;
}

/// Production issuer clock.
#[derive(Clone, Copy, Default)]
pub struct SystemIssuerClock;

impl ZitadelIssuerClock for SystemIssuerClock {
    fn unix_seconds(&self) -> JanusResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| unavailable())
    }
}

/// Narrow HTTP boundary. Implementations must never log request or response
/// bodies because both calls contain bearer material.
pub trait ZitadelTransport: Send + Sync {
    /// Exchange the signed service-account assertion for an access token.
    fn post_form(
        &self,
        endpoint: &str,
        body: &SecretValue,
        timeout: Duration,
    ) -> JanusResult<SecretValue>;

    /// Regenerate one exact application client secret.
    fn post_generate(
        &self,
        endpoint: &str,
        bearer: &SecretValue,
        body: &[u8],
        timeout: Duration,
    ) -> JanusResult<SecretValue>;
}

/// TLS transport with redirects disabled and bounded response bodies.
#[derive(Clone, Copy, Default)]
pub struct UreqZitadelTransport;

impl UreqZitadelTransport {
    fn agent(timeout: Duration) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .timeout(timeout)
            .build()
    }

    fn bounded_response(response: ureq::Response) -> JanusResult<SecretValue> {
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .into_reader()
            .take((MAX_HTTP_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
            return Err(unavailable());
        }
        Ok(SecretValue::new(bytes.as_slice().to_vec()))
    }
}

impl ZitadelTransport for UreqZitadelTransport {
    fn post_form(
        &self,
        endpoint: &str,
        body: &SecretValue,
        timeout: Duration,
    ) -> JanusResult<SecretValue> {
        let body = Zeroizing::new(
            String::from_utf8(body.expose_bytes().to_vec()).map_err(|_| unavailable())?,
        );
        let response = Self::agent(timeout)
            .post(endpoint)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body)
            .map_err(|_| unavailable())?;
        Self::bounded_response(response)
    }

    fn post_generate(
        &self,
        endpoint: &str,
        bearer: &SecretValue,
        body: &[u8],
        timeout: Duration,
    ) -> JanusResult<SecretValue> {
        let bearer = Zeroizing::new(
            String::from_utf8(bearer.expose_bytes().to_vec()).map_err(|_| unavailable())?,
        );
        let authorization = Zeroizing::new(format!("Bearer {}", bearer.as_str()));
        let response = Self::agent(timeout)
            .post(endpoint)
            .set("Authorization", &authorization)
            .set("Connect-Protocol-Version", "1")
            .set("Content-Type", "application/json")
            .send_bytes(body)
            .map_err(|_| unavailable())?;
        Self::bounded_response(response)
    }
}

/// Resolves a configured Zitadel application through an injected transport.
pub struct ZitadelOidcClientConnector<T = UreqZitadelTransport, C = SystemIssuerClock> {
    transport: T,
    clock: C,
}

impl Default for ZitadelOidcClientConnector {
    fn default() -> Self {
        Self {
            transport: UreqZitadelTransport,
            clock: SystemIssuerClock,
        }
    }
}

impl<T, C> ZitadelOidcClientConnector<T, C>
where
    T: ZitadelTransport,
    C: ZitadelIssuerClock,
{
    /// Construct with explicit boundaries for focused tests.
    pub fn new(transport: T, clock: C) -> Self {
        Self { transport, clock }
    }

    /// Regenerate the configured client secret. The supplied profile must have
    /// already been opened through Janus custody by the admin broker.
    pub fn resolve(
        &self,
        config: &ZitadelOidcClientConfig,
        machine_profile: SecretValue,
    ) -> JanusResult<SecretValue> {
        if machine_profile.expose_bytes().len() > MAX_MACHINE_PROFILE_BYTES {
            return Err(unavailable());
        }
        let profile: MachineKeyProfile =
            serde_json::from_slice(machine_profile.expose_bytes()).map_err(|_| unavailable())?;
        let started = Instant::now();
        let assertion = issue_assertion(&profile, &config.origin, self.clock.unix_seconds()?)?;
        let form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .append_pair("scope", API_SCOPE)
                .append_pair("assertion", &assertion)
                .finish(),
        );
        let token_body = self
            .transport
            .post_form(
                &config.endpoint("/oauth/v2/token"),
                &SecretValue::new(form.as_bytes().to_vec()),
                remaining(config.timeout, started)?,
            )
            .map_err(|_| unavailable())?;
        let token: AccessTokenResponse =
            serde_json::from_slice(token_body.expose_bytes()).map_err(|_| unavailable())?;
        if token.token_type != "Bearer"
            || token.access_token.is_empty()
            || token.access_token.len() > MAX_ACCESS_TOKEN_BYTES
            || token.expires_in == 0
        {
            return Err(unavailable());
        }
        let request = serde_json::to_vec(&GenerateClientSecretRequest {
            application_id: &config.application_id,
            project_id: &config.project_id,
        })
        .map_err(|_| unavailable())?;
        let response = self
            .transport
            .post_generate(
                &config.endpoint("/zitadel.application.v2.ApplicationService/GenerateClientSecret"),
                &SecretValue::new(token.access_token.as_bytes().to_vec()),
                &request,
                remaining(config.timeout, started)?,
            )
            .map_err(|_| unavailable())?;
        let generated: GenerateClientSecretResponse =
            serde_json::from_slice(response.expose_bytes()).map_err(|_| unavailable())?;
        if generated.client_secret.is_empty()
            || generated.client_secret.len() > MAX_CLIENT_SECRET_BYTES
            || generated
                .client_secret
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        {
            return Err(unavailable());
        }
        Ok(SecretValue::new(
            generated.client_secret.as_bytes().to_vec(),
        ))
    }
}

fn remaining(timeout: Duration, started: Instant) -> JanusResult<Duration> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(unavailable)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineKeyProfile {
    #[serde(rename = "type")]
    key_type: String,
    #[serde(rename = "keyId")]
    key_id: String,
    key: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "expirationDate")]
    _expiration_date: Option<String>,
}

impl Drop for MachineKeyProfile {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Serialize)]
struct AssertionHeader<'a> {
    alg: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

fn issue_assertion(
    profile: &MachineKeyProfile,
    audience: &str,
    now: u64,
) -> JanusResult<Zeroizing<String>> {
    if profile.key_type != "serviceaccount"
        || !numeric_id(&profile.key_id)
        || !numeric_id(&profile.user_id)
        || profile.key.len() > MAX_MACHINE_PROFILE_BYTES
    {
        return Err(unavailable());
    }
    let private_key = RsaPrivateKey::from_pkcs1_pem(&profile.key)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&profile.key))
        .map_err(|_| unavailable())?;
    if private_key.size() < 256 {
        return Err(unavailable());
    }
    let header = serde_json::to_vec(&AssertionHeader {
        alg: "RS256",
        kid: &profile.key_id,
    })
    .map_err(|_| unavailable())?;
    let claims = serde_json::to_vec(&AssertionClaims {
        iss: &profile.user_id,
        sub: &profile.user_id,
        aud: audience,
        iat: now,
        exp: now
            .checked_add(ASSERTION_TTL_SECONDS)
            .ok_or_else(unavailable)?,
    })
    .map_err(|_| unavailable())?;
    let mut assertion = Zeroizing::new(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    ));
    let signature = SigningKey::<sha2::Sha256>::new(private_key).sign(assertion.as_bytes());
    assertion.push('.');
    assertion.push_str(&URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    Ok(assertion)
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

impl Drop for AccessTokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateClientSecretRequest<'a> {
    application_id: &'a str,
    project_id: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateClientSecretResponse {
    client_secret: String,
}

impl Drop for GenerateClientSecretResponse {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use serde_json::Value;
    use std::sync::Mutex;

    const NOW: u64 = 1_800_000_000;

    struct FixedClock;

    impl ZitadelIssuerClock for FixedClock {
        fn unix_seconds(&self) -> JanusResult<u64> {
            Ok(NOW)
        }
    }

    #[derive(Default)]
    struct FakeTransport {
        form: Mutex<Option<(String, String)>>,
        generate: Mutex<Option<(String, String, Vec<u8>)>>,
        fail_with_secret: bool,
    }

    impl ZitadelTransport for FakeTransport {
        fn post_form(
            &self,
            endpoint: &str,
            body: &SecretValue,
            _timeout: Duration,
        ) -> JanusResult<SecretValue> {
            if self.fail_with_secret {
                return Err(JanusError::StoreUnavailable {
                    detail: "synthetic-sensitive-transport-detail".to_string(),
                });
            }
            *self.form.lock().unwrap() = Some((
                endpoint.to_string(),
                String::from_utf8(body.expose_bytes().to_vec()).unwrap(),
            ));
            Ok(SecretValue::new(
                br#"{"access_token":"synthetic-access-token","token_type":"Bearer","expires_in":300}"#
                    .to_vec(),
            ))
        }

        fn post_generate(
            &self,
            endpoint: &str,
            bearer: &SecretValue,
            body: &[u8],
            _timeout: Duration,
        ) -> JanusResult<SecretValue> {
            *self.generate.lock().unwrap() = Some((
                endpoint.to_string(),
                String::from_utf8(bearer.expose_bytes().to_vec()).unwrap(),
                body.to_vec(),
            ));
            Ok(SecretValue::new(
                br#"{"clientSecret":"synthetic-generated-value","creationDate":"2027-01-15T08:00:00Z"}"#
                    .to_vec(),
            ))
        }
    }

    fn fixture_profile() -> (SecretValue, rsa::RsaPublicKey) {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let pem = private.to_pkcs1_pem(Default::default()).unwrap();
        let profile = serde_json::json!({
            "type": "serviceaccount",
            "keyId": "333333333333333333",
            "key": pem.as_str(),
            "userId": "444444444444444444",
            "expirationDate": "2099-12-31T23:59:59Z"
        });
        (
            SecretValue::new(serde_json::to_vec(&profile).unwrap()),
            public,
        )
    }

    #[test]
    fn resolves_exact_application_with_signed_profile_and_no_value_return_channel() {
        let config = ZitadelOidcClientConfig::new(
            "https://identity.example.test",
            "111111111111111111",
            "222222222222222222",
            10,
        )
        .unwrap();
        let transport = FakeTransport::default();
        let (profile, public) = fixture_profile();
        let connector = ZitadelOidcClientConnector::new(transport, FixedClock);
        let resolved = connector.resolve(&config, profile).unwrap();
        assert_eq!(resolved.expose_bytes(), b"synthetic-generated-value");

        let (token_endpoint, form) = connector.transport.form.lock().unwrap().take().unwrap();
        assert_eq!(
            token_endpoint,
            "https://identity.example.test/oauth/v2/token"
        );
        let form = url::form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(form["scope"], API_SCOPE);
        let assertion = &form["assertion"];
        let segments = assertion.split('.').collect::<Vec<_>>();
        assert_eq!(segments.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "333333333333333333");
        assert_eq!(claims["iss"], "444444444444444444");
        assert_eq!(claims["sub"], "444444444444444444");
        assert_eq!(claims["aud"], "https://identity.example.test");
        assert_eq!(claims["iat"], NOW);
        assert_eq!(claims["exp"], NOW + ASSERTION_TTL_SECONDS);
        let signature =
            Signature::try_from(URL_SAFE_NO_PAD.decode(segments[2]).unwrap().as_slice()).unwrap();
        VerifyingKey::<sha2::Sha256>::new(public)
            .verify(
                format!("{}.{}", segments[0], segments[1]).as_bytes(),
                &signature,
            )
            .unwrap();

        let (generate_endpoint, bearer, request) =
            connector.transport.generate.lock().unwrap().take().unwrap();
        assert_eq!(
            generate_endpoint,
            "https://identity.example.test/zitadel.application.v2.ApplicationService/GenerateClientSecret"
        );
        assert_eq!(bearer, "synthetic-access-token");
        assert_eq!(
            serde_json::from_slice::<Value>(&request).unwrap(),
            serde_json::json!({
                "applicationId": "222222222222222222",
                "projectId": "111111111111111111"
            })
        );
    }

    #[test]
    fn rejects_origin_drift_and_redacts_transport_failure() {
        assert!(
            ZitadelOidcClientConfig::new("http://identity.example.test", "1", "2", 10).is_err()
        );
        assert!(
            ZitadelOidcClientConfig::new("https://identity.example.test/other", "1", "2", 10)
                .is_err()
        );
        let connector = ZitadelOidcClientConnector::new(
            FakeTransport {
                fail_with_secret: true,
                ..FakeTransport::default()
            },
            FixedClock,
        );
        let config =
            ZitadelOidcClientConfig::new("https://identity.example.test", "1", "2", 10).unwrap();
        let error = match connector.resolve(&config, fixture_profile().0) {
            Ok(_) => panic!("transport failure must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "store unavailable: Zitadel issuer operation failed"
        );
        assert!(!error.to_string().contains("synthetic-sensitive"));
    }
}
