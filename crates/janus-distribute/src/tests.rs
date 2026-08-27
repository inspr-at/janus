use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt;

use age::secrecy::ExposeSecret;
use age::{Decryptor, Identity};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use janus_core::SecretValue;
use janus_host::{
    seal_host_envelope, HostEnvelopeBindingV1, HostEnvelopeSealRequest, SignedHostEnvelopeV1,
};
use rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use zeroize::{Zeroize, Zeroizing};

use super::*;

const SCOPE_REF: &str = "scp_0123456789abcdef0123456789abcdef01234567";
const SERVICE_REF: &str = "svc_0bca8d31f7e2";
const SLOT_REF: &str = "slot_49c0e8a17d63";
const SECRET_REF: &str = "sec_7a6fd9e3b521";
const DECLARATION_REF: &str = "decl_a84f209c4b32";
const KEY_REF: &str = "key_7f4a29c10e8d";

struct DistributeFixture {
    _temporary: tempfile::TempDir,
    source_identity_path: std::path::PathBuf,
    source_identity: age::x25519::Identity,
    target_identity: age::ssh::Identity,
    target_recipient: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    value: Zeroizing<Vec<u8>>,
    source_packet: Vec<u8>,
}

impl DistributeFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source_identity = age::x25519::Identity::generate();
        let source_recipient = source_identity.to_public().to_string();
        let source_identity_path = temporary.path().join("source-identity.txt");
        fs::write(
            &source_identity_path,
            source_identity.to_string().expose_secret().as_bytes(),
        )
        .expect("write fixture identity");
        fs::set_permissions(&source_identity_path, fs::Permissions::from_mode(0o600))
            .expect("set fixture identity permissions");

        let target_private =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("generate fixture key");
        let target_recipient = target_private
            .public_key()
            .to_openssh()
            .expect("encode fixture recipient");
        let target_pem = target_private
            .to_openssh(LineEnding::LF)
            .expect("encode fixture identity");
        let target_identity =
            age::ssh::Identity::from_buffer(Cursor::new(target_pem.as_bytes()), None)
                .expect("parse fixture identity");

        let mut signing_seed = [0_u8; 32];
        OsRng.fill_bytes(&mut signing_seed);
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let verifying_key = signing_key.verifying_key();
        signing_seed.zeroize();

        let mut value = Zeroizing::new(vec![0_u8; 48]);
        OsRng.fill_bytes(value.as_mut_slice());
        for byte in value.iter_mut() {
            *byte = b'a' + (*byte % 26);
        }
        let source_packet = seal_host_envelope(HostEnvelopeSealRequest {
            binding: binding(
                "host_58f36c72a91e",
                "env_00000001",
                "op_00000001",
                SECRET_REF,
                1,
            ),
            host_recipient: &source_recipient,
            signing_key_id: KEY_REF,
            signing_key: &signing_key,
            value: SecretValue::new(value.to_vec()),
        })
        .expect("seal source packet");

        Self {
            _temporary: temporary,
            source_identity_path,
            source_identity,
            target_identity,
            target_recipient,
            signing_key,
            verifying_key,
            value,
            source_packet,
        }
    }

    fn request(&self) -> HostEnvelopeDistributeRequest<'_> {
        HostEnvelopeDistributeRequest {
            source_packet: &self.source_packet,
            local_identity_path: &self.source_identity_path,
            source_verifying_key: &self.verifying_key,
            binding: binding(
                "host_6b13c802e47a",
                "env_00000002",
                "op_00000002",
                SECRET_REF,
                2,
            ),
            host_recipient: &self.target_recipient,
            signing_key_id: KEY_REF,
            signing_key: &self.signing_key,
        }
    }
}

fn binding(
    host_ref: &str,
    envelope_ref: &str,
    operation_ref: &str,
    secret_ref: &str,
    generation: u64,
) -> HostEnvelopeBindingV1 {
    HostEnvelopeBindingV1 {
        schema: "inspr.janus.host-envelope-payload.v1".to_string(),
        schema_version: 1,
        envelope_ref: envelope_ref.to_string(),
        operation_ref: operation_ref.to_string(),
        host_ref: host_ref.to_string(),
        service_ref: SERVICE_REF.to_string(),
        slot_ref: SLOT_REF.to_string(),
        secret_ref: secret_ref.to_string(),
        scope_ref: SCOPE_REF.to_string(),
        declaration_fingerprint: DECLARATION_REF.to_string(),
        generation,
        revocation_epoch: 1,
        issued_at_unix_secs: 1_800_000_000,
        expires_at_unix_secs: 1_800_003_600,
    }
}

fn decrypt_value(packet: &[u8], identity: &dyn Identity) -> Result<Zeroizing<Vec<u8>>, ()> {
    let packet: SignedHostEnvelopeV1 = serde_json::from_slice(packet).map_err(|_| ())?;
    let ciphertext = STANDARD_NO_PAD
        .decode(packet.ciphertext.as_bytes())
        .map_err(|_| ())?;
    let decryptor = Decryptor::new_buffered(ciphertext.as_slice()).map_err(|_| ())?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
        .map_err(|_| ())?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext).map_err(|_| ())?;
    if plaintext.len() < 5 {
        return Err(());
    }
    let metadata_len = u32::from_be_bytes(plaintext[..4].try_into().map_err(|_| ())?) as usize;
    let value_offset = 4_usize.checked_add(metadata_len).ok_or(())?;
    if value_offset >= plaintext.len() {
        return Err(());
    }
    Ok(Zeroizing::new(plaintext[value_offset..].to_vec()))
}

fn assert_source_unchanged(before: &[u8], after: &[u8]) {
    assert!(
        before == after,
        "source packet changed (lengths {} and {})",
        before.len(),
        after.len()
    );
}

#[test]
fn distribute_reseals_to_one_ssh_ed25519_host_without_returning_value() {
    let fixture = DistributeFixture::new();
    let source_before = fixture.source_packet.clone();

    let result = distribute_host_envelope(fixture.request()).expect("distribute packet");
    assert_source_unchanged(&source_before, &fixture.source_packet);

    let source_value = decrypt_value(&fixture.source_packet, &fixture.source_identity)
        .expect("decrypt source fixture");
    let target_value =
        decrypt_value(&result.packet, &fixture.target_identity).expect("decrypt target fixture");
    assert!(
        source_value.as_slice() == target_value.as_slice(),
        "decrypted bytes differ (lengths {} and {})",
        source_value.len(),
        target_value.len()
    );
    assert!(
        target_value.as_slice() == fixture.value.as_slice(),
        "fixture bytes differ (lengths {} and {})",
        target_value.len(),
        fixture.value.len()
    );
    assert_eq!(result.outcome.action, "host.envelope.distribute");
    assert!(result.outcome.changed);
    assert!(!result.outcome.value_returned);
    assert!(decrypt_value(&fixture.source_packet, &fixture.target_identity).is_err());

    let outcome_debug = format!("{:?}", result.outcome);
    let outcome_json = serde_json::to_string(&result.outcome).expect("encode outcome");
    let packet_json = String::from_utf8(result.packet).expect("packet is JSON");
    for formatted in [&outcome_debug, &outcome_json, &packet_json] {
        assert!(
            !formatted
                .as_bytes()
                .windows(fixture.value.len())
                .any(|window| window == fixture.value.as_slice()),
            "formatted output contained fixture bytes"
        );
    }
}

#[test]
fn distribute_fails_for_missing_or_wrong_identity_without_changing_source() {
    let fixture = DistributeFixture::new();
    let source_before = fixture.source_packet.clone();
    let missing_path = fixture._temporary.path().join("missing-identity");
    let mut missing_request = fixture.request();
    missing_request.local_identity_path = &missing_path;
    let missing_error = distribute_host_envelope(missing_request)
        .err()
        .expect("missing identity rejected");
    assert_eq!(missing_error.reason_code(), "host_identity_unavailable");
    assert_source_unchanged(&source_before, &fixture.source_packet);

    let wrong_identity = age::x25519::Identity::generate();
    let wrong_path = fixture._temporary.path().join("wrong-identity.txt");
    fs::write(
        &wrong_path,
        wrong_identity.to_string().expose_secret().as_bytes(),
    )
    .expect("write wrong fixture identity");
    fs::set_permissions(&wrong_path, fs::Permissions::from_mode(0o600))
        .expect("set wrong fixture identity permissions");
    let mut wrong_request = fixture.request();
    wrong_request.local_identity_path = &wrong_path;
    let wrong_error = distribute_host_envelope(wrong_request)
        .err()
        .expect("wrong identity rejected");
    assert_eq!(wrong_error.reason_code(), "host_envelope_decrypt_denied");
    assert_source_unchanged(&source_before, &fixture.source_packet);
}

#[test]
fn distribute_rejects_empty_source_invalid_recipient_and_invalid_binding() {
    let fixture = DistributeFixture::new();
    let source_before = fixture.source_packet.clone();

    let mut empty_request = fixture.request();
    empty_request.source_packet = &[];
    let empty_error = distribute_host_envelope(empty_request)
        .err()
        .expect("empty packet rejected");
    assert_eq!(empty_error.reason_code(), "host_envelope_packet_invalid");

    let mut recipient_request = fixture.request();
    recipient_request.host_recipient = "invalid-recipient";
    let recipient_error = distribute_host_envelope(recipient_request)
        .err()
        .expect("invalid recipient rejected");
    assert_eq!(
        recipient_error.reason_code(),
        "host_envelope_recipient_invalid"
    );
    assert_source_unchanged(&source_before, &fixture.source_packet);

    let mut binding_request = fixture.request();
    binding_request.binding.host_ref = "invalid-host".to_string();
    let binding_error = distribute_host_envelope(binding_request)
        .err()
        .expect("invalid binding rejected");
    assert_eq!(binding_error.reason_code(), "host_envelope_binding_invalid");
    assert_source_unchanged(&source_before, &fixture.source_packet);
}

#[test]
fn distribute_rejects_secret_reference_mismatch_without_changing_source() {
    let fixture = DistributeFixture::new();
    let source_before = fixture.source_packet.clone();
    let mut request = fixture.request();
    request.binding.secret_ref = "sec_95cb124af8d0".to_string();
    let error = distribute_host_envelope(request)
        .err()
        .expect("secret reference mismatch rejected");
    assert_eq!(error.reason_code(), "host_envelope_secret_ref_mismatch");
    assert_source_unchanged(&source_before, &fixture.source_packet);
}

#[test]
fn distribute_rejects_untrusted_source_signature_without_changing_source() {
    let fixture = DistributeFixture::new();
    let source_before = fixture.source_packet.clone();
    let mut wrong_seed = [0_u8; 32];
    OsRng.fill_bytes(&mut wrong_seed);
    let wrong_verifying_key = SigningKey::from_bytes(&wrong_seed).verifying_key();
    wrong_seed.zeroize();

    let mut request = fixture.request();
    request.source_verifying_key = &wrong_verifying_key;
    let error = distribute_host_envelope(request)
        .err()
        .expect("untrusted source signature rejected");
    assert_eq!(error.reason_code(), "host_envelope_signature_invalid");
    assert_source_unchanged(&source_before, &fixture.source_packet);
}

#[test]
fn distribute_rejects_oversized_source_packet_without_changing_source() {
    let fixture = DistributeFixture::new();
    let source_before = fixture.source_packet.clone();
    let oversized_packet = vec![0_u8; 256 * 1024 + 1];

    let mut request = fixture.request();
    request.source_packet = &oversized_packet;
    let error = distribute_host_envelope(request)
        .err()
        .expect("oversized source packet rejected");
    assert_eq!(error.reason_code(), "host_envelope_packet_oversized");
    assert_source_unchanged(&source_before, &fixture.source_packet);
}
