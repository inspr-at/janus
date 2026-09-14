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
use sha2::Digest;
use std::fs;
use std::io::Read;
use std::path::{Component, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const MAX_HTTP_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_MACHINE_PROFILE_BYTES: usize = 32 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_CLIENT_SECRET_BYTES: usize = 4 * 1024;
const MAX_ORIGIN_BYTES: usize = 512;
const MAX_CA_BYTES: u64 = 128 * 1024;
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
    custom_ca: Option<PinnedCa>,
}

/// Exact custom trust anchor selected by the reviewed connector catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PinnedCa {
    file: PathBuf,
    sha256: String,
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
            custom_ca: None,
        })
    }

    pub(crate) fn new_with_optional_ca(
        origin: &str,
        project_id: &str,
        application_id: &str,
        timeout_seconds: u64,
        ca_file: Option<&str>,
        ca_sha256: Option<&str>,
    ) -> JanusResult<Self> {
        let mut config = Self::new(origin, project_id, application_id, timeout_seconds)?;
        config.custom_ca = match (ca_file, ca_sha256) {
            (None, None) => None,
            (Some(file), Some(sha256)) => Some(PinnedCa::new(file, sha256)?),
            _ => return Err(invalid_config()),
        };
        Ok(config)
    }

    pub(crate) fn custom_ca(&self) -> Option<&PinnedCa> {
        self.custom_ca.as_ref()
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.origin, path)
    }
}

impl PinnedCa {
    fn new(file: &str, sha256: &str) -> JanusResult<Self> {
        let file = PathBuf::from(file);
        if !file.is_absolute()
            || file.as_os_str().len() > 4096
            || file
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid_config());
        }
        Ok(Self {
            file,
            sha256: sha256.to_string(),
        })
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
#[derive(Clone, Default)]
pub struct UreqZitadelTransport {
    custom_ca: Option<PinnedCa>,
}

impl UreqZitadelTransport {
    pub(crate) fn new(custom_ca: Option<PinnedCa>) -> Self {
        Self { custom_ca }
    }

    fn agent(&self, timeout: Duration) -> JanusResult<ureq::Agent> {
        let mut builder = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .timeout(timeout);
        if let Some(custom_ca) = &self.custom_ca {
            builder = builder.tls_config(Arc::new(custom_tls_config(custom_ca)?));
        }
        Ok(builder.build())
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
        let response = self
            .agent(timeout)?
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
        let response = self
            .agent(timeout)?
            .post(endpoint)
            .set("Authorization", &authorization)
            .set("Connect-Protocol-Version", "1")
            .set("Content-Type", "application/json")
            .send_bytes(body)
            .map_err(|_| unavailable())?;
        Self::bounded_response(response)
    }
}

fn custom_tls_config(custom_ca: &PinnedCa) -> JanusResult<ureq::rustls::ClientConfig> {
    let metadata = fs::symlink_metadata(&custom_ca.file).map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CA_BYTES
    {
        return Err(unavailable());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&custom_ca.file)
        .map_err(|_| unavailable())?
        .take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 > MAX_CA_BYTES {
        return Err(unavailable());
    }
    if hex::encode(sha2::Sha256::digest(&bytes)) != custom_ca.sha256 {
        return Err(unavailable());
    }
    use ureq::rustls::pki_types::{pem::PemObject, CertificateDer};
    let certificates = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unavailable())?;
    if certificates.is_empty() {
        return Err(unavailable());
    }
    let mut roots = ureq::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for certificate in certificates {
        roots.add(certificate).map_err(|_| unavailable())?;
    }
    Ok(ureq::rustls::ClientConfig::builder_with_provider(
        ureq::rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&ureq::rustls::version::TLS12, &ureq::rustls::version::TLS13])
    .map_err(|_| unavailable())?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// Resolves a configured Zitadel application through an injected transport.
pub struct ZitadelOidcClientConnector<T = UreqZitadelTransport, C = SystemIssuerClock> {
    transport: T,
    clock: C,
}

impl Default for ZitadelOidcClientConnector {
    fn default() -> Self {
        Self {
            transport: UreqZitadelTransport::default(),
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

    /// Regenerate the configured client secret and immediately discard it.
    ///
    /// ZITADEL invalidates the previously active client secret when this
    /// operation succeeds. The replacement never crosses the connector
    /// boundary and is zeroized by `SecretValue` on drop.
    pub fn invalidate(
        &self,
        config: &ZitadelOidcClientConfig,
        machine_profile: SecretValue,
    ) -> JanusResult<()> {
        drop(self.resolve(config, machine_profile)?);
        Ok(())
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
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::thread;

    const NOW: u64 = 1_800_000_000;

    struct FixedClock;

    impl ZitadelIssuerClock for FixedClock {
        fn unix_seconds(&self) -> JanusResult<u64> {
            Ok(NOW)
        }
    }

    fn run_openssl(directory: &Path, arguments: &[&str]) {
        let status = Command::new("openssl")
            .args(arguments)
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run openssl for ephemeral test certificate");
        assert!(status.success(), "ephemeral openssl command failed");
    }

    fn generate_test_ca(directory: &Path, name: &str) -> (PathBuf, PathBuf) {
        let ca_directory = directory.join(name);
        fs::create_dir(&ca_directory).unwrap();
        run_openssl(
            &ca_directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "2",
                "-sha256",
                "-subj",
                "/CN=Janus ephemeral issuer CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        (ca_directory.join("ca.pem"), ca_directory.join("ca.key"))
    }

    fn generate_server_certificate(
        directory: &Path,
        ca_certificate: &Path,
        ca_private_key: &Path,
    ) -> (PathBuf, PathBuf) {
        let server_directory = directory.join("server");
        fs::create_dir(&server_directory).unwrap();
        run_openssl(
            &server_directory,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-subj",
                "/CN=127.0.0.1",
            ],
        );
        fs::write(
            server_directory.join("server.ext"),
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n",
        )
        .unwrap();
        run_openssl(
            &server_directory,
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                ca_certificate.to_str().unwrap(),
                "-CAkey",
                ca_private_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                "server.pem",
                "-days",
                "2",
                "-sha256",
                "-extfile",
                "server.ext",
            ],
        );
        (
            server_directory.join("server.pem"),
            server_directory.join("server.key"),
        )
    }

    fn start_https_server(
        certificate: &Path,
        private_key: &Path,
    ) -> (String, thread::JoinHandle<()>) {
        use ureq::rustls::pki_types::pem::PemObject as _;

        let certificate = ureq::rustls::pki_types::CertificateDer::from_pem_file(certificate)
            .expect("read test server certificate");
        let private_key = ureq::rustls::pki_types::PrivateKeyDer::from_pem_file(private_key)
            .expect("read test server private key");
        let server_config = ureq::rustls::ServerConfig::builder_with_provider(
            ureq::rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&ureq::rustls::version::TLS12, &ureq::rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = ureq::rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = ureq::rustls::StreamOwned::new(connection, stream);
            let mut request = [0u8; 4096];
            if std::io::Read::read(&mut stream, &mut request).is_ok() {
                let body = br#"{"access_token":"fixture","token_type":"Bearer","expires_in":300}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.conn.complete_io(&mut stream.sock);
            }
        });
        (format!("https://127.0.0.1:{port}"), handle)
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
    fn invalidation_regenerates_the_exact_application_and_returns_no_value() {
        let config = ZitadelOidcClientConfig::new(
            "https://identity.example.test",
            "111111111111111111",
            "222222222222222222",
            10,
        )
        .unwrap();
        let transport = FakeTransport::default();
        let (profile, _) = fixture_profile();
        let connector = ZitadelOidcClientConnector::new(transport, FixedClock);
        assert_eq!(connector.invalidate(&config, profile), Ok(()));
        let (endpoint, _, request) = connector.transport.generate.lock().unwrap().take().unwrap();
        assert_eq!(
            endpoint,
            "https://identity.example.test/zitadel.application.v2.ApplicationService/GenerateClientSecret"
        );
        let request: Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["applicationId"], "222222222222222222");
        assert_eq!(request["projectId"], "111111111111111111");
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

    #[test]
    fn pinned_ca_extends_public_trust_and_wrong_ca_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let (trusted_ca, trusted_key) = generate_test_ca(temporary.path(), "trusted-ca");
        let (wrong_ca, _) = generate_test_ca(temporary.path(), "wrong-ca");
        let (server_certificate, server_key) =
            generate_server_certificate(temporary.path(), &trusted_ca, &trusted_key);
        let trusted_digest = hex::encode(sha2::Sha256::digest(fs::read(&trusted_ca).unwrap()));
        let wrong_digest = hex::encode(sha2::Sha256::digest(fs::read(&wrong_ca).unwrap()));

        let (origin, success_server) = start_https_server(&server_certificate, &server_key);
        let trusted = PinnedCa::new(trusted_ca.to_str().unwrap(), &trusted_digest).unwrap();
        let transport = UreqZitadelTransport::new(Some(trusted));
        let result = transport.post_form(
            &format!("{origin}/oauth/v2/token"),
            &SecretValue::new(b"grant_type=fixture".to_vec()),
            Duration::from_secs(5),
        );
        assert!(result.is_ok());
        success_server.join().unwrap();

        let (origin, wrong_ca_server) = start_https_server(&server_certificate, &server_key);
        let wrong = PinnedCa::new(wrong_ca.to_str().unwrap(), &wrong_digest).unwrap();
        let transport = UreqZitadelTransport::new(Some(wrong));
        assert!(transport
            .post_form(
                &format!("{origin}/oauth/v2/token"),
                &SecretValue::new(b"grant_type=fixture".to_vec()),
                Duration::from_secs(5),
            )
            .is_err());
        wrong_ca_server.join().unwrap();
    }

    #[test]
    fn custom_ca_requires_a_complete_pinned_absolute_pair() {
        assert!(ZitadelOidcClientConfig::new_with_optional_ca(
            "https://identity.example.test",
            "1",
            "2",
            10,
            Some("/run/janus/issuer-ca.pem"),
            None,
        )
        .is_err());
        assert!(ZitadelOidcClientConfig::new_with_optional_ca(
            "https://identity.example.test",
            "1",
            "2",
            10,
            Some("issuer-ca.pem"),
            Some(&"a".repeat(64)),
        )
        .is_err());
        assert!(ZitadelOidcClientConfig::new_with_optional_ca(
            "https://identity.example.test",
            "1",
            "2",
            10,
            None,
            None,
        )
        .unwrap()
        .custom_ca()
        .is_none());
    }
}
