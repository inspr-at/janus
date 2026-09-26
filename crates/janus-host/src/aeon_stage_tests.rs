//! Strict Aeon mock and fail-closed tests for the Aeon stage reporter.
//!
//! `FakeAeon` implements the stage-handoff semantics of the pinned Aeon
//! commit (routed agent key, live grant, authority epoch, contiguous
//! sequences, exact replay, seal echo, Janus checks) and refuses any request
//! whose headers or JSON keys differ from what the contract allows.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tempfile::TempDir;

use super::*;

pub(crate) const PROJECT_NODE_ID: &str = "71d807c5-6ee1-4a18-8742-54ed5b74690d";
pub(crate) const HANDOFF_ID: &str = "3f1e2d4c-5b6a-4798-8a1b-2c3d4e5f6a7b";
pub(crate) const RELEASE_NODE_ID: &str = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d";
/// Far future so the managed end-to-end test may use the real clock.
pub(crate) const EXPIRES_AT: &str = "2099-09-27T07:00:00.123456Z";
pub(crate) const SEAL: &str = "5555555555555555555555555555555555555555555555555555555555555555";
pub(crate) const API_KEY: &str = "aeon_fixtureprefix_inertfixturevalue0123";
/// 2026-09-26T08:00:00Z
pub(crate) const NOW: i64 = 1_790_409_600;
pub(crate) const CREDENTIAL_READY_AT: &str = "2026-09-26T07:59:30Z";

#[derive(Clone, Debug)]
pub(crate) struct Captured {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: BTreeMap<String, Vec<String>>,
    pub(crate) body: Vec<u8>,
}

/// Mutable server state. Tests adjust it to simulate Aeon-side changes.
pub(crate) struct AeonState {
    pub(crate) journey: Value,
    pub(crate) handoff: Value,
    pub(crate) grant_live: bool,
    /// Whether the key's principal is the routed plugin principal, which
    /// Aeon requires for the handoff read (without stage_handoffs.read).
    pub(crate) routed_agent: bool,
    /// Principal name `GET /api/me` reports for the key.
    pub(crate) agent_name: &'static str,
    pub(crate) evidence: Vec<Value>,
    pub(crate) result: Option<Value>,
    pub(crate) requests: Vec<Captured>,
    /// Process the next request on this path, then drop the connection
    /// before answering: an ambiguous transport failure.
    pub(crate) drop_after: Option<String>,
    pub(crate) content_type: &'static str,
}

pub(crate) struct FakeAeon {
    pub(crate) origin: String,
    pub(crate) state: Arc<Mutex<AeonState>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeAeon {
    pub(crate) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Aeon");
        listener
            .set_nonblocking(true)
            .expect("nonblocking fake Aeon");
        let origin = format!("http://{}", listener.local_addr().expect("fake address"));
        let state = Arc::new(Mutex::new(AeonState {
            journey: journey_body(),
            handoff: handoff_body(),
            grant_live: true,
            routed_agent: true,
            agent_name: "janus",
            evidence: Vec::new(),
            result: None,
            requests: Vec::new(),
            drop_after: None,
            content_type: "application/json; charset=utf-8",
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        serve(stream, &thread_state);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fake Aeon accept failed: {error}"),
                }
            }
        });
        Self {
            origin,
            state,
            stop,
            handle: Some(handle),
        }
    }

    pub(crate) fn with<T>(&self, change: impl FnOnce(&mut AeonState) -> T) -> T {
        change(&mut self.state.lock().expect("fake Aeon state"))
    }

    pub(crate) fn requests(&self) -> Vec<Captured> {
        self.with(|state| state.requests.clone())
    }

    pub(crate) fn take_requests(&self) -> Vec<Captured> {
        self.with(|state| std::mem::take(&mut state.requests))
    }
}

impl Drop for FakeAeon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(crate) fn journey_body() -> Value {
    json!({
        "project_node_id": PROJECT_NODE_ID,
        "project_key": "JANUS",
        "node_key": "PRJ-12",
        "tenant_slug": "inspr",
        "profile": "professional",
        "revision": 7,
        "stage": "access",
        "stage_source": "journey",
        "stages": [{"key": "access", "state": "current", "gate_approval_id": null, "handoff_id": HANDOFF_ID}],
        "next_action": {"key": "approve_permit", "label": "Approve permit", "stage": "access", "available": true},
        "requirements_revision": 2,
        "requirements_digest_sha256": "6".repeat(64),
        "requirements_approval_scope": "requirements:2",
        "launch_readiness": {"can_admit": false, "reason": ""},
        "current_release_id": RELEASE_NODE_ID
    })
}

pub(crate) fn handoff_body() -> Value {
    json!({
        "id": HANDOFF_ID,
        "project_node_id": PROJECT_NODE_ID,
        "release_node_id": RELEASE_NODE_ID,
        "stage": "access",
        "operation": "apply",
        "plugin_id": "janus",
        "attempt": 1,
        "authority_epoch": 3,
        "journey_revision": 7,
        "state": "requested",
        "expires_at": EXPIRES_AT,
        "evidence_ceiling": ["authorization", "credential_handoff"],
        "plan_digest": "1".repeat(64),
        "predecessor_digest": "2".repeat(64),
        "context_digest": "3".repeat(64),
        "prerequisite_seal_sha256": SEAL
    })
}

fn serve(stream: TcpStream, state: &Arc<Mutex<AeonState>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone fake stream"));
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() || first.is_empty() {
        return;
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read fake header");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').expect("fake header shape");
        headers
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.trim().to_string());
    }
    let length = headers
        .get("content-length")
        .and_then(|values| values.first())
        .map_or(0, |raw| raw.parse::<usize>().expect("content length"));
    let mut body = vec![0; length];
    reader.read_exact(&mut body).expect("read fake body");
    let captured = Captured {
        method,
        path,
        headers,
        body,
    };
    let mut guard = state.lock().expect("fake Aeon state");
    guard.requests.push(captured.clone());
    let (status, response) = handle(&mut guard, &captured);
    let drop_connection = guard.drop_after.as_deref() == Some(captured.path.as_str());
    if drop_connection {
        guard.drop_after = None;
    }
    let content_type = guard.content_type;
    drop(guard);
    if drop_connection {
        return;
    }
    let body = response.to_string();
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

fn one<'a>(request: &'a Captured, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .filter(|values| values.len() == 1)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn error(status: u16, message: &str) -> (u16, Value) {
    (status, json!({"error": message}))
}

/// Contract-level request checks that apply to every route.
fn transport_refusal(request: &Captured) -> Option<(u16, Value)> {
    let allowed: BTreeSet<&str> = [
        "host",
        "accept",
        "accept-encoding",
        "authorization",
        "content-type",
        "content-length",
        "user-agent",
    ]
    .into_iter()
    .collect();
    if request
        .headers
        .keys()
        .any(|name| !allowed.contains(name.as_str()))
    {
        return Some(error(400, "unexpected header"));
    }
    if one(request, "authorization") != Some(&format!("Bearer {API_KEY}")) {
        return Some(error(401, "authentication required"));
    }
    if one(request, "accept") != Some("application/json") {
        return Some(error(406, "json only"));
    }
    match request.method.as_str() {
        "GET" if request.body.is_empty() && one(request, "content-type").is_none() => None,
        "POST" if one(request, "content-type") == Some("application/json") => None,
        _ => Some(error(400, "invalid request")),
    }
}

fn handle(state: &mut AeonState, request: &Captured) -> (u16, Value) {
    if let Some(refusal) = transport_refusal(request) {
        return refusal;
    }
    let journey_path = format!("/api/projects/{PROJECT_NODE_ID}/journey");
    let handoff_path = format!("/api/stage-handoffs/{HANDOFF_ID}");
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/me") => (
            200,
            json!({
                "dev_mode": false,
                "principal": {"id": "00000000-0000-4000-8000-0000000000aa",
                    "tenant_id": "00000000-0000-4000-8000-0000000000bb",
                    "kind": "agent", "name": state.agent_name, "roles": []},
                "tenant": {"id": "00000000-0000-4000-8000-0000000000bb",
                    "slug": "inspr", "name": "INSPR"},
                "identity": null
            }),
        ),
        ("GET", path) if path == journey_path => (200, state.journey.clone()),
        ("GET", path) if path == handoff_path => {
            if !state.routed_agent {
                return error(403, "permission denied");
            }
            let mut handoff = state.handoff.clone();
            if let Some(result) = &state.result {
                handoff["result"] = result.clone();
            }
            (200, handoff)
        }
        ("POST", path) if path == format!("{handoff_path}/evidence") => evidence(state, request),
        ("POST", path) if path == format!("{handoff_path}/result") => result(state, request),
        _ => error(404, "not found"),
    }
}

fn strict_object(body: &[u8], required: &[&str], optional: &[&str]) -> Option<Map<String, Value>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?.clone();
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let required_set: BTreeSet<&str> = required.iter().copied().collect();
    let allowed: BTreeSet<&str> = required.iter().chain(optional).copied().collect();
    (required_set.is_subset(&keys) && keys.is_subset(&allowed)).then_some(object)
}

fn evidence(state: &mut AeonState, request: &Captured) -> (u16, Value) {
    let Some(input) = strict_object(
        &request.body,
        &[
            "sequence",
            "kind",
            "outcome",
            "observed_at",
            "authority_epoch",
        ],
        &["authorized", "credential_ready"],
    ) else {
        return error(400, "invalid request");
    };
    let valid = match input["kind"].as_str() {
        Some("authorization") => {
            input.get("authorized").is_some_and(Value::is_boolean)
                && !input.contains_key("credential_ready")
        }
        Some("credential_handoff") => {
            input.get("credential_ready").is_some_and(Value::is_boolean)
                && !input.contains_key("authorized")
        }
        _ => false,
    };
    let observed = input["observed_at"].as_str().and_then(parse_instant);
    if !valid
        || observed.is_none()
        || !matches!(input["outcome"].as_str(), Some("satisfied" | "blocked"))
        || !input["sequence"].is_i64()
        || !input["authority_epoch"].is_i64()
    {
        return error(400, "invalid evidence");
    }
    if !state.grant_live {
        return error(403, "live agent grant required");
    }
    if input["authority_epoch"] != state.handoff["authority_epoch"] {
        return error(409, "stale authority");
    }
    let sequence = input["sequence"].as_i64().unwrap_or_default();
    let existing = state
        .evidence
        .iter()
        .find(|row| row["sequence"].as_i64() == Some(sequence))
        .cloned();
    let terminal = state.result.is_some() || state.handoff["state"] == "revoked";
    match existing {
        Some(row) if row == Value::Object(input.clone()) => return (201, evidence_echo(&row)),
        Some(_) => return error(409, "divergent evidence replay"),
        None if terminal => return error(409, "handoff is terminal"),
        None => {}
    }
    if sequence != state.evidence.len() as i64 + 1 {
        return error(409, "evidence sequence must be contiguous");
    }
    let row = Value::Object(input);
    state.evidence.push(row.clone());
    state.handoff["state"] = json!("active");
    (201, evidence_echo(&row))
}

fn evidence_echo(row: &Value) -> Value {
    let mut echo = row.clone();
    echo["backup_observed_at"] = json!(GO_ZERO_TIME);
    echo["handoff_id"] = json!(HANDOFF_ID);
    echo["received_at"] = json!("2026-09-26T08:00:01.250000Z");
    echo
}

fn result(state: &mut AeonState, request: &Captured) -> (u16, Value) {
    let Some(input) = strict_object(
        &request.body,
        &[
            "outcome",
            "terminal_sequence",
            "authority_epoch",
            "prerequisite_seal_sha256",
        ],
        &["blocker_code"],
    ) else {
        return error(400, "invalid request");
    };
    if !state.grant_live {
        return error(403, "live agent grant required");
    }
    let echo = |input: &Map<String, Value>| {
        let mut echo = Value::Object(input.clone());
        echo["handoff_id"] = json!(HANDOFF_ID);
        echo["completed_at"] = json!("2026-09-26T08:00:02.5Z");
        echo
    };
    if let Some(recorded) = &state.result {
        if *recorded == Value::Object(input.clone()) {
            return (200, echo(&input));
        }
        return error(409, "result already recorded");
    }
    if input["authority_epoch"] != state.handoff["authority_epoch"]
        || input["prerequisite_seal_sha256"] != state.handoff["prerequisite_seal_sha256"]
    {
        return error(409, "stale authority or dependency seal");
    }
    let last = state.evidence.len() as i64;
    if input["terminal_sequence"].as_i64() != Some(last) || last == 0 {
        return error(409, "terminal evidence is stale");
    }
    let latest = |kind: &str, flag: &str| {
        state
            .evidence
            .iter()
            .rev()
            .find(|row| row["kind"] == kind)
            .is_some_and(|row| row[flag] == json!(true) && row["outcome"] == "satisfied")
    };
    if input["outcome"] == "succeeded"
        && (state.evidence.last().map(|row| row["kind"].clone())
            != Some(json!("credential_handoff"))
            || !latest("authorization", "authorized")
            || !latest("credential_handoff", "credential_ready"))
    {
        return error(409, "Janus checks are incomplete");
    }
    state.result = Some(Value::Object(input.clone()));
    state.handoff["state"] = json!("succeeded");
    (200, echo(&input))
}

pub(crate) struct Fixture {
    pub(crate) temporary: TempDir,
    pub(crate) owner_uid: u32,
    pub(crate) api_key_file: String,
    pub(crate) journal_directory: String,
}

pub(crate) fn new_fixture() -> Fixture {
    let temporary = tempfile::tempdir().expect("temporary Aeon reporter root");
    let api_key_path = temporary.path().join("janus-reporter.key");
    let journal_directory = temporary.path().join("journal");
    fs::write(&api_key_path, API_KEY).expect("write Aeon key");
    fs::set_permissions(&api_key_path, fs::Permissions::from_mode(0o400)).expect("protect key");
    fs::create_dir(&journal_directory).expect("create journal directory");
    fs::set_permissions(&journal_directory, fs::Permissions::from_mode(0o700))
        .expect("protect journal directory");
    let owner_uid = fs::metadata(&api_key_path).expect("key metadata").uid();
    Fixture {
        owner_uid,
        api_key_file: api_key_path.to_string_lossy().into_owned(),
        journal_directory: journal_directory.to_string_lossy().into_owned(),
        temporary,
    }
}

pub(crate) fn project() -> AeonProjectBindingV1 {
    AeonProjectBindingV1 {
        project_node_id: PROJECT_NODE_ID.to_string(),
        project_key: "JANUS".to_string(),
        node_key: "PRJ-12".to_string(),
        tenant_slug: "inspr".to_string(),
    }
}

pub(crate) fn handoff() -> AeonHandoffBindingV1 {
    AeonHandoffBindingV1 {
        handoff_id: HANDOFF_ID.to_string(),
        release_node_id: RELEASE_NODE_ID.to_string(),
        operation: AeonOperation::Apply,
        authority_epoch: 3,
        plan_digest: "1".repeat(64),
        predecessor_digest: "2".repeat(64),
        context_digest: "3".repeat(64),
        expires_at: EXPIRES_AT.to_string(),
    }
}

fn static_config(fixture: &Fixture, origin: &str) -> AeonStageReporterConfigV1 {
    AeonStageReporterConfigV1 {
        schema: CONFIG_SCHEMA.to_string(),
        schema_version: 1,
        aeon_origin: origin.to_string(),
        aeon_ca_file: None,
        api_key_file: fixture.api_key_file.clone(),
        journal_directory: fixture.journal_directory.clone(),
        project: project(),
        handoff: handoff(),
        evidence: AeonStaticEvidenceV1 {
            credential_ready_observed_at: CREDENTIAL_READY_AT.to_string(),
        },
    }
}

pub(crate) fn managed_config(fixture: &Fixture, origin: &str) -> AeonManagedReporterConfigV1 {
    AeonManagedReporterConfigV1 {
        schema: MANAGED_CONFIG_SCHEMA.to_string(),
        schema_version: 1,
        aeon_origin: origin.to_string(),
        aeon_ca_file: None,
        api_key_file: fixture.api_key_file.clone(),
        journal_directory: fixture.journal_directory.clone(),
        project: project(),
        handoff: handoff(),
        evidence: AeonManagedEvidencePolicyV1 {
            source: MANAGED_EVIDENCE_SOURCE.to_string(),
        },
    }
}

fn run_static(fixture: &Fixture, config: AeonStageReporterConfigV1, now: i64) -> AeonResult<()> {
    let runtime = static_runtime(config, true)?;
    Reporter::new(runtime, fixture.owner_uid, true, now)?.run()
}

fn run(fixture: &Fixture, server: &FakeAeon) -> AeonResult<()> {
    run_static(fixture, static_config(fixture, &server.origin), NOW)
}

fn code(result: AeonResult<()>) -> &'static str {
    result.expect_err("must fail closed").reason_code()
}

fn journal_path(fixture: &Fixture) -> PathBuf {
    Path::new(&fixture.journal_directory).join(format!("aeon-{HANDOFF_ID}.json"))
}

fn body(request: &Captured) -> Value {
    serde_json::from_slice(&request.body).expect("request JSON")
}

fn posts(requests: &[Captured]) -> Vec<Captured> {
    requests
        .iter()
        .filter(|request| request.method == "POST")
        .cloned()
        .collect()
}

/// Every Janus write is exactly the value-free contract shape.
pub(crate) fn assert_value_free(requests: &[Captured], credential_ready_at: &str) {
    let writes = posts(requests);
    assert_eq!(writes.len(), 3, "two evidence rows and one result");
    assert_eq!(
        body(&writes[0]),
        json!({"sequence": 1, "kind": "authorization", "outcome": "satisfied",
               "observed_at": "2026-09-26T08:00:00Z", "authority_epoch": 3, "authorized": true})
    );
    assert_eq!(
        body(&writes[1]),
        json!({"sequence": 2, "kind": "credential_handoff", "outcome": "satisfied",
               "observed_at": credential_ready_at, "authority_epoch": 3, "credential_ready": true})
    );
    assert_eq!(
        body(&writes[2]),
        json!({"outcome": "succeeded", "terminal_sequence": 2, "authority_epoch": 3,
               "prerequisite_seal_sha256": SEAL})
    );
    for request in requests {
        let text = String::from_utf8_lossy(&request.body).to_ascii_lowercase();
        for forbidden in [
            "principal",
            "grant",
            "janus",
            "/",
            "secret",
            "http",
            "sha256:",
            "digest",
            "aeon_",
            "key",
            "project",
            "tenant",
        ] {
            assert!(!text.contains(forbidden), "request body leaked {forbidden}");
        }
        assert!(one(request, "idempotency-key").is_none());
    }
}

#[test]
fn static_reporter_records_only_two_value_free_facts_then_the_sealed_result() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run(&fixture, &server).expect("report succeeds");

    let requests = server.take_requests();
    let routes: Vec<(String, String)> = requests
        .iter()
        .map(|request| (request.method.clone(), request.path.clone()))
        .collect();
    assert_eq!(
        routes,
        vec![
            ("GET".into(), "/api/me".to_string()),
            (
                "GET".into(),
                format!("/api/projects/{PROJECT_NODE_ID}/journey")
            ),
            ("GET".into(), format!("/api/stage-handoffs/{HANDOFF_ID}")),
            (
                "POST".into(),
                format!("/api/stage-handoffs/{HANDOFF_ID}/evidence")
            ),
            (
                "POST".into(),
                format!("/api/stage-handoffs/{HANDOFF_ID}/evidence")
            ),
            (
                "POST".into(),
                format!("/api/stage-handoffs/{HANDOFF_ID}/result")
            ),
        ]
    );
    assert_value_free(&requests, CREDENTIAL_READY_AT);
    server.with(|state| {
        assert_eq!(state.handoff["state"], "succeeded");
        assert_eq!(state.evidence.len(), 2);
    });

    // The journal is namespaced, private, and a completed run is inert.
    let metadata = fs::metadata(journal_path(&fixture)).expect("Aeon journal");
    assert_eq!(metadata.mode() & 0o777, 0o600);
    run(&fixture, &server).expect("completed report is idempotent");
    assert!(server.requests().is_empty());
}

#[test]
fn wrong_project_or_tenant_identity_fails_closed_before_any_write() {
    for (field, value) in [
        (
            "project_node_id",
            json!("00000000-0000-4000-8000-000000000000"),
        ),
        ("project_key", json!("PHAROS")),
        ("node_key", json!("PRJ-13")),
        ("node_key", Value::Null),
        ("tenant_slug", json!("other")),
    ] {
        let fixture = new_fixture();
        let server = FakeAeon::start();
        server.with(|state| state.journey[field] = value.clone());
        assert_eq!(
            code(run(&fixture, &server)),
            "aeon_reporter_project_refused"
        );
        assert!(posts(&server.requests()).is_empty());
        assert!(!journal_path(&fixture).exists());
    }
}

#[test]
fn stale_release_or_authority_fails_closed() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| {
        state.journey["current_release_id"] = json!("00000000-0000-4000-8000-000000000001");
    });
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_release_stale");

    let server = FakeAeon::start();
    server.with(|state| state.handoff["authority_epoch"] = json!(4));
    assert_eq!(
        code(run(&fixture, &server)),
        "aeon_reporter_authority_stale"
    );
    assert!(posts(&server.requests()).is_empty());

    // Authority moves after the journal was written: Aeon refuses the write.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| state.drop_after = Some(format!("/api/stage-handoffs/{HANDOFF_ID}")));
    assert_eq!(
        code(run(&fixture, &server)),
        "aeon_reporter_transport_unavailable"
    );
    assert!(!journal_path(&fixture).exists(), "no journal before a pull");
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    server.with(|state| state.handoff["authority_epoch"] = json!(4));
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_conflict");
}

/// Write the journal and the first evidence row, then fail ambiguously.
fn run_until_journaled(fixture: &Fixture, server: &FakeAeon) {
    server.with(|state| {
        state.drop_after = Some(format!("/api/stage-handoffs/{HANDOFF_ID}/evidence"));
    });
    assert_eq!(
        code(run(fixture, server)),
        "aeon_reporter_transport_unavailable"
    );
    assert!(journal_path(fixture).exists());
}

#[test]
fn wrong_agent_plugin_operation_or_stage_fails_closed() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| state.routed_agent = false);
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_forbidden");

    for (field, value) in [
        ("plugin_id", json!("pharos")),
        ("operation", json!("prepare")),
        ("stage", json!("deploy")),
        (
            "release_node_id",
            json!("00000000-0000-4000-8000-000000000002"),
        ),
        (
            "project_node_id",
            json!("00000000-0000-4000-8000-000000000003"),
        ),
        ("id", json!("00000000-0000-4000-8000-000000000004")),
        ("plan_digest", json!("4".repeat(64))),
        ("expires_at", json!("2099-09-28T07:00:00Z")),
        (
            "evidence_ceiling",
            json!(["credential_handoff", "authorization"]),
        ),
        ("prerequisite_seal_sha256", json!("not-a-seal")),
    ] {
        let fixture = new_fixture();
        let server = FakeAeon::start();
        server.with(|state| state.handoff[field] = value.clone());
        assert_eq!(
            code(run(&fixture, &server)),
            "aeon_reporter_binding_refused",
            "{field}"
        );
        assert!(posts(&server.requests()).is_empty());
    }

    // The wrong key is refused by Aeon before any projection is returned.
    let fixture = new_fixture();
    fs::set_permissions(&fixture.api_key_file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &fixture.api_key_file,
        "aeon_otherprefix_inertothervalue01234",
    )
    .unwrap();
    let server = FakeAeon::start();
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_forbidden");
}

#[test]
fn another_agent_with_a_live_grant_is_refused_before_any_write() {
    // Aeon's writes accept any agent holding the operation grant; Janus
    // proves it is the routed `janus` principal on every run.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| state.agent_name = "pharos");
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_agent_refused");
    assert_eq!(server.requests().len(), 1);
    assert!(!journal_path(&fixture).exists());

    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    server.with(|state| {
        state.agent_name = "pharos";
        state.requests.clear();
    });
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_agent_refused");
    assert!(posts(&server.requests()).is_empty());
}

#[test]
fn a_lost_terminal_answer_is_reconciled_after_expiry_but_nothing_new_is_sent() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| {
        state.drop_after = Some(format!("/api/stage-handoffs/{HANDOFF_ID}/result"));
    });
    assert_eq!(
        code(run(&fixture, &server)),
        "aeon_reporter_transport_unavailable"
    );
    server.with(|state| assert!(state.result.is_some()));
    server.take_requests();

    let expired = parse_instant(EXPIRES_AT).expect("expiry").0 + 1;
    run_static(&fixture, static_config(&fixture, &server.origin), expired)
        .expect("stored result is reconciled");
    let writes = posts(&server.take_requests());
    assert_eq!(writes.len(), 1);
    assert!(writes[0].path.ends_with("/result"));

    // Only the credential fact was pending: expiry refuses new work.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    assert_eq!(
        code(run_static(
            &fixture,
            static_config(&fixture, &server.origin),
            expired
        )),
        "aeon_reporter_handoff_expired"
    );
}

#[test]
fn missing_or_expired_permit_fails_closed() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| state.grant_live = false);
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_forbidden");
    server.with(|state| assert!(state.evidence.is_empty()));

    // An expired handoff is refused locally before any network call.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    let expired = parse_instant(EXPIRES_AT).expect("expiry").0 + 1;
    assert_eq!(
        code(run_static(
            &fixture,
            static_config(&fixture, &server.origin),
            expired
        )),
        "aeon_reporter_handoff_expired"
    );
    assert!(server.requests().is_empty());

    // A permit revoked after the journal was written is still refused.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    server.with(|state| state.grant_live = false);
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_forbidden");
    let late = run_static(&fixture, static_config(&fixture, &server.origin), expired);
    assert_eq!(code(late), "aeon_reporter_handoff_expired");
}

#[test]
fn divergent_replay_and_duplicate_terminal_results_fail_closed() {
    // Another writer already recorded a different first fact.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| {
        state
            .evidence
            .push(json!({"sequence": 1, "kind": "authorization",
            "outcome": "blocked", "observed_at": "2026-09-26T07:00:00Z",
            "authority_epoch": 3, "authorized": false}));
    });
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_conflict");

    // A handoff that already carries a result is never reported again.
    for state_word in ["succeeded", "failed", "revoked", "blocked"] {
        let fixture = new_fixture();
        let server = FakeAeon::start();
        server.with(|state| state.handoff["state"] = json!(state_word));
        assert_eq!(code(run(&fixture, &server)), "aeon_reporter_handoff_closed");
    }
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| {
        state.result = Some(json!({"outcome": "failed", "terminal_sequence": 1,
            "authority_epoch": 3, "prerequisite_seal_sha256": SEAL,
            "blocker_code": "policy_refused"}));
    });
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_handoff_closed");

    // A different terminal result recorded after our journal was written.
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    server.with(|state| {
        state.result = Some(json!({"outcome": "failed", "terminal_sequence": 1,
            "authority_epoch": 3, "prerequisite_seal_sha256": SEAL,
            "blocker_code": "policy_refused"}));
    });
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_conflict");
}

#[test]
fn seal_mismatch_is_refused_by_aeon() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    server.with(|state| state.handoff["prerequisite_seal_sha256"] = json!("7".repeat(64)));
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_conflict");
    server.with(|state| assert!(state.result.is_none()));
}

#[test]
fn ambiguous_failures_replay_exact_journaled_bytes_without_a_new_pull() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);
    let first = posts(&server.take_requests());
    assert_eq!(first.len(), 1);
    let journal_before = fs::read(journal_path(&fixture)).unwrap();

    // Result is processed but its answer is lost.
    server.with(|state| {
        state.drop_after = Some(format!("/api/stage-handoffs/{HANDOFF_ID}/result"));
    });
    assert_eq!(
        code(run_static(
            &fixture,
            static_config(&fixture, &server.origin),
            NOW + 60
        )),
        "aeon_reporter_transport_unavailable"
    );
    let second = server.take_requests();
    assert_eq!(second[0].path, "/api/me", "identity is proven on recovery");
    let second = posts(&second);
    assert_eq!(second.len(), 3, "no new pull on recovery");
    assert_eq!(second[0].body, first[0].body, "exact first-fact replay");
    assert_ne!(fs::read(journal_path(&fixture)).unwrap(), journal_before);

    run_static(&fixture, static_config(&fixture, &server.origin), NOW + 120)
        .expect("exact result replay completes");
    let third = posts(&server.take_requests());
    assert_eq!(third.len(), 1);
    assert!(third[0].path.ends_with("/result"));
    server.with(|state| {
        assert_eq!(state.evidence.len(), 2);
        assert_eq!(state.result.as_ref().unwrap()["outcome"], "succeeded");
    });
}

#[test]
fn journal_is_bound_to_config_contract_and_namespace() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    run_until_journaled(&fixture, &server);

    // Changing any reviewed config value invalidates the journal.
    let mut changed = static_config(&fixture, &server.origin);
    changed.evidence.credential_ready_observed_at = "2026-09-26T07:59:31Z".to_string();
    assert_eq!(
        code(run_static(&fixture, changed, NOW)),
        "aeon_reporter_journal_invalid"
    );

    // A tampered request body is refused.
    let raw = fs::read_to_string(journal_path(&fixture)).unwrap();
    let tampered = raw.replace("\\\"authorized\\\":true", "\\\"authorized\\\":false");
    assert_ne!(raw, tampered);
    fs::write(journal_path(&fixture), tampered).unwrap();
    assert_eq!(
        code(run(&fixture, &server)),
        "aeon_reporter_journal_invalid"
    );

    // Classic journals and locks are never read or written by this adapter.
    let fixture = new_fixture();
    let classic = Path::new(&fixture.journal_directory).join("01ARZ3NDEKTSV4RRFFQ69G5FAV.json");
    fs::write(&classic, b"classic receipt bytes").unwrap();
    fs::set_permissions(&classic, fs::Permissions::from_mode(0o600)).unwrap();
    let unprefixed = Path::new(&fixture.journal_directory).join(format!("{HANDOFF_ID}.json"));
    fs::write(&unprefixed, b"not an Aeon journal").unwrap();
    let server = FakeAeon::start();
    run(&fixture, &server).expect("namespaced report succeeds");
    assert_eq!(fs::read(&classic).unwrap(), b"classic receipt bytes");
    assert_eq!(fs::read(&unprefixed).unwrap(), b"not an Aeon journal");
    let mut names: Vec<String> = fs::read_dir(&fixture.journal_directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            format!(".aeon-{HANDOFF_ID}.lock"),
            "01ARZ3NDEKTSV4RRFFQ69G5FAV.json".to_string(),
            format!("{HANDOFF_ID}.json"),
            format!("aeon-{HANDOFF_ID}.json"),
        ]
    );
}

#[test]
fn responses_are_strict_json_of_the_pinned_contract() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    server.with(|state| state.handoff["new_field"] = json!(true));
    assert_eq!(
        code(run(&fixture, &server)),
        "aeon_reporter_response_invalid"
    );

    let server = FakeAeon::start();
    server.with(|state| state.content_type = "text/html");
    assert_eq!(code(run(&fixture, &server)), "aeon_reporter_media_refused");
}

#[test]
fn api_key_custody_and_shape_are_strict() {
    for (key, mode) in [
        ("aeon_fixtureprefix_inertfixturevalue0123\n", 0o400),
        ("paimos_janusprefix_s3cretvalue0123456789", 0o400),
        ("aeon_fixture_prefix_inertfixturevalue0123", 0o400),
        ("aeon__inertfixturevalue012345678", 0o400),
        (API_KEY, 0o440),
    ] {
        let fixture = new_fixture();
        fs::set_permissions(&fixture.api_key_file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&fixture.api_key_file, key).unwrap();
        fs::set_permissions(&fixture.api_key_file, fs::Permissions::from_mode(mode)).unwrap();
        let server = FakeAeon::start();
        let reason = code(run(&fixture, &server));
        assert!(
            reason == "aeon_reporter_api_key_invalid"
                || reason == "aeon_reporter_api_key_unavailable",
            "{reason}"
        );
        assert!(server.requests().is_empty());
    }
}

#[test]
fn config_selects_adapter_by_schema_and_rejects_bad_shapes() {
    let fixture = new_fixture();
    let config = static_config(&fixture, "https://aeon.example");
    let raw = serde_json::to_vec(&config).unwrap();
    assert!(selects_aeon(&raw, CONFIG_SCHEMA));
    assert!(!selects_aeon(&raw, MANAGED_CONFIG_SCHEMA));
    let classic =
        include_bytes!("../../../examples/paimos-dependency-reporter/config.example.json");
    assert!(!selects_aeon(classic, CONFIG_SCHEMA));
    assert!(!selects_aeon(b"{\"schema\":1}", CONFIG_SCHEMA));

    let mut value = serde_json::to_value(&config).unwrap();
    value["handoff_secret_file"] = json!("/forbidden");
    assert!(decode::<AeonStageReporterConfigV1>(
        value.to_string().as_bytes(),
        "aeon_reporter_config_invalid"
    )
    .is_err());

    let mutations: Vec<fn(&mut AeonStageReporterConfigV1)> = vec![
        |config| config.aeon_origin = "http://aeon.example".into(),
        |config| config.aeon_origin = "https://aeon.example/api".into(),
        |config| config.api_key_file = "relative/key".into(),
        |config| config.project.project_node_id = PROJECT_NODE_ID.to_uppercase(),
        |config| config.project.project_key = "janus".into(),
        |config| config.project.node_key = "PRJ-012".into(),
        |config| config.project.tenant_slug = "Inspr".into(),
        |config| config.handoff.handoff_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        |config| config.handoff.authority_epoch = 0,
        |config| config.handoff.plan_digest = format!("sha256:{}", "1".repeat(64)),
        |config| config.handoff.expires_at = "tomorrow".into(),
        |config| config.evidence.credential_ready_observed_at = "2026-09-26T07:59:30.5Z".into(),
        |config| config.schema_version = 2,
    ];
    for mutate in mutations {
        let mut changed = config.clone();
        mutate(&mut changed);
        assert!(static_runtime(changed, false).is_err());
    }
}

#[test]
fn checked_example_parses_and_validates() {
    let raw = include_bytes!("../../../examples/aeon-stage-reporter/config.example.json");
    assert!(selects_aeon(raw, CONFIG_SCHEMA));
    let config: AeonStageReporterConfigV1 =
        decode(raw, "aeon_reporter_config_invalid").expect("example decodes");
    static_runtime(config, false).expect("example validates");
    let raw = include_bytes!("../../../examples/aeon-stage-reporter/managed-config.example.json");
    let config: AeonManagedReporterConfigV1 =
        decode(raw, "aeon_reporter_config_invalid").expect("managed example decodes");
    managed_reporter_binding(&config, false).expect("managed example validates");
}

#[test]
fn managed_binding_pins_config_and_evidence_time_comes_from_the_record() {
    let fixture = new_fixture();
    let server = FakeAeon::start();
    let config = managed_config(&fixture, &server.origin);
    let binding = managed_reporter_binding(&config, true).expect("binding");
    validate_managed_reporter_binding_shape(&binding).expect("binding shape");
    let raw = serde_json::to_vec(&config).unwrap();
    let path = fixture.temporary.path().join("managed-config.json");
    fs::write(&path, raw).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut other = binding.clone();
    other.authority_epoch = 4;
    assert_eq!(
        run_managed_completion_from_path(
            &path,
            &other,
            CREDENTIAL_READY_AT.into(),
            fixture.owner_uid,
            true
        )
        .expect_err("binding drift")
        .reason_code(),
        "aeon_reporter_binding_refused"
    );
    assert!(server.requests().is_empty());

    let runtime = managed_runtime(config, &binding, "2026-09-26T07:58:00Z".into(), true).unwrap();
    Reporter::new(runtime, fixture.owner_uid, true, NOW)
        .unwrap()
        .run()
        .expect("managed report succeeds");
    assert_value_free(&server.requests(), "2026-09-26T07:58:00Z");
}

#[test]
fn instants_parse_go_time_forms() {
    assert_eq!(parse_instant("2026-09-26T08:00:00Z"), Some((NOW, 0)));
    assert_eq!(
        parse_instant("2026-09-26T08:00:00.123456Z"),
        Some((NOW, 123_456_000))
    );
    assert_eq!(parse_instant("2026-09-26T10:00:00+02:00"), Some((NOW, 0)));
    assert_eq!(parse_instant("2026-09-26T07:30:00-00:30"), Some((NOW, 0)));
    assert_eq!(parse_instant(GO_ZERO_TIME).map(|(_, nanos)| nanos), Some(0));
    for bad in [
        "2026-09-26T08:00:00",
        "2026-09-26T08:00:00.Z",
        "2026-09-26T08:00:00.1234567891Z",
        "2026-09-26 08:00:00Z",
        "2026-09-26T08:00:00+2:00",
        "2026-02-30T08:00:00Z",
    ] {
        assert_eq!(parse_instant(bad), None, "{bad}");
    }
}
