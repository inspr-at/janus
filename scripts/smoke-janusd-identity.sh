#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
identity_bin="${JANUSD_IDENTITY_BIN:-${repo}/target/debug/janusd-identityd}"
fixture="$(mktemp -d)"
pid=""

cleanup() {
  if [[ -n "${pid}" ]]; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${fixture}"
}
trap cleanup EXIT

[[ -x "${identity_bin}" ]] || {
  echo "janusd-identityd binary is not executable" >&2
  exit 1
}

mkdir -p "${fixture}/registry" "${fixture}/run" "${fixture}/state"
chmod 0700 "${fixture}/registry" "${fixture}/run" "${fixture}/state"

python3 - "${fixture}/registry" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import time

root = pathlib.Path(sys.argv[1])
subject = "act_11111111111111111111111111111111"

def fingerprint(domain: str, value: bytes) -> str:
    digest = hashlib.sha256()
    encoded = domain.encode()
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)
    return "sha256:" + digest.hexdigest()

record = {
    "schema_version": 1,
    "subject_ref": subject,
    "subject_class": "human",
    "trust_adapter": "local_peer",
    "trust_domain_fingerprint": fingerprint("janus-identity-trust-domain-v1", b"smoke-host"),
    "local_uid": os.getuid(),
    "enrolled_at_unix_secs": int(time.time()),
    "review_fingerprint": fingerprint("janus-subject-review-v1", b"synthetic-smoke-review"),
}
path = root / f"{subject}.json"
path.write_text(json.dumps(record, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY

export JANUS_IDENTITY_SOCKET="${fixture}/run/identity.sock"
export JANUS_IDENTITY_REGISTRY_ROOT="${fixture}/registry"
export JANUS_IDENTITY_SIGNING_KEY_FILE="${fixture}/state/signing.key"
export JANUS_IDENTITY_TRANSPORT_MANIFEST="${repo}/config/identity/transport-manifest-v1.json"
export JANUS_IDENTITY_TRUST_DOMAIN="smoke-host"
export JANUS_IDENTITY_AUDIENCE="janus-identity-smoke"
export JANUS_RELEASE_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export JANUS_IDENTITY_ASSERTION_TTL_SECONDS="60"
export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="test"
export JANUS_DUTY_SURFACE_MANIFEST="${repo}/config/authorization/duty-surface-manifest-v1.json"
export JANUS_ACCOUNTABILITY_POSTURE="accountability_legacy"
export JANUS_RUNTIME_AUTHORITY_AUDIENCE="janus-runtime-smoke"
export JANUS_RUNTIME_AUTHORITY_VERIFYING_KEY_FILE="${fixture}/state/runtime-authority.pub"
export JANUS_OPERATION_VERIFYING_KEY_FILE="${fixture}/state/runtime-authority.pub"
export JANUS_OPERATION_DOMAIN_SERVICE="smoke-domain"
export JANUS_OPERATION_AUDIENCE="janus-runtime-smoke"
export JANUS_RUNTIME_AUTHORITY_AUDIT_FILE="${fixture}/state/runtime-authority.jsonl"

"${identity_bin}" >"${fixture}/stdout" 2>"${fixture}/stderr" &
pid="$!"
for _ in $(seq 1 100); do
  [[ -S "${JANUS_IDENTITY_SOCKET}" ]] && break
  kill -0 "${pid}" >/dev/null 2>&1 || {
    echo "janusd-identityd exited before creating its socket" >&2
    exit 1
  }
  sleep 0.02
done
[[ -S "${JANUS_IDENTITY_SOCKET}" ]] || {
  echo "janusd-identityd socket was not created" >&2
  exit 1
}

python3 - "${JANUS_IDENTITY_SOCKET}" <<'PY'
import json
import socket
import sys

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(sys.argv[1])
stream = client.makefile("rwb", buffering=0)
request = {
    "schema_version": 1,
    "scope_ref": "scp_1111111111111111111111111111111111111111",
    "surface": "janusd-use",
}

def transact(body):
    stream.write(json.dumps(body, separators=(",", ":")).encode() + b"\n")
    return json.loads(stream.readline())

first = transact(request)
second = transact(request)
if not first["ok"] or not second["ok"]:
    raise SystemExit("enrolled connected peer was denied")
for reply in (first, second):
    if reply["authority"] != "none" or reply["value_returned"] is not False:
        raise SystemExit("identity broker returned authority or a value")
    observation = reply["observation"]
    if observation["subject_ref"] != "act_11111111111111111111111111111111":
        raise SystemExit("identity broker did not resolve the kernel-connected peer")
    if observation["posture"] != "identity_shadow_only" or observation["authority"] != "none":
        raise SystemExit("identity observation posture broadened")
    if len(observation["signature"]) != 128:
        raise SystemExit("identity observation is not signed")
if first["observation"]["nonce_ref"] == second["observation"]["nonce_ref"]:
    raise SystemExit("identity broker reused a request nonce")

injected = dict(request)
injected["subject_ref"] = "act_22222222222222222222222222222222"
denied = transact(injected)
if denied["ok"] or denied["observation"] is not None or denied["value_returned"] is not False:
    raise SystemExit("identity broker accepted caller-supplied identity")
client.close()
PY

[[ ! -s "${fixture}/stdout" ]] || {
  echo "janusd-identityd wrote unexpected stdout" >&2
  exit 1
}

echo "ok: identity shadow broker kernel_peer=derived caller_identity=denied authority=none value_returned=false"
