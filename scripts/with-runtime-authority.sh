#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scope_environment="${1:?scope environment is required}"
shift
[[ "$#" -gt 0 ]] || { echo "wrapped command is required" >&2; exit 2; }

fixture="$(mktemp -d)"
authority_pid=""
cleanup() {
  status="$?"
  if [[ -n "${authority_pid}" ]]; then
    kill "${authority_pid}" >/dev/null 2>&1 || true
    wait "${authority_pid}" >/dev/null 2>&1 || true
  fi
  if [[ "${status}" -ne 0 && -s "${fixture}/identity.stderr" ]]; then
    sed -n '1,120p' "${fixture}/identity.stderr" >&2
  fi
  rm -rf "${fixture}"
  return "${status}"
}
trap cleanup EXIT

mkdir -p "${fixture}/registry" "${fixture}/run" "${fixture}/state" "${fixture}/audit"
chmod 0700 "${fixture}/registry" "${fixture}/run" "${fixture}/state" "${fixture}/audit"

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
    "trust_domain_fingerprint": fingerprint("janus-identity-trust-domain-v1", b"assurance-host"),
    "local_uid": os.getuid(),
    "enrolled_at_unix_secs": int(time.time()),
    "review_fingerprint": fingerprint("janus-subject-review-v1", b"synthetic-assurance-review"),
}
path = root / f"{subject}.json"
path.write_text(json.dumps(record, separators=(",", ":")), encoding="utf-8")
path.chmod(0o600)
PY

export JANUS_SCOPE_ORGANIZATION="fixture-org"
export JANUS_SCOPE_PROJECT="janus"
export JANUS_SCOPE_REPOSITORY="janus"
export JANUS_SCOPE_ENVIRONMENT="${scope_environment}"
export JANUS_IDENTITY_SOCKET="${fixture}/run/identity.sock"
export JANUS_IDENTITY_REGISTRY_ROOT="${fixture}/registry"
export JANUS_IDENTITY_SIGNING_KEY_FILE="${fixture}/state/identity-signing.key"
export JANUS_IDENTITY_TRANSPORT_MANIFEST="${repo}/config/identity/transport-manifest-v1.json"
export JANUS_IDENTITY_TRUST_DOMAIN="assurance-host"
export JANUS_IDENTITY_AUDIENCE="janus-identity-assurance"
export JANUS_IDENTITY_ASSERTION_TTL_SECONDS="60"
export JANUS_DUTY_SURFACE_MANIFEST="${repo}/config/authorization/duty-surface-manifest-v1.json"
export JANUS_ACCOUNTABILITY_POSTURE="accountability_legacy"
export JANUS_RUNTIME_AUTHORITY_AUDIENCE="janus-runtime-assurance"
export JANUS_RUNTIME_AUTHORITY_VERIFYING_KEY_FILE="${fixture}/state/runtime-authority.pub"
export JANUS_OPERATION_VERIFYING_KEY_FILE="${fixture}/state/runtime-authority.pub"
export JANUS_OPERATION_DOMAIN_SERVICE="assurance-domain"
export JANUS_OPERATION_AUDIENCE="janus-runtime-assurance"
export JANUS_RUNTIME_AUTHORITY_AUDIT_FILE="${fixture}/audit/runtime-authority.jsonl"
export JANUS_RELEASE_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

"${repo}/target/debug/janusd-identityd" >"${fixture}/identity.stdout" 2>"${fixture}/identity.stderr" &
authority_pid="$!"
for _ in $(seq 1 100); do
  [[ -S "${JANUS_IDENTITY_SOCKET}" ]] && break
  kill -0 "${authority_pid}" >/dev/null 2>&1 || {
    sed -n '1,80p' "${fixture}/identity.stderr" >&2
    exit 1
  }
  sleep 0.02
done
[[ -S "${JANUS_IDENTITY_SOCKET}" ]] || { echo "runtime authority socket unavailable" >&2; exit 1; }

"$@"
