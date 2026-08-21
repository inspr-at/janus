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

mkdir -p "${fixture}/review"
chmod 0700 "${fixture}/review"

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

# Reviewed offline enrollment of the assurance peer (JANUS-453), before the
# broker starts: no hand-written registry JSON.
export JANUS_IDENTITY_REVIEW_VERIFYING_KEY_FILE="${fixture}/review/reviewer.pub"
export JANUS_IDENTITY_ADMIN_AUDIT_FILE="${fixture}/audit/identity-admin.jsonl"
"${repo}/target/debug/janusd-identity-admin" review-keys \
  --signing-key-file "${fixture}/review/reviewer.key" \
  --verifying-key-file "${JANUS_IDENTITY_REVIEW_VERIFYING_KEY_FILE}" >/dev/null
python3 - "${fixture}/review/enroll.request.json" <<'PY'
import json
import os
import sys

request = {
    "schema_version": 1,
    "verb": "enroll",
    "trust_domain": "assurance-host",
    "local_uid": os.getuid(),
    "subject_class": "human",
    "ttl_seconds": 600,
    "reviewer": "synthetic-assurance-review",
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(request, handle, separators=(",", ":"))
PY
"${repo}/target/debug/janusd-identity-admin" review-sign \
  --request-file "${fixture}/review/enroll.request.json" \
  --signing-key-file "${fixture}/review/reviewer.key" \
  --out "${fixture}/review/enroll.evidence.json" >/dev/null
"${repo}/target/debug/janusd-identity-admin" enroll \
  --review-evidence-file "${fixture}/review/enroll.evidence.json" >/dev/null

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
