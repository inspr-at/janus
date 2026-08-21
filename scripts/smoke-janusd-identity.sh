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

identity_admin_bin="${JANUSD_IDENTITY_ADMIN_BIN:-${repo}/target/debug/janusd-identity-admin}"
[[ -x "${identity_admin_bin}" ]] || {
  echo "janusd-identity-admin binary is not executable" >&2
  exit 1
}
mkdir -p "${fixture}/review"
chmod 0700 "${fixture}/review"

# Enrollment goes through the reviewed, offline administrator (JANUS-453):
# reviewer keys, a signed operation-bound request, then `enroll` while the
# broker is not running. No hand-written registry JSON.
export JANUS_IDENTITY_REGISTRY_ROOT="${fixture}/registry"
export JANUS_IDENTITY_TRUST_DOMAIN="smoke-host"
export JANUS_IDENTITY_REVIEW_VERIFYING_KEY_FILE="${fixture}/review/reviewer.pub"
export JANUS_IDENTITY_ADMIN_AUDIT_FILE="${fixture}/state/identity-admin.jsonl"
export JANUS_ACCOUNTABILITY_POSTURE="accountability_legacy"
"${identity_admin_bin}" review-keys \
  --signing-key-file "${fixture}/review/reviewer.key" \
  --verifying-key-file "${JANUS_IDENTITY_REVIEW_VERIFYING_KEY_FILE}" >/dev/null
python3 - "${fixture}/review/enroll.request.json" <<'PY'
import json
import os
import sys

request = {
    "schema_version": 1,
    "verb": "enroll",
    "trust_domain": "smoke-host",
    "local_uid": os.getuid(),
    "subject_class": "human",
    "ttl_seconds": 600,
    "reviewer": "synthetic-smoke-review",
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(request, handle, separators=(",", ":"))
PY
"${identity_admin_bin}" review-sign \
  --request-file "${fixture}/review/enroll.request.json" \
  --signing-key-file "${fixture}/review/reviewer.key" \
  --out "${fixture}/review/enroll.evidence.json" >/dev/null
enrolled="$("${identity_admin_bin}" enroll --review-evidence-file "${fixture}/review/enroll.evidence.json")"
subject_ref="$(python3 - "${enrolled}" <<'PY'
import json
import sys

outcome = json.loads(sys.argv[1])
if not outcome["ok"] or outcome["status"] != "active" or outcome["value_returned"] is not False:
    raise SystemExit("identity admin enrollment outcome broadened")
if "local_uid" in sys.argv[1]:
    raise SystemExit("identity admin outcome leaked the local uid")
print(outcome["subject_ref"])
PY
)"
[[ "${subject_ref}" == act_* ]] || {
  echo "identity admin did not mint an opaque subject ref" >&2
  exit 1
}

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

# A dead socket left by a previous broker (torn-down sidecar, crash) must not
# block startup: the broker reclaims it and serves on the same path (JANUS-451).
python3 - "${JANUS_IDENTITY_SOCKET}" <<'PY'
import os
import socket
import sys

path = sys.argv[1]
leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
leftover.bind(path)
leftover.close()
os.chmod(path, 0o600)
PY
[[ -S "${JANUS_IDENTITY_SOCKET}" ]] || {
  echo "fixture stale socket was not created" >&2
  exit 1
}

"${identity_bin}" >"${fixture}/stdout" 2>"${fixture}/stderr" &
pid="$!"
# Readiness is accept-connect, never file existence: the stale file above would
# otherwise look ready before the broker listens.
ready=0
for _ in $(seq 1 200); do
  if python3 - "${JANUS_IDENTITY_SOCKET}" <<'PY'
import socket
import sys

probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
probe.settimeout(0.2)
try:
    probe.connect(sys.argv[1])
except OSError:
    raise SystemExit(1)
probe.close()
PY
  then
    ready=1
    break
  fi
  kill -0 "${pid}" >/dev/null 2>&1 || {
    echo "janusd-identityd exited before accepting connections" >&2
    cat "${fixture}/stderr" >&2 || true
    exit 1
  }
  sleep 0.02
done
[[ "${ready}" -eq 1 ]] || {
  echo "janusd-identityd never accepted a connection" >&2
  exit 1
}

python3 - "${JANUS_IDENTITY_SOCKET}" "${subject_ref}" <<'PY'
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
    if observation["subject_ref"] != sys.argv[2]:
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

# A runtime-authority request whose scope does not match the broker scope must
# be answered with its specific value-free reason code (JANUS-450).
mismatched = transact(
    {
        "schema_version": 1,
        "scope_ref": "scp_" + "1" * 40,
        "action": "warden.health",
        "operation": None,
        "audit_ref": "aud_" + "2" * 24,
    }
)
if mismatched["ok"] or mismatched.get("admission") is not None or mismatched["value_returned"] is not False:
    raise SystemExit("runtime authority admitted a mismatched scope")
if mismatched.get("reason_code") != "runtime_authority_request_context_mismatch":
    raise SystemExit(f"runtime authority denial reason code broadened: {mismatched.get('reason_code')!r}")
client.close()
PY

# The broker must leave value-free evidence for that denial.
python3 - "${JANUS_RUNTIME_AUTHORITY_AUDIT_FILE}" <<'PY'
import json
import pathlib
import sys

lines = [line for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
if len(lines) != 1:
    raise SystemExit(f"expected exactly one runtime authority audit line, found {len(lines)}")
event = json.loads(lines[0])
expected = {
    "outcome": "denied",
    "reason_code": "runtime_authority_request_context_mismatch",
    "actor_subject_ref": "unresolved",
    "action": "warden.health",
    "posture": "accountability_legacy",
    "admission_id": None,
    "value_returned": False,
}
for key, value in expected.items():
    if event.get(key) != value:
        raise SystemExit(f"runtime authority denial audit field {key!r} is {event.get(key)!r}")
if "uid" in lines[0] or "pid" in lines[0]:
    raise SystemExit("runtime authority denial audit leaked peer credentials")
PY

[[ ! -s "${fixture}/stdout" ]] || {
  echo "janusd-identityd wrote unexpected stdout" >&2
  exit 1
}

# While the broker runs, `list` works (shared lifecycle lock) and mutations
# fail closed with identity_broker_running (JANUS-453).
listed="$("${identity_admin_bin}" list)"
python3 - "${listed}" "${subject_ref}" <<'PY'
import json
import sys

outcome = json.loads(sys.argv[1])
entries = outcome["entries"]
if not any(entry["subject_ref"] == sys.argv[2] and entry["status"] == "active" for entry in entries):
    raise SystemExit("identity admin list did not show the enrolled subject")
if "local_uid" in sys.argv[1]:
    raise SystemExit("identity admin list leaked a local uid")
PY
"${identity_admin_bin}" review-sign \
  --request-file "${fixture}/review/enroll.request.json" \
  --signing-key-file "${fixture}/review/reviewer.key" \
  --out "${fixture}/review/enroll-2.evidence.json" >/dev/null
if "${identity_admin_bin}" enroll --review-evidence-file "${fixture}/review/enroll-2.evidence.json" \
  >/dev/null 2>"${fixture}/review/locked.stderr"; then
  echo "identity admin mutated the registry while the broker was running" >&2
  exit 1
fi
grep -q 'reason_code=identity_broker_running' "${fixture}/review/locked.stderr" || {
  echo "identity admin did not report identity_broker_running" >&2
  cat "${fixture}/review/locked.stderr" >&2 || true
  exit 1
}

# Clean shutdown on SIGTERM exits 0 and unlinks the socket (JANUS-451).
kill -TERM "${pid}"
if wait "${pid}"; then
  status=0
else
  status=$?
fi
pid=""
[[ "${status}" -eq 0 ]] || {
  echo "janusd-identityd did not exit cleanly on SIGTERM (status ${status})" >&2
  cat "${fixture}/stderr" >&2 || true
  exit 1
}
[[ ! -e "${JANUS_IDENTITY_SOCKET}" ]] || {
  echo "janusd-identityd left its socket behind on shutdown" >&2
  exit 1
}

# Consumed review evidence is single-use, and the administrator audit is
# write-ahead, value-free, and complete.
if "${identity_admin_bin}" enroll --review-evidence-file "${fixture}/review/enroll.evidence.json" \
  >/dev/null 2>"${fixture}/review/replay.stderr"; then
  echo "identity admin accepted replayed review evidence" >&2
  exit 1
fi
grep -q 'reason_code=identity_review_replayed' "${fixture}/review/replay.stderr" || {
  echo "identity admin did not report identity_review_replayed" >&2
  cat "${fixture}/review/replay.stderr" >&2 || true
  exit 1
}
python3 - "${JANUS_IDENTITY_ADMIN_AUDIT_FILE}" "${subject_ref}" <<'PY'
import json
import pathlib
import sys

lines = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.strip()]
outcomes = [line["outcome"] for line in lines]
if outcomes[:2] != ["authorized", "applied"]:
    raise SystemExit(f"identity admin audit is not write-ahead: {outcomes!r}")
if lines[1]["target_subject_ref"] != sys.argv[2] or lines[1]["action"] != "enroll":
    raise SystemExit("identity admin audit does not bind the applied enrollment")
if any("local_uid" in line or line.get("value_returned") is not False for line in lines):
    raise SystemExit("identity admin audit broadened")
PY

echo "ok: identity shadow broker enrollment=janusd-identity-admin kernel_peer=derived caller_identity=denied runtime_denial=audited broker_lock=enforced replay=denied stale_socket=reclaimed shutdown=unlinked authority=none value_returned=false"
