#!/usr/bin/env bash
# Requires bash 4.2+ (associative arrays). CI's ubuntu-24.04 runners and a
# Nix dev shell both satisfy this; macOS's preinstalled /bin/bash (3.2) does
# not — use a newer bash from Nix or Homebrew there.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

# JANUS-438: the engine assurance gate used to be one 9m17s serial script.
# Every phase below is registered with a stable slug, a fan-out group, and
# the exact human label its "==>" progress line already used. `tests` runs
# checks and cargo tests plus one container minimization proof against a
# cache-backed candidate; `smoke` builds the daemon binaries once and then
# runs the with-runtime-authority smoke scripts. The two groups run as independent CI jobs
# (check-assurance-tests, check-assurance-smoke) with a fan-in job
# (check-assurance) that keeps the original required check name. `--phase
# all` (the default, used by local devs and docs) still runs every phase.
#
# `--list-phases` prints this table so
# scripts/check-engine-assurance-inventory.py can prove, by construction,
# that a future edit cannot silently drop, rename, or regroup a gate: the
# table it inspects is the exact table this script dispatches from, not a
# separately maintained description of it.

declare -a PHASE_SLUGS=()
declare -A PHASE_GROUP=()
declare -A PHASE_LABEL=()

phase() {
  local slug="$1" group="$2" label="$3"
  PHASE_SLUGS+=("${slug}")
  PHASE_GROUP["${slug}"]="${group}"
  PHASE_LABEL["${slug}"]="${label}"
}

phase release-docs            tests "release documentation contract"
phase external-stage-pins     tests "immutable Paimos external-stage v1 pins"
phase release-admission       tests "trusted release admission fixtures"
phase endpoint-policy         tests "closed runtime endpoint policy matrix"
phase duty-journal-boundary   tests "durable duty authority boundary"
phase security-properties     tests "bounded security properties"
phase minimization-self-test  tests "minimization proof runner"
phase adversarial-scenarios   tests "reviewed adversarial recovery corpus"
phase cargo-test-all          tests "cargo tests"
phase minimization-rust       tests "cross-surface Rust minimization proof"
phase build-smoke-binaries    smoke "build smoke binaries"
phase managed-service-ux-rust smoke "managed-service secret UX"
phase runtime-planes-smoke    smoke "runtime process-plane boundary smoke"
phase identity-smoke          smoke "authenticated actor identity-shadow smoke"
phase warden-mcp-smoke        smoke "local Warden MCP smoke"
phase env-file-smoke          smoke "split-plane env-file smoke"
phase migration-smoke         smoke "local janusd-admin migration smoke"
phase scope-transfer-smoke    smoke "local janusd-admin scope-transfer smoke"
phase recovery-drill-smoke    smoke "sealed clean-state recovery-drill smoke"
phase retention-smoke         smoke "offline retention quarantine and purge smoke"
phase lifecycle-entry-smoke   smoke "local janusd-admin lifecycle-entry smoke"
phase lifecycle-queue-smoke   smoke "local janusd-admin lifecycle action queue smoke"
phase pharos-retirement-smoke smoke "local Pharos retirement smoke"

if [[ "${1:-}" == "--list-phases" ]]; then
  for slug in "${PHASE_SLUGS[@]}"; do
    printf '%s\t%s\t%s\n' "${slug}" "${PHASE_GROUP[${slug}]}" "${PHASE_LABEL[${slug}]}"
  done
  exit 0
fi

if [[ "${1:-}" == "--self-test" ]]; then
  test "${#PHASE_SLUGS[@]}" -gt 0
  seen=""
  tests_count=0
  smoke_count=0
  for slug in "${PHASE_SLUGS[@]}"; do
    case " ${seen} " in
      *" ${slug} "*) echo "duplicate phase slug: ${slug}" >&2; exit 1 ;;
    esac
    seen="${seen} ${slug}"
    case "${PHASE_GROUP[${slug}]}" in
      tests) tests_count=$((tests_count + 1)) ;;
      smoke) smoke_count=$((smoke_count + 1)) ;;
      *) echo "unknown phase group for ${slug}: ${PHASE_GROUP[${slug}]}" >&2; exit 1 ;;
    esac
    test -n "${PHASE_LABEL[${slug}]}"
  done
  test "$((tests_count + smoke_count))" -eq "${#PHASE_SLUGS[@]}"
  echo "ok: engine assurance phase table self-test passed (${tests_count} tests, ${smoke_count} smoke)"
  exit 0
fi

phase_filter="all"
if [[ "${1:-}" == "--phase" ]]; then
  phase_filter="${2:?--phase requires tests, smoke, or all}"
fi
case "${phase_filter}" in
  all | tests | smoke) ;;
  *)
    echo "unknown phase: ${phase_filter} (expected tests, smoke, or all)" >&2
    exit 2
    ;;
esac

run_release_docs() {
python3 scripts/check-release-docs.py
}

run_external_stage_pins() {
python3 scripts/check-paimos-external-stage-pins.py --self-test
python3 scripts/check-paimos-external-stage-pins.py
}

run_release_admission() {
scripts/test-release-admission.sh
}

run_endpoint_policy() {
cargo test --locked -p janus-core runtime_endpoint_policy
cargo test --locked -p janus-warden endpoint_guard
}

run_duty_journal_boundary() {
python3 scripts/check-duty-journal-boundary.py --self-test
python3 scripts/check-duty-journal-boundary.py
cargo test --locked -p janus-core duty
cargo test --locked -p janus-local duty
cargo test --locked -p janus-local authority
}

run_security_properties() {
python3 scripts/run-security-properties.py --self-test
python3 scripts/run-security-properties.py --release
}

run_minimization_self_test() {
python3 scripts/run-minimization-proof.py --self-test
}

run_adversarial_scenarios() {
python3 scripts/run-adversarial-scenarios.py --self-test
python3 scripts/run-adversarial-scenarios.py
}

run_cargo_test_all() {
cargo test --all --locked
}

run_minimization_rust() {
python3 scripts/run-minimization-proof.py --stack rust
}

run_build_smoke_binaries() {
cargo build --locked -p janus-host -p janus-warden -p janusd
}

run_managed_service_ux_rust() {
python3 scripts/run-managed-service-ux-assurance.py --self-test
python3 scripts/run-managed-service-ux-assurance.py --stack rust
}

run_runtime_planes_smoke() {
scripts/with-runtime-authority.sh test scripts/smoke-janusd-planes.sh
}

run_identity_smoke() {
JANUSD_IDENTITY_BIN="${repo}/target/debug/janusd-identityd" scripts/smoke-janusd-identity.sh
}

run_warden_mcp_smoke() {
scripts/with-runtime-authority.sh dev python3 scripts/smoke-warden-mcp.py --bin target/debug/janus-warden
}

run_env_file_smoke() {
scripts/with-runtime-authority.sh dev env JANUSD_USE_BIN="${repo}/target/debug/janusd-use" \
  JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" \
  scripts/smoke-janusd-env-file.sh
}

run_migration_smoke() {
scripts/with-runtime-authority.sh test env JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-migration.sh
}

run_scope_transfer_smoke() {
scripts/with-runtime-authority.sh prod env JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-scope-transfer.sh
}

run_recovery_drill_smoke() {
scripts/with-runtime-authority.sh dev env JANUSD_USE_BIN="${repo}/target/debug/janusd-use" \
  JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" \
  JANUS_WARDEN_BIN="${repo}/target/debug/janus-warden" \
  scripts/smoke-janusd-recovery-drill.sh
}

run_retention_smoke() {
scripts/with-runtime-authority.sh test env JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-retention.sh
}

run_lifecycle_entry_smoke() {
scripts/with-runtime-authority.sh dev env JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-lifecycle-entry.sh
}

run_lifecycle_queue_smoke() {
scripts/with-runtime-authority.sh dev env JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-lifecycle-queue.sh
}

run_pharos_retirement_smoke() {
scripts/with-runtime-authority.sh test env JANUSD_ADMIN_BIN="${repo}/target/debug/janusd-admin" scripts/smoke-janusd-pharos-retirement.sh
}

if [[ "${phase_filter}" == "all" || "${phase_filter}" == "smoke" ]]; then
  # Isolated fixtures have no durable operator binding registry. They must
  # opt in explicitly to the only non-production compatibility posture;
  # trusted product modes reject this value in the runtime loader.
  export JANUS_ROLE_AUTHORIZATION_MODE="unsafe_disabled_dev"
  export JANUS_PRODUCT_MODE="self_hosted"
fi

for slug in "${PHASE_SLUGS[@]}"; do
  group="${PHASE_GROUP[${slug}]}"
  if [[ "${phase_filter}" != "all" && "${phase_filter}" != "${group}" ]]; then
    continue
  fi
  echo "==> janus engine release assurance: ${PHASE_LABEL[${slug}]}"
  "run_${slug//-/_}"
done

echo "ok: janus engine release assurance passed (phase=${phase_filter})"
