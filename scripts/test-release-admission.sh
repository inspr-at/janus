#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
admit="${repo}/scripts/admit-engine-release.sh"
policy="${repo}/config/release-channels/v1.json"
image="ghcr.io/inspr-at/janus/janus-engine"
tag="rust-engine-v0.1.17"
digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
revoked="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
source_manifest="${work}/source-release.json"
source_bundle="${work}/source-release.sigstore.json"
scanner_summary="${work}/trivy-summary.json"

jq -n \
  --arg tag "${tag}" \
  --arg image "${image}" \
  --arg digest "${digest}" '
  {
    schema_version: 1,
    repository: "inspr-at/janus",
    tag: $tag,
    commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    workflow: ".github/workflows/rust.yml",
    image: $image,
    image_digest: $digest
  }
' >"${source_manifest}"
printf '{}\n' >"${source_bundle}"
jq -n '
  {
    schema_version: 1,
    scanner: "trivy",
    policy: "candidate_container_critical_high",
    counts: {CRITICAL: 0, HIGH: 0},
    passed: true
  }
' >"${scanner_summary}"

evidence_args=(
  --source-manifest "${source_manifest}"
  --source-bundle "${source_bundle}"
  --scanner-summary "${scanner_summary}"
)

base_args=(
  --policy "${policy}"
  --channel stable
  --mode enterprise
  --previous-mode enterprise
  --image "${image}"
  --tag "${tag}"
  --digest "${digest}"
  "${evidence_args[@]}"
)

JANUS_COSIGN_BIN=true JANUS_GH_BIN=true \
  "${admit}" "${base_args[@]}" --output "${work}/trusted.json" >/dev/null
jq -e '
  .policy_id == "janus-engine-release-v1" and
  .channel == "stable" and
  .mode == "enterprise" and
  .policy_version == 3 and
  .artifact.digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .signature.verified and .provenance.verified and .sbom.verified and
  .source.verified and .source.commit == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and
  (.source.manifest_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  (.source.bundle_sha256 | test("^sha256:[0-9a-f]{64}$")) and
  .scanner.verified and .scanner.critical == 0 and .scanner.high == 0 and
  (.scanner.summary_sha256 | test("^sha256:[0-9a-f]{64}$"))
' "${work}/trusted.json" >/dev/null
[[ ! -w "${work}/trusted.json" ]]

expect_denied() {
  local expected="$1"
  shift
  local error_file="${work}/error"
  if JANUS_COSIGN_BIN="${JANUS_TEST_COSIGN_BIN:-true}" \
    JANUS_GH_BIN="${JANUS_TEST_GH_BIN:-true}" \
    "${admit}" "$@" --output "${work}/denied.json" >/dev/null 2>"${error_file}"; then
    printf 'expected admission denial: %s\n' "${expected}" >&2
    exit 1
  fi
  grep -qx "${expected}" "${error_file}"
}

expect_denied release_development_artifact \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "${image}" --tag "${tag}-dev" --digest "${digest}" "${evidence_args[@]}"
expect_denied release_digest_revoked \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "${image}" --tag "${tag}" --digest "${revoked}" "${evidence_args[@]}"
expect_denied release_channel_denied \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "ghcr.io/attacker/janus" --tag "${tag}" --digest "${digest}" "${evidence_args[@]}"
expect_denied release_mode_downgrade \
  --policy "${policy}" --channel stable --mode production --previous-mode enterprise \
  --image "${image}" --tag "${tag}" --digest "${digest}" "${evidence_args[@]}"

JANUS_TEST_COSIGN_BIN=false expect_denied release_signature_untrusted "${base_args[@]}"
JANUS_TEST_GH_BIN=false expect_denied release_provenance_untrusted "${base_args[@]}"

compatible_gh="${work}/gh-compatible"
# shellcheck disable=SC2016 # literal lines for the fixture executable
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'args=" $* "' \
  '[[ "$args" == *" --signer-workflow "* ]]' \
  '[[ "$args" == *" --source-ref "* ]]' \
  '[[ "$args" == *" --cert-oidc-issuer "* ]]' \
  '[[ "$args" != *" --cert-identity "* ]]' \
  >"${compatible_gh}"
chmod 0700 "${compatible_gh}"
JANUS_COSIGN_BIN=true JANUS_GH_BIN="${compatible_gh}" \
  "${admit}" "${base_args[@]}" --output "${work}/gh-compatible.json" >/dev/null

sbom_failing_gh="${work}/gh-sbom-failing"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case "$*" in *spdx.dev/Document/v2.3*) exit 1 ;; *) exit 0 ;; esac' \
  >"${sbom_failing_gh}"
chmod 0700 "${sbom_failing_gh}"
JANUS_TEST_GH_BIN="${sbom_failing_gh}" expect_denied release_sbom_untrusted "${base_args[@]}"

source_failing_cosign="${work}/cosign-source-failing"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case "${1:-}" in verify-blob) exit 1 ;; *) exit 0 ;; esac' \
  >"${source_failing_cosign}"
chmod 0700 "${source_failing_cosign}"
JANUS_TEST_COSIGN_BIN="${source_failing_cosign}" expect_denied release_source_untrusted "${base_args[@]}"

jq '.workflow = ".github/workflows/unreviewed.yml"' \
  "${source_manifest}" >"${work}/wrong-source.json"
expect_denied release_source_untrusted \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "${image}" --tag "${tag}" --digest "${digest}" \
  --source-manifest "${work}/wrong-source.json" \
  --source-bundle "${source_bundle}" --scanner-summary "${scanner_summary}"

jq '.counts.HIGH = 1 | .passed = false' \
  "${scanner_summary}" >"${work}/finding-summary.json"
expect_denied release_scanner_untrusted \
  --policy "${policy}" --channel stable --mode enterprise --previous-mode enterprise \
  --image "${image}" --tag "${tag}" --digest "${digest}" \
  --source-manifest "${source_manifest}" --source-bundle "${source_bundle}" \
  --scanner-summary "${work}/finding-summary.json"

printf 'ok: release admission fixtures passed\n'
