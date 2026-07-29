#!/usr/bin/env bash
set -euo pipefail

policy=""
channel=""
mode=""
previous_mode=""
image=""
tag=""
digest=""
output=""
source_manifest=""
source_bundle=""
scanner_summary=""

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

required_value() {
  if [[ "$#" -ne 2 || -z "$2" ]]; then
    fail "release_admission_invalid_arguments"
  fi
  printf '%s' "$2"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --policy)
      policy="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --channel)
      channel="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --mode)
      mode="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --previous-mode)
      previous_mode="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --image)
      image="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --tag)
      tag="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --digest)
      digest="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --output)
      output="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --source-manifest)
      source_manifest="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --source-bundle)
      source_bundle="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    --scanner-summary)
      scanner_summary="$(required_value "$1" "${2:-}")"
      shift 2
      ;;
    *)
      fail "release_admission_invalid_arguments"
      ;;
  esac
done

[[ -n "${policy}" && -n "${channel}" && -n "${mode}" && -n "${previous_mode}" ]] ||
  fail "release_admission_invalid_arguments"
[[ -n "${image}" && -n "${tag}" && -n "${digest}" && -n "${output}" ]] ||
  fail "release_admission_invalid_arguments"
[[ -n "${source_manifest}" && -n "${source_bundle}" && -n "${scanner_summary}" ]] ||
  fail "release_admission_invalid_arguments"
[[ -f "${policy}" && ! -L "${policy}" ]] || fail "release_policy_unavailable"
for evidence in "${source_manifest}" "${source_bundle}" "${scanner_summary}"; do
  [[ -f "${evidence}" && ! -L "${evidence}" ]] || fail "release_evidence_unavailable"
done
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "release_digest_invalid"

jq_bin="${JANUS_JQ_BIN:-jq}"
gh_bin="${JANUS_GH_BIN:-gh}"
cosign_bin="${JANUS_COSIGN_BIN:-cosign}"
command -v "${jq_bin}" >/dev/null 2>&1 || fail "release_verifier_unavailable"
command -v "${gh_bin}" >/dev/null 2>&1 || fail "release_verifier_unavailable"
command -v "${cosign_bin}" >/dev/null 2>&1 || fail "release_verifier_unavailable"

policy_id="$("${jq_bin}" -er 'select(.schema_version == 1) | .policy_id | select(type == "string" and length > 0)' "${policy}")" ||
  fail "release_policy_invalid"
policy_version="$("${jq_bin}" -er '.policy_version | select(type == "number" and . > 0 and floor == .)' "${policy}")" ||
  fail "release_policy_invalid"
required_mode="$("${jq_bin}" -r --arg mode "${mode}" '
  if (.required_modes | type) == "array" then
    (.required_modes | index($mode) != null)
  else
    error("required_modes")
  end
' "${policy}")" ||
  fail "release_policy_invalid"
[[ "${required_mode}" == "true" ]] || fail "release_mode_not_admissible"

mode_rank() {
  case "$1" in
    dev) printf '0' ;;
    self_hosted) printf '1' ;;
    production) printf '2' ;;
    enterprise) printf '3' ;;
    *) fail "release_mode_invalid" ;;
  esac
}

deny_downgrade="$("${jq_bin}" -r '
  if (.deny_mode_downgrade | type) == "boolean" then
    .deny_mode_downgrade
  else
    error("deny_mode_downgrade")
  end
' "${policy}")" ||
  fail "release_policy_invalid"
if [[ "${deny_downgrade}" == "true" ]] &&
  (( $(mode_rank "${previous_mode}") > $(mode_rank "${mode}") )); then
  fail "release_mode_downgrade"
fi

channel_json="$(
  "${jq_bin}" -cer --arg channel "${channel}" '
    [.channels[] | select(.name == $channel)] |
    if length == 1 then .[0] else error("channel") end
  ' "${policy}"
)" || fail "release_channel_denied"

expected_image="$("${jq_bin}" -er '.image' <<<"${channel_json}")" || fail "release_policy_invalid"
tag_prefix="$("${jq_bin}" -er '.tag_prefix' <<<"${channel_json}")" || fail "release_policy_invalid"
tag_pattern="$("${jq_bin}" -er '.tag_pattern' <<<"${channel_json}")" || fail "release_policy_invalid"
repository="$("${jq_bin}" -er '.repository' <<<"${channel_json}")" || fail "release_policy_invalid"
signer_workflow="$("${jq_bin}" -er '.signer_workflow' <<<"${channel_json}")" || fail "release_policy_invalid"
source_workflow="$("${jq_bin}" -er '.source_manifest_workflow' <<<"${channel_json}")" || fail "release_policy_invalid"
identity_prefix="$("${jq_bin}" -er '.certificate_identity_prefix' <<<"${channel_json}")" || fail "release_policy_invalid"
oidc_issuer="$("${jq_bin}" -er '.oidc_issuer' <<<"${channel_json}")" || fail "release_policy_invalid"
provenance_predicate="$("${jq_bin}" -er '.provenance_predicate_type' <<<"${channel_json}")" || fail "release_policy_invalid"
sbom_predicate="$("${jq_bin}" -er '.sbom_predicate_type' <<<"${channel_json}")" || fail "release_policy_invalid"

[[ "${image}" == "${expected_image}" && "${tag}" == "${tag_prefix}"* ]] ||
  fail "release_channel_denied"
case "$(printf '%s' "${tag}" | tr '[:upper:]' '[:lower:]')" in
  *-dev*|*.dev*|*snapshot*|*dirty*) fail "release_development_artifact" ;;
esac
[[ "${tag}" =~ ^${tag_pattern}$ ]] || fail "release_channel_denied"
revoked="$("${jq_bin}" -r --arg digest "${digest}" '
  if (.revoked_digests | type) == "array" then
    (.revoked_digests | index($digest) != null)
  else
    error("revoked_digests")
  end
' "${policy}")" ||
  fail "release_policy_invalid"
[[ "${revoked}" == "false" ]] || fail "release_digest_revoked"

ref="${image}@${digest}"
source_ref="refs/tags/${tag}"
identity="${identity_prefix}${tag}"

"${cosign_bin}" verify "${ref}" \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "${oidc_issuer}" >/dev/null ||
  fail "release_signature_untrusted"

"${gh_bin}" attestation verify "oci://${ref}" \
  --bundle-from-oci \
  --repo "${repository}" \
  --signer-workflow "${signer_workflow}" \
  --source-ref "${source_ref}" \
  --cert-oidc-issuer "${oidc_issuer}" \
  --predicate-type "${provenance_predicate}" >/dev/null ||
  fail "release_provenance_untrusted"

"${gh_bin}" attestation verify "oci://${ref}" \
  --bundle-from-oci \
  --repo "${repository}" \
  --signer-workflow "${signer_workflow}" \
  --source-ref "${source_ref}" \
  --cert-oidc-issuer "${oidc_issuer}" \
  --predicate-type "${sbom_predicate}" >/dev/null ||
  fail "release_sbom_untrusted"

"${jq_bin}" -e \
  --arg repository "${repository}" \
  --arg tag "${tag}" \
  --arg workflow "${source_workflow}" \
  --arg image "${image}" \
  --arg digest "${digest}" '
    (keys | sort) == ([
      "commit",
      "image",
      "image_digest",
      "repository",
      "schema_version",
      "tag",
      "workflow"
    ] | sort) and
    .schema_version == 1 and
    .repository == $repository and
    .tag == $tag and
    .workflow == $workflow and
    .image == $image and
    .image_digest == $digest and
    (.commit | type == "string" and test("^[0-9a-f]{40}$"))
  ' "${source_manifest}" >/dev/null ||
  fail "release_source_untrusted"
"${jq_bin}" empty "${source_bundle}" >/dev/null 2>&1 ||
  fail "release_source_untrusted"
"${cosign_bin}" verify-blob \
  --bundle "${source_bundle}" \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "${oidc_issuer}" \
  "${source_manifest}" >/dev/null ||
  fail "release_source_untrusted"

"${jq_bin}" -e '
  (keys | sort) == (["counts", "passed", "policy", "scanner", "schema_version"] | sort) and
  .schema_version == 1 and
  .scanner == "trivy" and
  .policy == "candidate_container_critical_high" and
  .passed == true and
  (.counts | keys | sort) == (["CRITICAL", "HIGH"] | sort) and
  .counts.CRITICAL == 0 and
  .counts.HIGH == 0
' "${scanner_summary}" >/dev/null ||
  fail "release_scanner_untrusted"

source_commit="$("${jq_bin}" -er '.commit' "${source_manifest}")" ||
  fail "release_source_untrusted"
sha256_file() {
  python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(f"sha256:{digest.hexdigest()}")
PY
}
source_manifest_sha256="$(sha256_file "${source_manifest}")" ||
  fail "release_evidence_unavailable"
source_bundle_sha256="$(sha256_file "${source_bundle}")" ||
  fail "release_evidence_unavailable"
scanner_summary_sha256="$(sha256_file "${scanner_summary}")" ||
  fail "release_evidence_unavailable"

output_parent="$(dirname "${output}")"
[[ -d "${output_parent}" && ! -L "${output_parent}" && ! -L "${output}" ]] ||
  fail "release_receipt_unavailable"
umask 077
temporary="$(mktemp "${output}.tmp.XXXXXX")"
cleanup() {
  if [[ -n "${temporary:-}" && -e "${temporary}" ]]; then
    rm -f -- "${temporary}"
  fi
}
trap cleanup EXIT

"${jq_bin}" -n \
  --arg policy_id "${policy_id}" \
  --argjson policy_version "${policy_version}" \
  --arg channel "${channel}" \
  --arg mode "${mode}" \
  --arg previous_mode "${previous_mode}" \
  --arg image "${image}" \
  --arg tag "${tag}" \
  --arg digest "${digest}" \
  --arg identity "${identity}" \
  --arg oidc_issuer "${oidc_issuer}" \
  --arg repository "${repository}" \
  --arg signer_workflow "${signer_workflow}" \
  --arg source_ref "${source_ref}" \
  --arg provenance_predicate "${provenance_predicate}" \
  --arg sbom_predicate "${sbom_predicate}" \
  --arg source_commit "${source_commit}" \
  --arg source_manifest_sha256 "${source_manifest_sha256}" \
  --arg source_bundle_sha256 "${source_bundle_sha256}" \
  --arg scanner_summary_sha256 "${scanner_summary_sha256}" '
  {
    schema_version: 1,
    policy_id: $policy_id,
    policy_version: $policy_version,
    channel: $channel,
    mode: $mode,
    previous_mode: $previous_mode,
    artifact: {
      image: $image,
      tag: $tag,
      digest: $digest,
      development: false
    },
    signature: {
      verified: true,
      identity: $identity,
      oidc_issuer: $oidc_issuer
    },
    provenance: {
      verified: true,
      repository: $repository,
      signer_workflow: $signer_workflow,
      source_ref: $source_ref,
      predicate_type: $provenance_predicate
    },
    sbom: {
      verified: true,
      predicate_type: $sbom_predicate
    },
    source: {
      verified: true,
      commit: $source_commit,
      manifest_sha256: $source_manifest_sha256,
      bundle_sha256: $source_bundle_sha256
    },
    scanner: {
      verified: true,
      name: "trivy",
      policy: "candidate_container_critical_high",
      summary_sha256: $scanner_summary_sha256,
      critical: 0,
      high: 0
    }
  }
' >"${temporary}"
chmod 0444 "${temporary}"
mv -f -- "${temporary}" "${output}"
temporary=""
printf 'release_trust_ok policy=%s version=%s channel=%s artifact=%s\n' \
  "${policy_id}" "${policy_version}" "${channel}" "${ref}"
