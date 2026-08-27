#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo}"

python3 scripts/check-action-pins.py --self-test
python3 scripts/smoke-warden-mcp.py --self-test
python3 scripts/check-browser-qa-hygiene.py --self-test --repository
python3 scripts/run-attended-browser-qa.py --self-test
python3 scripts/check-release-main-ancestry.py --self-test
python3 scripts/check-release-mode-receipts.py --self-test
python3 scripts/check-github-repository-posture.py --self-test
python3 scripts/check-duty-journal-boundary.py --self-test
python3 scripts/check-duty-journal-boundary.py
python3 scripts/classify-pr-paths.py --self-test
bash scripts/assure-engine-release.sh --self-test
python3 scripts/check-engine-assurance-inventory.py --self-test
python3 scripts/check-engine-assurance-inventory.py
python3 scripts/report-pr-critical-path.py --self-test
ruby scripts/check-workflow-security.rb --self-test
python3 scripts/check-security-gates.py --self-test
python3 scripts/check-security-gates.py --check-installed-tools
python3 scripts/test-docker-base-pins.py
python3 scripts/check-docker-base-pins.py
scripts/check-rust-audit.py --self-test
scripts/test-gitleaks.sh
(
  cd go-envelope
  go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
  go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
)

if [[ -n "${JANUS_SECURITY_IMAGE:-}" ]]; then
  report="$(mktemp)"
  summary="$(mktemp)"
  cleanup() { rm -f -- "${report}" "${summary}"; }
  trap cleanup EXIT
  trivy image --scanners vuln --format json --output "${report}" "${JANUS_SECURITY_IMAGE}"
  python3 scripts/check-security-gates.py \
    --trivy-report "${report}" \
    --summary "${summary}" \
    --subject "${JANUS_SECURITY_IMAGE}"
fi

echo "ok: local release-security parity gates passed"
