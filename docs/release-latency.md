# Native Rust releases

Rust engine releases retain both `linux/amd64` and `linux/arm64`. Each image is
built on a native, free GitHub-hosted runner (`ubuntu-24.04` and
`ubuntu-24.04-arm`), then the release job creates one OCI index from the two
canonical digests. QEMU is not part of the Rust publication path.

## Why ARM64 stays

ARM64 is a current deployment architecture, not a preview feature. Dropping it
would move compatibility risk to operators and make a later restoration a
breaking release concern. The former latency came from emulation rather than
from the architecture: release `rust-engine-v0.1.24` took 5,410 seconds, of
which the QEMU multi-architecture build consumed 4,299 seconds. On an Apple
Silicon preflight constrained to 2 CPU and 2 GiB, a cold native ARM64 build took
233.13 seconds and an unchanged warm build took 0.23 seconds. The checked
baseline is `config/assurance/rust-release-latency-v1.json`.

## Trust and cache boundaries

Pull requests and protected-main pushes build and scan both native candidates.
BuildKit cache scopes are architecture-specific:
`rust-engine-linux-amd64` and `rust-engine-linux-arm64`. Cache entries only
accelerate deterministic Dockerfile steps; they do not supply the published
identity. A release rebuilds from the tagged commit, pushes two untagged
canonical digests, and records each digest with the same 40-character commit
and workflow run id.

The final publication job runs only after all Rust checks and both native jobs
succeed. `scripts/check-native-release-set.py` rejects missing architectures,
duplicate digests, stale runs, cross-commit records, extra platforms, and any
published index whose platform-to-digest mapping differs. Only then are the
release tag and SHA tag attached. Scanning, source binding, signing, SBOM,
attestations, both mode admissions, and the published behavior smoke test all
use the final exact index digest. The release attaches
`rust-release-platforms.json` as its machine-readable platform receipt.

## Timing and diagnosis

The terminal `release-timing` job queries the completed jobs in its own GitHub
Actions run, records the native builds and every release-assurance phase in
`rust-release-timing.json`, and enforces a 900-second end-to-end budget. A
budget failure blocks workflow success even if registry assembly completed; do
not promote that release until the cause is understood.

Start diagnosis with the timing asset and job summary:

- a slow native build points to cache loss, runner contention, or dependency
  compilation;
- a slow Nix or assurance job is independent of the image cache and should be
  investigated in that proof boundary;
- a slow final image job points to registry, scanner, Sigstore, attestation, or
  admission services.

Apple Silicon can reproduce the ARM64 Docker build locally as a preflight, but
local results are not release evidence. Blacksmith is deliberately out of scope
while the public repository remains eligible for GitHub's free native ARM64
runner.

## Failure and rollback

If one native runner is unavailable, retry the unchanged workflow. Do not
replace it with QEMU or publish a single-platform stable tag. If GitHub removes
the native ARM64 runner or the repository becomes ineligible, pause Rust
releases and review a pinned native provider in a separate change. Existing
immutable digests and signed admission evidence remain valid; rollback deploys
a previously admitted exact digest and its matching product-mode receipt.
