# Protected PR and Go release critical paths

JANUS-438. Every pull request used to wait for the full Rust engine release
assurance gate (one 9m17s serial step) plus Nix packaging, even when the
change only touched the Go envelope, its browser QA, or documentation.
Separately, the managed-service browser assurance step paid a cold
Playwright Chromium download (about 6 minutes) on every run instead of only
when the pinned browser actually changed. This document records what
changed, what deliberately did not change, and what evidence is still
pending real CI runs.

## Path classification: a fail-closed allowlist, not a trigger-level filter

`scripts/classify-pr-paths.py` answers one narrow question for a pull
request: is every changed path *provably* outside the Rust/Nix surface? It
is an allowlist (`go-envelope/`, `browser-qa/`, `docs/`, plus a few named
files such as `package.json`), not a denylist. Anything this classifier has
never reviewed — including itself, `scripts/**`, every workflow file, and
every GitHub action — trips every expensive gate. A
false "go-only" verdict could silently drop a security or release-assurance
gate; a false negative only costs a few CI minutes on a change that did not
need them. That asymmetry is the whole design.

Classification deliberately does **not** happen via a `paths:` filter on the
workflow's `pull_request:` trigger. A path-filtered trigger means the
workflow never runs at all for an out-of-scope PR, and a required check that
is never posted blocks merging exactly like a failing one — the opposite of
what acceptance criterion 2 asks for. Instead, `rust.yml` gains a `classify`
job that runs on every pull request, and `check-nix`, `check-assurance-tests`,
and `check-assurance-smoke` each keep their required check name and run
unconditionally, but internally take one of two step branches: the real
work, or an explicit `<check>=not_applicable reason=go_only_change` success.
Every branch condition is pinned exactly in
`scripts/check-workflow-security.rb`, with negative fixtures proving the
bypass cannot be silently loosened, and the classifier itself carries a
positive/negative fixture for every relevant file family
(`scripts/classify-pr-paths.py --self-test`).

Push-to-main and release events never classify as go-only: the `classify`
job only runs `if: github.event_name == 'pull_request'`, and every
downstream gate fails open (runs its real work) whenever classification did
not definitively report `go_only=true`.

## Engine assurance: split into two proof-family jobs, not shortened

The 9m17s `scripts/assure-engine-release.sh` ran 23 named checks serially.
Ten of them are in `tests`: the release/security/duty-boundary/minimization/
adversarial checks, `cargo test --all --locked`, and the Rust minimization
proof. That last proof inspects the hardened container, so CI prepares its
candidate with the BuildKit layer cache maintained by the native amd64 gate
(typically the base branch's latest); on a cache miss the tests job builds the
candidate itself. The other thirteen
(`smoke`) build the daemon binaries once and then run the
with-runtime-authority smoke scripts. Neither group's commands depend on the
other's output, so they now
run as two independent CI jobs — `check-assurance-tests` and
`check-assurance-smoke` — with a `check-assurance` fan-in job that keeps the
original required check name and re-verifies the phase inventory.

The phase table lives in the script itself, not in a separately maintained
description, so it cannot drift from what actually runs.
`scripts/check-engine-assurance-inventory.py` parses that source table and
compares it against the reviewed baseline
(`config/assurance/engine-release-phases-v1.json`) on every assurance run.
The baseline pins both the dispatch metadata and a SHA-256 of each phase's
actual `run_*` function body, plus a SHA-256 of the complete assurance script
covering dispatch and environment setup. Deleting or changing a command also
fails closed. A future edit that silently drops, renames, regroups, or guts one
of the 23 gates fails this check before it fails anything more expensive.
`--phase all` (the default, used by local devs and the docs that reference this
script by name) still runs every phase; only the tests/smoke split order changed
slightly, since neither group has an ordering dependency on the other.

The reviewed target is a warm critical path (the slower of the two proof
families) under 6 minutes. This change proves the split and the inventory
guard, not five live GitHub timings against that target — see "Evidence"
below.

## Playwright Chromium: cached, not re-downloaded

`go-envelope.yml`'s managed-service browser assurance step now caches
`~/.cache/ms-playwright` keyed by OS, `package-lock.json` (which pins the
exact `@playwright/test` version), and the version string itself. On a cache
hit it runs `playwright install-deps chromium` only (system packages, no
browser download); on a miss it runs the original
`playwright install --with-deps chromium`. `scripts/check-browser-qa-hygiene.py`
and the browser assurance scripts it guards are unchanged in strength — only
the download path changed.

## Timing and budget plumbing (measurement, not enforcement yet)

Both `rust.yml` and `go-envelope.yml` gain a `pr-path-timing` job that
reports a value-free critical-path summary — job names, ISO timestamps, and
a caller-supplied cache-hit map only, never logs, secrets, request values,
or host paths (`scripts/report-pr-critical-path.py`, self-tested to prove
exactly that). `go-envelope.yml` checks its own PR run against the reviewed
Go-only PR budget (warm under 5 minutes, cold under 8 minutes), selected by
the Playwright cache outcome. `rust.yml` applies the same budget only when
the PR classified as go-only; a non-go-only PR gets an explicit
`not_applicable` verdict rather than a fabricated number.

Both jobs are **informational for now**: the timing step never fails the
build. Once real runs accumulate evidence, tightening either job to a
blocking gate is a follow-up, not part of this change.

## Go-release candidate reuse: fail-closed, unchanged

Acceptance criterion 8 asked whether a Go-release candidate could reuse its
PR build-and-test evidence instead of rebuilding at release time, provided
the reuse can be bound to an exact commit, digest, source manifest,
signature, SBOM, and scanner result. This change does not adopt that reuse:
proving that binding end-to-end (in particular, that the exact artifact
tested on the PR is byte-identical to the one released, not just built from
the same source) is a trust-boundary change to `admit-engine-release.sh` and
the release admission contract that deserves its own reviewed change, not a
side effect of a CI-latency ticket. `go-envelope.yml`'s `image` job keeps
its independent rebuild-from-tag. Cost: the release pipeline still repeats
work the PR pipeline already did. Benefit: no release ships without a fresh,
source-bound build of the exact tagged commit.

## Evidence

Acceptance criterion 9 requires before/after evidence from at least five
comparable PR and release runs. This change implements the classifier, the
assurance split, the inventory guard, the cache, and the timing plumbing —
it does not fabricate that evidence. Attach real run timings (via the
`rust-pr-path-timing` / `go-pr-path-timing` artifacts and the Rust release
timing artifact) to JANUS-438 once CI has produced at least five comparable
runs on each pipeline.
