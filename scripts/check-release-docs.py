#!/usr/bin/env python3
"""Keep release version, assurance claims, and local documentation links honest."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise RuntimeError(message)


def check_links(path: pathlib.Path) -> None:
    text = path.read_text()
    for raw in re.findall(r"(?<!!)\[[^]]+\]\(([^)]+)\)", text):
        target = raw.strip().split(maxsplit=1)[0].strip("<>")
        if target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            fail(f"broken local documentation link in {path.relative_to(ROOT)}: {raw}")


def main() -> int:
    try:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
        version = cargo["workspace"]["package"]["version"]
        tag = f"rust-engine-v{version}"
        readme = (ROOT / "README.md").read_text()
        normalized_readme = " ".join(readme.split())
        admission = (ROOT / "docs/release-admission.md").read_text()
        smoke = (ROOT / "scripts/smoke-published-engine.sh").read_text()
        rust_workflow = (ROOT / ".github/workflows/rust.yml").read_text()
        go_workflow = (ROOT / ".github/workflows/go-envelope.yml").read_text()

        if readme.count(tag) != 3:
            fail(f"README must contain exactly three current release references: {tag}")
        if tag not in admission or tag not in smoke:
            fail("operator docs or published smoke default drifted from workspace version")
        for required in (
            "behavioral assurance script is intentionally not presented as the complete",
            "source/tag/commit/image-digest manifest",
            "signed-source manifest and bundle hashes",
            "scratch filesystem",
            "scripts/run-security-gates.sh",
            "property replay receipt",
        ):
            if required not in normalized_readme:
                fail(f"README assurance contract is missing: {required}")
        for asset in (
            "source-release.json",
            "source-release.sigstore.json",
            "rust-trivy-summary.json",
            "rust-engine-admission.json",
            "rust-engine-admission-enterprise.json",
            "rust-release-platforms.json",
            "rust-release-timing.json",
            "janus-property-replay.json",
        ):
            if asset not in rust_workflow:
                fail(f"Rust release workflow does not publish {asset}")
        for asset in (
            "source-release.json",
            "source-release.sigstore.json",
            "go-trivy-summary.json",
            "go-envelope-admission.json",
        ):
            if asset not in go_workflow:
                fail(f"Go release workflow does not publish {asset}")
        for binding in (
            "--source-manifest",
            "--source-bundle",
            "--scanner-summary",
        ):
            if binding not in admission:
                fail(f"release admission docs omit required evidence: {binding}")
        latency = (ROOT / "docs/release-latency.md").read_text()
        for required in (
            "ubuntu-24.04-arm",
            "rust-engine-linux-amd64",
            "rust-engine-linux-arm64",
            "900-second",
            "rust-release-platforms.json",
            "rust-release-timing.json",
            "replace it with QEMU",
        ):
            if required not in latency:
                fail(f"native release documentation is missing: {required}")
        if "Deploy exactly the receipt matching `JANUS_PRODUCT_MODE`" not in admission:
            fail("release admission docs omit the runtime-mode receipt boundary")
        for replay_contract in (
            "name: rust-property-replay",
            "if-no-files-found: ignore",
            "include-hidden-files: true",
            "retention-days: 7",
        ):
            if replay_contract not in rust_workflow:
                fail("Rust release workflow does not preserve bounded property replay")
        dockerfile = (ROOT / "Dockerfile.engine").read_text()
        if "FROM scratch" not in dockerfile or "USER 65532:65532" not in dockerfile:
            fail("documented minimal runtime posture is not implemented")
        if re.search(r"^FROM debian", dockerfile, re.MULTILINE):
            fail("broad Debian runtime returned")

        for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
            check_links(path)
    except (OSError, KeyError, RuntimeError, tomllib.TOMLDecodeError) as error:
        print(f"release documentation check failed: {error}", file=sys.stderr)
        return 1
    print(f"release documentation check passed: {tag}, truthful assurance, local links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
