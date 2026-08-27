#!/usr/bin/env python3
"""Classify a pull request's changed files as Go-only or not (JANUS-438).

Every pull request currently waits for the full Rust engine release
assurance gate and Nix packaging, even when it only touches the Go
envelope, its browser QA, or documentation. This classifier answers one
narrow, fail-closed question: is every changed path *provably* outside
the Rust/Nix surface?

The policy is an allowlist, not a denylist: only paths under a reviewed
"go-only" prefix are ever treated as safe to skip. Any path this
classifier has never seen — including itself, `scripts/**`, and every
`.github/workflows/**` file — trips every expensive gate. That asymmetry is
deliberate: a false "go-only" verdict
could silently drop a security or release-assurance gate; a false
negative only costs CI minutes on a change that didn't need them.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Prefixes (POSIX-style, relative to the repository root) that are reviewed
# to affect only the Go envelope, its browser QA, or documentation: never
# the Rust engine, Nix packaging, or the shared workflow-security posture.
GO_ONLY_PREFIXES = (
    "go-envelope/",
    "browser-qa/",
    "docs/",
)
# These documents are executable assurance inputs: the duty-journal boundary
# phase validates required recovery/rollback markers in them. Keep the broader
# docs family cheap while failing closed for the two files that can break a
# skipped Rust assurance phase.
GO_ONLY_EXCLUDED_FILES = frozenset(
    {
        "docs/durable-duty-journal.md",
        "docs/runtime-accountability-runbook.md",
    }
)
# Individual files outside those prefixes that are also proven go-only.
GO_ONLY_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "README.md",
    }
)


def is_go_only_path(path: str) -> bool:
    if path in GO_ONLY_EXCLUDED_FILES:
        return False
    if path in GO_ONLY_FILES:
        return True
    return any(path.startswith(prefix) for prefix in GO_ONLY_PREFIXES)


def classify(paths: list[str]) -> dict:
    changed = [path for path in paths if path]
    if not changed:
        # An empty diff is never provably go-only; fail closed.
        return {"go_only": False, "file_count": 0, "reason": "no_changed_files"}
    go_only = all(is_go_only_path(path) for path in changed)
    return {
        "go_only": go_only,
        "file_count": len(changed),
        "reason": "go_only_allowlist" if go_only else "affects_rust_or_shared_surface",
    }


def changed_paths(base: str, head: str, root: Path = ROOT) -> list[str]:
    output = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--no-renames",
            "--name-only",
            "-z",
            f"{base}...{head}",
        ],
        check=True,
        capture_output=True,
    ).stdout
    return [item.decode("utf-8", errors="strict") for item in output.split(b"\0") if item]


# One fixture per relevant file family from JANUS-438 acceptance criterion 1:
# every family must trip the gates (go_only is False) except the reviewed
# go-only family itself.
FIXTURES = {
    "go_only": [
        "go-envelope/main.go",
        "browser-qa/managed-secret-ux.spec.mjs",
        "docs/release-latency.md",
        "README.md",
        "package.json",
        "package-lock.json",
    ],
    "assurance_docs": [
        "docs/durable-duty-journal.md",
        "docs/runtime-accountability-runbook.md",
    ],
    "rust": ["crates/janus-core/src/lib.rs"],
    "rust_lock": ["Cargo.lock"],
    "rust_toolchain": ["rust-toolchain.toml"],
    "nix": ["flake.nix"],
    "nix_lock": ["flake.lock"],
    "docker": ["Dockerfile.engine"],
    "docker_ignore": ["Dockerfile.engine.dockerignore"],
    "workflow": [".github/workflows/rust.yml"],
    "go_workflow": [".github/workflows/go-envelope.yml"],
    "github_action": [".github/actions/reviewed/action.yml"],
    "assurance_config": ["config/assurance/engine-release-phases-v1.json"],
    "classifier_self": ["scripts/classify-pr-paths.py"],
    "scripts_shared": ["scripts/assure-engine-release.sh"],
    "mixed": ["go-envelope/main.go", "crates/janus-core/src/lib.rs"],
    "empty": [],
}


def self_test() -> None:
    result = classify(FIXTURES["go_only"])
    assert result["go_only"] is True, "the reviewed go-only family failed to classify as go-only"
    for name in (
        "rust",
        "assurance_docs",
        "rust_lock",
        "rust_toolchain",
        "nix",
        "nix_lock",
        "docker",
        "docker_ignore",
        "workflow",
        "go_workflow",
        "github_action",
        "assurance_config",
        "classifier_self",
        "scripts_shared",
        "mixed",
        "empty",
    ):
        result = classify(FIXTURES[name])
        assert result["go_only"] is False, f"{name} family was incorrectly classified as go-only"
    # A change to the classifier itself can never be waved through, even
    # alongside otherwise go-only paths.
    assert classify(["scripts/classify-pr-paths.py", "go-envelope/main.go"])["go_only"] is False

    # Git's rename detection normally reports only the destination. A move
    # from a protected Rust path into an allowlisted docs path must expose
    # both sides so the deleted source cannot be classified as Go-only.
    with tempfile.TemporaryDirectory(prefix="janus-classifier-") as directory:
        repository = Path(directory)
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(["git", "config", "user.name", "Janus Classifier Fixture"], cwd=repository, check=True)
        subprocess.run(["git", "config", "user.email", "classifier@example.invalid"], cwd=repository, check=True)
        source = repository / "crates/janus-core/src/lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("pub fn fixture() {}\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=repository, check=True)
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True
        ).stdout.strip()
        destination = repository / "docs/lib.rs"
        destination.parent.mkdir()
        subprocess.run(["git", "mv", str(source), str(destination)], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "rename fixture"], cwd=repository, check=True)
        paths = changed_paths(base, "HEAD", repository)
        assert paths == ["crates/janus-core/src/lib.rs", "docs/lib.rs"], paths
        assert classify(paths)["go_only"] is False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--base", help="base ref/sha to diff from")
    parser.add_argument("--head", default="HEAD", help="head ref/sha to diff to")
    parser.add_argument("--files", nargs="*", help="explicit changed-file list (testing)")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--github-output",
        type=Path,
        help="append go_only=<true|false> to this $GITHUB_OUTPUT file",
    )
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("ok: PR path classifier self-test passed")
            return 0
        if args.files is not None:
            paths = args.files
        elif args.base:
            paths = changed_paths(args.base, args.head)
        else:
            parser.error("classification requires --files or --base")
        document = classify(paths)
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        print(f"pr_path_classifier=blocked reason={error} value_returned=false", file=sys.stderr)
        return 1
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"go_only={'true' if document['go_only'] else 'false'}\n")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
