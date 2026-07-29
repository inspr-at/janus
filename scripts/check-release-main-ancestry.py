#!/usr/bin/env python3
"""Fail closed unless a release tag names an exact protected-main commit."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/assurance/source-release-signing-v1.json"
COMMIT = re.compile(r"[0-9a-f]{40}")


class LineageError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LineageError(message)


def git(repo: pathlib.Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LineageError("release_lineage_git_failure") from error
    return result.stdout.strip()


def load_policy() -> dict[str, Any]:
    try:
        policy = json.loads(POLICY.read_text())
    except (OSError, ValueError) as error:
        raise LineageError("release_lineage_policy_invalid") from error
    require(policy.get("schema_version") == 1, "release_lineage_policy_invalid")
    require(
        policy.get("repository") == "inspr-at/janus",
        "release_lineage_policy_invalid",
    )
    require(
        policy.get("protected_branch") == "main",
        "release_lineage_policy_invalid",
    )
    signed_subset = policy.get("signed_subset")
    require(
        isinstance(signed_subset, list) and len(signed_subset) == 2,
        "release_lineage_policy_invalid",
    )
    for item in signed_subset:
        require(
            isinstance(item, dict)
            and isinstance(item.get("tag_prefix"), str)
            and isinstance(item.get("tag_pattern"), str),
            "release_lineage_policy_invalid",
        )
        try:
            re.compile(item["tag_pattern"])
        except re.error as error:
            raise LineageError("release_lineage_policy_invalid") from error
    return policy


def validate_lineage(
    repo: pathlib.Path,
    policy: dict[str, Any],
    repository: str,
    tag: str,
    commit: str,
    main_ref: str,
) -> None:
    require(repository == policy["repository"], "release_repository_denied")
    require(COMMIT.fullmatch(commit) is not None, "release_commit_invalid")

    matches = [
        item
        for item in policy["signed_subset"]
        if re.fullmatch(item["tag_pattern"], tag) is not None
    ]
    require(len(matches) == 1, "release_tag_invalid")
    require(tag.startswith(matches[0]["tag_prefix"]), "release_tag_invalid")

    tag_commit = git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    require(COMMIT.fullmatch(tag_commit) is not None, "release_tag_invalid")
    require(tag_commit == commit, "release_tag_commit_mismatch")

    protected_commit = git(repo, "rev-parse", "--verify", f"{main_ref}^{{commit}}")
    require(
        COMMIT.fullmatch(protected_commit) is not None,
        "release_protected_main_unavailable",
    )
    try:
        subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", tag_commit, main_ref],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            raise LineageError("release_not_on_protected_main") from error
        raise LineageError("release_lineage_git_failure") from error
    except OSError as error:
        raise LineageError("release_lineage_git_failure") from error


def expect_denied(expected: str, action: object) -> None:
    try:
        action()
    except LineageError as error:
        require(str(error) == expected, "release_lineage_self_test_failed")
        return
    raise LineageError("release_lineage_self_test_failed")


def self_test(policy: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="janus-release-lineage-") as directory:
        repo = pathlib.Path(directory)
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "Janus fixture")
        git(repo, "config", "user.email", "fixture@invalid")
        (repo / "fixture").write_text("main\n")
        git(repo, "add", "fixture")
        git(repo, "commit", "-m", "main")
        main_commit = git(repo, "rev-parse", "HEAD")
        git(repo, "tag", "go-envelope-v1.170")
        git(repo, "switch", "-c", "side")
        (repo / "fixture").write_text("side\n")
        git(repo, "commit", "-am", "side")
        side_commit = git(repo, "rev-parse", "HEAD")
        git(repo, "tag", "rust-engine-v0.1.99")

        validate_lineage(
            repo,
            policy,
            "inspr-at/janus",
            "go-envelope-v1.170",
            main_commit,
            "refs/heads/main",
        )
        expect_denied(
            "release_not_on_protected_main",
            lambda: validate_lineage(
                repo,
                policy,
                "inspr-at/janus",
                "rust-engine-v0.1.99",
                side_commit,
                "refs/heads/main",
            ),
        )
        expect_denied(
            "release_tag_commit_mismatch",
            lambda: validate_lineage(
                repo,
                policy,
                "inspr-at/janus",
                "go-envelope-v1.170",
                side_commit,
                "refs/heads/main",
            ),
        )
        expect_denied(
            "release_repository_denied",
            lambda: validate_lineage(
                repo,
                policy,
                "attacker/janus",
                "go-envelope-v1.170",
                main_commit,
                "refs/heads/main",
            ),
        )
        expect_denied(
            "release_tag_invalid",
            lambda: validate_lineage(
                repo,
                policy,
                "inspr-at/janus",
                "go-envelope-v1.170-dev",
                main_commit,
                "refs/heads/main",
            ),
        )
        expect_denied(
            "release_lineage_git_failure",
            lambda: validate_lineage(
                repo,
                policy,
                "inspr-at/janus",
                "go-envelope-v1.170",
                main_commit,
                "refs/heads/forged-main",
            ),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repository")
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--fetch-main", action="store_true")
    parser.add_argument(
        "--main-ref",
        default="refs/remotes/origin/main",
    )
    args = parser.parse_args()
    try:
        policy = load_policy()
        if args.self_test:
            self_test(policy)
        if any((args.repository, args.tag, args.commit, args.fetch_main)):
            require(
                all((args.repository, args.tag, args.commit)),
                "release_lineage_invalid_arguments",
            )
            if args.fetch_main:
                git(
                    ROOT,
                    "fetch",
                    "--no-tags",
                    "--prune",
                    "origin",
                    f"+refs/heads/{policy['protected_branch']}:{args.main_ref}",
                )
            validate_lineage(
                ROOT,
                policy,
                args.repository,
                args.tag,
                args.commit,
                args.main_ref,
            )
    except LineageError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("release_lineage=trusted protected_branch=main value_returned=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
