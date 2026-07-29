#!/usr/bin/env python3
"""Reject attended-browser artifacts before they enter the Janus tree."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN_COMPONENTS = {
    ".playwright-mcp",
    ".playwright",
    "playwright-report",
    "test-results",
    "chrome-debug-profile",
}
FORBIDDEN_NAMES = {
    "DevToolsActivePort",
    "storage-state.json",
    "cookies.json",
}
FORBIDDEN_SUFFIXES = (
    ".trace.zip",
    ".har",
    ".webm",
)
REQUIRED_IGNORES = {
    "/.playwright-mcp/",
    "/.playwright/",
    "/test-results/",
    "/playwright-report/",
    "/browser-qa/test-results/",
}


class HygieneError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HygieneError(message)


def forbidden(path: str) -> bool:
    candidate = pathlib.PurePosixPath(path)
    return (
        any(component in FORBIDDEN_COMPONENTS for component in candidate.parts)
        or candidate.name in FORBIDDEN_NAMES
        or candidate.name.endswith(FORBIDDEN_SUFFIXES)
    )


def check_paths(paths: list[str], source: str) -> None:
    rejected = [path for path in paths if path and forbidden(path)]
    require(not rejected, f"browser_artifact_{source}")


def git_paths(*args: str) -> list[str]:
    try:
        output = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise HygieneError("browser_artifact_git_failure") from error
    return [
        item.decode("utf-8", errors="strict")
        for item in output.split(b"\0")
        if item
    ]


def validate_repository() -> None:
    ignores = set((ROOT / ".gitignore").read_text().splitlines())
    require(REQUIRED_IGNORES.issubset(ignores), "browser_artifact_ignore_policy")
    check_paths(git_paths("ls-files", "-z"), "tracked")
    check_paths(
        git_paths(
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
        ),
        "staged",
    )
    check_paths(
        git_paths("ls-files", "--others", "--exclude-standard", "-z"),
        "untracked",
    )


def expect_denied(paths: list[str]) -> None:
    try:
        check_paths(paths, "fixture")
    except HygieneError:
        return
    raise HygieneError("browser_artifact_negative_fixture")


def self_test() -> None:
    check_paths(
        [
            "browser-qa/managed-secret-ux.spec.mjs",
            "docs/assets/janus-login-hero.png",
        ],
        "fixture",
    )
    for path in (
        ".playwright-mcp/page-1.yml",
        "playwright-report/index.html",
        "test-results/result.json",
        "browser-qa/chrome-debug-profile/Default/Cookies",
        "browser-qa/storage-state.json",
        "browser-qa/run.trace.zip",
        "browser-qa/video.webm",
        "browser-qa/network.har",
        "browser-qa/DevToolsActivePort",
    ):
        expect_denied([path])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repository", action="store_true")
    args = parser.parse_args()
    try:
        require(
            args.self_test or args.repository,
            "browser_artifact_invalid_arguments",
        )
        if args.self_test:
            self_test()
        if args.repository:
            validate_repository()
    except (OSError, UnicodeError, HygieneError) as error:
        print(
            f"browser_qa_hygiene=blocked reason={error} value_returned=false",
            file=sys.stderr,
        )
        return 1
    print("browser_qa_hygiene=trusted value_returned=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
