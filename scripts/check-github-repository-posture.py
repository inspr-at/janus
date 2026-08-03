#!/usr/bin/env python3
"""Validate the live GitHub controls that protect Janus releases and secrets."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any

REPOSITORY = "inspr-at/janus"
BRANCH_RULESET = "CodeQL merge protection"
BRANCH_RULESET_ID = 19622624
BRANCH_RULESET_REVISION = "2026-07-23T15:41:48.674+02:00"
TAG_RULESET = "Janus release tag protection"
TAG_RULESET_ID = 19952373
TAG_RULESET_REVISION = "2026-07-29T08:47:18.572+02:00"
TAG_PATTERNS = {
    "refs/tags/go-envelope-v*",
    "refs/tags/rust-engine-v*",
}
TAG_RULES = {"creation", "update", "deletion", "non_fast_forward"}


class PostureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PostureError(message)


def validate_repository(value: dict[str, Any]) -> None:
    require(value.get("full_name") == REPOSITORY, "repository_identity")
    require(value.get("visibility") == "public", "repository_visibility")
    require(value.get("default_branch") == "main", "repository_default_branch")
    security = value.get("security_and_analysis")
    require(isinstance(security, dict), "repository_security_state")
    for control in (
        "dependabot_security_updates",
        "secret_scanning",
        "secret_scanning_push_protection",
    ):
        require(
            isinstance(security.get(control), dict)
            and security[control].get("status") == "enabled",
            f"repository_{control}",
        )
    for reviewed_off in (
        "secret_scanning_non_provider_patterns",
        "secret_scanning_validity_checks",
    ):
        require(
            isinstance(security.get(reviewed_off), dict)
            and security[reviewed_off].get("status") == "disabled",
            f"repository_{reviewed_off}_review_required",
        )


def validate_rulesets(values: list[dict[str, Any]]) -> None:
    branch_rules = [
        item
        for item in values
        if item.get("id") == BRANCH_RULESET_ID
        and item.get("name") == BRANCH_RULESET
        and item.get("target") == "branch"
        and item.get("enforcement") == "active"
        and "~DEFAULT_BRANCH"
        in ((item.get("conditions") or {}).get("ref_name") or {}).get("include", [])
    ]
    require(len(branch_rules) == 1, "default_branch_ruleset")
    require(
        branch_rules[0].get("source") == REPOSITORY
        and branch_rules[0].get("source_type") == "Repository"
        and branch_rules[0].get("updated_at") == BRANCH_RULESET_REVISION,
        "default_branch_ruleset_revision",
    )
    require(
        any(
            "code_scanning"
            in {
                rule.get("type")
                for rule in item.get("rules", [])
                if isinstance(rule, dict)
            }
            for item in branch_rules
        ),
        "default_branch_code_scanning_rule",
    )

    matches = [
        item
        for item in values
        if item.get("id") == TAG_RULESET_ID
        and item.get("name") == TAG_RULESET
        and item.get("target") == "tag"
        and item.get("enforcement") == "active"
    ]
    require(len(matches) == 1, "release_tag_ruleset")
    ruleset = matches[0]
    require(
        ruleset.get("source") == REPOSITORY
        and ruleset.get("source_type") == "Repository"
        and ruleset.get("updated_at") == TAG_RULESET_REVISION,
        "release_tag_ruleset_revision",
    )
    ref_names = (ruleset.get("conditions") or {}).get("ref_name") or {}
    require(
        set(ref_names.get("include") or []) == TAG_PATTERNS
        and not (ref_names.get("exclude") or []),
        "release_tag_patterns",
    )
    require(
        TAG_RULES.issubset(
            {
                rule.get("type")
                for rule in ruleset.get("rules", [])
                if isinstance(rule, dict)
            }
        ),
        "release_tag_rules",
    )
    bypass = ruleset.get("bypass_actors")
    require(
        bypass is None
        or (
            isinstance(bypass, list)
            and len(bypass) == 1
            and bypass[0].get("actor_type") == "OrganizationAdmin"
            and bypass[0].get("bypass_mode") == "always"
        ),
        "release_tag_bypass",
    )


def validate_alerts(values: list[dict[str, Any]]) -> None:
    require(isinstance(values, list), "secret_alert_state")
    require(not values, "unresolved_secret_scanning_alerts")


def api_failure_reason(label: str, error: BaseException) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        match = re.search(r"\bHTTP ([1-5][0-9]{2})\b", stderr)
        status = match.group(1) if match else "unknown"
    elif isinstance(error, OSError):
        status = "unavailable"
    else:
        status = "invalid_json"
    return f"github_posture_api_{label}_{status}"


def gh_json(
    endpoint: str,
    *fields: str,
    label: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Any:
    command = ["gh", "api", "--method", "GET", endpoint]
    for field in fields:
        command.extend(("-f", field))
    try:
        result = runner(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise PostureError(api_failure_reason(label, error)) from error


def live_state() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    repository = gh_json(f"repos/{REPOSITORY}", label="repository")
    summaries = gh_json(f"repos/{REPOSITORY}/rulesets", label="ruleset_summaries")
    require(isinstance(summaries, list), "github_ruleset_state")
    rulesets = []
    for summary in summaries:
        ruleset_id = summary.get("id") if isinstance(summary, dict) else None
        require(isinstance(ruleset_id, int), "github_ruleset_state")
        detail = gh_json(
            f"repos/{REPOSITORY}/rulesets/{ruleset_id}",
            label="ruleset_detail",
        )
        require(isinstance(detail, dict), "github_ruleset_state")
        rulesets.append(detail)
    alerts = gh_json(
        f"repos/{REPOSITORY}/secret-scanning/alerts",
        "state=open",
        "per_page=100",
        label="secret_alerts",
    )
    require(
        isinstance(repository, dict)
        and isinstance(rulesets, list)
        and isinstance(alerts, list),
        "github_posture_api",
    )
    return repository, rulesets, alerts


def fixture() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    repository = {
        "full_name": REPOSITORY,
        "visibility": "public",
        "default_branch": "main",
        "security_and_analysis": {
            "dependabot_security_updates": {"status": "enabled"},
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "secret_scanning_non_provider_patterns": {"status": "disabled"},
            "secret_scanning_validity_checks": {"status": "disabled"},
        },
    }
    rulesets = [
        {
            "id": BRANCH_RULESET_ID,
            "name": BRANCH_RULESET,
            "source": REPOSITORY,
            "source_type": "Repository",
            "updated_at": BRANCH_RULESET_REVISION,
            "target": "branch",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
            },
            "bypass_actors": [],
            "rules": [{"type": "code_scanning"}],
        },
        {
            "id": TAG_RULESET_ID,
            "name": TAG_RULESET,
            "source": REPOSITORY,
            "source_type": "Repository",
            "updated_at": TAG_RULESET_REVISION,
            "target": "tag",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": sorted(TAG_PATTERNS), "exclude": []}
            },
            "bypass_actors": [
                {
                    "actor_id": None,
                    "actor_type": "OrganizationAdmin",
                    "bypass_mode": "always",
                }
            ],
            "rules": [{"type": item} for item in sorted(TAG_RULES)],
        },
    ]
    return repository, rulesets, []


def expect_denied(action: object) -> None:
    try:
        action()
    except PostureError:
        return
    raise PostureError("repository_posture_negative_fixture")


def expect_api_failure(action: object, expected: str) -> None:
    try:
        action()
    except PostureError as error:
        require(str(error) == expected, "repository_posture_api_fixture")
        return
    raise PostureError("repository_posture_api_fixture")


def self_test() -> None:
    repository, rulesets, alerts = fixture()
    validate_repository(repository)
    validate_rulesets(rulesets)
    validate_alerts(alerts)

    for control in (
        "secret_scanning",
        "secret_scanning_push_protection",
        "dependabot_security_updates",
    ):
        changed = copy.deepcopy(repository)
        changed["security_and_analysis"][control]["status"] = "disabled"
        expect_denied(lambda value=changed: validate_repository(value))
    wrong_repository = copy.deepcopy(repository)
    wrong_repository["full_name"] = "attacker/janus"
    expect_denied(lambda: validate_repository(wrong_repository))
    missing_tag_rules = copy.deepcopy(rulesets[:1])
    expect_denied(lambda: validate_rulesets(missing_tag_rules))
    weakened_tag_rules = copy.deepcopy(rulesets)
    weakened_tag_rules[1]["rules"].pop()
    expect_denied(lambda: validate_rulesets(weakened_tag_rules))
    changed_revision = copy.deepcopy(rulesets)
    changed_revision[1]["updated_at"] = "2026-08-03T00:00:00Z"
    expect_denied(lambda: validate_rulesets(changed_revision))
    weakened_bypass = copy.deepcopy(rulesets)
    weakened_bypass[1]["bypass_actors"] = []
    expect_denied(lambda: validate_rulesets(weakened_bypass))
    redacted_bypass = copy.deepcopy(rulesets)
    redacted_bypass[1].pop("bypass_actors")
    validate_rulesets(redacted_bypass)
    expect_denied(lambda: validate_alerts([{"number": 1}]))

    def denied_runner(*_args: object, **_kwargs: object) -> Any:
        raise subprocess.CalledProcessError(
            1,
            ["gh", "api"],
            stderr="gh: Resource not accessible by integration (HTTP 403)",
        )

    def missing_runner(*_args: object, **_kwargs: object) -> Any:
        raise FileNotFoundError("gh")

    expect_api_failure(
        lambda: gh_json(
            f"repos/{REPOSITORY}/secret-scanning/alerts",
            label="secret_alerts",
            runner=denied_runner,
        ),
        "github_posture_api_secret_alerts_403",
    )
    expect_api_failure(
        lambda: gh_json(
            f"repos/{REPOSITORY}",
            label="repository",
            runner=missing_runner,
        ),
        "github_posture_api_repository_unavailable",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    try:
        require(args.self_test or args.live, "repository_posture_invalid_arguments")
        if args.self_test:
            self_test()
        if args.live:
            repository, rulesets, alerts = live_state()
            validate_repository(repository)
            validate_rulesets(rulesets)
            validate_alerts(alerts)
    except PostureError as error:
        print(
            f"github_repository_posture=blocked reason={error} value_returned=false",
            file=sys.stderr,
        )
        return 1
    print("github_repository_posture=trusted value_returned=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
