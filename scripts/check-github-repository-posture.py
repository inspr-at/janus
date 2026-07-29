#!/usr/bin/env python3
"""Validate the live GitHub controls that protect Janus releases and secrets."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
from typing import Any

REPOSITORY = "inspr-at/janus"
TAG_RULESET = "Janus release tag protection"
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
        if item.get("target") == "branch"
        and item.get("enforcement") == "active"
        and "~DEFAULT_BRANCH"
        in ((item.get("conditions") or {}).get("ref_name") or {}).get("include", [])
    ]
    require(branch_rules, "default_branch_ruleset")
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
        if item.get("name") == TAG_RULESET
        and item.get("target") == "tag"
        and item.get("enforcement") == "active"
    ]
    require(len(matches) == 1, "release_tag_ruleset")
    ruleset = matches[0]
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
        isinstance(bypass, list)
        and len(bypass) == 1
        and bypass[0].get("actor_type") == "OrganizationAdmin"
        and bypass[0].get("bypass_mode") == "always",
        "release_tag_bypass",
    )


def validate_alerts(values: list[dict[str, Any]]) -> None:
    require(isinstance(values, list), "secret_alert_state")
    require(not values, "unresolved_secret_scanning_alerts")


def gh_json(endpoint: str, *fields: str) -> Any:
    command = ["gh", "api", "--method", "GET", endpoint]
    for field in fields:
        command.extend(("-f", field))
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise PostureError("github_posture_api") from error


def live_state() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    repository = gh_json(f"repos/{REPOSITORY}")
    summaries = gh_json(f"repos/{REPOSITORY}/rulesets")
    require(isinstance(summaries, list), "github_ruleset_state")
    rulesets = []
    for summary in summaries:
        ruleset_id = summary.get("id") if isinstance(summary, dict) else None
        require(isinstance(ruleset_id, int), "github_ruleset_state")
        detail = gh_json(f"repos/{REPOSITORY}/rulesets/{ruleset_id}")
        require(isinstance(detail, dict), "github_ruleset_state")
        rulesets.append(detail)
    alerts = gh_json(
        f"repos/{REPOSITORY}/secret-scanning/alerts",
        "state=open",
        "per_page=100",
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
            "name": "CodeQL merge protection",
            "target": "branch",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
            },
            "bypass_actors": [],
            "rules": [{"type": "code_scanning"}],
        },
        {
            "name": TAG_RULESET,
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
    expect_denied(lambda: validate_alerts([{"number": 1}]))


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
