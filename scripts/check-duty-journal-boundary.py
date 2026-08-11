#!/usr/bin/env python3
"""Fail closed when runtime accountability coverage or wiring drifts."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def validate_documents(runtime: list[dict], duty: dict, warden: list[dict]) -> None:
    runtime_actions = {entry["action"] for entry in runtime}
    duty_actions = {entry["action"] for entry in duty["actions"]}
    require(len(runtime_actions) == len(runtime), "runtime action catalog contains duplicates")
    require(len(duty_actions) == len(duty["actions"]), "duty manifest contains duplicates")
    require(runtime_actions == duty_actions, "duty manifest does not exactly cover runtime catalog")
    require(duty["authority_service"] == "janusd-identityd", "authority service changed")
    require(duty["remote_authorizing_transports"] == [], "remote authorizing transport appeared")
    endpoint_transport = {entry["action"]: entry["transport"] for entry in runtime}
    for entry in duty["actions"]:
        require(
            entry["transport"] == endpoint_transport[entry["action"]],
            f"transport drift for {entry['action']}",
        )
        require(entry["classification"] in {"no_conflict", "recorded"}, "open duty classification")
        require(
            bool(entry["allowed_duties"]) == (entry["classification"] == "recorded"),
            f"duty classification mismatch for {entry['action']}",
        )
    warden_actions = {f"warden.{entry['name']}" for entry in warden}
    require(
        warden_actions == {action for action in runtime_actions if action.startswith("warden.")},
        "Warden tool catalog and runtime catalog differ",
    )
    require(
        {
            "admin.web_transaction",
            "admin.dynamic_custody",
            "admin.dynamic_delivery",
            "admin.dynamic_transport",
        }.issubset(runtime_actions),
        "private daemon surface is absent from runtime catalog",
    )


def validate_sources(core_roles: str, broker: str, local_roles: str, authority: str,
                     identity: str, janusd: str, warden_main: str, daemons: str,
                     design: str, runbook: str) -> None:
    for marker in (
        "BrokerAdmission(&'a crate::VerifiedRuntimeAdmission)",
        "admission.authorizes(input.permission, input.scope)",
        "admission.is_fresh_at(input.now)",
    ):
        require(marker in core_roles, f"role policy broker boundary missing: {marker}")
    require("DutyAuthorization::AccountabilityLegacy" not in broker,
            "production SecretBroker still selects legacy duty authorization")
    require("DutyAuthorization::AccountabilityLegacy" not in local_roles,
            "runtime role enforcement still selects legacy duty authorization")
    for marker in (
        "pub struct RuntimeAuthorityBroker",
        "authenticate_local_uid",
        "verify_once(reference, now)",
        "authorize_and_admit_in_posture",
        "verify_health()",
        "runtime_authority_posture_mismatch",
    ):
        require(marker in authority, f"runtime authority boundary missing: {marker}")
    require("with_runtime_authority" in identity, "identity socket does not route authority requests")
    require("authorize_runtime_action_from_env" in janusd,
            "CLI runtime authority call is missing")
    require("enforce_daemon_runtime_authority" in janusd,
            "daemon runtime authority gate is missing")
    require("authorize_runtime_action_from_env" in warden_main,
            "Warden runtime authority call is missing")
    for action in ("WebTransaction", "DynamicCustody", "DynamicDelivery", "DynamicTransport"):
        require(f"RuntimeAction::{action}" in daemons, f"daemon authority action missing: {action}")
    require("cannot advertise `enforced_recorded`" not in design,
            "foundation documentation still says runtime wiring is absent")
    for marker in ("accountability_legacy", "authenticated_observe", "enforced_recorded",
                   "active_legacy_operations", "rollback", "restore rehearsal"):
        require(marker in runbook, f"accountability runbook missing: {marker}")


def self_test() -> None:
    runtime = [{"action": "warden.health", "transport": "mcp_stdio"}]
    duty = {"authority_service": "janusd-identityd", "remote_authorizing_transports": [],
            "actions": [{"action": "warden.health", "transport": "mcp_stdio",
                         "classification": "no_conflict", "allowed_duties": []}]}
    warden = [{"name": "health"}]
    try:
        validate_documents(runtime, duty, warden)
    except ValueError as error:
        require(str(error) == "private daemon surface is absent from runtime catalog",
                "unexpected self-test denial")
    else:
        raise AssertionError("incomplete surface fixture was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("runtime accountability boundary self-test passed")
            return 0
        validate_documents(
            json.loads((ROOT / "config/runtime-endpoints/v1.json").read_text()),
            json.loads((ROOT / "config/authorization/duty-surface-manifest-v1.json").read_text()),
            json.loads((ROOT / "crates/janus-warden/tests/fixtures/tool_catalog.snapshot.json").read_text()),
        )
        daemon_sources = "\n".join(
            path.read_text() for path in (ROOT / "crates/janusd/src/lifecycle_entry").glob("dynamic_*.rs")
        ) + (ROOT / "crates/janusd/src/lifecycle_entry/web_transaction.rs").read_text()
        validate_sources(
            (ROOT / "crates/janus-core/src/roles.rs").read_text(),
            (ROOT / "crates/janus-core/src/broker.rs").read_text(),
            (ROOT / "crates/janus-local/src/roles.rs").read_text(),
            (ROOT / "crates/janus-local/src/authority.rs").read_text(),
            (ROOT / "crates/janus-local/src/identity.rs").read_text(),
            (ROOT / "crates/janusd/src/main.rs").read_text(),
            (ROOT / "crates/janus-warden/src/main.rs").read_text(),
            daemon_sources,
            (ROOT / "docs/durable-duty-journal.md").read_text(),
            (ROOT / "docs/runtime-accountability-runbook.md").read_text(),
        )
    except (OSError, KeyError, json.JSONDecodeError, ValueError, AssertionError) as error:
        print(f"runtime accountability boundary blocked: {error}", file=sys.stderr)
        return 1
    print("runtime accountability boundary verified: catalog=closed broker=wired posture=explicit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
