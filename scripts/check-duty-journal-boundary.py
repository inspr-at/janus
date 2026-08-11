#!/usr/bin/env python3
"""Keep caller-created duty history out of the production policy boundary."""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate(
    roles: str,
    broker: str,
    local_roles: str,
    local_duty: str,
    design: str,
) -> None:
    required_roles = (
        "pub enum DutyAuthorization<'a>",
        "AccountabilityLegacy",
        "Recorded {",
        "pub duty_authorization: DutyAuthorization<'a>",
        "candidate.scope() != input.scope",
        "view.conflict_reason(candidate",
    )
    for marker in required_roles:
        if marker not in roles:
            raise ValueError(f"role policy boundary missing: {marker}")
    for forbidden in ("DutyEvidence", "pub duties:", "duties: &[]"):
        if forbidden in roles or forbidden in broker or forbidden in local_roles:
            raise ValueError(f"caller-created duty input returned: {forbidden}")
    if "DutyAuthorization::AccountabilityLegacy" not in broker:
        raise ValueError("broker pre-cutover posture is not explicit")
    if "DutyAuthorization::AccountabilityLegacy" not in local_roles:
        raise ValueError("runtime pre-cutover posture is not explicit")
    for marker in (
        "actor: &crate::BrokerAuthenticatedActorV1",
        "operation: VerifiedAuthoritativeOperation",
        "fn authorize_candidate(",
        "legacy_duty_import_forbidden",
        "journal index diverged",
        "failed audit intentionally leaves the conservative synced duty",
    ):
        if marker not in local_duty:
            raise ValueError(f"broker journal boundary missing: {marker}")
    if "cannot advertise `enforced_recorded`" not in design:
        raise ValueError("slice-two documentation overstates enforcement")


def self_test() -> None:
    roles = """
pub enum DutyAuthorization<'a> { AccountabilityLegacy, Recorded { view: &'a V, candidate: &'a C } }
pub duty_authorization: DutyAuthorization<'a>
candidate.scope() != input.scope
view.conflict_reason(candidate, conflicts)
"""
    broker = "DutyAuthorization::AccountabilityLegacy"
    local_roles = "DutyAuthorization::AccountabilityLegacy"
    local_duty = """
actor: &crate::BrokerAuthenticatedActorV1
operation: VerifiedAuthoritativeOperation
fn authorize_candidate(
legacy_duty_import_forbidden
journal index diverged
failed audit intentionally leaves the conservative synced duty
"""
    design = "This slice cannot advertise `enforced_recorded`."
    validate(roles, broker, local_roles, local_duty, design)
    mutations = (
        (roles.replace("Recorded {", "Observed {"), broker, local_roles, local_duty, design),
        (roles + "\npub duties: &[DutyEvidence]", broker, local_roles, local_duty, design),
        (roles, "", local_roles, local_duty, design),
        (roles, broker, local_roles, local_duty.replace("legacy_duty_import_forbidden", ""), design),
        (roles, broker, local_roles, local_duty, "enforced now"),
    )
    for fixture in mutations:
        try:
            validate(*fixture)
        except ValueError:
            continue
        raise AssertionError("negative duty-boundary fixture was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("duty journal boundary self-test passed")
            return 0
        validate(
            (ROOT / "crates/janus-core/src/roles.rs").read_text(),
            (ROOT / "crates/janus-core/src/broker.rs").read_text(),
            (ROOT / "crates/janus-local/src/roles.rs").read_text(),
            (ROOT / "crates/janus-local/src/duty.rs").read_text(),
            (ROOT / "docs/durable-duty-journal.md").read_text(),
        )
    except (OSError, ValueError, AssertionError) as error:
        print(f"duty journal boundary blocked: {error}", file=sys.stderr)
        return 1
    print("duty journal boundary verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
