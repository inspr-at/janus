#!/usr/bin/env python3
"""Prove the engine assurance gate's phase inventory is intact (JANUS-438).

`scripts/assure-engine-release.sh` used to be one 9m17s serial script. It is
now split into two independently-schedulable CI job groups — `tests` (checks,
cargo test, and a cache-backed container minimization proof) and `smoke`
(build the daemon binaries once, then the with-runtime-authority smoke scripts) — with a
fan-in job that keeps the original `check-assurance` required check name.

`scripts/assure-engine-release.sh --list-phases` prints the exact table the
script dispatches from: not a separately maintained description of it. This
combines that live table with SHA-256 hashes of the dispatched `run_*`
function bodies, then compares it against a reviewed baseline
(`config/assurance/engine-release-phases-v1.json`) so a future edit cannot
silently drop a gate, rename it out from under `report-rust-release-timing.py`,
or move it into the wrong fan-out group.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/assure-engine-release.sh"
BASELINE = ROOT / "config/assurance/engine-release-phases-v1.json"
GROUPS = ("tests", "smoke")
FUNCTION_PATTERN = re.compile(
    r"^run_([a-z0-9_]+)\(\) \{\n(?P<body>.*?)^\}\n", re.MULTILINE | re.DOTALL
)
PHASE_PATTERN = re.compile(
    r'^phase +([a-z0-9-]+) +(tests|smoke) +"([^"]+)"$', re.MULTILINE
)


class InventoryError(RuntimeError):
    pass


def command_hashes(script: Path) -> dict[str, str]:
    source = script.read_text(encoding="utf-8")
    hashes = {}
    for match in FUNCTION_PATTERN.finditer(source):
        slug = match.group(1).replace("_", "-")
        body = match.group("body")
        hashes[slug] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return hashes


def list_phases(script: Path) -> list[dict]:
    source = script.read_text(encoding="utf-8")
    commands = command_hashes(script)
    phases = []
    for slug, group, label in PHASE_PATTERN.findall(source):
        command_hash = commands.pop(slug, None)
        if command_hash is None:
            raise InventoryError(f"phase {slug} has no run function")
        phases.append(
            {
                "slug": slug,
                "group": group,
                "label": label,
                "commands_sha256": command_hash,
            }
        )
    if commands:
        raise InventoryError(f"unregistered run functions: {', '.join(sorted(commands))}")
    return phases


def validate(phases: list[dict]) -> None:
    if not phases:
        raise InventoryError("no phases declared")
    slugs = [phase["slug"] for phase in phases]
    if len(slugs) != len(set(slugs)):
        raise InventoryError("duplicate phase slug")
    for phase in phases:
        if phase["group"] not in GROUPS:
            raise InventoryError(f"unknown phase group: {phase['group']}")
        if not phase["label"]:
            raise InventoryError(f"phase {phase['slug']} has no label")
        command_hash = phase.get("commands_sha256")
        if not isinstance(command_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", command_hash):
            raise InventoryError(f"phase {phase['slug']} has no reviewed command hash")


def compare(actual: list[dict], baseline: list[dict]) -> None:
    if actual != baseline:
        raise InventoryError("phase inventory diverged from the reviewed baseline")


def self_test() -> None:
    good = [
        {"slug": "a", "group": "tests", "label": "A", "commands_sha256": "a" * 64},
        {"slug": "b", "group": "smoke", "label": "B", "commands_sha256": "b" * 64},
    ]
    validate(good)
    compare(good, good)

    negative_fixtures = {
        "no phases declared": [],
        "duplicate phase slug": [
            {"slug": "a", "group": "tests", "label": "A", "commands_sha256": "a" * 64},
            {"slug": "a", "group": "smoke", "label": "B", "commands_sha256": "b" * 64},
        ],
        "unknown phase group: bogus": [
            {"slug": "a", "group": "bogus", "label": "A", "commands_sha256": "a" * 64}
        ],
        "phase a has no label": [
            {"slug": "a", "group": "tests", "label": "", "commands_sha256": "a" * 64}
        ],
        "phase a has no reviewed command hash": [
            {"slug": "a", "group": "tests", "label": "A", "commands_sha256": "invalid"}
        ],
    }
    for expected, fixture in negative_fixtures.items():
        try:
            validate(fixture)
        except InventoryError as caught:
            if str(caught) != expected:
                raise AssertionError(f"unexpected error for {expected!r}: {caught}")
            continue
        raise AssertionError(f"negative phase fixture was accepted: {expected}")

    try:
        compare(good, [good[0]])
    except InventoryError:
        pass
    else:
        raise AssertionError("negative baseline fixture was accepted")

    try:
        compare(good, [good[1], good[0]])
    except InventoryError:
        pass
    else:
        raise AssertionError("reordered baseline fixture was accepted")

    with tempfile.TemporaryDirectory(prefix="janus-assurance-inventory-") as directory:
        fixture = Path(directory) / "assure.sh"
        fixture.write_text(
            'phase a tests "A"\n\nrun_a() {\nprintf "first\\n"\n}\n',
            encoding="utf-8",
        )
        first = list_phases(fixture)
        validate(first)
        fixture.write_text(
            'phase a tests "A"\n\nrun_a() {\nprintf "changed\\n"\n}\n',
            encoding="utf-8",
        )
        second = list_phases(fixture)
        if first[0]["commands_sha256"] == second[0]["commands_sha256"]:
            raise AssertionError("changed phase commands retained the reviewed hash")
        try:
            compare(second, first)
        except InventoryError:
            pass
        else:
            raise AssertionError("changed phase commands matched the reviewed baseline")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("ok: engine assurance inventory self-test passed")
            return 0
        baseline_document = json.loads(BASELINE.read_text())
        baseline = baseline_document["phases"]
        validate(baseline)
        actual = list_phases(SCRIPT)
        validate(actual)
        compare(actual, baseline)
    except (
        InventoryError,
        OSError,
        json.JSONDecodeError,
        KeyError,
    ) as error:
        print(
            f"engine_assurance_inventory=blocked reason={error} value_returned=false",
            file=sys.stderr,
        )
        return 1
    tests = sum(1 for phase in actual if phase["group"] == "tests")
    smoke = sum(1 for phase in actual if phase["group"] == "smoke")
    print(
        "engine_assurance_inventory=trusted "
        f"phases={len(actual)} tests={tests} smoke={smoke} value_returned=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
