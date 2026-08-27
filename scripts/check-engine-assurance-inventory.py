#!/usr/bin/env python3
"""Prove the engine assurance gate's phase inventory is intact (JANUS-438).

`scripts/assure-engine-release.sh` used to be one 9m17s serial script. It is
now split into two independently-schedulable CI job groups — `tests` (pure
checks, cargo test, no built binaries) and `smoke` (build the daemon
binaries once, then the with-runtime-authority smoke scripts) — with a
fan-in job that keeps the original `check-assurance` required check name.

`scripts/assure-engine-release.sh --list-phases` prints the exact table the
script dispatches from: not a separately maintained description of it. This
compares that live table against a reviewed baseline
(`config/assurance/engine-release-phases-v1.json`) so a future edit cannot
silently drop a gate, rename it out from under `report-rust-release-timing.py`,
or move it into the wrong fan-out group.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/assure-engine-release.sh"
BASELINE = ROOT / "config/assurance/engine-release-phases-v1.json"
GROUPS = ("tests", "smoke")


class InventoryError(RuntimeError):
    pass


def list_phases(script: Path) -> list[dict]:
    try:
        output = subprocess.run(
            ["bash", str(script), "--list-phases"],
            check=True,
            capture_output=True,
            cwd=ROOT,
        ).stdout.decode("utf-8")
    except subprocess.CalledProcessError as error:
        raise InventoryError("assurance script rejected --list-phases") from error
    phases = []
    for line in output.splitlines():
        if not line:
            continue
        columns = line.split("\t")
        if len(columns) != 3:
            raise InventoryError(f"malformed phase line: {line!r}")
        slug, group, label = columns
        phases.append({"slug": slug, "group": group, "label": label})
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


def compare(actual: list[dict], baseline: list[dict]) -> None:
    if actual != baseline:
        raise InventoryError("phase inventory diverged from the reviewed baseline")


def self_test() -> None:
    good = [
        {"slug": "a", "group": "tests", "label": "A"},
        {"slug": "b", "group": "smoke", "label": "B"},
    ]
    validate(good)
    compare(good, good)

    negative_fixtures = {
        "no phases declared": [],
        "duplicate phase slug": [
            {"slug": "a", "group": "tests", "label": "A"},
            {"slug": "a", "group": "smoke", "label": "B"},
        ],
        "unknown phase group: bogus": [{"slug": "a", "group": "bogus", "label": "A"}],
        "phase a has no label": [{"slug": "a", "group": "tests", "label": ""}],
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
        subprocess.SubprocessError,
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
