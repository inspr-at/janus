#!/usr/bin/env python3
"""Emit machine-readable Rust release latency evidence and enforce its budget."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REQUIRED = {
    "check-fast": ("release security policy and negative fixtures",),
    "check-nix": ("nix package",),
    "check-assurance": ("engine release assurance gate",),
    "image-amd64": ("build native amd64 image",),
    "image-arm64": ("build native arm64 image",),
    "image": (
        "scan exact published candidate digest", "sign and verify released source binding",
        "cosign sign (keyless)", "SBOM (SPDX)", "build provenance attestation",
        "SPDX SBOM attestation", "verify published engine digest and mode receipts",
    ),
}


def timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def seconds(start: str, end: str) -> int:
    return round((timestamp(end) - timestamp(start)).total_seconds())


def report(run: dict, jobs: list[dict], budget: int) -> dict:
    found = {job.get("name"): job for job in jobs}
    evidence: dict[str, object] = {}
    for name, required_steps in REQUIRED.items():
        job = found.get(name)
        if not job or job.get("conclusion") != "success":
            raise ValueError(f"required successful job missing: {name}")
        step_map = {step.get("name"): step for step in job.get("steps", [])}
        step_evidence = {}
        for step_name in required_steps:
            step = step_map.get(step_name)
            if not step or step.get("conclusion") != "success":
                raise ValueError(f"required successful step missing: {name}/{step_name}")
            step_evidence[step_name] = seconds(step["started_at"], step["completed_at"])
        evidence[name] = {
            "duration_seconds": seconds(job["started_at"], job["completed_at"]),
            "steps_seconds": step_evidence,
        }
    elapsed = seconds(run["created_at"], found["image"]["completed_at"])
    return {
        "schema_version": 1, "run_id": str(run["id"]), "commit": run["head_sha"],
        "budget_seconds": budget, "release_elapsed_seconds": elapsed,
        "budget_passed": elapsed <= budget, "jobs": evidence,
    }


def self_test() -> None:
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    stamp = lambda n: (base + dt.timedelta(seconds=n)).isoformat().replace("+00:00", "Z")
    jobs = []
    for index, (name, required_steps) in enumerate(REQUIRED.items()):
        steps = [{"name": step, "conclusion": "success", "started_at": stamp(index * 10), "completed_at": stamp(index * 10 + 2)} for step in required_steps]
        jobs.append({"name": name, "conclusion": "success", "started_at": stamp(index * 10), "completed_at": stamp(index * 10 + 9), "steps": steps})
    run = {"id": 1, "head_sha": "a" * 40, "created_at": stamp(0)}
    assert report(run, jobs, 900)["release_elapsed_seconds"] == 59
    for fixture in (jobs[:-1], [{**jobs[0], "conclusion": "failure"}, *jobs[1:]]):
        try:
            report(run, fixture, 900)
        except ValueError:
            continue
        raise AssertionError("negative timing fixture was accepted")
    assert report(run, jobs, 10)["budget_passed"] is False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--budget-seconds", type=int, default=900)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("Rust release timing self-test passed")
            return 0
        if not all((args.run, args.jobs, args.output, args.summary)):
            parser.error("reporting requires run, jobs, output, and summary")
        document = report(json.loads(args.run.read_text()), json.loads(args.jobs.read_text())["jobs"], args.budget_seconds)
        args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        rows = ["## Rust release timing", "", f"Total: **{document['release_elapsed_seconds']}s** / {document['budget_seconds']}s budget", "", "| Job | Seconds |", "|---|---:|"]
        rows += [f"| {name} | {value['duration_seconds']} |" for name, value in document["jobs"].items()]
        args.summary.write_text("\n".join(rows) + "\n")
        result = "passed" if document["budget_passed"] else "blocked"
        print(f"Rust release timing {result}: {document['release_elapsed_seconds']}s")
        return 0 if document["budget_passed"] else 1
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"Rust release timing blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
