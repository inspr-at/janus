#!/usr/bin/env python3
"""Emit a value-free PR critical-path timing summary with a budget verdict.

JANUS-438 acceptance criteria 4 and 7: every protected pull-request run
uploads job/step durations, cache hit/miss, its critical path, and a budget
verdict — never raw logs, secrets, request values, or host paths. This
reporter only ever consumes job names, ISO timestamps, conclusions, and a
caller-supplied cache-hit map, so there is nothing value-bearing it *could*
leak; the input shape is the enforcement.

Reused by both protected pull-request pipelines:
  - rust.yml: reports its own PR-path critical path. A numeric budget only
    applies when the change is proven Go-only (see scripts/classify-pr-paths.py);
    otherwise the verdict is explicitly "not_applicable" rather than a
    fabricated number.
  - go-envelope.yml: reports the Go pipeline's own PR-path critical path
    against the reviewed Go-only PR budget (warm under 5 minutes, cold under
    8 minutes), selected by the Playwright Chromium cache outcome.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def seconds(start: str, end: str) -> int:
    return round((timestamp(end) - timestamp(start)).total_seconds())


def report(
    run: dict,
    jobs: list[dict],
    cache: dict[str, bool],
    budget_seconds: int | None,
) -> dict:
    if not jobs:
        raise ValueError("no jobs to report")
    timed_jobs = [job for job in jobs if job.get("started_at") and job.get("completed_at")]
    if not timed_jobs:
        raise ValueError("no jobs carry start/completion timestamps")
    for job in timed_jobs:
        if job.get("conclusion") not in ("success", "skipped"):
            raise ValueError(f"job did not succeed or skip cleanly: {job.get('name')}")
    started = min(timestamp(job["started_at"]) for job in timed_jobs)
    completed = max(timestamp(job["completed_at"]) for job in timed_jobs)
    critical_path = round((completed - started).total_seconds())
    document: dict[str, object] = {
        "schema_version": 1,
        "run_id": str(run["id"]),
        "commit": run["head_sha"],
        "critical_path_seconds": critical_path,
        "jobs_seconds": {
            job["name"]: seconds(job["started_at"], job["completed_at"]) for job in timed_jobs
        },
        "cache": {name: ("hit" if hit else "miss") for name, hit in sorted(cache.items())},
    }
    if budget_seconds is None:
        document["budget_seconds"] = None
        document["budget_verdict"] = "not_applicable"
    else:
        document["budget_seconds"] = budget_seconds
        document["budget_verdict"] = "passed" if critical_path <= budget_seconds else "blocked"
    return document


def parse_cache_hit(pairs: list[str]) -> dict[str, bool]:
    cache: dict[str, bool] = {}
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            raise ValueError(f"malformed --cache-hit value: {pair!r}")
        if value not in ("true", "false"):
            raise ValueError(f"--cache-hit value must be true or false: {pair!r}")
        cache[name] = value == "true"
    return cache


def self_test() -> None:
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    stamp = lambda n: (base + dt.timedelta(seconds=n)).isoformat().replace("+00:00", "Z")
    jobs = [
        {"name": "a", "conclusion": "success", "started_at": stamp(0), "completed_at": stamp(30)},
        {"name": "b", "conclusion": "skipped", "started_at": stamp(5), "completed_at": stamp(65)},
    ]
    run = {"id": 7, "head_sha": "b" * 40}
    cache = {"playwright": True, "rust-cache": False}

    document = report(run, jobs, cache, 90)
    assert document["critical_path_seconds"] == 65
    assert document["cache"] == {"playwright": "hit", "rust-cache": "miss"}
    assert document["budget_verdict"] == "passed"

    assert report(run, jobs, cache, 60)["budget_verdict"] == "blocked"

    not_applicable = report(run, jobs, cache, None)
    assert not_applicable["budget_seconds"] is None
    assert not_applicable["budget_verdict"] == "not_applicable"

    # Value-free by construction: nothing beyond names/timestamps/booleans
    # the caller explicitly supplied ever appears in the document.
    serialized = json.dumps(document)
    for forbidden in ("secret", "token", "/Users/", "/home/", "Authorization"):
        assert forbidden not in serialized, f"leaked forbidden token: {forbidden}"

    for fixture, reason in (
        ([], "no jobs to report"),
        ([{"name": "x", "conclusion": "failure", "started_at": stamp(0), "completed_at": stamp(1)}], "job did not succeed or skip cleanly: x"),
        ([{"name": "x", "conclusion": "success"}], "no jobs carry start/completion timestamps"),
    ):
        try:
            report(run, fixture, cache, None)
        except ValueError as caught:
            assert str(caught) == reason, f"unexpected error: {caught}"
            continue
        raise AssertionError(f"negative timing fixture was accepted: {reason}")

    assert parse_cache_hit(["a=true", "b=false"]) == {"a": True, "b": False}
    for bad in ("noequals", "=true", "a=maybe"):
        try:
            parse_cache_hit([bad])
        except ValueError:
            continue
        raise AssertionError(f"malformed cache-hit fixture was accepted: {bad}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--cache-hit", action="append", default=[], metavar="NAME=true|false")
    parser.add_argument("--budget-seconds", type=int, default=None)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("ok: PR critical-path reporter self-test passed")
            return 0
        if not all((args.run, args.jobs, args.output, args.summary)):
            parser.error("reporting requires --run, --jobs, --output, and --summary")
        cache = parse_cache_hit(args.cache_hit)
        document = report(
            json.loads(args.run.read_text()),
            json.loads(args.jobs.read_text())["jobs"],
            cache,
            args.budget_seconds,
        )
        args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        budget_line = (
            "Budget: not applicable (change is not Go-only-classified)"
            if document["budget_seconds"] is None
            else f"Budget: **{document['critical_path_seconds']}s** / {document['budget_seconds']}s ({document['budget_verdict']})"
        )
        rows = ["## PR critical path", "", budget_line, "", "| Job | Seconds |", "|---|---:|"]
        rows += [f"| {name} | {value} |" for name, value in document["jobs_seconds"].items()]
        rows += ["", "| Cache | Status |", "|---|---|"]
        rows += [f"| {name} | {value} |" for name, value in document["cache"].items()]
        args.summary.write_text("\n".join(rows) + "\n")
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"pr_critical_path=blocked reason={error} value_returned=false", file=sys.stderr)
        return 1
    blocked = document["budget_verdict"] == "blocked"
    print(f"pr_critical_path={'blocked' if blocked else 'trusted'} value_returned=false")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
