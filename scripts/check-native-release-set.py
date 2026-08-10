#!/usr/bin/env python3
"""Fail closed when assembling or verifying the native Rust image index."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PLATFORMS = ("linux/amd64", "linux/arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def validate(records: list[dict[str, str]], commit: str, run_id: str) -> dict[str, object]:
    if not COMMIT.fullmatch(commit) or not run_id.isdecimal():
        raise ValueError("invalid expected workflow identity")
    by_platform: dict[str, dict[str, str]] = {}
    for record in records:
        if set(record) != {"platform", "digest", "commit", "run_id"}:
            raise ValueError("invalid native record schema")
        platform = record["platform"]
        if platform not in PLATFORMS or platform in by_platform:
            raise ValueError(f"unexpected or duplicate platform: {platform}")
        if not DIGEST.fullmatch(record["digest"]):
            raise ValueError(f"invalid digest for {platform}")
        if record["commit"] != commit or record["run_id"] != run_id:
            raise ValueError(f"stale or cross-workflow record for {platform}")
        by_platform[platform] = record
    if tuple(sorted(by_platform)) != tuple(sorted(PLATFORMS)):
        raise ValueError("native records must contain exactly amd64 and arm64")
    if len({record["digest"] for record in records}) != len(PLATFORMS):
        raise ValueError("native platform digests must be distinct")
    return {
        "schema_version": 1,
        "commit": commit,
        "run_id": run_id,
        "platforms": [by_platform[platform] for platform in PLATFORMS],
    }


def verify_index(document: dict[str, object], raw_index: dict[str, object]) -> None:
    manifests = raw_index.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("published image is not an OCI index")
    actual: dict[str, str] = {}
    for manifest in manifests:
        if not isinstance(manifest, dict) or not isinstance(manifest.get("platform"), dict):
            raise ValueError("invalid OCI index manifest")
        platform = manifest["platform"]
        key = f"{platform.get('os')}/{platform.get('architecture')}"
        digest = manifest.get("digest")
        if key not in PLATFORMS or key in actual or not isinstance(digest, str):
            raise ValueError(f"unexpected or duplicate published platform: {key}")
        actual[key] = digest
    expected = {item["platform"]: item["digest"] for item in document["platforms"]}  # type: ignore[index]
    if actual != expected:
        raise ValueError(f"published platform set mismatch: expected={expected} actual={actual}")


def self_test() -> None:
    commit = "a" * 40
    run_id = "123"
    records = [
        {"platform": "linux/amd64", "digest": "sha256:" + "1" * 64, "commit": commit, "run_id": run_id},
        {"platform": "linux/arm64", "digest": "sha256:" + "2" * 64, "commit": commit, "run_id": run_id},
    ]
    document = validate(records, commit, run_id)
    verify_index(document, {"manifests": [
        {"digest": records[0]["digest"], "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": records[1]["digest"], "platform": {"os": "linux", "architecture": "arm64"}},
    ]})
    mutations = [records[:1], [records[0], records[0]], [records[0], {**records[1], "commit": "b" * 40}],
                 [records[0], {**records[1], "run_id": "122"}], [records[0], {**records[1], "digest": records[0]["digest"]}]]
    for fixture in mutations:
        try:
            validate(fixture, commit, run_id)
        except ValueError:
            continue
        raise AssertionError("negative native-record fixture was accepted")
    try:
        verify_index(document, {"manifests": [{"digest": records[0]["digest"], "platform": {"os": "linux", "architecture": "amd64"}}]})
    except ValueError:
        return
    raise AssertionError("missing published architecture was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--amd64-digest")
    parser.add_argument("--arm64-digest")
    parser.add_argument("--commit")
    parser.add_argument("--run-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-image")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("native release set self-test passed")
            return 0
        if not all((args.amd64_digest, args.arm64_digest, args.commit, args.run_id, args.output)):
            parser.error("record creation requires both digests, commit, run-id, and output")
        records = [
            {"platform": "linux/amd64", "digest": args.amd64_digest, "commit": args.commit, "run_id": args.run_id},
            {"platform": "linux/arm64", "digest": args.arm64_digest, "commit": args.commit, "run_id": args.run_id},
        ]
        document = validate(records, args.commit, args.run_id)
        args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        if args.verify_image:
            raw = subprocess.run(
                ["docker", "buildx", "imagetools", "inspect", "--raw", args.verify_image],
                check=True, capture_output=True, text=True,
            ).stdout
            verify_index(document, json.loads(raw))
        print("native release set verified")
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"native release set blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
