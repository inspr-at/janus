#!/usr/bin/env python3
"""Verify Janus's exact immutable Paimos external-stage v1 contract pins."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

CONTRACT_DIRECTORY = Path("contracts/paimos-external-stage-v1")
EXPECTED_FILES = {
    "dependency-janus-v1.json": (1115, "52a647abd52e229fcdef8461eeb9f7d31f07632501ad33f594cdfbc155c23d4b"),
    "owner-pharos-v1.json": (1504, "8ab2ab9df3f5e12cf225a83d77129bdcab14241bc2a5ab03505811a556e016fc"),
}
EXPECTED_MANIFEST_SHA256 = "6aaad204b9e086e49eb0c7c10681ae334819c8d06faf621c68df16bde9ecef87"
EXPECTED_SET_SHA256 = "0318f4025902c9d5dd790384950cc9daebb16e02e79a4a90ce7dddc673e68bed"
EXPECTED_COMMIT = "e5f4c86bc061775c853d5847e8fb8bb7e3a31c34"
EXPECTED_RELEASE = "v5.11.0"
SET_DOMAIN = b"paimos.external-stage.fixtures.v1\x00"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify(repo_root: Path) -> None:
    contract = repo_root / CONTRACT_DIRECTORY
    inventory = {path.name for path in contract.iterdir() if path.is_file()}
    expected_inventory = {*EXPECTED_FILES, "manifest-v1.json"}
    if inventory != expected_inventory:
        raise ValueError("external-stage v1 fixture inventory drifted")

    manifest_raw = (contract / "manifest-v1.json").read_bytes()
    if digest(manifest_raw) != EXPECTED_MANIFEST_SHA256:
        raise ValueError("external-stage v1 manifest bytes drifted")
    if not manifest_raw.endswith(b"\n") or manifest_raw.endswith(b"\n\n"):
        raise ValueError("external-stage v1 manifest must have one trailing LF")
    manifest = json.loads(manifest_raw)
    if set(manifest) != {
        "schema_major",
        "contract",
        "media_type",
        "encoding",
        "paimos_commit",
        "paimos_release",
        "fixture_digest",
        "fixtures",
    }:
        raise ValueError("external-stage v1 manifest schema drifted")
    if (
        manifest["schema_major"] != 1
        or manifest["contract"] != "paimos.external-stage.v1"
        or manifest["media_type"] != "application/vnd.paimos.external-stage.v1+json"
        or manifest["encoding"] != "utf-8-json-lf"
        or manifest["paimos_commit"] != EXPECTED_COMMIT
        or manifest["paimos_release"] != EXPECTED_RELEASE
        or manifest["fixture_digest"] != f"sha256:{EXPECTED_SET_SHA256}"
    ):
        raise ValueError("external-stage v1 contract tuple drifted")

    fixture_manifest = {
        item["file"]: item
        for item in manifest["fixtures"]
        if isinstance(item, dict) and isinstance(item.get("file"), str)
    }
    if set(fixture_manifest) != set(EXPECTED_FILES) or len(manifest["fixtures"]) != len(EXPECTED_FILES):
        raise ValueError("external-stage v1 manifest fixture set drifted")

    fixture_set = hashlib.sha256()
    fixture_set.update(SET_DOMAIN)
    for name in sorted(EXPECTED_FILES):
        raw = (contract / name).read_bytes()
        expected_bytes, expected_sha256 = EXPECTED_FILES[name]
        entry = fixture_manifest[name]
        if len(raw) != expected_bytes or digest(raw) != expected_sha256:
            raise ValueError(f"external-stage v1 fixture bytes drifted: {name}")
        if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
            raise ValueError(f"external-stage v1 fixture must have one trailing LF: {name}")
        if entry.get("bytes") != expected_bytes or entry.get("sha256") != expected_sha256:
            raise ValueError(f"external-stage v1 manifest digest drifted: {name}")
        fixture_set.update(name.encode("utf-8"))
        fixture_set.update(b"\x00")
        fixture_set.update(raw)
        fixture_set.update(b"\x00")
    if fixture_set.hexdigest() != EXPECTED_SET_SHA256:
        raise ValueError("external-stage v1 fixture-set digest drifted")


def self_test(repo_root: Path) -> None:
    verify(repo_root)
    with tempfile.TemporaryDirectory() as temporary:
        test_root = Path(temporary)
        destination = test_root / CONTRACT_DIRECTORY
        destination.parent.mkdir(parents=True)
        shutil.copytree(repo_root / CONTRACT_DIRECTORY, destination)
        fixture = destination / "dependency-janus-v1.json"
        raw = fixture.read_bytes()
        fixture.write_bytes(raw[:-2] + b" \n")
        try:
            verify(test_root)
        except ValueError:
            return
        raise AssertionError("tampered external-stage fixture was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(args.repo_root)
            print("Paimos external-stage v1 pin verifier self-test passed")
        else:
            verify(args.repo_root)
            print("Paimos external-stage v1 pins verified")
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"Paimos external-stage v1 pins blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
