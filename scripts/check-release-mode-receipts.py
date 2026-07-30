#!/usr/bin/env python3
"""Validate mode-specific release receipts without exposing their payloads."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import sys
from typing import Any


class ReceiptError(RuntimeError):
    """A value-free release receipt validation failure."""


SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
TOP_LEVEL_KEYS = {
    "schema_version",
    "policy_id",
    "policy_version",
    "channel",
    "mode",
    "previous_mode",
    "artifact",
    "signature",
    "provenance",
    "sbom",
    "source",
    "scanner",
}
NESTED_KEYS = {
    "artifact": {"image", "tag", "digest", "development"},
    "signature": {"verified", "identity", "oidc_issuer"},
    "provenance": {
        "verified",
        "repository",
        "signer_workflow",
        "source_ref",
        "predicate_type",
    },
    "sbom": {"verified", "predicate_type"},
    "source": {"verified", "commit", "manifest_sha256", "bundle_sha256"},
    "scanner": {
        "verified",
        "name",
        "policy",
        "subject",
        "summary_sha256",
        "critical",
        "high",
    },
}


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ReceiptError(reason)


def require_closed_receipt(receipt: dict[str, Any]) -> None:
    require(set(receipt) == TOP_LEVEL_KEYS, "receipt_shape")
    for field, keys in NESTED_KEYS.items():
        value = receipt.get(field)
        require(isinstance(value, dict) and set(value) == keys, f"{field}_shape")
    require(
        isinstance(receipt.get("schema_version"), int)
        and not isinstance(receipt["schema_version"], bool)
        and receipt["schema_version"] == 1,
        "schema_version",
    )
    require(
        isinstance(receipt.get("policy_id"), str) and bool(receipt["policy_id"]),
        "policy_id",
    )
    require(
        isinstance(receipt.get("policy_version"), int)
        and not isinstance(receipt["policy_version"], bool)
        and receipt["policy_version"] > 0,
        "policy_version",
    )
    require(
        isinstance(receipt.get("channel"), str) and bool(receipt["channel"]),
        "channel",
    )

    artifact = receipt["artifact"]
    require(
        isinstance(artifact["image"], str) and bool(artifact["image"]),
        "artifact_image",
    )
    require(
        isinstance(artifact["tag"], str) and bool(artifact["tag"]),
        "artifact_tag",
    )
    require(
        isinstance(artifact["digest"], str)
        and SHA256.fullmatch(artifact["digest"]) is not None,
        "artifact_digest",
    )
    require(artifact["development"] is False, "development_artifact")

    for field in ("signature", "provenance", "sbom", "source", "scanner"):
        require(receipt[field]["verified"] is True, f"{field}_unverified")

    source = receipt["source"]
    require(
        isinstance(source["commit"], str)
        and COMMIT.fullmatch(source["commit"]) is not None,
        "source_commit",
    )
    for field in ("manifest_sha256", "bundle_sha256"):
        require(
            isinstance(source[field], str) and SHA256.fullmatch(source[field]) is not None,
            f"source_{field}",
        )

    scanner = receipt["scanner"]
    require(scanner["name"] == "trivy", "scanner_name")
    require(
        scanner["policy"] == "candidate_container_critical_high",
        "scanner_policy",
    )
    require(
        scanner["subject"] == f'{artifact["image"]}@{artifact["digest"]}',
        "scanner_subject",
    )
    require(
        isinstance(scanner["summary_sha256"], str)
        and SHA256.fullmatch(scanner["summary_sha256"]) is not None,
        "scanner_summary",
    )
    for field in ("critical", "high"):
        require(
            isinstance(scanner[field], int)
            and not isinstance(scanner[field], bool)
            and scanner[field] == 0,
            "scanner_findings",
        )


def validate_pair(
    production: dict[str, Any],
    enterprise: dict[str, Any],
) -> None:
    require_closed_receipt(production)
    require_closed_receipt(enterprise)
    require(
        production["mode"] == "production"
        and production["previous_mode"] == "production",
        "production_mode",
    )
    require(
        enterprise["mode"] == "enterprise"
        and enterprise["previous_mode"] == "enterprise",
        "enterprise_mode",
    )
    normalized = copy.deepcopy(enterprise)
    normalized["mode"] = "production"
    normalized["previous_mode"] = "production"
    require(production == normalized, "cross_mode_binding")


def load_receipt(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ReceiptError("receipt_unreadable") from error
    require(isinstance(value, dict), "receipt_shape")
    return value


def fixture(mode: str) -> dict[str, Any]:
    digest = "sha256:" + ("a" * 64)
    return {
        "schema_version": 1,
        "policy_id": "janus-engine-release-v1",
        "policy_version": 3,
        "channel": "stable",
        "mode": mode,
        "previous_mode": mode,
        "artifact": {
            "image": "ghcr.io/inspr-at/janus/janus-engine",
            "tag": "rust-engine-v0.1.20",
            "digest": digest,
            "development": False,
        },
        "signature": {
            "verified": True,
            "identity": "workflow-identity",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
        },
        "provenance": {
            "verified": True,
            "repository": "inspr-at/janus",
            "signer_workflow": "inspr-at/janus/.github/workflows/rust.yml",
            "source_ref": "refs/tags/rust-engine-v0.1.20",
            "predicate_type": "https://slsa.dev/provenance/v1",
        },
        "sbom": {
            "verified": True,
            "predicate_type": "https://spdx.dev/Document/v2.3",
        },
        "source": {
            "verified": True,
            "commit": "b" * 40,
            "manifest_sha256": "sha256:" + ("c" * 64),
            "bundle_sha256": "sha256:" + ("d" * 64),
        },
        "scanner": {
            "verified": True,
            "name": "trivy",
            "policy": "candidate_container_critical_high",
            "subject": f"ghcr.io/inspr-at/janus/janus-engine@{digest}",
            "summary_sha256": "sha256:" + ("e" * 64),
            "critical": 0,
            "high": 0,
        },
    }


def self_test() -> None:
    production = fixture("production")
    enterprise = fixture("enterprise")
    validate_pair(production, enterprise)

    mutations = (
        ("wrong_mode", lambda value: value.__setitem__("mode", "enterprise")),
        (
            "cross_mode_digest",
            lambda value: value["artifact"].__setitem__(
                "digest", "sha256:" + ("f" * 64)
            ),
        ),
        (
            "scanner_subject",
            lambda value: value["scanner"].__setitem__("subject", "mismatch"),
        ),
        ("scanner_findings", lambda value: value["scanner"].__setitem__("high", 1)),
        (
            "boolean_scanner_count",
            lambda value: value["scanner"].__setitem__("high", False),
        ),
        ("boolean_schema", lambda value: value.__setitem__("schema_version", True)),
        ("unexpected_field", lambda value: value.__setitem__("unexpected", True)),
    )
    for name, mutate in mutations:
        changed = copy.deepcopy(production)
        mutate(changed)
        try:
            validate_pair(changed, enterprise)
        except ReceiptError:
            continue
        raise ReceiptError(f"negative_fixture_accepted_{name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production", type=pathlib.Path)
    parser.add_argument("--enterprise", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            require(
                args.production is None and args.enterprise is None,
                "invalid_arguments",
            )
            self_test()
        else:
            require(
                args.production is not None and args.enterprise is not None,
                "invalid_arguments",
            )
            validate_pair(
                load_receipt(args.production),
                load_receipt(args.enterprise),
            )
    except ReceiptError as error:
        print(
            f"release_mode_receipts=blocked reason={error} value_returned=false",
            file=sys.stderr,
        )
        return 1
    print("release_mode_receipts=trusted value_returned=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
