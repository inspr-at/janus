#!/usr/bin/env python3
"""Prove the custody trust-context topology stays separated (JANUS-421).

`config/trust-context/deployments-v1.json` records the decision that personal
/ INSPR material and Augmentoring business material live in two separate
Janus deployments. This check keeps that registry honest: every context must
name its own deployment, identity provider, tracker instance, recovery
ownership, and material classes, and no two contexts may share any of them.
Material bindings must point at exactly one context and explicitly forbid the
other. Reused tracker keys (`AGM-5`) must be qualified by instance.

The check is value-free: it reads public identifiers only and never touches a
secret, a host, or a tracker.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "config/trust-context/deployments-v1.json"
DECISIONS = ("separate-deployments", "enforced-tenancy", "no-personal-custody")
# Only the separated topology has validation semantics in this registry
# version; the other two decisions would need a different registry shape.
IMPLEMENTED_DECISIONS = ("separate-deployments",)
STATUSES = ("proposed", "accepted")
# Ticket-derived invariants: these do not come from the registry itself, so a
# registry edit cannot relabel where the driver material is allowed to live.
PERSONAL_CONTEXT = "personal-inspr"
BUSINESS_CONTEXT = "business-augmentoring"
PERSONAL_DEPLOYMENT = "https://vault.barta.cm"
BUSINESS_DEPLOYMENT = "https://janus.agm.ng"
PINNED_CLASSES = {
    "personal-apple-release-signing": PERSONAL_CONTEXT,
    "augmentoring-platform": BUSINESS_CONTEXT,
}
EVIDENCE_STATUSES = ("verified", "open")
DEPLOYMENT_FIELDS = (
    "public_url",
    "host",
    "config_repository",
    "config_path",
    "catalog_path",
    "oidc_issuer",
    "data_volume",
)
TRACKER_FIELDS = ("instance", "url")
RECOVERY_FIELDS = ("ownership", "reference", "backup_restore_gate")
UNIQUE_PER_CONTEXT = (
    ("deployment", "public_url"),
    ("deployment", "host"),
    ("deployment", "config_repository"),
    ("deployment", "config_path"),
    ("deployment", "oidc_issuer"),
    ("deployment", "data_volume"),
    ("deployment", "catalog_path"),
    ("tracker", "instance"),
    ("tracker", "url"),
    ("recovery", "ownership"),
    ("recovery", "backup_restore_gate"),
)
UNIQUE_TOP_LEVEL = ("legal_owner", "operational_owner")


class TrustContextError(RuntimeError):
    """Registry violates the separated trust-context contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TrustContextError(message)


def _require_fields(mapping: object, fields: tuple, where: str) -> None:
    _require(isinstance(mapping, dict), f"{where} must be an object")
    for field in fields:
        value = mapping.get(field)
        _require(
            isinstance(value, str) and value.strip() != "",
            f"{where}.{field} must be a non-empty string",
        )


def validate(registry: dict) -> dict:
    _require(registry.get("schema_version") == 1, "schema_version must be 1")
    _require(registry.get("owner") == "JANUS-421", "owner must be JANUS-421")
    _require(
        registry.get("decision") in DECISIONS,
        f"decision must be one of {', '.join(DECISIONS)}",
    )
    _require(
        registry.get("decision") in IMPLEMENTED_DECISIONS,
        "this registry shape only describes the separate-deployments decision",
    )
    _require(registry.get("status") in STATUSES, f"status must be one of {', '.join(STATUSES)}")
    _require_fields(registry, ("proposed_on", "proposed_by"), "registry")
    if registry["status"] == "accepted":
        _require_fields(registry, ("accepted_by", "accepted_on"), "accepted registry")
    else:
        _require(
            registry.get("accepted_by") is None and registry.get("accepted_on") is None,
            "a proposed decision must not carry acceptance fields",
        )
    record = registry.get("decision_record")
    _require(isinstance(record, str) and record.startswith("docs/"), "decision_record must be a docs/ path")
    _require((ROOT / record).is_file(), f"decision record {record} is missing")

    contexts = registry.get("contexts")
    _require(isinstance(contexts, list) and len(contexts) == 2, "exactly two trust contexts must be declared")
    ids = []
    for context in contexts:
        _require_fields(context, ("id", "label", "legal_owner", "operational_owner"), "context")
        where = f"context {context['id']}"
        _require_fields(context.get("deployment"), DEPLOYMENT_FIELDS, f"{where}.deployment")
        _require_fields(context.get("tracker"), TRACKER_FIELDS, f"{where}.tracker")
        projects = context["tracker"].get("projects")
        _require(
            isinstance(projects, list) and projects and all(isinstance(x, str) and x for x in projects),
            f"{where}.tracker.projects must be a non-empty list",
        )
        _require_fields(context.get("recovery"), RECOVERY_FIELDS, f"{where}.recovery")
        _require(
            context["deployment"]["public_url"].startswith("https://")
            and context["deployment"]["oidc_issuer"].startswith("https://")
            and context["tracker"]["url"].startswith("https://"),
            f"{where} public identifiers must be https URLs",
        )
        classes = context.get("material_classes")
        _require(
            isinstance(classes, list) and classes and all(isinstance(c, str) and c for c in classes),
            f"{where}.material_classes must be a non-empty list",
        )
        prefixes = context.get("secret_name_prefixes")
        _require(
            isinstance(prefixes, list) and prefixes and all(isinstance(p, str) and p for p in prefixes),
            f"{where}.secret_name_prefixes must be a non-empty list",
        )
        ids.append(context["id"])
    _require(
        ids == [PERSONAL_CONTEXT, BUSINESS_CONTEXT],
        f"contexts must be exactly {PERSONAL_CONTEXT} then {BUSINESS_CONTEXT}",
    )
    by_id = {context["id"]: context for context in contexts}
    _require(
        by_id[PERSONAL_CONTEXT]["deployment"]["public_url"] == PERSONAL_DEPLOYMENT,
        f"{PERSONAL_CONTEXT} must be deployed at {PERSONAL_DEPLOYMENT}",
    )
    _require(
        by_id[BUSINESS_CONTEXT]["deployment"]["public_url"] == BUSINESS_DEPLOYMENT,
        f"{BUSINESS_CONTEXT} must be deployed at {BUSINESS_DEPLOYMENT}",
    )
    for field in UNIQUE_TOP_LEVEL:
        values = [context[field] for context in contexts]
        _require(len(set(values)) == 2, f"contexts share {field}; the trust boundary is crossed")

    for section, field in UNIQUE_PER_CONTEXT:
        values = [context[section][field] for context in contexts]
        _require(
            len(set(values)) == len(values),
            f"contexts share {section}.{field} ({values[0]}); the trust boundary is crossed",
        )

    all_classes = [c for context in contexts for c in context["material_classes"]]
    _require(len(set(all_classes)) == len(all_classes), "a material class is bound to both contexts")
    all_prefixes = [p for context in contexts for p in context["secret_name_prefixes"]]
    _require(len(set(all_prefixes)) == len(all_prefixes), "a secret-name prefix is claimed by both contexts")
    for context in contexts:
        for prefix in context["secret_name_prefixes"]:
            for other in contexts:
                if other is context:
                    continue
                for foreign in other["secret_name_prefixes"]:
                    _require(
                        not (foreign.startswith(prefix) or prefix.startswith(foreign)),
                        f"secret-name prefix {prefix} ({context['id']}) overlaps {foreign} ({other['id']})",
                    )

    class_owner = {c: context["id"] for context in contexts for c in context["material_classes"]}
    for pinned_class, pinned_context in PINNED_CLASSES.items():
        _require(
            class_owner.get(pinned_class) == pinned_context,
            f"material class {pinned_class} must belong to {pinned_context}; relabeling it is not allowed",
        )
    bindings = registry.get("material_bindings")
    _require(isinstance(bindings, list) and bindings, "material_bindings must be a non-empty list")
    for binding in bindings:
        _require_fields(
            binding,
            ("material_class", "driver", "context", "canonical_until_gates_pass"),
            "material binding",
        )
        where = f"binding {binding['material_class']}"
        _require(binding["material_class"] in class_owner, f"{where} names an undeclared material class")
        _require(
            class_owner[binding["material_class"]] == binding["context"],
            f"{where} binds a class to a context that does not own it",
        )
        never = binding.get("must_never_enter")
        _require(isinstance(never, list) and never, f"{where}.must_never_enter must list the other context")
        _require(binding["context"] not in never, f"{where} forbids its own context")
        _require(
            set(never) == set(ids) - {binding["context"]},
            f"{where}.must_never_enter must name every other context",
        )
        gates = binding.get("migration_gates")
        _require(
            isinstance(gates, list) and gates and all(isinstance(g, str) and g for g in gates),
            f"{where}.migration_gates must be a non-empty list; no migration starts ungated",
        )

    evidence = registry.get("boundary_evidence")
    _require(isinstance(evidence, list) and evidence, "boundary_evidence must be a non-empty list")
    open_properties = []
    for item in evidence:
        _require_fields(item, ("property", "status", "evidence"), "boundary evidence entry")
        _require(item["status"] in EVIDENCE_STATUSES, f"boundary evidence {item['property']} has an unknown status")
        if item["status"] == "open":
            open_properties.append(item["property"])
    if registry["status"] == "accepted":
        _require(not open_properties, "an accepted decision must not carry open boundary evidence")

    disambiguation = registry.get("tracker_key_disambiguation")
    _require(isinstance(disambiguation, list) and disambiguation, "tracker_key_disambiguation must be a non-empty list")
    seen = set()
    for entry in disambiguation:
        _require_fields(entry, ("key", "instance", "qualified", "meaning"), "tracker key entry")
        _require(entry["instance"] in ("ppm", "pma"), f"tracker key {entry['key']} names an unknown instance")
        _require(
            entry["qualified"].endswith(f"{entry['instance']}:{entry['key']}"),
            f"tracker key {entry['key']} must be qualified as <instance>:<key>",
        )
        pair = (entry["instance"], entry["key"])
        _require(pair not in seen, f"tracker key {entry['qualified']} is listed twice")
        seen.add(pair)
    reused = {key for _, key in seen if sum(1 for _, other in seen if other == key) > 1}
    for key in ("AGM-5",):
        _require(key in reused, f"reused tracker key {key} must be disambiguated on both instances")

    return {
        "decision": registry["decision"],
        "status": registry["status"],
        "contexts": ids,
        "material_bindings": len(bindings),
        "open_evidence": len(open_properties),
        "disambiguated_keys": sorted(reused),
    }


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def self_test() -> None:
    baseline = load(REGISTRY)
    summary = validate(baseline)
    assert summary["decision"] == "separate-deployments", summary
    assert summary["status"] == "proposed", summary
    assert summary["contexts"] == ["personal-inspr", "business-augmentoring"], summary
    assert "AGM-5" in summary["disambiguated_keys"], summary

    def mutated(apply) -> dict:
        copy = json.loads(json.dumps(baseline))
        apply(copy)
        return copy

    def expect_failure(label: str, apply) -> None:
        try:
            validate(mutated(apply))
        except TrustContextError:
            return
        raise AssertionError(f"self-test mutation was not rejected: {label}")

    def share_issuer(copy: dict) -> None:
        copy["contexts"][1]["deployment"]["oidc_issuer"] = copy["contexts"][0]["deployment"]["oidc_issuer"]

    def share_url(copy: dict) -> None:
        copy["contexts"][1]["deployment"]["public_url"] = copy["contexts"][0]["deployment"]["public_url"]

    def share_host(copy: dict) -> None:
        copy["contexts"][1]["deployment"]["host"] = copy["contexts"][0]["deployment"]["host"]
        copy["contexts"][1]["deployment"]["data_volume"] = "janus_data2@csb1"

    def share_config(copy: dict) -> None:
        copy["contexts"][1]["deployment"]["config_repository"] = copy["contexts"][0]["deployment"]["config_repository"]
        copy["contexts"][1]["deployment"]["config_path"] = copy["contexts"][0]["deployment"]["config_path"]

    def share_volume(copy: dict) -> None:
        copy["contexts"][1]["deployment"]["data_volume"] = copy["contexts"][0]["deployment"]["data_volume"]

    def share_tracker(copy: dict) -> None:
        copy["contexts"][1]["tracker"] = dict(copy["contexts"][0]["tracker"])

    def share_backup_gate(copy: dict) -> None:
        copy["contexts"][0]["recovery"]["backup_restore_gate"] = copy["contexts"][1]["recovery"]["backup_restore_gate"]

    def share_recovery_ownership(copy: dict) -> None:
        copy["contexts"][0]["recovery"]["ownership"] = copy["contexts"][1]["recovery"]["ownership"]

    def share_legal_owner(copy: dict) -> None:
        copy["contexts"][1]["legal_owner"] = copy["contexts"][0]["legal_owner"]

    def share_operational_owner(copy: dict) -> None:
        copy["contexts"][1]["operational_owner"] = copy["contexts"][0]["operational_owner"]

    def apple_into_business_binding(copy: dict) -> None:
        for binding in copy["material_bindings"]:
            if binding["material_class"] == "personal-apple-release-signing":
                binding["context"] = "business-augmentoring"
                binding["must_never_enter"] = ["personal-inspr"]

    def apple_relabelled_into_business(copy: dict) -> None:
        # Consistent relabel: move the class list entry AND the binding.
        copy["contexts"][0]["material_classes"].remove("personal-apple-release-signing")
        copy["contexts"][1]["material_classes"].append("personal-apple-release-signing")
        apple_into_business_binding(copy)

    def swap_deployment_urls(copy: dict) -> None:
        a = copy["contexts"][0]["deployment"]["public_url"]
        copy["contexts"][0]["deployment"]["public_url"] = copy["contexts"][1]["deployment"]["public_url"]
        copy["contexts"][1]["deployment"]["public_url"] = a

    def rename_context(copy: dict) -> None:
        copy["contexts"][0]["id"] = "personal-other"
        for binding in copy["material_bindings"]:
            if binding["context"] == "personal-inspr":
                binding["context"] = "personal-other"
            binding["must_never_enter"] = [
                "personal-other" if x == "personal-inspr" else x for x in binding["must_never_enter"]
            ]

    def class_in_both(copy: dict) -> None:
        copy["contexts"][1]["material_classes"].append("personal-apple-release-signing")

    def prefix_overlap(copy: dict) -> None:
        copy["contexts"][1]["secret_name_prefixes"].append("csb1-janus-")

    def ungated_binding(copy: dict) -> None:
        copy["material_bindings"][0]["migration_gates"] = []

    def unqualified_key(copy: dict) -> None:
        copy["tracker_key_disambiguation"][0]["qualified"] = "AGM-5"

    def drop_pma_agm5(copy: dict) -> None:
        copy["tracker_key_disambiguation"] = [
            entry
            for entry in copy["tracker_key_disambiguation"]
            if not (entry["key"] == "AGM-5" and entry["instance"] == "pma")
        ]

    def third_context(copy: dict) -> None:
        copy["contexts"].append(json.loads(json.dumps(copy["contexts"][0])))

    def unknown_decision(copy: dict) -> None:
        copy["decision"] = "mixed"

    def unimplemented_decision(copy: dict) -> None:
        copy["decision"] = "no-personal-custody"

    def missing_record(copy: dict) -> None:
        copy["decision_record"] = "docs/does-not-exist.md"

    def accepted_without_acceptor(copy: dict) -> None:
        copy["status"] = "accepted"

    def accepted_with_open_evidence(copy: dict) -> None:
        copy["status"] = "accepted"
        copy["accepted_by"] = "someone"
        copy["accepted_on"] = "2026-08-28"

    def unknown_evidence_status(copy: dict) -> None:
        copy["boundary_evidence"][0]["status"] = "assumed"

    mutations = (
        ("shared OIDC issuer", share_issuer),
        ("shared public URL", share_url),
        ("shared host", share_host),
        ("shared config declaration", share_config),
        ("shared data volume", share_volume),
        ("shared tracker instance", share_tracker),
        ("shared backup gate", share_backup_gate),
        ("shared recovery ownership", share_recovery_ownership),
        ("shared legal owner", share_legal_owner),
        ("shared operational owner", share_operational_owner),
        ("Apple binding pointed at business", apple_into_business_binding),
        ("Apple class relabelled into business", apple_relabelled_into_business),
        ("deployment URLs swapped between contexts", swap_deployment_urls),
        ("context renamed away from the pinned id", rename_context),
        ("material class in both contexts", class_in_both),
        ("overlapping secret-name prefix", prefix_overlap),
        ("ungated migration", ungated_binding),
        ("unqualified reused tracker key", unqualified_key),
        ("pma:AGM-5 not disambiguated", drop_pma_agm5),
        ("third unscoped context", third_context),
        ("unknown decision", unknown_decision),
        ("decision without registry semantics", unimplemented_decision),
        ("missing decision record", missing_record),
        ("accepted without acceptor", accepted_without_acceptor),
        ("accepted while boundary evidence is open", accepted_with_open_evidence),
        ("unknown boundary evidence status", unknown_evidence_status),
    )
    for label, apply in mutations:
        expect_failure(label, apply)

    def same_context_prefix_refinement(copy: dict) -> None:
        copy["contexts"][0]["secret_name_prefixes"].append("csb1-janus-")

    validate(mutated(same_context_prefix_refinement))

    with tempfile.TemporaryDirectory() as scratch:
        broken = Path(scratch) / "broken.json"
        broken.write_text("{")
        try:
            load(broken)
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("malformed registry JSON was accepted")
    print(f"trust-context self-test passed: {len(mutations)} boundary violations rejected value_returned=false")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true", help="run the negative-fixture self-test")
    parser.add_argument("--registry", type=Path, default=REGISTRY, help="registry path (default: reviewed baseline)")
    args = parser.parse_args(argv)
    if args.self_test and args.registry != REGISTRY:
        parser.error("--self-test always uses the reviewed baseline; drop --registry")
    try:
        if args.self_test:
            self_test()
            return 0
        summary = validate(load(args.registry))
    except (OSError, json.JSONDecodeError, TrustContextError, AssertionError) as error:
        print(f"trust-context check failed: {error}", file=sys.stderr)
        return 1
    print(
        "trust-context check passed: decision={decision} status={status} contexts={contexts} "
        "bindings={material_bindings} open_evidence={open_evidence} "
        "disambiguated={disambiguated_keys} value_returned=false".format(**summary)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
