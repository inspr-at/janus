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
    "inspr-platform": PERSONAL_CONTEXT,
    "augmentoring-platform": BUSINESS_CONTEXT,
    "augmentoring-service": BUSINESS_CONTEXT,
}
# Every pinned class must be bound exactly once; a registry that drops or
# duplicates a binding silently loses its must_never_enter and migration gates.
REQUIRED_BINDINGS = tuple(PINNED_CLASSES)
EVIDENCE_STATUSES = ("verified", "open")
# The boundary-evidence rows are part of the reviewed decision, not free-form
# registry content: each id must appear exactly once so a row cannot be
# deleted or renamed to clear the path to acceptance.
REQUIRED_EVIDENCE = (
    "oidc-issuer-distinct",
    "host-volume-distinct",
    "catalog-prefixes-disjoint",
    "tracker-recovery-distinct",
    "agenix-recipients-disjoint",
    "zitadel-role-bindings-disjoint",
    "backup-credentials-per-context",
)
# Acceptance is an assurance field, not a label: only the named human owner
# may accept, and only once every evidence row is verified.
ACCEPTANCE_AUTHORITY = "Markus Barta"
# Rows that were open when the decision was proposed. The self-test rebuilds a
# canonical proposed fixture from these, so the negative fixtures keep working
# after the documented registry-only acceptance edit flips the live registry.
CANONICAL_OPEN_EVIDENCE = (
    "agenix-recipients-disjoint",
    "zitadel-role-bindings-disjoint",
    "backup-credentials-per-context",
)
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
    _require(
        registry.get("acceptance_authority") == ACCEPTANCE_AUTHORITY,
        f"acceptance_authority must be exactly {ACCEPTANCE_AUTHORITY}",
    )
    if registry["status"] == "accepted":
        _require_fields(registry, ("accepted_by", "accepted_on"), "accepted registry")
        _require(
            registry["accepted_by"] == ACCEPTANCE_AUTHORITY,
            f"only {ACCEPTANCE_AUTHORITY} may accept this decision",
        )
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
    _require(
        set(class_owner) == set(PINNED_CLASSES),
        "declared material classes must be exactly the pinned set; add a pin before declaring a class",
    )
    bindings = registry.get("material_bindings")
    _require(isinstance(bindings, list) and bindings, "material_bindings must be a non-empty list")
    bound = [binding.get("material_class") for binding in bindings if isinstance(binding, dict)]
    for required in REQUIRED_BINDINGS:
        count = bound.count(required)
        _require(
            count == 1,
            f"material class {required} must be bound exactly once (found {count}); "
            "a missing or duplicate binding loses its must_never_enter and migration gates",
        )
    _require(len(bindings) == len(REQUIRED_BINDINGS), "material_bindings must contain only the pinned classes")
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
    evidence_ids = [item.get("id") for item in evidence if isinstance(item, dict)]
    for required in REQUIRED_EVIDENCE:
        count = evidence_ids.count(required)
        _require(
            count == 1,
            f"boundary evidence {required} must appear exactly once (found {count}); "
            "deleting or renaming a row cannot clear the path to acceptance",
        )
    _require(len(evidence) == len(REQUIRED_EVIDENCE), "boundary_evidence must contain only the reviewed rows")
    open_properties = []
    for item in evidence:
        _require_fields(item, ("id", "property", "status", "evidence"), "boundary evidence entry")
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


def canonical_proposed_fixture(live: dict) -> dict:
    """Return the live registry normalised to its proposed lifecycle shape.

    Only lifecycle fields change: status, acceptance fields, and the status of
    the evidence rows that were open at proposal time. Everything the
    boundary checks care about is taken from the live registry, so the
    fixtures still exercise the real declaration.
    """
    fixture = json.loads(json.dumps(live))
    fixture["status"] = "proposed"
    fixture["accepted_by"] = None
    fixture["accepted_on"] = None
    for row in fixture.get("boundary_evidence", []):
        if isinstance(row, dict) and row.get("id") in CANONICAL_OPEN_EVIDENCE:
            row["status"] = "open"
    return fixture


def accepted_fixture(proposed: dict) -> dict:
    """The documented registry-only acceptance edit applied to a fixture."""
    fixture = json.loads(json.dumps(proposed))
    for row in fixture["boundary_evidence"]:
        row["status"] = "verified"
    fixture["status"] = "accepted"
    fixture["accepted_by"] = ACCEPTANCE_AUTHORITY
    fixture["accepted_on"] = "2026-08-28"
    return fixture


def self_test() -> None:
    live = load(REGISTRY)
    live_summary = validate(live)
    assert live_summary["decision"] == "separate-deployments", live_summary
    assert live_summary["material_bindings"] == len(REQUIRED_BINDINGS), live_summary
    assert live_summary["status"] in STATUSES, live_summary
    if live_summary["status"] == "proposed":
        assert live_summary["open_evidence"] == len(CANONICAL_OPEN_EVIDENCE), live_summary
    else:
        assert live_summary["open_evidence"] == 0 and live["accepted_by"] == ACCEPTANCE_AUTHORITY, live_summary

    # Negative fixtures derive from a canonical proposed shape, never from the
    # live lifecycle state, so the acceptance edit cannot make them evaporate.
    baseline = canonical_proposed_fixture(live)
    summary = validate(baseline)
    assert summary["status"] == "proposed" and summary["open_evidence"] == len(CANONICAL_OPEN_EVIDENCE), summary
    assert summary["contexts"] == [PERSONAL_CONTEXT, BUSINESS_CONTEXT], summary
    assert "AGM-5" in summary["disambiguated_keys"], summary

    def mutated(base: dict, apply) -> dict:
        copy = json.loads(json.dumps(base))
        apply(copy)
        return copy

    def expect_failure(base: dict, label: str, apply) -> None:
        try:
            validate(mutated(base, apply))
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

    def apple_binding(copy: dict) -> dict:
        return next(b for b in copy["material_bindings"] if b["material_class"] == "personal-apple-release-signing")

    def apple_into_business_binding(copy: dict) -> None:
        binding = apple_binding(copy)
        binding["context"] = BUSINESS_CONTEXT
        binding["must_never_enter"] = [PERSONAL_CONTEXT]

    def apple_relabelled_into_business(copy: dict) -> None:
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
            if binding["context"] == PERSONAL_CONTEXT:
                binding["context"] = "personal-other"
            binding["must_never_enter"] = [
                "personal-other" if x == PERSONAL_CONTEXT else x for x in binding["must_never_enter"]
            ]

    def class_in_both(copy: dict) -> None:
        copy["contexts"][1]["material_classes"].append("personal-apple-release-signing")

    def prefix_overlap(copy: dict) -> None:
        copy["contexts"][1]["secret_name_prefixes"].append("csb1-janus-")

    def ungated_binding(copy: dict) -> None:
        apple_binding(copy)["migration_gates"] = []

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

    def unknown_evidence_status(copy: dict) -> None:
        copy["boundary_evidence"][0]["status"] = "assumed"

    def delete_apple_binding(copy: dict) -> None:
        copy["material_bindings"] = [
            b for b in copy["material_bindings"] if b["material_class"] != "personal-apple-release-signing"
        ]

    def duplicate_apple_binding(copy: dict) -> None:
        copy["material_bindings"].append(json.loads(json.dumps(apple_binding(copy))))

    def duplicate_apple_binding_weakened(copy: dict) -> None:
        weak = json.loads(json.dumps(apple_binding(copy)))
        weak["migration_gates"] = ["none"]
        copy["material_bindings"].insert(0, weak)

    def rename_binding_class(copy: dict) -> None:
        copy["contexts"][0]["material_classes"].remove("personal-apple-release-signing")
        copy["contexts"][0]["material_classes"].append("personal-apple-signing")
        apple_binding(copy)["material_class"] = "personal-apple-signing"

    def unbound_declared_class(copy: dict) -> None:
        copy["material_bindings"] = [
            b for b in copy["material_bindings"] if b["material_class"] != "augmentoring-service"
        ]

    def unpinned_extra_class(copy: dict) -> None:
        copy["contexts"][1]["material_classes"].append("augmentoring-extra")
        copy["material_bindings"].append(
            {
                "material_class": "augmentoring-extra",
                "driver": "pma:AGM-4",
                "context": BUSINESS_CONTEXT,
                "must_never_enter": [PERSONAL_CONTEXT],
                "migration_gates": ["some gate"],
                "canonical_until_gates_pass": "somewhere",
            }
        )

    def accept_as_authority(copy: dict) -> None:
        copy["status"] = "accepted"
        copy["accepted_by"] = ACCEPTANCE_AUTHORITY
        copy["accepted_on"] = "2026-08-28"

    def delete_open_evidence_then_accept(copy: dict) -> None:
        copy["boundary_evidence"] = [r for r in copy["boundary_evidence"] if r["status"] == "verified"]
        accept_as_authority(copy)

    def rename_open_evidence_then_accept(copy: dict) -> None:
        for row in copy["boundary_evidence"]:
            if row["status"] == "open":
                row["id"] = row["id"] + "-x"
                row["status"] = "verified"
        accept_as_authority(copy)

    def duplicate_evidence_row(copy: dict) -> None:
        copy["boundary_evidence"].append(json.loads(json.dumps(copy["boundary_evidence"][0])))

    def duplicate_evidence_row_verified_then_accept(copy: dict) -> None:
        for row in list(copy["boundary_evidence"]):
            if row["status"] == "open":
                twin = json.loads(json.dumps(row))
                twin["status"] = "verified"
                copy["boundary_evidence"].append(twin)
        accept_as_authority(copy)

    def status_flip_with_open_evidence_by_authority(copy: dict) -> None:
        accept_as_authority(copy)

    def unauthorized_acceptor_all_verified(copy: dict) -> None:
        for row in copy["boundary_evidence"]:
            row["status"] = "verified"
        copy["status"] = "accepted"
        copy["accepted_by"] = "someone"
        copy["accepted_on"] = "2026-08-28"

    def wrong_acceptance_authority(copy: dict) -> None:
        copy["acceptance_authority"] = "someone"

    def missing_evidence_id(copy: dict) -> None:
        del copy["boundary_evidence"][0]["id"]

    def accepted_without_acceptor(copy: dict) -> None:
        copy["status"] = "accepted"

    def accepted_with_open_evidence(copy: dict) -> None:
        copy["status"] = "accepted"
        copy["accepted_by"] = "someone"
        copy["accepted_on"] = "2026-08-28"

    # Lifecycle-independent boundary mutations: must fail on both shapes.
    boundary_mutations = (
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
        ("unknown boundary evidence status", unknown_evidence_status),
        ("Apple binding deleted", delete_apple_binding),
        ("Apple binding duplicated", duplicate_apple_binding),
        ("Apple binding duplicated with weakened gates first", duplicate_apple_binding_weakened),
        ("binding class renamed away from the pin", rename_binding_class),
        ("declared class left unbound", unbound_declared_class),
        ("unpinned extra class bound", unpinned_extra_class),
        ("evidence row duplicated", duplicate_evidence_row),
        ("acceptance authority reassigned", wrong_acceptance_authority),
        ("evidence row without id", missing_evidence_id),
    )
    # Lifecycle mutations: only meaningful from the canonical proposed shape.
    proposed_mutations = (
        ("accepted without acceptor", accepted_without_acceptor),
        ("accepted by a stranger while evidence is open", accepted_with_open_evidence),
        ("open evidence deleted then accepted", delete_open_evidence_then_accept),
        ("open evidence renamed then accepted", rename_open_evidence_then_accept),
        ("open evidence shadowed by a verified twin then accepted", duplicate_evidence_row_verified_then_accept),
        ("status flipped by the authority while evidence is open", status_flip_with_open_evidence_by_authority),
        ("unauthorized acceptor with all evidence verified", unauthorized_acceptor_all_verified),
    )
    for label, apply in boundary_mutations + proposed_mutations:
        expect_failure(baseline, f"{label} (proposed baseline)", apply)

    def same_context_prefix_refinement(copy: dict) -> None:
        copy["contexts"][0]["secret_name_prefixes"].append("csb1-janus-")

    validate(mutated(baseline, same_context_prefix_refinement))

    # Explicit proof for the documented registry-only acceptance edit: the
    # accepted shape validates, and every boundary mutation still fails on it.
    accepted = accepted_fixture(baseline)
    accepted_summary = validate(accepted)
    assert accepted_summary["status"] == "accepted" and accepted_summary["open_evidence"] == 0, accepted_summary

    def reopen_evidence_while_accepted(copy: dict) -> None:
        copy["boundary_evidence"][-1]["status"] = "open"

    def delete_verified_evidence_while_accepted(copy: dict) -> None:
        copy["boundary_evidence"].pop()

    def rename_verified_evidence_while_accepted(copy: dict) -> None:
        copy["boundary_evidence"][-1]["id"] = copy["boundary_evidence"][-1]["id"] + "-x"

    def swap_acceptor_while_accepted(copy: dict) -> None:
        copy["accepted_by"] = "someone"

    def drop_acceptor_while_accepted(copy: dict) -> None:
        copy["accepted_by"] = None

    def proposed_with_acceptance_fields(copy: dict) -> None:
        copy["status"] = "proposed"

    accepted_mutations = (
        ("evidence reopened while accepted", reopen_evidence_while_accepted),
        ("verified evidence deleted while accepted", delete_verified_evidence_while_accepted),
        ("verified evidence renamed while accepted", rename_verified_evidence_while_accepted),
        ("acceptor swapped while accepted", swap_acceptor_while_accepted),
        ("acceptor dropped while accepted", drop_acceptor_while_accepted),
        ("proposed while carrying acceptance fields", proposed_with_acceptance_fields),
    )
    for label, apply in boundary_mutations + accepted_mutations:
        expect_failure(accepted, f"{label} (accepted baseline)", apply)

    # The self-test must stay green whichever lifecycle shape the live
    # registry is in, and normalising the accepted shape must round-trip.
    assert canonical_proposed_fixture(accepted) == baseline, "canonical fixture does not round-trip"
    rejected = 2 * len(boundary_mutations) + len(proposed_mutations) + len(accepted_mutations)

    with tempfile.TemporaryDirectory() as scratch:
        broken = Path(scratch) / "broken.json"
        broken.write_text("{")
        try:
            load(broken)
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("malformed registry JSON was accepted")
    print(
        f"trust-context self-test passed: live registry status={live_summary['status']}, "
        f"{rejected} boundary violations rejected across proposed and accepted shapes value_returned=false"
    )


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
