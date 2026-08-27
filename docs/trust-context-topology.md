# Custody trust-context topology

_Decision record for JANUS-421. Status: **proposed** on 2026-08-27 by the
JANUS-421 builder, for acceptance by Markus Barta. Acceptance is recorded by
setting `status`, `accepted_by`, and `accepted_on` in
[`config/trust-context/deployments-v1.json`](../config/trust-context/deployments-v1.json),
which `scripts/check-trust-context.py` validates in the fast check job. Until
then the decision is recorded but not complete, and no credential migration
may start._

## Decision

**Separate deployments by trust context.** Personal / INSPR material and
Augmentoring business material never share a Janus deployment. Trust context
is a property of the deployment, not a label inside one deployment.

| | Personal / INSPR | Augmentoring business |
| --- | --- | --- |
| Deployment | `https://vault.barta.cm` | `https://janus.agm.ng` |
| Host and declaration | `csb1`, `nixcfg` `hosts/csb1/docker/compose-spec.nix` | `agm1`, `agm-nixcfg` `modules/agm-janus.nix` |
| Identity provider | `https://auth.inspr.at` (INSPR Zitadel) | `https://zitadel.agm.ng` (Augmentoring Zitadel) |
| Legal owner | Markus Barta, natural person (INSPR is the personal umbrella) | Augmentoring, the business entity operating `agm.ng` |
| Operational owner | Markus Barta as Janus maintainer | Augmentoring platform operations (Markus Barta acting for Augmentoring) |
| Custody keys | csb1 age store and agenix identities | agm1 age store and agenix identities |
| Backup and restore gate | personal-deployment off-host backup and restore evidence | legacy `ppm:AGM-18` live restore drill |
| Recovery ownership | maintainer vault, two-of-three recovery share, contacts named in the maintainer's personal estate document (`paimos` `docs/CONTINUITY.md` §2.3) | Augmentoring operations and the encrypted backup escrow from legacy `ppm:AGM-18` |
| Tracker instance | `ppm` at `pm.barta.cm`, projects `JANUS` and `PAI` | `pma` at `paimos.agm.ng`, project `AGM`; items opened before the Augmentoring tracker moved to `pma` stay on `ppm` until complete |
| Catalog secret prefixes | `csb1-*`, `traefik-*` | `agm1-*` |

Why not the alternatives:

- **First-class tenancy inside one deployment** would need an explicit
  threat model plus enforcement across visibility, authorization, recovery,
  backup and export, and administration before any material moves. The
  existing catalog `owner` and runtime `scope` fields identify a team and an
  execution boundary; they prove neither legal ownership nor custody-key
  separation, so they cannot carry a trust boundary. Both deployments already
  exist with their own identity providers, hosts, and trackers, so tenancy
  would add enforcement work to reach a state the estate already has.
- **No Janus custody for personal material** would cancel PAI-752 outright.
  The maintainer vault plus the release-workflow certificate-expiry check is a
  safe state today, and this decision keeps it canonical until every gate
  below passes, but it does not foreclose a personal deployment that already
  runs.

An unscoped mixture is not an option. The `csb1` host also runs Augmentoring
workloads. That is host co-tenancy: the `vault.barta.cm` catalog lists only
`csb1-*` and `traefik-*` platform entries, and no Augmentoring service secret
is catalogued there. Whether any of those platform entries (edge TLS, DNS,
backup credentials) also serve the co-hosted business workloads is a host-level
question recorded as open evidence below, not a custody crossing inside Janus.

## Boundary rules

Nothing below may cross from one context to the other. Each rule carries its
verification status; the machine-readable list is `boundary_evidence` in the
registry, and an `accepted` registry may not carry open evidence.

| Rule | Status | Evidence |
| --- | --- | --- |
| 1. **Administrative identities.** A Zitadel user in one issuer is never bound to a Janus role in the other deployment. | issuers distinct: verified; role bindings disjoint: **open** | distinct `OIDC_ISSUER` values in both declarations; a value-free listing of `janus:*` grants per Zitadel project is still needed |
| 2. **Custody keys.** age identities, agenix recipients, host envelopes, and `janus_data` volumes are per host. No recipient from one context is added to ciphertext in the other, including through the agenix write path or the host-envelope distribute verb. | hosts and volumes distinct: verified; recipient sets disjoint: **open** | separate NixOS hosts and config repositories; a value-free recipient fingerprint comparison of both `secrets.nix` files is still needed, and a maintainer key present in both is a crossing to resolve |
| 3. **Backups.** Each deployment backs up to its own destination with its own credentials. A restore drill for one context proves nothing for the other. | **open** | csb1 restic covers every csb1 docker volume under a personal-catalog credential, which includes co-hosted Augmentoring workload volumes; the personal backup gate must show a `janus_data@csb1` restore, and legacy `ppm:AGM-18` must use a destination credential outside the personal catalog |
| 4. **Recovery contacts and policy.** Recovery ownership is per context as in the table. Break-glass, delegation, and retention policy are configured per deployment. | references distinct: verified | `paimos` `docs/CONTINUITY.md` §2.3 versus legacy `ppm:AGM-18` |
| 5. **Evidence exports.** Value-free evidence stays in the tracker instance of its context. Reused keys are qualified by instance. | verified | `ppm` versus `pma`; disambiguation table below |
| 6. **Catalogs.** A secret name carrying one context's prefix never appears in the other deployment's catalog. | prefixes disjoint: verified | csb1 catalog `csb1-*`, `traefik-*`; agm1 catalog `agm1-*` |

`scripts/check-trust-context.py` validates the registry's self-consistency,
not runtime state: it rejects shared issuers, URLs, hosts, config
declarations, volumes, catalogs, trackers, owners, and backup gates; pins the
Apple release-signing class to the personal context and the Augmentoring
platform class to the business context so a registry edit cannot relabel
them; requires every binding to forbid the other context and to carry
migration gates; and refuses an `accepted` status while any boundary evidence
is open.

## Material bindings

| Material | Driver | Context | Canonical until gates pass | Gates before any migration |
| --- | --- | --- | --- | --- |
| Personal Apple release-signing credentials | PAI-752 | personal / INSPR (`vault.barta.cm`) | maintainer vault plus the Paimos release-workflow certificate-expiry check | JANUS-420 issuer not-after tracking complete; personal-deployment off-host backup and restore evidence recorded; JANUS-422 retrieval drill passed on `vault.barta.cm` with a genuinely distinct recovery contact |
| Augmentoring platform and service secrets | `pma:AGM-4` | Augmentoring business (`janus.agm.ng`) | agm1 agenix custody | legacy `ppm:AGM-18` backup and restore gate passed |

The Apple material must never enter `janus.agm.ng`, even though it gates a
public software release. No credential migration starts because of this
decision; the decision only fixes where each class of material may go once
its gates pass and the decision itself is accepted.

## Reconciliation with related work

Tracker and foreign-repository edits are not made from this repository. The
text below is the reconciliation to apply once the decision is accepted.

- **PAI-752** (ppm, backlog). Add to notes: "JANUS-421 decided separate
  deployments. Selected context: personal / INSPR. Exact deployment:
  `https://vault.barta.cm` on csb1. Owner: Markus Barta as Janus maintainer.
  Recovery boundary: maintainer vault two-of-three share; nothing crosses to
  `janus.agm.ng`. Not cancelled. Gates unchanged: JANUS-420, personal-
  deployment off-host backup and restore evidence, JANUS-422 on
  `vault.barta.cm`. Maintainer vault and the release-workflow expiry check
  stay canonical until then."
- **JANUS-422** (ppm, new). Add to notes: "JANUS-421 selected the personal /
  INSPR context and deployment `https://vault.barta.cm`. Legacy `ppm:AGM-18`
  is not carried over; the precondition is equivalent off-host backup and
  restore evidence for `janus_data@csb1`." Drill design stays with
  JANUS-422.
- **`pma:AGM-4`** (pma, new). Add to notes: "Scoped by JANUS-421 to the
  Augmentoring business context only: custody moves into
  `https://janus.agm.ng` after legacy `ppm:AGM-18` passes, and never receives
  personal / INSPR material." The title may be sharpened to say business
  custody; today it reads "Migrate secret custody into Janus (ex AGM-11)".
- **Continuity documentation** (`paimos` repository). `docs/CONTINUITY.md`
  §2.3 and `scripts/release/README.md` keep the maintainer vault as the
  working custody path and should cite this record as the eventual Janus
  target. Proposed as a Paimos ticket, not edited here.

## Tracker key disambiguation

`AGM-5` exists on both tracker instances with unrelated meanings. Every
reference must be qualified:

| Qualified key | Meaning |
| --- | --- |
| legacy `ppm:AGM-5` | "Janus at janus.agm.ng — business credential custody" (done). The origin of the business deployment. |
| `pma:AGM-5` | "Switch Pharos beacon to Janus token mode (ex AGM-12)". A Pharos ticket unrelated to custody topology. |
| `pma:AGM-4` | "Migrate secret custody into Janus (ex AGM-11)". Current business custody work; scoped to the business context by this decision. |
| legacy `ppm:AGM-18` | agm1 backup and restore gate. Business deployment only; stays on `ppm` until complete. |

## Re-verification

```bash
python3 scripts/check-trust-context.py --self-test
python3 scripts/check-trust-context.py
```

Both commands read public identifiers only and print `value_returned=false`.
Live deployment claims still require the nixcfg and agm-nixcfg admission
evidence; this record fixes the topology, not the runtime state.
