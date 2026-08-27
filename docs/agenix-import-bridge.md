# Agenix import bridge

`janus-agenix-import <name>` is the generic host-local bridge from materialized
agenix secrets into the Janus age store. The command accepts exactly one
catalog-declared secret name. It derives the source as
`JANUS_AGENIX_MATERIAL_ROOT/<name>`; the root defaults to `/run/agenix` and
must be absolute and resolve to a directory. The trusted root may be agenix's
generation symlink; every name-derived component and the secret file itself
must not be a symlink. Operators cannot supply a source path or secret value
on the command line.

The command uses the existing `JANUS_AGE_*` variables for the store, manifest,
profile, identity, and recipients, including their `JANUS_WARDEN_AGE_*`
aliases, plus the canonical `JANUS_SCOPE_*` scope configuration.
`JANUS_AGE_SCOPE`, when set, applies the same manifest-membership subset as
`janusd`; lifecycle metadata overlays are not needed for this create-if-absent
operation. The source must be a non-empty regular file no larger than 64 KiB.
Name-derived symlinks and names outside the reviewed catalog fail closed.

On the first import, Janus seals the material with the configured age
recipients and becomes its custodian; the catalog descriptor then reports the
secret as present. A repeated import is a value-free no-op and never replaces
existing Janus ciphertext, even if the agenix material is no longer present.
The command emits only a value-free JSON outcome and provides no reveal path.

This replaces per-secret import scripts with one name-derived action. It does
not export values back to agenix or distribute them to another host. The
host-envelope reseal work in JANUS-444 and its JANUS-443 epic follow later.
