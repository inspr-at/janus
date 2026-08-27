# Agenix import bridge

`janus-agenix-import <name>` is the generic host-local bridge from materialized
agenix secrets into the Janus age store. The command accepts exactly one
catalog-declared secret name. It derives the source as
`JANUS_AGENIX_MATERIAL_ROOT/<name>`; the root defaults to `/run/agenix` and
must be an absolute, non-symlink directory. Operators cannot supply a source
path or secret value on the command line.

The command uses the same `JANUS_AGE_*` store, manifest, profile, identity, and
recipient environment as `janusd`, including its `JANUS_WARDEN_AGE_*` aliases
and canonical `JANUS_SCOPE_*` scope configuration. The source must be a
non-empty regular file no larger than 64 KiB. Symlinks and names outside the
reviewed catalog fail closed.

On the first import, Janus seals the material with the configured age
recipients and becomes its custodian; the catalog descriptor then reports the
secret as present. A repeated import is a value-free no-op and never replaces
existing Janus ciphertext, even if the agenix material is no longer present.
The command emits only a value-free JSON outcome and provides no reveal path.

This replaces per-secret import scripts with one name-derived action. It does
not export values back to agenix or distribute them to another host. The
host-envelope reseal work in JANUS-444 and its JANUS-443 epic follow later.
