# Secretspec-compatible allowlist subset

Janus supports a **secretspec-compatible allowlist subset (revision 1.0,
membership semantics)**. The manifest is an allowlist input, not an authority
or value source. Unknown fields fail closed.

## Supported fields and membership

The supported manifest fields are:

- `[project]`: `name` and `revision`.
- `[profiles.<name>]`: secret names with optional `description` and `required`.
- `[profiles.<name>.defaults]`: `required` and `inherit`.
- `[scopes.<name>]`: a non-empty `secrets` list used only as a membership filter.

`required` defaults to `true`. A non-default profile inherits the effective
fields and members of `[profiles.default]`; its own secret fields take
precedence. `inherit = false` makes the non-default profile independent.
Selecting a missing profile fails closed.

A selected scope filters the resolved profile. A missing scope, an empty scope,
duplicate or invalid members, or a member outside the resolved profile fails
closed with a value-free reason. With no scope selection, the full resolved
profile is used. Warden reads an optional scope from
`JANUS_WARDEN_SECRETSPEC_SCOPE` for both its secretspec and age backends;
`janusd` reads `JANUS_AGE_SCOPE` for its age backend. These settings are
independent of Janus `ScopeRef` configuration.

## Dotenv provider URI forms

The explicit dotenv backend accepts the existing `dotenv:<path>` form. It also
accepts `dotenv://<absolute-path>` and resolves it to the same file. The
double-slash form must contain an absolute path without an authority component;
relative and authority-looking forms fail closed with a value-free reason.

## Rejected fields

Janus rejects every authority or value field outside the subset, including:

- Per-secret `providers`, `ref`, `refs`, `generate`, `type`, `default`,
  `composed`, `extract`, `encoding`, `prompt`, and `as_path`.
- Project `extends` and `[project].require_reason`.
- Profile `defaults.default` and `defaults.providers`.
- The top-level `[providers]` table.

The parser also retains its rejection of the legacy top-level project
`provider` field. Janus does not load plugin, exec, or socket providers from a
secretspec manifest and does not depend on the `secretspec` crate.
