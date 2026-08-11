# Janus env-file handoff example

This bundle is the checked nonprod fixture for `janusd-use env-file` service
handoff. It is intentionally small and local: no host deploy, no network
service, no production path.

Files:
- `secretspec.toml`: one manifest-declared canary secret.
- `metadata.toml`: owner/class/lifecycle overlay. The canary is `break_glass`
  so the smoke retains the approval-required path; its disposable runtime copy
  is then reclassified to `normal` to exercise direct CLI permit issuance too.
- `approved-use.env-file.toml.in`: reviewed env-file profile template.
- `consumer-contract.md`: named nonprod consumer contract for the fixture
  service.

Run it from the repo root:

```bash
devenv shell -- ./scripts/smoke-janusd-env-file.sh
```

The smoke renders the template into a disposable runtime, preflights the target
without a permit or secret read, verifies the approval-backed BreakGlass path,
then verifies the direct non-approval Normal path. Both paths write a private
env file that a tiny fixture service consumes without printing the secret
literal.
