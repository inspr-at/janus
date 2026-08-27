# Catalog material lifetime

Janus catalog entries may carry optional, value-free issuer lifetime metadata:
`issued_at`, `not_after`, an opaque `issuer` label, and provenance. A reviewed
metadata overlay uses `reviewed_manual`; public X.509 certificate import uses
`parsed_at_import`. Strict UTC timestamps use `YYYY-MM-DDTHH:MM:SSZ`. A
malformed date is rejected with a stable reason code and the rejected input is
not echoed.

Material expiry and age-based staleness answer different questions and remain
separate statuses. A recently imported certificate can be age-fresh while its
issuer expiry is already in the renewal warning window. The default warning
lead is 30 days. At `not_after`, normal approved use fails closed through the
catalog descriptor; no permit, grant, delegation, session, or break-glass
lifetime is changed. Entries without `not_after` keep the existing stale and
approved-use behavior.

Externally issued material uses `RotationStrategy::Manual`. Janus exposes a
reviewed human action to renew with the issuer and then update lifetime
metadata; it does not claim it can generate the replacement. Existing external
release-workflow expiry controls remain in force and are not replaced by this
catalog evidence.
