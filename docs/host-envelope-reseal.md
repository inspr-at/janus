# Host envelope reseal

An authorized host-envelope reseal takes an existing signed packet for one
`sec_…`, decrypts it with the current host's local identity, and produces a new
signed envelope for one target host. The source signature and secret binding
are verified, and the target binding names a new host, envelope, and operation
while retaining the same secret reference.

The operation returns only the new single-recipient packet and a value-free
`host.envelope.reseal` outcome. It never returns the secret value, never changes
the source packet, and does not turn either packet into a multi-recipient
envelope. Decrypted bytes remain bounded in memory and are zeroized after the
new packet is sealed.

An in-process or local-peer handoff of the returned packet is sufficient for
this primitive. Fleet and remote distribution belong to JANUS-443 and are not
part of the reseal operation.
