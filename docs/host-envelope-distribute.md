# Host envelope distribution

One authorized distribute action gives host Y a value that the local host
already holds, without a human editor and without revealing or returning the
value. The input is the local host's existing signed envelope, its local
identity path, host Y's `ssh-ed25519` public host key, and a new binding for Y.

Distribution preserves the single-recipient envelope model. It opens the
source envelope only inside the bounded host reseal boundary and produces a
new signed envelope addressed only to Y; it never modifies the source packet
or converts it into a multi-recipient packet. Returning that packet for a
local-peer handoff is sufficient, so this seam adds no remote transport.

This action composes the JANUS-444 `reseal_host_envelope` primitive from PR
#100 and does not replace it. JANUS-445 import and JANUS-447 write remain
sibling capabilities rather than parts of distribution.
