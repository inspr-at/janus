//! Value-free distribution of an existing host envelope to one other host.

#![forbid(unsafe_code)]

use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use janus_host::{
    reseal_host_envelope, HostEnvelopeBindingV1, HostEnvelopeError, HostEnvelopeResealRequest,
};
use serde::{Deserialize, Serialize};

/// Inputs for distributing a locally held value to exactly one host.
pub struct HostEnvelopeDistributeRequest<'a> {
    pub source_packet: &'a [u8],
    pub local_identity_path: &'a Path,
    pub source_verifying_key: &'a VerifyingKey,
    pub binding: HostEnvelopeBindingV1,
    pub host_recipient: &'a str,
    pub signing_key_id: &'a str,
    pub signing_key: &'a SigningKey,
}

/// Value-free result metadata for one distribution action.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostEnvelopeDistributeOutcome {
    pub action: String,
    pub host_ref: String,
    pub secret_ref: String,
    pub envelope_ref: String,
    pub operation_ref: String,
    pub changed: bool,
    pub value_returned: bool,
}

/// Newly sealed single-recipient packet and value-free result metadata.
pub struct HostEnvelopeDistributeResult {
    pub packet: Vec<u8>,
    pub outcome: HostEnvelopeDistributeOutcome,
}

/// Give one target host a value already held by the local host.
pub fn distribute_host_envelope(
    request: HostEnvelopeDistributeRequest<'_>,
) -> Result<HostEnvelopeDistributeResult, HostEnvelopeError> {
    let resealed = reseal_host_envelope(HostEnvelopeResealRequest {
        source_packet: request.source_packet,
        local_identity_path: request.local_identity_path,
        source_verifying_key: request.source_verifying_key,
        binding: request.binding,
        host_recipient: request.host_recipient,
        signing_key_id: request.signing_key_id,
        signing_key: request.signing_key,
    })?;
    let outcome = HostEnvelopeDistributeOutcome {
        action: "host.envelope.distribute".to_string(),
        host_ref: resealed.outcome.host_ref,
        secret_ref: resealed.outcome.secret_ref,
        envelope_ref: resealed.outcome.envelope_ref,
        operation_ref: resealed.outcome.operation_ref,
        changed: resealed.outcome.changed,
        value_returned: false,
    };
    Ok(HostEnvelopeDistributeResult {
        packet: resealed.packet,
        outcome,
    })
}

#[cfg(test)]
mod tests;
