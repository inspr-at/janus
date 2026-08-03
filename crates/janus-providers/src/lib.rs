//! # janus-providers — adapters for external provider contracts
//!
//! [`janus_core::SecretStore`] is the provider-neutral boundary, and the
//! `secretspec.toml` manifest remains the allowlist regardless of the selected
//! backend. This crate owns adapters such as [`SecretspecStore`], which binds
//! that manifest to an explicit secretspec provider.
//!
//! Native custody implementations may live in dedicated crates when their
//! ownership and dependencies warrant it. The self-hosted default is the
//! age-backed store in `janus-provider-age`; future OpenBao-, KMS-, or HSM-class
//! custody must preserve the same `SecretStore` contract rather than expanding
//! the core policy surface.

#![forbid(unsafe_code)]

pub mod secretspec;

pub use secretspec::SecretspecStore;
