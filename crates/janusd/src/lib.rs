//! Shared implementation for the hard-separated Janus runtime entry points.

#![forbid(unsafe_code)]

#[path = "main.rs"]
mod runtime;

pub use runtime::{
    run_dynamic_custody_service, run_dynamic_delivery_service, run_for_plane,
    run_web_transaction_service,
};
