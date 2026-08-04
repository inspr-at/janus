//! Dedicated process for transporting prepared dynamic host packages.

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        anyhow::bail!(
            "janusd-dynamic-transportd accepts no arguments reason_code=dynamic_transport_arguments_denied value_returned=false"
        );
    }
    janusd::run_dynamic_transport_service().await
}
