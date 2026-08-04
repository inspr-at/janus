//! Dedicated process for preparing dynamic host-bound packages.

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        anyhow::bail!("janusd-dynamic-deliveryd accepts no arguments");
    }
    janusd::run_dynamic_delivery_service().await
}
