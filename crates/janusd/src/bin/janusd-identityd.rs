//! Private, non-authorizing local identity-shadow broker.

#![forbid(unsafe_code)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        anyhow::bail!(
            "janusd-identityd accepts no arguments reason_code=identity_arguments_denied value_returned=false"
        );
    }
    if let Err(error) = janusd::run_identity_shadow_service().await {
        // One stable value-free line first, then the context chain, so an
        // operator can grep the reason without reading the source (JANUS-450).
        eprintln!(
            "janusd-identityd failed reason_code={} value_returned=false",
            janusd::startup_failure_reason_code(&error)
        );
        eprintln!("{error:#}");
        std::process::exit(1);
    }
    Ok(())
}
