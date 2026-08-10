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
    janusd::run_identity_shadow_service().await
}
