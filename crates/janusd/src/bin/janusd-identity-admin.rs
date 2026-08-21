//! Offline, authority-side subject-registry administration (JANUS-453).

#![forbid(unsafe_code)]

use anyhow::Result;

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = janusd::run_identity_admin(&args) {
        eprintln!(
            "janusd-identity-admin failed reason_code={} value_returned=false",
            janusd::startup_failure_reason_code(&error)
        );
        eprintln!("{error:#}");
        std::process::exit(1);
    }
    Ok(())
}
