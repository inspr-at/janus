//! Privileged no-argument retained-credential re-attestation reporter.

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!(
            "janus-paimos-managed-credential-reattestation-reporter denied reason_code=managed_credential_reattestation_arguments_denied value_returned=false"
        );
        std::process::exit(1);
    }
    if let Err(error) = janus_host::paimos_reattestation::run_from_system() {
        eprintln!(
            "janus-paimos-managed-credential-reattestation-reporter denied reason_code={} value_returned=false",
            error.reason_code()
        );
        std::process::exit(1);
    }
}
