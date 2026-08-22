//! One-shot, dependency-only Paimos external-stage reporter.

#![forbid(unsafe_code)]

fn main() {
    if std::env::args_os().count() != 1 {
        eprintln!(
            "janus-paimos-dependency-reporter denied reason_code=paimos_reporter_arguments_denied value_returned=false"
        );
        std::process::exit(1);
    }
    if let Err(error) = janus_host::paimos::run_from_system() {
        eprintln!(
            "janus-paimos-dependency-reporter denied reason_code={} value_returned=false",
            error.reason_code()
        );
        std::process::exit(1);
    }
}
