//! Fixed privileged consumer for one managed-transaction completion.

#![forbid(unsafe_code)]

fn main() {
    if std::env::args_os().count() != 1 {
        eprintln!(
            "janus-paimos-managed-completion-reporter denied reason_code=managed_completion_arguments_denied value_returned=false"
        );
        std::process::exit(1);
    }
    if let Err(error) = janus_host::paimos_completion::run_from_system() {
        eprintln!(
            "janus-paimos-managed-completion-reporter denied reason_code={} value_returned=false",
            error.reason_code()
        );
        std::process::exit(1);
    }
}
