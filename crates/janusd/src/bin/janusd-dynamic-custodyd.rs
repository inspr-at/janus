use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        anyhow::bail!(
            "janusd-dynamic-custodyd accepts no arguments reason_code=dynamic_custody_arguments_denied value_returned=false"
        );
    }
    janusd::run_dynamic_custody_service().await
}
