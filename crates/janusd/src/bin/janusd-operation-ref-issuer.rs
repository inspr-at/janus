//! Offline controller-side operation-reference issuer (JANUS-470).

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let ["--request-file", request, "--signing-key-file", signing, "--out", out] = args.as_slice()
    else {
        anyhow::bail!(
            "usage: janusd-operation-ref-issuer --request-file REQUEST --signing-key-file KEY --out OUTPUT"
        );
    };
    let outcome = janus_local::issue_authoritative_operation_ref(
        Path::new(request),
        Path::new(signing),
        Path::new(out),
        SystemTime::now(),
    )
    .context("operation reference issuance refused")?;
    println!("{}", serde_json::to_string(&outcome)?);
    Ok(())
}
