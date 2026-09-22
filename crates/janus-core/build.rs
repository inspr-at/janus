#[path = "src/calendar_version.rs"]
mod calendar_version;
use std::{env, fs, path::PathBuf};
fn main() {
    let path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../go-envelope/internal/versioninfo/release.json");
    println!("cargo:rerun-if-changed={}", path.display());
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("canonical release source missing"))
            .expect("canonical release JSON");
    assert_eq!(value["version_scheme"].as_str(), Some("inspr-calendar-v2"));
    assert_eq!(
        value["version"].as_str(),
        Some(env::var("CARGO_PKG_VERSION").unwrap().as_str()),
        "Cargo mirror differs from canonical source"
    );
    let version = value["version"].as_str().expect("version");
    assert!(
        calendar_version::valid_calendar(version),
        "invalid UTC coordinate"
    );
    assert_eq!(
        value["reserved_at"],
        format!(
            "20{}-{}-{}T{}:{}:{}Z",
            &version[0..2],
            &version[2..4],
            &version[4..6],
            &version[6..8],
            &version[8..10],
            &version[10..12]
        )
    );
    let anchor = value["channels"]["stable"]["migration"]["first_calendar_version"]
        .as_str()
        .expect("migration anchor");
    assert!(calendar_version::valid_calendar(anchor) && version >= anchor);
    assert_eq!(
        value["channels"]["stable"]["migration"]["legacy_scheme"],
        "legacy"
    );
    assert!(value["channels"]["stable"]["release_sequence"]
        .as_u64()
        .is_some_and(|n| n > 0));
    assert_eq!(
        version == anchor,
        value["channels"]["stable"]["release_sequence"].as_u64() == Some(1)
    );
    println!("cargo:rustc-env=JANUS_FIRST_CALENDAR_VERSION={anchor}");
    println!("cargo:rustc-env=JANUS_VERSION_SCHEME=inspr-calendar-v2");
    println!(
        "cargo:rustc-env=JANUS_RELEASE_SEQUENCE={}",
        value["channels"]["stable"]["release_sequence"]
    );
}
