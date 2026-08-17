{ pkgs, ... }:

let
  go_1_26_6 = pkgs.go_1_26.overrideAttrs (_: {
    version = "1.26.6";
    src = pkgs.fetchurl {
      url = "https://go.dev/dl/go1.26.6.src.tar.gz";
      hash = "sha256-oHIcVMaIkBRI13rZs+x+p8R0cwdV/4kTgukuy5P/LLE=";
    };
  });
in

{
  packages = with pkgs; [
    age
    cargo
    cargo-audit
    clippy
    cosign
    gh
    gitleaks
    go_1_26_6
    gotools
    rustc
    rustfmt
    trivy
  ];

  enterShell = ''
    echo "Janus dev environment"
    echo "  rust: cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings"
    echo "  go:   cd go-envelope && go test ./..."
    echo "  sec:  scripts/run-security-gates.sh"
  '';
}
