#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version="0.1.4"
source_commit="efc5e63a6a37cc9d1fd9aa437f8808b3a6536acf"
tgz_sha256="b5e773eeca6eff42432efe4c776e9079132ccaa58f65a48a64bbc5b6a18d55b0"
tgz_url="https://github.com/inspr-at/flow-shell/releases/download/v${version}/inspr-flow-shell-${version}.tgz"
vendor_dir="${repo_root}/go-envelope/ui/vendor/flow-shell"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [[ -n "${FLOW_SHELL_TGZ:-}" ]]; then
  tgz_path="$FLOW_SHELL_TGZ"
else
  tgz_path="${work}/inspr-flow-shell-${version}.tgz"
  curl -fsSL "$tgz_url" -o "$tgz_path"
fi

actual=$(shasum -a 256 "$tgz_path" | awk '{print $1}')
if [[ "$actual" != "$tgz_sha256" ]]; then
  printf 'error: runtime tgz sha256 mismatch (expected %s, got %s)\n' "$tgz_sha256" "$actual" >&2
  exit 1
fi

rm -rf "$vendor_dir"
mkdir -p "$vendor_dir/src/assets"
tar -xzf "$tgz_path" -C "$work"
pkg="${work}/package"
cp "$pkg/LICENSE" "$pkg/NOTICES.json" "$vendor_dir/"
cp "$pkg/src"/*.js "$pkg/src"/*.css "$vendor_dir/src/"
cp "$pkg/src/assets/inspr-logo.svg" "$vendor_dir/src/assets/"

python3 - "$vendor_dir" "$version" "$source_commit" "$tgz_sha256" <<'PY'
import hashlib
import json
import pathlib
import sys

vendor, version, commit, tgz_sha = sys.argv[1:5]
root = pathlib.Path(vendor)
files = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or path.name == "manifest.json":
        continue
    rel = path.relative_to(root).as_posix()
    data = path.read_bytes()
    files.append(
        {
            "path": rel,
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
    )
manifest = {
    "schema": "inspr.janus.flow-shell-vendor/1",
    "package": "@inspr/flow-shell",
    "version": version,
    "source_commit": commit,
    "runtime_tgz_sha256": "sha256:" + tgz_sha,
    "runtime_tgz_url": f"https://github.com/inspr-at/flow-shell/releases/download/v{version}/inspr-flow-shell-{version}.tgz",
    "license": "AGPL-3.0-only",
    "notices_path": "NOTICES.json",
    "files": files,
}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"vendored {len(files)} files into {root}")
PY
