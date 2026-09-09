#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
vendor_dir="${repo_root}/go-envelope/ui/vendor/flow-shell"
manifest="${vendor_dir}/manifest.json"

if [[ ! -f "$manifest" ]]; then
  printf 'error: missing flow-shell vendor manifest at %s\n' "$manifest" >&2
  exit 1
fi

python3 - "$manifest" "$vendor_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
vendor_dir = pathlib.Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text())
expected_tgz = "sha256:17a56f0b2899c91847521672bc9b58b82e85e0259dd69f8e9f416949561641c7"
expected_commit = "4b10524cd2a22e136e750ebfef2bf12eb2b7db5a"
if manifest.get("version") != "0.1.5":
    raise SystemExit("unexpected flow-shell version pin")
if manifest.get("source_commit") != expected_commit:
    raise SystemExit("unexpected flow-shell source commit pin")
if manifest.get("runtime_tgz_sha256") != expected_tgz:
    raise SystemExit("unexpected flow-shell runtime tgz digest pin")
if manifest.get("package") != "@inspr/flow-shell":
    raise SystemExit("unexpected flow-shell package name")
for entry in manifest.get("files", []):
    rel = entry["path"]
    path = vendor_dir / rel
    if not path.is_file():
        raise SystemExit(f"missing vendored file: {rel}")
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != entry["sha256"]:
        raise SystemExit(f"digest mismatch for {rel}")
for path in vendor_dir.rglob("*"):
    if path.is_file() and path.name != "manifest.json":
        rel = path.relative_to(vendor_dir).as_posix()
        if rel not in {entry["path"] for entry in manifest["files"]}:
            raise SystemExit(f"unlisted vendored file: {rel}")
print("flow-shell vendor manifest verified")
PY
