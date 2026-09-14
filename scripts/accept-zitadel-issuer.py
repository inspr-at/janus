#!/usr/bin/env python3
"""Run the value-free JANUS-465 Zitadel issuer acceptance in an isolated lab.

The driver never prints or writes decrypted client credentials. It invokes the
released janusd-admin with distinct create-only targets, proves the first
credential works, regenerates the application secret, proves the replacement
works and the first no longer works, then exercises a configured out-of-scope
alias. Finally it invokes Janus's durable provider invalidation operation,
which regenerates and discards the new secret, and proves the replacement can
no longer authenticate. API application credentials use an explicitly selected
introspection probe; they do not mint service-account access tokens.
This proves invalidation of the known credential; it
does not claim that ZITADEL stores no current secret.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse

SCHEMA = "janus.zitadel-issuer-acceptance.v1"
INTROSPECTION_SCHEMA = "janus.zitadel-issuer-introspection-acceptance.v1"
PROBE_KINDS = {"client-credentials", "introspection"}
MAX_CONFIG_BYTES = 64 * 1024
MAX_SECRET_BYTES = 4096
MAX_HTTP_BYTES = 64 * 1024
SUCCESS_KEYS = {
    "action",
    "changed",
    "secret_name",
    "shape_sha256",
    "recipients_sha256",
    "issuer_aliases_sha256",
    "reason",
    "value_returned",
}
INVALIDATION_SUCCESS_KEYS = {
    "action",
    "changed",
    "state",
    "method",
    "operation_ref_sha256",
    "issuer_alias_sha256",
    "connector_config_sha256",
    "reason",
    "value_returned",
}
REQUIRED_KEYS = {
    "schema",
    "janusd_admin",
    "janusd_admin_sha256",
    "age",
    "age_sha256",
    "issuer_config",
    "store_recipients_file",
    "output_recipients_file",
    "manifest_file",
    "metadata_file",
    "profile",
    "store_dir",
    "store_identity_file",
    "output_identity_file",
    "export_root",
    "invalidation_state_dir",
    "invalidation_operation_ref",
    "audit_file",
    "evidence_file",
    "scope",
    "allowed_alias",
    "denied_alias",
    "client_id",
    "token_endpoint",
    "token_scope",
    "env_key",
    "initial_name",
    "replacement_name",
    "denied_name",
}
SCOPE_KEYS = {"organization", "project", "repository", "environment"}
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
OPERATION_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ADMISSION_REQUIRED_ENV = (
    "JANUS_IDENTITY_SOCKET",
    "JANUS_DUTY_SURFACE_MANIFEST",
    "JANUS_DUTY_JOURNAL_ROOT",
    "JANUS_DUTY_SIGNING_KEY_FILE",
    "JANUS_RELEASE_EXECUTOR",
    "JANUS_RUNTIME_AUTHORITY_VERIFYING_KEY_FILE",
    "JANUS_RUNTIME_AUTHORITY_AUDIENCE",
    "JANUS_RELEASE_DIGEST",
    "JANUS_ACCOUNTABILITY_POSTURE",
    "JANUS_ROLE_AUTHORIZATION_MODE",
    "JANUS_ROLE_BINDINGS_ROOT",
    "JANUS_ROLE_AUDIT_FILE",
    "JANUS_PRODUCT_MODE",
)
ADMISSION_OPTIONAL_ENV = (
    "JANUS_ACCOUNTABILITY_CONFIG_FILE",
    "JANUS_ROLE_POLICY_FILE",
    "JANUS_RELEASE_CHANNEL_POLICY",
    "JANUS_RELEASE_ADMISSION_RECEIPT",
    "JANUS_RELEASE_ARTIFACT_DIGEST",
    "JANUS_RELEASE_AUDIT_FILE",
    "JANUS_MIGRATION_MANIFEST",
    "JANUS_SCOPE_TRANSFER_MANIFEST",
    "JANUS_RECOVERY_DRILL_MANIFEST",
    "JANUS_RECOVERY_DRILL_EVIDENCE",
    "JANUS_RETENTION_POLICY",
    "JANUS_RETENTION_EVIDENCE",
)


class AcceptanceError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise AcceptanceError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_path(value: object, label: str, *, kind: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"{label} must be an absolute path")
    path = Path(value)
    if path.resolve(strict=False) != path:
        fail(f"{label} must be canonical and contain no symlink components")
    if kind in {"private_file", "private_dir", "mutable_file", "mutable_dir"} and str(path).startswith("/nix/store/"):
        fail(f"{label} must be outside the Nix store")
    if kind == "output_file":
        parent = path.parent
        if not parent.is_dir() or parent.is_symlink():
            fail(f"{label} parent is unavailable")
        mode = stat.S_IMODE(parent.stat().st_mode)
        if mode & 0o077:
            fail(f"{label} parent must be private")
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077:
                fail(f"{label} existing target custody is invalid")
        return path
    if not path.exists() or path.is_symlink():
        fail(f"{label} is unavailable")
    metadata = path.stat()
    if kind in {"file", "private_file", "executable"} and not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular file")
    if kind in {"private_dir", "mutable_dir"} and not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a directory")
    if kind == "executable" and not os.access(path, os.X_OK):
        fail(f"{label} must be executable")
    if kind in {"private_file", "private_dir", "mutable_dir"}:
        if kind == "private_file" and metadata.st_nlink != 1:
            fail(f"{label} must have one hard link")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            fail(f"{label} must be private")
    return path


def load_config(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        fail("acceptance config exceeds its size bound")
    try:
        config = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("acceptance config is not valid JSON")
    if (not isinstance(config, dict) or not REQUIRED_KEYS.issubset(config)
            or set(config) - REQUIRED_KEYS - {"probe_kind"} or config.get("schema") != SCHEMA):
        fail("acceptance config schema or fields are invalid")
    if (not isinstance(config.get("probe_kind", "client-credentials"), str)
            or config.get("probe_kind", "client-credentials") not in PROBE_KINDS):
        fail("credential probe kind is invalid")
    scope = config.get("scope")
    if not isinstance(scope, dict) or set(scope) != SCOPE_KEYS:
        fail("acceptance scope is invalid")
    for key, value in scope.items():
        if not isinstance(value, str) or not value or len(value) > 128 or any(c.isspace() for c in value):
            fail(f"acceptance scope {key} is invalid")
    for key in ("allowed_alias", "denied_alias"):
        value = config[key]
        if not isinstance(value, str) or not value.startswith("issuer:zitadel-oidc-client:") or len(value) > 512:
            fail(f"{key} is invalid")
    if config["allowed_alias"] == config["denied_alias"]:
        fail("allowed and denied aliases must differ")
    for key in ("initial_name", "replacement_name", "denied_name", "env_key"):
        value = config[key]
        if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
            fail(f"{key} is invalid")
    if len({config["initial_name"], config["replacement_name"], config["denied_name"]}) != 3:
        fail("acceptance secret names must be distinct")
    if not isinstance(config["invalidation_operation_ref"], str) or not OPERATION_REF.fullmatch(
        config["invalidation_operation_ref"]
    ):
        fail("invalidation_operation_ref is invalid")
    endpoint = urllib.parse.urlsplit(str(config["token_endpoint"]))
    if (
        endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
    ):
        fail("token_endpoint must be an exact HTTPS URL")
    if config.get("probe_kind") == "introspection" and endpoint.path != "/oauth/v2/introspect":
        fail("introspection requires its exact endpoint")
    if not isinstance(config["client_id"], str) or not config["client_id"] or len(config["client_id"]) > 256:
        fail("client_id is invalid")
    if not isinstance(config["token_scope"], str) or not config["token_scope"] or len(config["token_scope"]) > 1024:
        fail("token_scope is invalid")
    if not isinstance(config["profile"], str) or not config["profile"] or len(config["profile"]) > 128:
        fail("profile is invalid")
    if config["metadata_file"] is not None and not isinstance(config["metadata_file"], str):
        fail("metadata_file must be an absolute path or null")
    return config


def validate_alias_bindings(config: dict[str, object], path: Path) -> None:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CONFIG_BYTES:
        fail("issuer catalog exceeds its size bound")
    try:
        catalog = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("issuer catalog is not valid JSON")
    if not isinstance(catalog, dict) or catalog.get("schema") != "janus.issuer-connectors.v1":
        fail("issuer catalog schema is invalid")
    entries = catalog.get("connectors")
    if not isinstance(entries, list):
        fail("issuer catalog connectors are invalid")
    selected = {}
    for alias_key in ("allowed_alias", "denied_alias"):
        matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("alias") == config[alias_key]]
        if len(matches) != 1 or matches[0].get("kind") != "zitadel-oidc-client":
            fail(f"{alias_key} is not uniquely configured as a Zitadel connector")
        selected[alias_key] = matches[0]
    allowed = selected["allowed_alias"]
    denied = selected["denied_alias"]
    if (
        allowed.get("credential_ref") != denied.get("credential_ref")
        or allowed.get("origin") != denied.get("origin")
        or not allowed.get("credential_ref")
        or not allowed.get("origin")
        or (allowed.get("project_id"), allowed.get("application_id"))
        == (denied.get("project_id"), denied.get("application_id"))
    ):
        fail("scope-denial aliases must bind one principal and origin to distinct applications")
    endpoint = urllib.parse.urlsplit(str(config["token_endpoint"]))
    if f"{endpoint.scheme}://{endpoint.netloc}" != allowed["origin"]:
        fail("token endpoint does not match the configured Zitadel origin")


def validate(config: dict[str, object], *, require_fresh: bool) -> dict[str, Path]:
    paths = {
        "janusd_admin": checked_path(config["janusd_admin"], "janusd_admin", kind="executable"),
        "age": checked_path(config["age"], "age", kind="executable"),
        "issuer_config": checked_path(config["issuer_config"], "issuer_config", kind="file"),
        "store_recipients_file": checked_path(
            config["store_recipients_file"], "store_recipients_file", kind="file"
        ),
        "output_recipients_file": checked_path(
            config["output_recipients_file"], "output_recipients_file", kind="file"
        ),
        "manifest_file": checked_path(config["manifest_file"], "manifest_file", kind="file"),
        "store_dir": checked_path(config["store_dir"], "store_dir", kind="private_dir"),
        "store_identity_file": checked_path(
            config["store_identity_file"], "store_identity_file", kind="private_file"
        ),
        "output_identity_file": checked_path(
            config["output_identity_file"], "output_identity_file", kind="private_file"
        ),
        "export_root": checked_path(config["export_root"], "export_root", kind="mutable_dir"),
        "invalidation_state_dir": checked_path(
            config["invalidation_state_dir"], "invalidation_state_dir", kind="mutable_dir"
        ),
        "audit_file": checked_path(config["audit_file"], "audit_file", kind="output_file"),
        "evidence_file": checked_path(config["evidence_file"], "evidence_file", kind="output_file"),
    }
    if config["metadata_file"] is not None:
        paths["metadata_file"] = checked_path(config["metadata_file"], "metadata_file", kind="file")
    validate_alias_bindings(config, paths["issuer_config"])
    for binary in ("janusd_admin", "age"):
        expected = config[f"{binary}_sha256"]
        if not isinstance(expected, str) or len(expected) != 64 or sha256_file(paths[binary]) != expected:
            fail(f"{binary} digest mismatch")
    if require_fresh:
        if paths["evidence_file"].exists():
            fail("evidence target already exists")
        for name in ("initial_name", "replacement_name", "denied_name"):
            target = paths["export_root"] / f"{config[name]}.age"
            if target.exists():
                fail(f"{name} target already exists")
        operation_digest = hashlib.sha256(
            str(config["invalidation_operation_ref"]).encode()
        ).hexdigest()
        if (paths["invalidation_state_dir"] / f"invalidate_{operation_digest}.json").exists():
            fail("invalidation operation already exists")
    return paths


def runtime_environment(config: dict[str, object], paths: dict[str, Path]) -> dict[str, str]:
    missing = [key for key in ADMISSION_REQUIRED_ENV if not os.environ.get(key)]
    if missing:
        fail("released janusd-admin admission environment is incomplete")
    if os.environ["JANUS_ROLE_AUTHORIZATION_MODE"] != "enforced":
        fail("released janusd-admin role authorization must be enforced")
    env = {
        key: os.environ[key]
        for key in (
            "LANG",
            "LC_ALL",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "NIX_SSL_CERT_FILE",
            "TZ",
            *ADMISSION_REQUIRED_ENV,
            *ADMISSION_OPTIONAL_ENV,
        )
        if key in os.environ
    }
    scope = config["scope"]
    assert isinstance(scope, dict)
    env.update(
        {
            "JANUS_AGE_MANIFEST_FILE": str(paths["manifest_file"]),
            "JANUS_AGE_PROFILE": str(config["profile"]),
            "JANUS_AGE_STORE_DIR": str(paths["store_dir"]),
            "JANUS_AGE_IDENTITY_FILE": str(paths["store_identity_file"]),
            "JANUS_AGE_RECIPIENTS_FILE": str(paths["store_recipients_file"]),
            "JANUS_FORGE_AUDIT_FILE": str(paths["audit_file"]),
            "JANUS_FORGE_EXECUTOR": "janus-465-zitadel-acceptance",
            "JANUS_SCOPE_ORGANIZATION": str(scope["organization"]),
            "JANUS_SCOPE_PROJECT": str(scope["project"]),
            "JANUS_SCOPE_REPOSITORY": str(scope["repository"]),
            "JANUS_SCOPE_ENVIRONMENT": str(scope["environment"]),
        }
    )
    if "metadata_file" in paths:
        env["JANUS_AGE_METADATA_FILE"] = str(paths["metadata_file"])
    return env


def run_create(
    config: dict[str, object],
    paths: dict[str, Path],
    name_key: str,
    alias_key: str,
    *,
    expect_success: bool,
) -> dict[str, object] | None:
    name = str(config[name_key])
    command = [
        str(paths["janusd_admin"]), "forge", "create-generated",
        "--secret", name,
        "--shape", f"env:{config['env_key']}={config[alias_key]}",
        "--reason", "JANUS-465 isolated Zitadel acceptance",
        "--recipients-from", str(paths["output_recipients_file"]),
        "--export-root", str(paths["export_root"]),
        "--issuer-config", str(paths["issuer_config"]),
    ]
    result = subprocess.run(
        command,
        env=runtime_environment(config, paths),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if expect_success:
        if result.returncode != 0:
            fail("released janusd-admin issuer create failed")
        try:
            outcome = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("janusd-admin issuer create returned invalid JSON")
        if (
            not isinstance(outcome, dict)
            or set(outcome) != SUCCESS_KEYS
            or outcome["action"] != "agenix.create.generated"
            or outcome["changed"] is not True
            or outcome["secret_name"] != name
            or outcome["value_returned"] is not False
            or not isinstance(outcome["issuer_aliases_sha256"], str)
        ):
            fail("janusd-admin issuer create outcome is not value-free or canonical")
        return outcome
    if result.returncode == 0:
        fail("out-of-scope issuer alias unexpectedly succeeded")
    if (paths["export_root"] / f"{name}.age").exists():
        fail("out-of-scope issuer attempt wrote a ciphertext")
    return None


def run_invalidate(config: dict[str, object], paths: dict[str, Path]) -> dict[str, object]:
    command = [
        str(paths["janusd_admin"]),
        "forge",
        "invalidate-issuer",
        "--alias",
        str(config["allowed_alias"]),
        "--operation-ref",
        str(config["invalidation_operation_ref"]),
        "--reason",
        "JANUS-465 isolated Zitadel acceptance cleanup",
        "--state-dir",
        str(paths["invalidation_state_dir"]),
        "--issuer-config",
        str(paths["issuer_config"]),
    ]
    result = subprocess.run(
        command,
        env=runtime_environment(config, paths),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail("released janusd-admin issuer invalidation failed")
    try:
        outcome = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("janusd-admin issuer invalidation returned invalid JSON")
    if (
        not isinstance(outcome, dict)
        or set(outcome) != INVALIDATION_SUCCESS_KEYS
        or outcome["action"] != "issuer.credential.invalidate"
        or outcome["changed"] is not True
        or outcome["state"] != "committed"
        or outcome["method"] != "regenerate-and-discard"
        or outcome["reason"] != "JANUS-465 isolated Zitadel acceptance cleanup"
        or outcome["value_returned"] is not False
        or not all(
            isinstance(outcome[key], str)
            and re.fullmatch(r"[0-9a-f]{64}", outcome[key]) is not None
            for key in (
                "operation_ref_sha256",
                "issuer_alias_sha256",
                "connector_config_sha256",
            )
        )
        or outcome["operation_ref_sha256"]
        != hashlib.sha256(str(config["invalidation_operation_ref"]).encode()).hexdigest()
        or outcome["issuer_alias_sha256"]
        != hashlib.sha256(str(config["allowed_alias"]).encode()).hexdigest()
    ):
        fail("janusd-admin issuer invalidation outcome is not value-free or canonical")
    return outcome


def probe_ciphertext(config_path: Path, config: dict[str, object], paths: dict[str, Path], secret_name: str) -> bool:
    ciphertext = paths["export_root"] / f"{secret_name}.age"
    if not ciphertext.is_file() or ciphertext.is_symlink():
        fail("expected issuer ciphertext is unavailable")
    decrypt = subprocess.Popen(
        [
            str(paths["age"]),
            "--decrypt",
            "--identity",
            str(paths["output_identity_file"]),
            str(ciphertext),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert decrypt.stdout is not None
    probe = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "_probe", "--config", str(config_path)],
        stdin=decrypt.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    decrypt.stdout.close()
    decrypt_stderr = decrypt.stderr.read() if decrypt.stderr is not None else b""
    decrypt_code = decrypt.wait()
    if decrypt_code != 0 or decrypt_stderr:
        fail("age decryption failed")
    if probe.returncode != 0:
        fail("Zitadel token probe failed")
    try:
        outcome = json.loads(probe.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Zitadel token probe returned invalid evidence")
    if not isinstance(outcome, dict) or set(outcome) != {"accepted"} or not isinstance(outcome["accepted"], bool):
        fail("Zitadel token probe evidence is invalid")
    return outcome["accepted"]


def token_probe(config: dict[str, object]) -> bool:
    payload = bytearray(sys.stdin.buffer.read(MAX_SECRET_BYTES + 1))
    if not payload or len(payload) > MAX_SECRET_BYTES or b"\n" not in payload:
        fail("decrypted issuer payload is invalid")
    line, remainder = payload.split(b"\n", 1)
    if remainder.strip():
        fail("decrypted issuer payload has unexpected fields")
    prefix = f"{config['env_key']}=".encode()
    if not line.startswith(prefix) or len(line) == len(prefix):
        fail("decrypted issuer payload binding is invalid")
    secret = bytearray(line[len(prefix):])
    try:
        endpoint = urllib.parse.urlsplit(str(config["token_endpoint"]))
        introspection = config.get("probe_kind") == "introspection"
        # A known inactive token tests API-client authentication without claiming
        # that an application client can mint service-account access tokens.
        form = ({"token": "janus-acceptance-known-inactive-token"} if introspection else
                {"grant_type": "client_credentials", "scope": config["token_scope"]})
        body = urllib.parse.urlencode(form).encode()
        basic = base64.b64encode(str(config["client_id"]).encode() + b":" + bytes(secret)).decode("ascii")
        connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443, timeout=30)
        connection.request(
            "POST",
            endpoint.path or "/oauth/v2/token",
            body=body,
            headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
        )
        response = connection.getresponse()
        response_body = bytearray(response.read(MAX_HTTP_BYTES + 1))
        connection.close()
        if len(response_body) > MAX_HTTP_BYTES:
            fail("Zitadel token response exceeds its size bound")
        if response.status in (400, 401, 403):
            return False
        if not 200 <= response.status < 300:
            fail("Zitadel token endpoint is unavailable")
        try:
            token = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("Zitadel token endpoint returned invalid JSON")
        if introspection:
            if not isinstance(token, dict) or token.get("active") is not False:
                fail("introspection must report the known inactive token")
            return True
        accepted = (
            isinstance(token, dict)
            and token.get("token_type") == "Bearer"
            and isinstance(token.get("access_token"), str)
            and bool(token["access_token"])
        )
        if not accepted:
            fail("Zitadel token endpoint returned an invalid success payload")
        return True
    finally:
        for index in range(len(secret)):
            secret[index] = 0
        for index in range(len(payload)):
            payload[index] = 0


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def run(config_path: Path) -> None:
    config = load_config(config_path)
    paths = validate(config, require_fresh=True)
    first = run_create(config, paths, "initial_name", "allowed_alias", expect_success=True)
    if not probe_ciphertext(config_path, config, paths, str(config["initial_name"])):
        fail("initial generated credential was rejected")
    second = run_create(config, paths, "replacement_name", "allowed_alias", expect_success=True)
    if not probe_ciphertext(config_path, config, paths, str(config["replacement_name"])):
        fail("replacement generated credential was rejected")
    if probe_ciphertext(config_path, config, paths, str(config["initial_name"])):
        fail("initial generated credential remained valid after regeneration")
    run_create(config, paths, "denied_name", "denied_alias", expect_success=False)
    invalidation = run_invalidate(config, paths)
    if probe_ciphertext(config_path, config, paths, str(config["replacement_name"])):
        fail("replacement generated credential remained valid after invalidation")
    evidence = {
            "schema": SCHEMA,
            "release_binary_sha256": config["janusd_admin_sha256"],
            "issuer_config_sha256": sha256_file(paths["issuer_config"]),
            "initial_create": True,
            "initial_token_accepted_before_rotation": True,
            "replacement_create": True,
            "replacement_token_accepted": True,
            "initial_token_denied_after_rotation": True,
            "configured_scope_denied": True,
            "replacement_token_denied_after_invalidation": True,
            "final_provider_credential_invalidated": True,
            "invalidation_method": invalidation["method"],
            "invalidation_operation_ref_sha256": invalidation["operation_ref_sha256"],
            "provider_secret_absence_proven": False,
            "value_returned": False,
            "initial_shape_sha256": first["shape_sha256"] if first else None,
            "replacement_shape_sha256": second["shape_sha256"] if second else None,
        }
    if config.get("probe_kind") == "introspection":
        evidence["schema"] = INTROSPECTION_SCHEMA
        evidence["probe_kind"] = "introspection"
        # Separate evidence vocabulary: these prove client authentication,
        # never token issuance or revocation of an already-issued bearer token.
        for name in list(evidence):
            if "_token_" in name:
                evidence[name.replace("_token_", "_credential_")] = evidence.pop(name)
    write_evidence(
        paths["evidence_file"],
        evidence,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "evidence_file": str(paths["evidence_file"]),
                "value_returned": False,
            },
            separators=(",", ":"),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "run", "_probe"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    try:
        config_path = args.config.resolve(strict=True)
        config = load_config(config_path)
        if args.command == "check":
            validate(config, require_fresh=False)
            print(json.dumps({"ok": True, "schema": SCHEMA, "value_returned": False}, separators=(",", ":")))
        elif args.command == "_probe":
            print(json.dumps({"accepted": token_probe(config)}, separators=(",", ":")))
        else:
            run(config_path)
        return 0
    except (AcceptanceError, OSError, subprocess.SubprocessError):
        print("JANUS-465 Zitadel acceptance failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
