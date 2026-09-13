#!/usr/bin/env python3

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).with_name("accept-zitadel-issuer.py")
SPEC = importlib.util.spec_from_file_location("accept_zitadel_issuer", MODULE_PATH)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)

ADMISSION_ENV = {
    "JANUS_IDENTITY_SOCKET": "/run/janus/identity.sock",
    "JANUS_DUTY_SURFACE_MANIFEST": "/etc/janus/duties.json",
    "JANUS_RUNTIME_AUTHORITY_VERIFYING_KEY_FILE": "/etc/janus/runtime.pub",
    "JANUS_RUNTIME_AUTHORITY_AUDIENCE": "lab-audience",
    "JANUS_RELEASE_DIGEST": "sha256:" + "a" * 64,
    "JANUS_ACCOUNTABILITY_POSTURE": "authenticated_observe",
    "JANUS_ROLE_AUTHORIZATION_MODE": "enforced",
    "JANUS_ROLE_BINDINGS_ROOT": "/var/lib/janus/roles",
    "JANUS_ROLE_AUDIT_FILE": "/var/lib/janus/role-audit.jsonl",
    "JANUS_PRODUCT_MODE": "self_hosted",
}


class Input:
    def __init__(self, payload):
        self.buffer = io.BytesIO(payload)


class Response:
    status = 200
    payload = b'{"access_token":"opaque-token","token_type":"Bearer","expires_in":60}'

    def read(self, _size):
        return self.payload


class Connection:
    request_headers = None

    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, _method, _path, *, body, headers):
        self.__class__.request_headers = headers
        self.body = body

    def getresponse(self):
        return Response()

    def close(self):
        pass


class ZitadelIssuerAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.paths = {}
        for name in (
            "janusd_admin",
            "age",
            "issuer_config",
            "store_recipients_file",
            "output_recipients_file",
            "manifest_file",
            "store_identity_file",
            "output_identity_file",
        ):
            path = self.root / name
            path.write_text("fixture", encoding="utf-8")
            os.chmod(path, 0o700 if name in ("janusd_admin", "age") else 0o600)
            self.paths[name] = path
        for name in ("store_dir", "export_root"):
            path = self.root / name
            path.mkdir()
            os.chmod(path, 0o700)
            self.paths[name] = path
        self.paths["audit_file"] = self.root / "audit.jsonl"
        self.paths["evidence_file"] = self.root / "evidence.json"
        self.config = {
            "schema": acceptance.SCHEMA,
            **{name: str(path) for name, path in self.paths.items()},
            "janusd_admin_sha256": acceptance.sha256_file(self.paths["janusd_admin"]),
            "age_sha256": acceptance.sha256_file(self.paths["age"]),
            "profile": "lab",
            "metadata_file": None,
            "scope": {"organization": "inspr", "project": "lab", "repository": "janus", "environment": "isolated"},
            "allowed_alias": "issuer:zitadel-oidc-client:INSPR Lab/acceptance",
            "denied_alias": "issuer:zitadel-oidc-client:INSPR Other/denied",
            "client_id": "123456789",
            "token_endpoint": "https://identity.example.test/oauth/v2/token",
            "token_scope": "openid",
            "env_key": "OIDC_CLIENT_SECRET",
            "initial_name": "JANUS465_INITIAL",
            "replacement_name": "JANUS465_REPLACEMENT",
            "denied_name": "JANUS465_DENIED",
        }
        self.paths["issuer_config"].write_text(
            json.dumps(
                {
                    "schema": "janus.issuer-connectors.v1",
                    "connectors": [
                        {
                            "kind": "zitadel-oidc-client",
                            "alias": self.config["allowed_alias"],
                            "credential_ref": "lab-machine-profile",
                            "origin": "https://identity.example.test",
                            "project_id": "1",
                            "application_id": "2",
                            "timeout_seconds": 10,
                        },
                        {
                            "kind": "zitadel-oidc-client",
                            "alias": self.config["denied_alias"],
                            "credential_ref": "lab-machine-profile",
                            "origin": "https://identity.example.test",
                            "project_id": "3",
                            "application_id": "4",
                            "timeout_seconds": 10,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        os.chmod(self.config_path, 0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def test_check_binds_exact_binaries_and_private_mutable_paths(self):
        loaded = acceptance.load_config(self.config_path)
        paths = acceptance.validate(loaded, require_fresh=True)
        self.assertEqual(paths["janusd_admin"], self.paths["janusd_admin"])
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            acceptance.AcceptanceError, "admission environment is incomplete"
        ):
            acceptance.runtime_environment(loaded, paths)
        self.config["janusd_admin_sha256"] = "0" * 64
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "digest mismatch"):
            acceptance.validate(acceptance.load_config(self.config_path), require_fresh=True)

    def test_scope_denial_requires_two_distinct_aliases_for_one_issuer_principal(self):
        catalog = json.loads(self.paths["issuer_config"].read_text(encoding="utf-8"))
        catalog["connectors"] = catalog["connectors"][:1]
        self.paths["issuer_config"].write_text(json.dumps(catalog), encoding="utf-8")
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "denied_alias is not uniquely configured"
        ):
            acceptance.validate(
                acceptance.load_config(self.config_path), require_fresh=True
            )

    def test_token_probe_consumes_secret_in_memory_and_returns_only_acceptance(self):
        with mock.patch.object(
            acceptance.sys,
            "stdin",
            Input(b"OIDC_CLIENT_SECRET=sensitive-canary\n"),
        ), mock.patch.object(acceptance.http.client, "HTTPSConnection", Connection):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertTrue(acceptance.token_probe(self.config))
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Basic ", Connection.request_headers["Authorization"])
        self.assertNotIn("sensitive-canary", Connection.request_headers["Authorization"])

    def test_token_probe_rejects_unexpected_success_payload_as_an_error(self):
        with mock.patch.object(
            acceptance.sys,
            "stdin",
            Input(b"OIDC_CLIENT_SECRET=sensitive-canary\n"),
        ), mock.patch.object(acceptance.http.client, "HTTPSConnection", Connection), mock.patch.object(
            Response, "payload", b'{"status":"ok"}'
        ):
            with self.assertRaisesRegex(
                acceptance.AcceptanceError, "invalid success payload"
            ):
                acceptance.token_probe(self.config)

    def test_create_invokes_released_cli_shape_and_denied_alias_stays_absent(self):
        self.paths["janusd_admin"].write_text(
            """#!/bin/sh
set -eu
[ "$JANUS_SCOPE_PROJECT" = lab ]
[ "$#" -eq 14 ]
[ "$1" = forge ] && [ "$2" = create-generated ] && [ "$3" = --secret ]
name=$4
[ "$5" = --shape ]
if [ "$name" = JANUS465_DENIED ]; then
  [ "$6" = 'env:OIDC_CLIENT_SECRET=issuer:zitadel-oidc-client:INSPR Other/denied' ]
else
  [ "$6" = 'env:OIDC_CLIENT_SECRET=issuer:zitadel-oidc-client:INSPR Lab/acceptance' ]
fi
[ "$7" = --reason ] && [ "$8" = 'JANUS-465 isolated Zitadel acceptance' ]
[ "$9" = --recipients-from ] && [ "${10}" = '@OUTPUT_RECIPIENTS@' ]
[ "${11}" = --export-root ] && [ "${12}" = '@EXPORT_ROOT@' ]
[ "${13}" = --issuer-config ] && [ "${14}" = '@ISSUER_CONFIG@' ]
[ "$name" != JANUS465_DENIED ] || exit 1
printf '{"action":"agenix.create.generated","changed":true,"secret_name":"%s","shape_sha256":"shape","recipients_sha256":"recipients","issuer_aliases_sha256":"aliases","reason":"JANUS-465 isolated Zitadel acceptance","value_returned":false}\n' "$name"
"""
            .replace("@OUTPUT_RECIPIENTS@", str(self.paths["output_recipients_file"]))
            .replace("@EXPORT_ROOT@", str(self.paths["export_root"]))
            .replace("@ISSUER_CONFIG@", str(self.paths["issuer_config"])),
            encoding="utf-8",
        )
        os.chmod(self.paths["janusd_admin"], 0o700)
        self.config["janusd_admin_sha256"] = acceptance.sha256_file(
            self.paths["janusd_admin"]
        )
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        loaded = acceptance.load_config(self.config_path)
        paths = acceptance.validate(loaded, require_fresh=True)
        with mock.patch.dict(os.environ, ADMISSION_ENV, clear=False):
            outcome = acceptance.run_create(
                loaded, paths, "initial_name", "allowed_alias", expect_success=True
            )
            self.assertEqual(outcome["secret_name"], "JANUS465_INITIAL")
            self.assertIsNone(
                acceptance.run_create(
                    loaded,
                    paths,
                    "denied_name",
                    "denied_alias",
                    expect_success=False,
                )
            )
        self.assertFalse((self.paths["export_root"] / "JANUS465_DENIED.age").exists())

    def test_run_orders_create_rotate_old_denial_and_scope_denial_value_free(self):
        calls = []
        probes = []

        def create(_config, _paths, name_key, alias_key, *, expect_success):
            calls.append((name_key, alias_key, expect_success))
            if not expect_success:
                return None
            return {"shape_sha256": f"digest-{name_key}"}

        def probe(_config_path, _config, _paths, secret_name):
            probes.append(secret_name)
            return len(probes) < 3

        written = {}
        with mock.patch.object(acceptance, "validate", return_value=self.paths), mock.patch.object(
            acceptance, "run_create", side_effect=create
        ), mock.patch.object(acceptance, "probe_ciphertext", side_effect=probe), mock.patch.object(
            acceptance, "write_evidence", side_effect=lambda path, value: written.update(path=path, value=value)
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                acceptance.run(self.config_path)

        self.assertEqual(
            calls,
            [
                ("initial_name", "allowed_alias", True),
                ("replacement_name", "allowed_alias", True),
                ("denied_name", "denied_alias", False),
            ],
        )
        self.assertEqual(
            probes,
            ["JANUS465_INITIAL", "JANUS465_REPLACEMENT", "JANUS465_INITIAL"],
        )
        self.assertTrue(written["value"]["initial_token_denied_after_rotation"])
        self.assertTrue(written["value"]["configured_scope_denied"])
        self.assertFalse(written["value"]["value_returned"])
        self.assertFalse(written["value"]["final_provider_secret_revoked"])
        self.assertEqual(
            written["value"]["final_provider_secret_revoke_reason"],
            "unsupported_by_janus_0.1.39",
        )
        self.assertNotIn("sensitive", output.getvalue())


if __name__ == "__main__":
    unittest.main()
