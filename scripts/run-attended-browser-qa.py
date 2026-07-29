#!/usr/bin/env python3
"""Launch one owned, attended Janus QA browser without retaining navigation data."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWED_ORIGINS = {
    "https://pharos.barta.cm/",
    "https://vault.barta.cm/",
}
MAC_CHROME = pathlib.Path(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
NIX_CHROME = re.compile(r"/nix/store/[0-9a-z]{32}-[^/]+/bin/(?:chromium|google-chrome)")
BUILD = re.compile(r"[0-9a-f]{7,40}")
SESSION_ID = re.compile(r"browser_[0-9a-f]{16}")
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
EXISTING_PROFILE_DIRECTORY = re.compile(r"Profile [1-9][0-9]{0,2}")
OUTCOMES = {"closed", "browser_failed", "timeout", "interrupted", "opened"}
RECEIPT_KEYS = {
    "schema_version",
    "session_id",
    "started_at",
    "finished_at",
    "outcome",
    "build",
    "value_returned",
}


class SessionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SessionError(message)


def inside(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    require(
        value in ALLOWED_ORIGINS
        and parsed.scheme == "https"
        and parsed.path == "/"
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and not parsed.password,
        "attended_browser_origin_denied",
    )
    return value


def validate_chrome(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    require(path.is_absolute(), "attended_browser_executable_denied")
    require(
        path == MAC_CHROME or NIX_CHROME.fullmatch(str(path)) is not None,
        "attended_browser_executable_denied",
    )
    require(path.is_file() and os.access(path, os.X_OK), "attended_browser_unavailable")
    return path


def validate_profile(value: str) -> pathlib.Path:
    profile = pathlib.Path(value).expanduser()
    require(profile.is_absolute(), "attended_browser_profile_denied")
    resolved = profile.resolve(strict=False)
    personal_root = (
        pathlib.Path.home()
        / "Library"
        / "Application Support"
        / "Google"
        / "Chrome"
    ).resolve(strict=False)
    require(not inside(resolved, ROOT), "attended_browser_profile_in_repository")
    require(
        not inside(resolved, personal_root),
        "attended_browser_personal_profile_denied",
    )
    require(resolved != pathlib.Path.home(), "attended_browser_profile_denied")
    require("janus" in resolved.name.lower(), "attended_browser_profile_not_dedicated")
    for lock in ("SingletonCookie", "SingletonLock", "SingletonSocket"):
        require(not (resolved / lock).exists(), "attended_browser_profile_in_use")
    return resolved


def validate_existing_profile_directory(value: str) -> str:
    require(
        EXISTING_PROFILE_DIRECTORY.fullmatch(value) is not None,
        "attended_browser_existing_profile_denied",
    )
    return value


def select_profile_mode(
    isolated_profile: str | None,
    existing_profile_directory: str | None,
) -> str:
    require(
        bool(isolated_profile) != bool(existing_profile_directory),
        "attended_browser_profile_mode_denied",
    )
    return "isolated" if isolated_profile else "existing"


def validate_build(value: str) -> str:
    require(BUILD.fullmatch(value) is not None, "attended_browser_build_denied")
    return value


def ensure_private_directory(path: pathlib.Path) -> None:
    require(not path.is_symlink(), "attended_browser_directory_denied")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    require(not path.is_symlink(), "attended_browser_directory_denied")
    require((path.stat().st_mode & 0o077) == 0, "attended_browser_directory_not_private")


def terminate_owned(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def receipt_root() -> pathlib.Path:
    if sys.platform == "darwin":
        return pathlib.Path.home() / "Library" / "Logs" / "Janus" / "browser-qa"
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return pathlib.Path(state_home) / "janus" / "browser-qa"
    return pathlib.Path.home() / ".local" / "state" / "janus" / "browser-qa"


def write_receipt(directory: pathlib.Path, receipt: dict[str, object]) -> None:
    require(set(receipt) == RECEIPT_KEYS, "attended_browser_receipt_fields")
    require(receipt.get("schema_version") == 1, "attended_browser_receipt_invalid")
    require(receipt.get("value_returned") is False, "attended_browser_receipt_invalid")
    require(
        isinstance(receipt.get("session_id"), str)
        and SESSION_ID.fullmatch(receipt["session_id"]) is not None,
        "attended_browser_receipt_invalid",
    )
    require(
        isinstance(receipt.get("started_at"), str)
        and UTC_TIMESTAMP.fullmatch(receipt["started_at"]) is not None
        and isinstance(receipt.get("finished_at"), str)
        and UTC_TIMESTAMP.fullmatch(receipt["finished_at"]) is not None,
        "attended_browser_receipt_invalid",
    )
    require(receipt.get("outcome") in OUTCOMES, "attended_browser_receipt_invalid")
    require(
        isinstance(receipt.get("build"), str)
        and validate_build(receipt["build"]) == receipt["build"],
        "attended_browser_receipt_invalid",
    )
    ensure_private_directory(directory)
    receipt_path = directory / f"{receipt['session_id']}.json"
    require(
        not receipt_path.exists() and not receipt_path.is_symlink(),
        "attended_browser_receipt_exists",
    )
    descriptor = os.open(
        receipt_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt, sort_keys=True) + "\n")
    except BaseException:
        receipt_path.unlink(missing_ok=True)
        raise
    require(
        (receipt_path.stat().st_mode & 0o077) == 0,
        "attended_browser_receipt_not_private",
    )


def self_test() -> None:
    for denied in (
        "https://vault.barta.cm/?intent=opaque",
        "https://vault.barta.cm/oidc/callback",
        "https://attacker.invalid/",
        "http://vault.barta.cm/",
    ):
        try:
            validate_origin(denied)
        except SessionError:
            continue
        raise SessionError("attended_browser_origin_fixture")

    for denied in (
        ROOT / "janus-qa-profile",
        pathlib.Path.home()
        / "Library"
        / "Application Support"
        / "Google"
        / "Chrome"
        / "Default",
        pathlib.Path.home() / "browser-profile",
    ):
        try:
            validate_profile(str(denied))
        except SessionError:
            continue
        raise SessionError("attended_browser_profile_fixture")

    require(
        validate_existing_profile_directory("Profile 2") == "Profile 2",
        "attended_browser_existing_profile_fixture",
    )
    for denied in (
        "",
        "Default",
        "Profile 0",
        "Profile 01",
        "Profile 2/Default",
        "../Profile 2",
        "Markus-Debug",
        "Profile 2\n--remote-debugging-port=9222",
    ):
        try:
            validate_existing_profile_directory(denied)
        except SessionError:
            continue
        raise SessionError("attended_browser_existing_profile_fixture")
    for isolated, existing in (
        (None, None),
        ("/tmp/Janus QA Browser", "Profile 2"),
    ):
        try:
            select_profile_mode(isolated, existing)
        except SessionError:
            continue
        raise SessionError("attended_browser_profile_mode_fixture")
    require(
        select_profile_mode("/tmp/Janus QA Browser", None) == "isolated"
        and select_profile_mode(None, "Profile 2") == "existing",
        "attended_browser_profile_mode_fixture",
    )

    for denied in ("", "main", "ABCDEF1", "abcdef", "abcdefg/unsafe"):
        try:
            validate_build(denied)
        except SessionError:
            continue
        raise SessionError("attended_browser_build_fixture")
    require(
        validate_build("9c9eb9e59edc") == "9c9eb9e59edc",
        "attended_browser_build_fixture",
    )

    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    terminate_owned(sleeper)
    require(sleeper.poll() is not None, "attended_browser_process_fixture")
    with tempfile.TemporaryDirectory(prefix="janus-browser-receipt-") as directory:
        root = pathlib.Path(directory) / "receipts"
        receipt = {
            "schema_version": 1,
            "session_id": "browser_0123456789abcdef",
            "started_at": "2026-07-29T00:00:00Z",
            "finished_at": "2026-07-29T00:01:00Z",
            "outcome": "closed",
            "build": "9c9eb9e59edc",
            "value_returned": False,
        }
        write_receipt(root, receipt)
        stored = json.loads((root / "browser_0123456789abcdef.json").read_text())
        require(stored == receipt, "attended_browser_receipt_fixture")
        opened = dict(receipt)
        opened["session_id"] = "browser_abcdef0123456789"
        opened["outcome"] = "opened"
        write_receipt(root, opened)
        stored_opened = json.loads(
            (root / "browser_abcdef0123456789.json").read_text()
        )
        require(stored_opened == opened, "attended_browser_receipt_fixture")


def run_session(
    chrome: pathlib.Path,
    profile: pathlib.Path,
    origin: str,
    build: str,
    timeout_seconds: int,
) -> None:
    ensure_private_directory(profile)
    cache_root = (
        pathlib.Path.home() / "Library" / "Caches" / "Janus" / "browser-qa"
    )
    ensure_private_directory(cache_root)
    session_dir = pathlib.Path(
        tempfile.mkdtemp(prefix="session-", dir=str(cache_root))
    )
    session_dir.chmod(0o700)
    session_id = f"browser_{uuid.uuid4().hex[:16]}"
    started = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    state = {
        "schema_version": 1,
        "session_id": session_id,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "value_returned": False,
    }
    state_path = session_dir / "owned-session.json"
    state_path.write_text(json.dumps(state, sort_keys=True) + "\n")
    state_path.chmod(0o600)

    process: subprocess.Popen[bytes] | None = None
    outcome = "interrupted"
    try:
        process = subprocess.Popen(
            [
                str(chrome),
                f"--user-data-dir={profile}",
                "--profile-directory=Default",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--new-window",
                origin,
            ],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        state["pid"] = process.pid
        state_path.write_text(json.dumps(state, sort_keys=True) + "\n")
        state_path.chmod(0o600)
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.25)
        if process.poll() is None:
            outcome = "timeout"
            terminate_owned(process)
            raise SessionError("attended_browser_timeout")
        return_code = process.returncode
        outcome = "closed" if return_code == 0 else "browser_failed"
        require(return_code == 0, "attended_browser_failed")
    except KeyboardInterrupt:
        outcome = "interrupted"
        raise SessionError("attended_browser_interrupted")
    except OSError as error:
        outcome = "browser_failed"
        raise SessionError("attended_browser_failed") from error
    finally:
        if process is not None:
            terminate_owned(process)
        shutil.rmtree(session_dir)
        finished = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        duration = max(0, int((finished - started).total_seconds()))
        write_receipt(
            receipt_root(),
            {
                "schema_version": 1,
                "session_id": session_id,
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "finished_at": finished.isoformat().replace("+00:00", "Z"),
                "outcome": outcome,
                "build": build,
                "value_returned": False,
            },
        )
        print(
            "attended_browser_qa="
            f"{outcome} session_id={session_id} duration_seconds={duration} "
            "value_returned=false"
        )


def open_existing_profile(
    chrome: pathlib.Path,
    profile_directory: str,
    origin: str,
    build: str,
) -> None:
    require(sys.platform == "darwin", "attended_browser_existing_profile_unsupported")
    require(chrome == MAC_CHROME, "attended_browser_existing_profile_unsupported")
    profile_directory = validate_existing_profile_directory(profile_directory)
    session_id = f"browser_{uuid.uuid4().hex[:16]}"
    started = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    try:
        subprocess.run(
            [
                "/usr/bin/open",
                "-a",
                "Google Chrome",
                "--args",
                f"--profile-directory={profile_directory}",
                "--new-window",
                origin,
            ],
            check=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SessionError("attended_browser_existing_profile_failed") from error
    finished = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    write_receipt(
        receipt_root(),
        {
            "schema_version": 1,
            "session_id": session_id,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": finished.isoformat().replace("+00:00", "Z"),
            "outcome": "opened",
            "build": build,
            "value_returned": False,
        },
    )
    print(
        "attended_browser_qa="
        f"opened session_id={session_id} value_returned=false"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--chrome", default=str(MAC_CHROME))
    parser.add_argument("--profile-dir")
    parser.add_argument("--existing-profile-directory")
    parser.add_argument("--origin", choices=sorted(ALLOWED_ORIGINS))
    parser.add_argument("--build")
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            mode = select_profile_mode(
                args.profile_dir,
                args.existing_profile_directory,
            )
            require(
                bool(args.origin)
                and bool(args.build)
                and 1 <= args.timeout_seconds <= 14400,
                "attended_browser_invalid_arguments",
            )
            chrome = validate_chrome(args.chrome)
            origin = validate_origin(args.origin)
            build = validate_build(args.build)
            if mode == "isolated":
                run_session(
                    chrome,
                    validate_profile(args.profile_dir),
                    origin,
                    build,
                    args.timeout_seconds,
                )
            else:
                open_existing_profile(
                    chrome,
                    args.existing_profile_directory,
                    origin,
                    build,
                )
    except (OSError, SessionError) as error:
        print(
            f"attended_browser_qa=blocked reason={error} value_returned=false",
            file=sys.stderr,
        )
        return 1
    if args.self_test:
        print("attended_browser_qa=self_test_passed value_returned=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
