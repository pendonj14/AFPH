#!/usr/bin/env python3
"""Strict startup preflight for the supported Assault Fire PH local setup."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

VALIDATED_TCLS_SHA256 = "3ff351e0adb594d7544e28db2e966a6d6eb548e9df70daaf4daf58f2ee438d56"
ORIGINAL_TCLS_SHA256 = "13ead403452e0f25cf00658369bf4bf5ff34ed1b16027f7833fb27d398386cd1"

REQUIRED_HOSTS = (
    "tversion.levelupgames.ph",
    "tauthproxy.levelupgames.ph",
    "tdir.levelupgames.ph",
)
LOOPBACK_IPV4 = "127.0.0.1"

PREFLIGHT_STATUS_SCHEMA = 2


def parse_ipv4_setting(name: str, value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return LOOPBACK_IPV4
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise ValueError(f"{name} must be an IPv4 address like 100.64.1.2; got {value!r}") from None


def default_preflight_status_path() -> Path:
    """Machine-readable launch gate shared by the server and launch helpers."""
    override = (os.environ.get("AF_PREFLIGHT_STATUS_PATH") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "runtime" / "preflight_status.json"


def default_server_log_path() -> Path:
    override = (os.environ.get("AF_LOG_PATH") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().with_name("af_server_live.log")


@dataclass(frozen=True)
class KeyCheck:
    apclient_sha256: str
    derived_public_sha256: str
    exact_bytes_match: bool
    same_rsa_key: bool
    apclient_length: int
    rsa_key_size: int | None


@dataclass
class PreflightReport:
    client_root: Path | None = None
    tcls_path: Path | None = None
    apclient_path: Path | None = None
    private_key_path: Path | None = None
    tcls_sha256: str | None = None
    tcls_class: str = "unavailable"
    key_check: KeyCheck | None = None
    host_file_path: Path | None = None
    host_file_values: dict[str, list[str]] = field(default_factory=dict)
    host_resolved_values: dict[str, str | None] = field(default_factory=dict)
    expected_ip: str = LOOPBACK_IPV4
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_tcls_hash(sha256_hex: str) -> str:
    value = sha256_hex.lower()
    if value == VALIDATED_TCLS_SHA256:
        return "validated-raw-pem-patched"
    if value == ORIGINAL_TCLS_SHA256:
        return "original-needs-raw-pem-patch"
    return "unknown"


def derive_public_pem(private_key_path: Path) -> tuple[bytes, int | None]:
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("PRIVATE.PEM does not contain an RSA private key")
    public_key = private_key.public_key()
    return (
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        int(public_key.key_size),
    )


def public_key_numbers(pem: bytes) -> tuple[int, int]:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("PEM does not contain an RSA public key")
    nums = key.public_numbers()
    if not isinstance(nums, rsa.RSAPublicNumbers):
        raise ValueError("PEM does not contain RSA public numbers")
    return int(nums.n), int(nums.e)


def check_key_pair(private_key_path: Path, apclient_path: Path) -> KeyCheck:
    apclient = apclient_path.read_bytes()
    derived, key_size = derive_public_pem(private_key_path)
    try:
        same_rsa_key = public_key_numbers(apclient) == public_key_numbers(derived)
    except (ValueError, TypeError):
        same_rsa_key = False
    return KeyCheck(
        apclient_sha256=hashlib.sha256(apclient).hexdigest(),
        derived_public_sha256=hashlib.sha256(derived).hexdigest(),
        exact_bytes_match=(apclient == derived),
        same_rsa_key=same_rsa_key,
        apclient_length=len(apclient),
        rsa_key_size=key_size,
    )


def check_apclient_hash(apclient_path: Path, expected_sha256: str) -> KeyCheck:
    apclient = apclient_path.read_bytes()
    actual = hashlib.sha256(apclient).hexdigest()
    expected = expected_sha256.lower()
    try:
        key_size = public_key_numbers(apclient)[0].bit_length()
    except (ValueError, TypeError):
        key_size = None
    return KeyCheck(
        apclient_sha256=actual,
        derived_public_sha256=expected,
        exact_bytes_match=(actual == expected),
        same_rsa_key=(actual == expected),
        apclient_length=len(apclient),
        rsa_key_size=key_size,
    )


def resolve_client_root(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env

    explicit = (env.get("AF_CLIENT_ROOT") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()

    game_dir = (env.get("AF_GAME_DIR") or "").strip()
    if game_dir:
        path = Path(game_dir).expanduser().resolve()
        if path.name.lower() == "win32" and path.parent.name.lower() == "binaries":
            return path.parent.parent

    raise ValueError(
        'client root is unknown; set AF_CLIENT_ROOT to the Assault Fire PH root '
        '(example: $env:AF_CLIENT_ROOT = "D:\\AssaultFirePH"). '
        "For PvE, AF_GAME_DIR=...\\Binaries\\Win32 can also supply it."
    )


def default_hosts_path(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    system_root = (env.get("SystemRoot") or env.get("WINDIR") or "").strip()
    if not system_root:
        raise ValueError("SystemRoot/WINDIR is unavailable; cannot locate the Windows hosts file")
    return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"


def parse_hosts_file(path: Path) -> dict[str, list[str]]:
    found = {name: [] for name in REQUIRED_HOSTS}
    text = path.read_text(encoding="utf-8", errors="replace")

    for raw_line in text.splitlines():
        content = raw_line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if len(parts) < 2:
            continue

        address = parts[0]
        names = {name.lower() for name in parts[1:]}
        for required in REQUIRED_HOSTS:
            if required in names:
                found[required].append(address)

    return found


def evaluate_preflight(
    *,
    private_key_path: Path | None,
    client_root: Path | None = None,
    hosts_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    resolver: Callable[[str], str] = socket.gethostbyname,
    validated_tcls_sha256: str = VALIDATED_TCLS_SHA256,
    expected_ip: str | None = None,
    apclient_sha256: str | None = None,
) -> PreflightReport:
    report = PreflightReport(
        private_key_path=(
            Path(private_key_path).expanduser().resolve()
            if private_key_path is not None
            else None
        ),
        expected_ip=expected_ip or LOOPBACK_IPV4,
    )

    try:
        report.client_root = (
            Path(client_root).expanduser().resolve()
            if client_root is not None
            else resolve_client_root(env)
        )
    except Exception as exc:
        report.errors.append(str(exc))
        return report

    report.tcls_path = report.client_root / "TCLS" / "Tenio" / "TCLS.dll"
    report.apclient_path = report.client_root / "TCLS" / "config" / "APClient.dat"

    required_files = [("TCLS.dll", report.tcls_path), ("APClient.dat", report.apclient_path)]
    if apclient_sha256 is None:
        required_files.append(("PRIVATE.PEM", report.private_key_path))
    for label, path in required_files:
        if not path.is_file():
            report.errors.append(f"{label} not found: {path}")

    if report.tcls_path.is_file():
        try:
            report.tcls_sha256 = sha256_file(report.tcls_path)
            if report.tcls_sha256.lower() == validated_tcls_sha256.lower():
                report.tcls_class = "validated-raw-pem-patched"
            else:
                report.tcls_class = classify_tcls_hash(report.tcls_sha256)
                if report.tcls_class == "original-needs-raw-pem-patch":
                    report.errors.append(
                        "TCLS.dll is the verified original/pre-patch build; "
                        "apply tools/patches/patch_tcls_apclient_raw_pem.py first"
                    )
                else:
                    report.errors.append(
                        "TCLS.dll is not the validated raw-PEM-compatible PH build "
                        f"(SHA256={report.tcls_sha256.upper()})"
                    )
        except Exception as exc:
            report.errors.append(f"could not hash TCLS.dll: {exc}")

    if report.apclient_path.is_file() and (
        apclient_sha256 is not None or report.private_key_path.is_file()
    ):
        try:
            if apclient_sha256 is not None:
                report.key_check = check_apclient_hash(
                    report.apclient_path, apclient_sha256
                )
                if not report.key_check.exact_bytes_match:
                    report.errors.append(
                        "APClient.dat SHA256 does not match the host's (--apclient-sha256); "
                        "copy the host's APClient.dat"
                    )
            else:
                report.key_check = check_key_pair(
                    report.private_key_path, report.apclient_path
                )
                if not report.key_check.exact_bytes_match:
                    report.errors.append(
                        "APClient.dat exact byte match is NO; regenerate/install the matching public key"
                    )
                if not report.key_check.same_rsa_key:
                    report.errors.append(
                        "APClient.dat and PRIVATE.PEM same RSA key is NO"
                    )
            if report.key_check.rsa_key_size != 1024:
                report.errors.append(
                    f"RSA key size is {report.key_check.rsa_key_size!r}, expected 1024 bits"
                )
            if report.key_check.apclient_length != 272:
                report.errors.append(
                    f"APClient.dat is {report.key_check.apclient_length} bytes, expected 272"
                )
        except Exception as exc:
            report.errors.append(f"could not parse/compare RSA material: {exc}")

    try:
        report.host_file_path = (
            Path(hosts_path).expanduser().resolve()
            if hosts_path is not None
            else default_hosts_path(env)
        )
        report.host_file_values = parse_hosts_file(report.host_file_path)
    except Exception as exc:
        report.errors.append(f"could not read Windows hosts file: {exc}")
        report.host_file_values = {name: [] for name in REQUIRED_HOSTS}

    for name in REQUIRED_HOSTS:
        values = report.host_file_values.get(name, [])
        if values != [report.expected_ip]:
            if not values:
                report.errors.append(
                    f"hosts entry missing: {report.expected_ip} {name}"
                )
            else:
                report.errors.append(
                    f"hosts entry for {name} must be exactly {report.expected_ip}; found {values}"
                )

        try:
            resolved = resolver(name)
        except Exception:
            resolved = None
        report.host_resolved_values[name] = resolved
        if resolved != report.expected_ip:
            report.errors.append(
                f"{name} resolves to {resolved!r}, expected {report.expected_ip}"
            )

    return report


def preflight_check_flags(report: PreflightReport) -> dict[str, bool]:
    check = report.key_check
    host_ok = all(
        report.host_file_values.get(name, []) == [report.expected_ip]
        and report.host_resolved_values.get(name) == report.expected_ip
        for name in REQUIRED_HOSTS
    )
    return {
        "client_root": report.client_root is not None,
        "tcls_validated_build": report.tcls_class == "validated-raw-pem-patched",
        "apclient_exact_bytes": bool(check and check.exact_bytes_match),
        "same_rsa_key": bool(check and check.same_rsa_key),
        "rsa_1024": bool(check and check.rsa_key_size == 1024),
        "apclient_272_bytes": bool(check and check.apclient_length == 272),
        "hosts": host_ok,
    }


def preflight_status_payload(
    report: PreflightReport,
    *,
    listeners_ready: bool = False,
    log_written: bool = False,
    runtime_errors: list[str] | tuple[str, ...] = (),
    log_path: Path | None = None,
    remote_host: str | None = None,
) -> dict:
    flags = preflight_check_flags(report)
    passed = bool(report.ok and all(flags.values()) and log_written)
    launch_ready = bool(passed and (listeners_ready or remote_host))
    errors = list(report.errors)
    errors.extend(str(x) for x in runtime_errors if str(x).strip())
    return {
        "schema": PREFLIGHT_STATUS_SCHEMA,
        "checked_at_unix": time.time(),
        "server_pid": None if remote_host else os.getpid(),
        "passed": passed,
        "listeners_ready": bool(listeners_ready),
        "log_written": bool(log_written),
        "launch_ready": launch_ready,
        "checks": flags,
        "client_root": str(report.client_root) if report.client_root else None,
        "tcls_path": str(report.tcls_path) if report.tcls_path else None,
        "tcls_sha256": report.tcls_sha256,
        "apclient_path": str(report.apclient_path) if report.apclient_path else None,
        "private_key_path": str(report.private_key_path) if report.private_key_path else None,
        "server_log_path": str(log_path) if log_path else None,
        "hosts": {
            name: {
                "file_values": report.host_file_values.get(name, []),
                "resolved": report.host_resolved_values.get(name),
            }
            for name in REQUIRED_HOSTS
        },
        "errors": errors,
        **({"mode": "remote", "remote_host": remote_host} if remote_host else {}),
    }


def _status_target(status_path: Path | None = None) -> Path:
    return (
        Path(status_path).expanduser().resolve()
        if status_path is not None
        else default_preflight_status_path()
    )


def _atomic_write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)
    return path


def write_preflight_status(
    report: PreflightReport,
    status_path: Path | None = None,
    *,
    listeners_ready: bool = False,
    log_written: bool = False,
    runtime_errors: list[str] | tuple[str, ...] = (),
    log_path: Path | None = None,
    remote_host: str | None = None,
) -> Path:
    path = _status_target(status_path)
    return _atomic_write_json(
        path,
        preflight_status_payload(
            report,
            listeners_ready=listeners_ready,
            log_written=log_written,
            runtime_errors=runtime_errors,
            log_path=log_path,
            remote_host=remote_host,
        ),
    )


def _append_lines_to_log(lines: list[str], path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fp:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        fp.write(f"\n[{stamp}] --- PREFLIGHT ---\n")
        for line in lines:
            fp.write(line + "\n")
    return True


def persist_preflight_log(
    lines: list[str],
    *,
    log_path: Path | None = None,
) -> Path | None:
    requested = (
        Path(log_path).expanduser().resolve()
        if log_path is not None
        else default_server_log_path()
    )
    fallback = Path(__file__).resolve().with_name("af_server_live.log")
    candidates = [requested]
    if fallback != requested:
        candidates.append(fallback)

    for path in candidates:
        try:
            _append_lines_to_log(lines, path)
            return path
        except OSError as exc:
            print(
                f"[PREFLIGHT] WARNING - could not append server log {path}: {exc}",
                flush=True,
            )
    return None


def preflight_report_lines(
    report: PreflightReport,
    *,
    listeners_ready: bool = False,
    log_written: bool = True,
    remote: bool = False,
) -> list[str]:
    lines = [
        "[PREFLIGHT] Assault Fire PH startup checks",
        f"[PREFLIGHT] client root             : {report.client_root}",
    ]

    if report.tcls_path is not None:
        lines.append(f"[PREFLIGHT] TCLS.dll                : {report.tcls_path}")
    lines.append(
        "[PREFLIGHT] TCLS validated build    : "
        + ("YES" if report.tcls_class == "validated-raw-pem-patched" else "NO")
    )
    if report.tcls_sha256:
        lines.append(f"[PREFLIGHT] TCLS SHA256             : {report.tcls_sha256.upper()}")

    check = report.key_check
    lines.append(
        "[PREFLIGHT] APClient exact bytes    : "
        + ("YES" if check and check.exact_bytes_match else "NO")
    )
    lines.append(
        "[PREFLIGHT] same RSA key            : "
        + ("YES" if check and check.same_rsa_key else "NO")
    )
    if check:
        lines.append(
            f"[PREFLIGHT] RSA/APClient format     : "
            f"{check.rsa_key_size}-bit / {check.apclient_length} bytes"
        )

    if report.host_file_path is not None:
        lines.append(f"[PREFLIGHT] hosts file              : {report.host_file_path}")
    for name in REQUIRED_HOSTS:
        file_values = report.host_file_values.get(name, [])
        resolved = report.host_resolved_values.get(name)
        passed = file_values == [report.expected_ip] and resolved == report.expected_ip
        lines.append(
            f"[PREFLIGHT] hosts {name:<27}: "
            f"{'YES' if passed else 'NO'} "
            f"(file={file_values or 'missing'}, resolved={resolved})"
        )

    flags = preflight_check_flags(report)
    checks_ok = bool(report.ok and all(flags.values()) and log_written)
    gate_ok = bool(checks_ok and listeners_ready)
    lines.append(
        "[PREFLIGHT] game launch gate         : "
        + ("UNLOCKED" if gate_ok else "LOCKED")
    )

    if not checks_ok:
        lines.append(
            (
                "[PREFLIGHT] FAILED - remote client checks failed; "
                if remote
                else "[PREFLIGHT] FAILED - server listeners will NOT start; "
            )
            + "supported game launch helpers remain LOCKED."
        )
        if not log_written:
            lines.append(
                "[PREFLIGHT]   - preflight report could not be persisted to a server log"
            )
        for error in report.errors:
            lines.append(f"[PREFLIGHT]   - {error}")
    elif not listeners_ready:
        lines.append(
            "[PREFLIGHT] PASS - client checks succeeded; launch gate remains "
            "LOCKED until all required server listeners bind successfully."
        )
    else:
        lines.append(
            (
                "[PREFLIGHT] PASS - remote client checks succeeded; "
                if remote
                else "[PREFLIGHT] PASS - all required checks and listeners succeeded; "
            )
            + "supported game launch helpers are UNLOCKED."
        )
    return lines


def print_preflight_report(
    report: PreflightReport,
    *,
    log_path: Path | None = None,
    listeners_ready: bool = False,
    remote: bool = False,
) -> Path | None:
    # Print the check result first, then persist the exact same block.
    preview = preflight_report_lines(
        report,
        listeners_ready=listeners_ready,
        log_written=True,
        remote=remote,
    )
    for line in preview:
        print(line, flush=True)

    persisted = persist_preflight_log(preview, log_path=log_path)
    if persisted is None:
        print(
            "[PREFLIGHT] FAILED - no writable server log; launch gate remains LOCKED.",
            flush=True,
        )
    return persisted


def update_launch_gate_status(
    *,
    ready: bool,
    reason: str | None = None,
    status_path: Path | None = None,
    log_path: Path | None = None,
) -> bool:
    path = _status_target(status_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[PREFLIGHT] cannot update launch gate status: {exc}", flush=True)
        return False

    runtime_errors = [
        str(x) for x in (payload.get("runtime_errors") or []) if str(x).strip()
    ]
    if reason:
        runtime_errors.append(str(reason))

    launch_ready = bool(
        ready
        and payload.get("passed") is True
        and payload.get("log_written") is True
    )
    payload["listeners_ready"] = bool(ready)
    payload["launch_ready"] = launch_ready
    payload["updated_at_unix"] = time.time()
    payload["runtime_errors"] = runtime_errors
    if reason:
        payload["errors"] = list(payload.get("errors") or []) + [str(reason)]

    try:
        _atomic_write_json(path, payload)
    except Exception as exc:
        print(f"[PREFLIGHT] cannot persist launch gate update: {exc}", flush=True)
        return False

    line = (
        "[PREFLIGHT] game launch gate         : "
        + ("UNLOCKED" if launch_ready else "LOCKED")
    )
    if reason:
        line += f" ({reason})"
    print(line, flush=True)
    persisted = persist_preflight_log([line], log_path=log_path)
    return bool(persisted is not None and launch_ready == bool(ready))


def run_server_preflight(
    private_key_path: Path,
    *,
    status_path: Path | None = None,
    log_path: Path | None = None,
) -> bool:
    report = evaluate_preflight(private_key_path=private_key_path)

    persisted_log = print_preflight_report(
        report,
        log_path=log_path,
        listeners_ready=False,
    )
    log_written = persisted_log is not None
    if not log_written:
        report.errors.append(
            "preflight report could not be persisted to a server log"
        )

    try:
        written = write_preflight_status(
            report,
            status_path=status_path,
            listeners_ready=False,
            log_written=log_written,
            log_path=persisted_log,
        )
    except Exception as exc:
        report.errors.append(
            f"could not write launch-gate status; refusing startup: {exc}"
        )
        written = None
        try:
            _status_target(status_path).unlink(missing_ok=True)
        except Exception:
            pass

    if written is not None:
        print(f"[PREFLIGHT] launch-gate status       : {written}", flush=True)

    flags = preflight_check_flags(report)
    return bool(
        report.ok
        and all(flags.values())
        and log_written
        and written is not None
    )


def run_remote_preflight(
    remote_host: str,
    apclient_sha256: str,
    *,
    status_path: Path | None = None,
    log_path: Path | None = None,
    **evaluate_kwargs,
) -> bool:
    remote_host = parse_ipv4_setting("--remote-host", remote_host)
    report = evaluate_preflight(
        private_key_path=None,
        apclient_sha256=apclient_sha256,
        expected_ip=remote_host,
        **evaluate_kwargs,
    )

    persisted_log = print_preflight_report(
        report,
        log_path=log_path,
        listeners_ready=True,
        remote=True,
    )
    log_written = persisted_log is not None
    if not log_written:
        report.errors.append(
            "preflight report could not be persisted to a server log"
        )

    written = write_preflight_status(
        report,
        status_path=status_path,
        listeners_ready=False,
        log_written=log_written,
        log_path=persisted_log,
        remote_host=remote_host,
    )
    print(f"[PREFLIGHT] launch-gate status       : {written}", flush=True)

    flags = preflight_check_flags(report)
    return bool(report.ok and all(flags.values()) and log_written)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Remote client preflight for a friend PC joining a host over Tailscale."
    )
    parser.add_argument("--remote-host", required=True)
    parser.add_argument("--apclient-sha256", required=True)
    args = parser.parse_args()
    try:
        passed = run_remote_preflight(args.remote_host, args.apclient_sha256)
    except Exception as exc:
        print(f"[PREFLIGHT] FAILED - {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2)
    raise SystemExit(0 if passed else 2)
