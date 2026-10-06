#!/usr/bin/env python3
"""Shared launch gate for Assault Fire PH compatibility helpers."""
from __future__ import annotations

import ctypes
import json
import ntpath
import os
import subprocess
from pathlib import Path
from typing import Callable, Mapping

PREFLIGHT_STATUS_SCHEMA = 2
REQUIRED_CHECKS = (
    "client_root",
    "tcls_validated_build",
    "apclient_exact_bytes",
    "same_rsa_key",
    "rsa_1024",
    "apclient_272_bytes",
    "hosts",
)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
REQUIRED_TCP_PORTS = (9060, 8000, 9010, 65005, 65006)


class LaunchGateError(RuntimeError):
    pass


def default_status_path() -> Path:
    override = (os.environ.get("AF_PREFLIGHT_STATUS_PATH") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "runtime" / "preflight_status.json"


def load_status(path: Path | None = None) -> tuple[dict, Path]:
    target = (
        Path(path).expanduser().resolve()
        if path is not None
        else default_status_path()
    )
    if not target.is_file():
        raise LaunchGateError(
            "server preflight status is missing. Start "
            "server/assaultfire_server_v143b.py first and fix every "
            "[PREFLIGHT] failure before launching the game. "
            f"Expected status: {target}"
        )
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:
        raise LaunchGateError(
            f"server preflight status is unreadable: {target}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise LaunchGateError(f"invalid server preflight status format: {target}")
    return data, target


def _windows_pid_alive(pid: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return False
    try:
        code = ctypes.c_uint32(0)
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return int(code.value) == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def default_pid_alive(pid: int) -> bool:
    if int(pid) <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(int(pid))
    try:
        os.kill(int(pid), 0)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    return True


def default_listening_ports(pid: int) -> set[int]:
    """Return TCP LISTENING ports owned by pid without opening probe connections."""
    if os.name != "nt":
        return set()
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return set()

    out: set[int] = set()
    for raw in proc.stdout.splitlines():
        parts = raw.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        # Do not depend on the localized Windows state word ("LISTENING").
        # A TCP listening row has an unspecified foreign endpoint with port 0.
        foreign = parts[2]
        if not foreign.endswith(":0"):
            continue
        try:
            owner = int(parts[-1])
        except ValueError:
            continue
        if owner != int(pid):
            continue
        local = parts[1].rsplit(":", 1)
        if len(local) != 2:
            continue
        try:
            out.add(int(local[1]))
        except ValueError:
            continue
    return out


def validate_status(
    data: Mapping,
    *,
    pid_alive: Callable[[int], bool] = default_pid_alive,
    listening_ports: Callable[[int], set[int]] = default_listening_ports,
) -> list[str]:
    errors: list[str] = []
    remote = data.get("mode") == "remote"

    if data.get("schema") != PREFLIGHT_STATUS_SCHEMA:
        errors.append(
            f"unsupported preflight status schema {data.get('schema')!r}; "
            f"expected {PREFLIGHT_STATUS_SCHEMA}"
        )

    checks = data.get("checks")
    if not isinstance(checks, Mapping):
        checks = {}
        errors.append("preflight status has no checks map")

    failed = [name for name in REQUIRED_CHECKS if checks.get(name) is not True]
    if failed:
        errors.append("required checks are not PASS: " + ", ".join(failed))

    if data.get("passed") is not True:
        errors.append("server preflight result is FAILED")
    if data.get("log_written") is not True:
        errors.append("server preflight report was not persisted to the server log")
    if not remote and data.get("listeners_ready") is not True:
        errors.append("server listener startup is not complete")
    if data.get("launch_ready") is not True:
        errors.append("game launch gate is LOCKED")

    if not remote:
        server_pid = data.get("server_pid")
        try:
            server_pid = int(server_pid)
        except (TypeError, ValueError):
            server_pid = 0
        server_alive = bool(server_pid and pid_alive(server_pid))
        if not server_alive:
            errors.append(
                f"server process from preflight is not running (PID={server_pid or 'missing'})"
            )
        elif os.name == "nt":
            owned_ports = set(listening_ports(server_pid))
            missing_ports = [port for port in REQUIRED_TCP_PORTS if port not in owned_ports]
            if missing_ports:
                errors.append(
                    "server core listeners are not ready under the preflight PID; "
                    "missing TCP port(s): " + ", ".join(str(p) for p in missing_ports)
                )

    if not data.get("client_root"):
        errors.append("preflight client root is missing")
    if not data.get("tcls_path"):
        errors.append("preflight TCLS path is missing")

    for item in data.get("errors") or []:
        msg = str(item).strip()
        if msg and msg not in errors:
            errors.append(msg)

    return errors


def require_launch_ready(
    path: Path | None = None,
    *,
    pid_alive: Callable[[int], bool] = default_pid_alive,
    listening_ports: Callable[[int], set[int]] = default_listening_ports,
) -> dict:
    data, target = load_status(path)
    errors = validate_status(
        data,
        pid_alive=pid_alive,
        listening_ports=listening_ports,
    )
    if errors:
        detail = "\n".join(f"  - {item}" for item in errors)
        raise LaunchGateError(
            "GAME LAUNCH BLOCKED: server preflight has not passed.\n"
            f"Status: {target}\n"
            f"{detail}\n"
            + (
                "Re-run START_ASSAULT_FIRE.ps1 -RemoteHost <host> -ApClientSha256 <hash> and do not continue until every "
                if data.get("mode") == "remote"
                else "Start/restart the server and do not continue until every "
            )
            + "required [PREFLIGHT] check passes and 'game launch gate : UNLOCKED'."
        )
    return data


def _device_path_to_dos_path(
    value: str, *, device_map: Mapping[str, str] | None = None
) -> str:
    """Translate GetMappedFileNameW \\Device\\... paths to a drive-letter path."""
    raw = str(value)
    if not raw.lower().startswith("\\device\\"):
        return raw

    if device_map is None:
        if os.name != "nt":
            return raw
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.QueryDosDeviceW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        kernel32.QueryDosDeviceW.restype = ctypes.c_uint32
        device_map = {}
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:"
            buf = ctypes.create_unicode_buffer(4096)
            if not kernel32.QueryDosDeviceW(drive, buf, len(buf)):
                continue
            # QueryDosDevice returns multiple NUL-separated targets; the
            # ctypes buffer exposes the first mapping, which is sufficient.
            device_map[drive] = buf.value.split("\0", 1)[0]

    for drive, mapped_device in device_map.items():
        device = str(mapped_device).rstrip("\\")
        if not device:
            continue
        if raw.lower() == device.lower():
            return str(drive)
        prefix = device + "\\"
        if raw.lower().startswith(prefix.lower()):
            return str(drive) + raw[len(device):]
    return raw


def _normalized_windows_path(value: str | os.PathLike[str]) -> str:
    raw = _device_path_to_dos_path(os.fspath(value))
    # The compared paths always identify Windows client files. Use Windows
    # path semantics even when unit tests run on a non-Windows host.
    return ntpath.normcase(ntpath.abspath(raw))


def require_loaded_tcls_matches(status: Mapping, loaded_tcls_path: str) -> None:
    expected = status.get("tcls_path")
    if not expected:
        raise LaunchGateError("GAME LAUNCH BLOCKED: preflight TCLS path is missing")
    if _normalized_windows_path(str(expected)) != _normalized_windows_path(loaded_tcls_path):
        raise LaunchGateError(
            "GAME LAUNCH BLOCKED: client.exe loaded a different TCLS.dll than "
            "the one that passed server preflight.\n"
            f"  preflight: {expected}\n"
            f"  loaded   : {loaded_tcls_path}\n"
            "Set AF_CLIENT_ROOT to the client you are actually launching, "
            "restart the server, and wait for preflight PASS."
        )


def expected_tgame_path(
    status: Mapping, *, device_map: Mapping[str, str] | None = None
) -> str:
    root = status.get("client_root")
    if not root:
        raise LaunchGateError("GAME LAUNCH BLOCKED: preflight client root is missing")
    normalized_root = _device_path_to_dos_path(str(root), device_map=device_map)
    if normalized_root.lower().startswith("\\device\\"):
        raise LaunchGateError(
            "GAME LAUNCH BLOCKED: Windows returned a device path for the client root, "
            "but it could not be mapped to a drive letter. Check that the game is "
            "installed on a mounted local drive and restart the launcher."
        )
    if os.name == "nt" or ntpath.splitdrive(normalized_root)[0]:
        return ntpath.join(normalized_root, "Binaries", "Win32", "TGame.exe")
    return os.fspath(Path(normalized_root) / "Binaries" / "Win32" / "TGame.exe")


def require_game_image_matches(status: Mapping, loaded_tgame_path: str) -> None:
    expected = expected_tgame_path(status)
    if _normalized_windows_path(expected) != _normalized_windows_path(loaded_tgame_path):
        raise LaunchGateError(
            "GAME LAUNCH BLOCKED: TGame.exe belongs to a different client than "
            "the one that passed server preflight.\n"
            f"  expected : {expected}\n"
            f"  loaded   : {loaded_tgame_path}\n"
            "Close the other TGame/client copy, set AF_CLIENT_ROOT to the client "
            "you are actually launching, restart the server, and retry."
        )
