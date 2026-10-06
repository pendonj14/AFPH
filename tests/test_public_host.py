from __future__ import annotations

import functools
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from server.assaultfire_ds_spawner import SpawnerConfig

ROOT = Path(__file__).resolve().parents[1]

GOLDEN = {
    "dir": "00010101010101010100000000030000001341737361756c742046697265204c6f63616c0000000000000000167463703a2f2f3132372e302e302e313a36353030350000000009312e302e302e3234000000000300000000000000010001000000113132372e302e302e313a36353030353b000000",
    "ping": "82022001000800228b000001000000007f0000010000000a3132372e302e302e310000000000000003e8",
    "zone": "820220000008003e8b0000010100007f0000000a3132372e302e302e3100fdee00000001fffffffe000000010000000000000000000000000000000000000000000000000001",
    "a133": "3243a13300080054010001000000010100007f0000000a3132372e302e302e3100fdee0000000100000001000000114c6f63616c205375626368616e6e656c0000000064000000010000000000000000000000010000000000000000",
    "a356": "3243a3560008002e81000001000100000000000e4c6f63616c204368616e6e656c0000000064000000010100007f0100007f0100007f",
}

BUILD_CODE = r'''
import json
import assaultfire_server_v143b as s

calls = {
    "dir": lambda: s.build_dir_leaf(),
    "ping": lambda: s.tgame_build_geo_pinglist_response(0),
    "zone": lambda: s._v48_build_geo_zonelist(0),
    "a133": lambda: s._v76_build_zone_channel_list_response(),
    "a356": lambda: s._v74_build_main_channel_list_response(),
}
out = {name: fn().hex() for name, fn in calls.items()}
print("RESULT " + json.dumps(out))
'''

LOOPBACK_BYTES = (b"127.0.0.1", bytes.fromhex("0100007f"), bytes.fromhex("7f000001"))


def run_server_code(code: str, public_host: str | None = None) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as td:
        env = os.environ.copy()
        env.pop("AF_PUBLIC_HOST", None)
        env.pop("AF_DS_PUBLIC_HOST", None)
        env.update(
            AF_ACCOUNT_DB=str(Path(td) / "accounts.sqlite3"),
            AF_LOG_PATH=str(Path(td) / "server.log"),
            AF_RUNTIME_MODE="production",
            AF_DEV_WEB="0",
        )
        if public_host is not None:
            env["AF_PUBLIC_HOST"] = public_host
        return subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT / "server",
            env=env, capture_output=True, text=True, timeout=60,
        )


@functools.cache
def build_outputs(public_host: str | None) -> dict:
    proc = run_server_code(BUILD_CODE, public_host)
    if proc.returncode != 0:
        raise RuntimeError(f"server import failed for {public_host!r}: {proc.stdout}{proc.stderr}")
    line = [x for x in proc.stdout.splitlines() if x.startswith("RESULT ")][-1]
    return json.loads(line[len("RESULT "):])


def geo(text: str) -> bytes:
    raw = text.encode("ascii") + b"\x00"
    return struct.pack(">I", len(raw)) + raw


def body_len(packet: bytes) -> int:
    return struct.unpack(">H", packet[6:8])[0]


class PublicHostWireTests(unittest.TestCase):
    HOSTS = ("100.64.1.2", "100.101.102.103")

    def built(self, host: str | None, name: str) -> bytes:
        return bytes.fromhex(build_outputs(host)[name])

    def assert_no_loopback(self, out: bytes, name: str, host: str) -> None:
        for needle in LOOPBACK_BYTES:
            self.assertNotIn(needle, out, f"{name} still carries {needle!r} for {host}")

    def assert_body_len(self, out: bytes, expected: int, name: str, host: str) -> None:
        self.assertEqual(body_len(out), expected, f"{name} BodyLen for {host}")
        self.assertEqual(len(out) - 8, expected, f"{name} actual body length for {host}")

    def test_default_hosts_match_golden(self):
        for host in (None, "127.0.0.1"):
            for name, golden in GOLDEN.items():
                with self.subTest(host=host, builder=name):
                    self.assertEqual(self.built(host, name).hex(), golden)

    def test_dir_leaf_advertises_host(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                out = self.built(host, "dir")
                self.assertIn(geo(f"tcp://{host}:65005"), out)
                self.assertIn(geo(f"{host}:65005;"), out)
                self.assert_no_loopback(out, "dir", host)

    def test_pinglist_advertises_host(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                out = self.built(host, "ping")
                self.assertIn(socket.inet_aton(host) + geo(host), out)
                self.assert_body_len(out, 8 + 12 + len(geo(host)), "ping", host)
                self.assert_no_loopback(out, "ping", host)

    def test_zonelist_advertises_host(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                out = self.built(host, "zone")
                self.assertIn(socket.inet_aton(host)[::-1] + geo(host), out)
                self.assert_body_len(out, 48 + len(geo(host)), "zone", host)
                self.assert_no_loopback(out, "zone", host)

    def test_zone_channel_list_advertises_host(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                out = self.built(host, "a133")
                self.assertIn(socket.inet_aton(host)[::-1] + geo(host), out)
                self.assert_body_len(out, 70 + len(geo(host)), "a133", host)
                self.assert_no_loopback(out, "a133", host)

    def test_main_channel_list_advertises_host(self):
        for host in self.HOSTS:
            with self.subTest(host=host):
                out = self.built(host, "a356")
                self.assertIn(socket.inet_aton(host)[::-1] * 3, out)
                self.assert_body_len(out, 46, "a356", host)
                self.assert_no_loopback(out, "a356", host)

    def test_tailscale_host_literal_byte_order(self):
        host = "100.64.1.2"
        with self.subTest(builder="ping"):
            self.assertIn(bytes.fromhex("64400102"), self.built(host, "ping"))
        for name in ("zone", "a133", "a356"):
            with self.subTest(builder=name):
                self.assertIn(bytes.fromhex("02014064"), self.built(host, name))


class PublicHostValidationTests(unittest.TestCase):
    def test_invalid_host_stops_server_import(self):
        for value in ("not-an-ip", "127.1"):
            with self.subTest(value=value):
                proc = run_server_code("import assaultfire_server_v143b", value)
                output = proc.stdout + proc.stderr
                self.assertNotEqual(proc.returncode, 0, f"import accepted AF_PUBLIC_HOST={value!r}")
                self.assertIn("[CONFIG] AF_PUBLIC_HOST", output)
                self.assertIn(value, output)
                self.assertNotIn("Traceback", output)


class SpawnerPublicHostTests(unittest.TestCase):
    CASES = (
        ({}, "127.0.0.1"),
        ({"AF_PUBLIC_HOST": "100.64.1.2"}, "100.64.1.2"),
        ({"AF_PUBLIC_HOST": "100.64.1.2", "AF_DS_PUBLIC_HOST": "100.64.9.9"}, "100.64.9.9"),
        ({"AF_PUBLIC_HOST": ""}, "127.0.0.1"),
        ({"AF_PUBLIC_HOST": " 100.64.1.2 "}, "100.64.1.2"),
        ({"AF_DS_PUBLIC_HOST": "  ", "AF_PUBLIC_HOST": "100.64.1.2"}, "100.64.1.2"),
    )

    def test_precedence(self):
        for env, want in self.CASES:
            with self.subTest(env=env), mock.patch.dict(os.environ):
                os.environ.pop("AF_PUBLIC_HOST", None)
                os.environ.pop("AF_DS_PUBLIC_HOST", None)
                os.environ.update(env)
                self.assertEqual(SpawnerConfig.from_env().public_host, want)


class PublicHostSourcePinTests(unittest.TestCase):
    def test_pinglist_size_assert_is_not_gated_on_default_host(self):
        source = (ROOT / "server" / "assaultfire_server_v143b.py").read_text(encoding="utf-8")
        needle = 'PUBLIC_HOST == "127.0.0.1" and ('
        self.assertFalse(needle in source, f"{needle!r} still in assaultfire_server_v143b.py")

    def test_handoff_host_reads_spawner_config(self):
        source = (ROOT / "server" / "assaultfire_server_v143b.py").read_text(encoding="utf-8")
        want = "handoff_host = V143B_DS_CONFIG.public_host"
        stale = "handoff_host = PUBLIC_HOST"
        self.assertTrue(want in source, f"{want!r} missing from assaultfire_server_v143b.py")
        self.assertFalse(stale in source, f"{stale!r} still in assaultfire_server_v143b.py")


if __name__ == "__main__":
    unittest.main()
