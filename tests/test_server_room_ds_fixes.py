from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run_server_code(code: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as td:
        env = os.environ.copy()
        env.update(
            AF_ACCOUNT_DB=str(Path(td) / "accounts.sqlite3"),
            AF_RUNTIME_MODE="production",
            AF_DEV_WEB="0",
            AF_DS_RUNTIME_DIR=str(Path(td) / "ds_runtime"),
            AF_DS_PUBLIC_PORT_BASE="0",
            AF_DS_TARGET_PORT_BASE="0",
            AF_DS_CREATE_COOLDOWN="0",
            AF_DS_SPAWNER_ENABLED="1",
        )
        return subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT / "server",
            env=env, capture_output=True, text=True, timeout=60,
        )


class ServerRoomDsFixesTests(unittest.TestCase):
    def test_restored_room_gets_lazy_reservation_and_non_ds_mode_skips(self):
        code = r'''
import assaultfire_server_v143b as s
sp = s._v143b_init_spawner()
try:
    s.V150_ROOM_REGISTRY.create_room({
        "room_id": 7, "name": "r", "mode_id": 0x2001, "map_id": 0x2F,
        "sub_mode_id": 0x1001, "flags": 0x3008, "fighter_capacity": 4,
        "observer_capacity": 0, "map_string": "",
    }, owner_uin=10001, owner_name="Owner")
    sp.seed_room_ids(7)
    assert sp.new_room_id() == 8
    room = s.V150_ROOM_REGISTRY.get_room(7)
    alloc = s._v143b_ensure_room_ds(room)
    assert alloc is not None and alloc.room_id == 7, alloc
    assert alloc.map_name == "SV-Maya_3_Main", alloc.map_name
    assert s._v143b_ensure_room_ds(room) is alloc
    assert 0x201 not in s.AFDEV_MODE_IDS
    assert s._v143b_reserve_room_ds({"uin": 10002}, {"mode_id": 0x201}) is None
    print("OK")
finally:
    sp.shutdown_all()
'''
        result = run_server_code(code)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_start_room_alloc_parses_map_string_and_empty_capture(self):
        code = r'''
import struct
import assaultfire_server_v143b as s

def body(map_string, sub, flags):
    raw = map_string.encode() + b"\0"
    out = struct.pack(">QIH", 10001, 0x2001, 7) + struct.pack(">I", len(raw)) + raw
    out += struct.pack(">II", sub, flags)
    out = out.ljust(8 + 32 + len(raw) - 1, b"\0")
    return out + bytes([1, 1]) + struct.pack(">I", 7)

r = s._v72_parse_start_room_alloc(body("SV-Factory_1_Main", 0x1003, 0x3008))
assert r["sub_mode_id"] == 0x1003 and r["room_flags"] == 0x3008, r
assert r["maps"] == [7] and r["map_string"] == "SV-Factory_1_Main", r
assert r["hard_level"] == 1 and r["map_count"] == 1 and r["tail"] == b"", r

old = body("", 0x1001, 0x3008)
assert len(old) == 46, len(old)
r = s._v72_parse_start_room_alloc(old)
assert r["sub_mode_id"] == 0x1001 and r["room_flags"] == 0x3008, r
assert r["match"][11:15] == struct.pack(">I", 0x1001) and r["maps"] == [7], r
assert r["map_string"] == "" and r["consumed"] == 46, r
print("OK")
'''
        result = run_server_code(code)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
