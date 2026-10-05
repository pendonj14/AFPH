from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from server.assaultfire_ds_spawner import (
    DedicatedServerSpawner,
    SpawnerConfig,
    resolve_room_target,
)


class SpawnerFixTests(unittest.TestCase):
    def make(self, td):
        spawner = DedicatedServerSpawner(SpawnerConfig(
            enabled=True, max_instances=1, public_port_base=0, target_port_base=0,
            runtime_dir=Path(td) / "runtime", create_cooldown=0,
            bridge_script=Path(td) / "missing_bridge.py",
        ))
        self.addCleanup(spawner.shutdown_all)
        return spawner

    def test_unarmed_release_ignores_stale_pid_file(self):
        with tempfile.TemporaryDirectory() as td:
            spawner = self.make(td)
            a = spawner.reserve_lobby(owner_id=1, mode_id=0x2001, map_id=0x2F)
            sleeper = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
            try:
                inst = Path(td) / "runtime" / a.instance_id
                inst.mkdir(parents=True, exist_ok=True)
                (inst / "AFDEV_PID.txt").write_text(str(sleeper.pid))
                spawner.release_lobby(a.room_id)
                self.assertIsNone(sleeper.poll())
            finally:
                sleeper.kill()
                sleeper.wait()

    def test_arm_lobby_accepts_afdev_ready(self):
        with tempfile.TemporaryDirectory() as td:
            spawner = self.make(td)
            a = spawner.reserve_lobby(owner_id=1, mode_id=0x2001, map_id=0x2F)
            a.state = "AFDEV_READY"
            a.bridge_proc = object()
            try:
                self.assertIs(spawner.arm_lobby(a.room_id), a)
            finally:
                a.bridge_proc = None

    def test_resolver_family_and_routes(self):
        self.assertEqual(resolve_room_target(0x2001, 0x2F, "Bio2-Maya_7_Main"),
                         ("SV-Maya_3_Main", "PVEGame.TGSVGame"))
        self.assertEqual(resolve_room_target(0x2001, 0x2F, "SV-Factory_1_Main")[0],
                         "SV-Factory_1_Main")
        self.assertEqual(resolve_room_target(0x20B, 26, "", sub_mode_id=0x206),
                         ("TDB-Tank_02_Main", "TGTankGame.TGTankDBMatch"))
        self.assertEqual(resolve_room_target(0x2002, 0x5F),
                         ("IF2-Factory_83_Main", "TGIFGame.TGIF2Game"))

    def test_failed_bridge_exit_ends_round(self):
        with tempfile.TemporaryDirectory() as td:
            spawner = self.make(td)
            a = spawner.reserve_lobby(owner_id=1, mode_id=0x2001, map_id=0x2F)
            proc = subprocess.Popen([sys.executable, "-c", "pass"])
            proc.wait()
            a.bridge_proc = proc
            a.state = "ARMED"
            spawner._monitor_bridge(a)
            self.assertEqual(a.state, "ROUND_ENDED")

    def test_end_round_only_if_idle(self):
        with tempfile.TemporaryDirectory() as td:
            spawner = self.make(td)
            a = spawner.reserve_lobby(owner_id=1, mode_id=0x2001, map_id=0x2F)
            a.state = "READY"
            a.match_players = {2}
            self.assertFalse(spawner.end_round(a.room_id, only_if_idle=True))
            self.assertEqual(a.state, "READY")

    def test_udp_port_out_of_range_is_unavailable(self):
        self.assertFalse(DedicatedServerSpawner._udp_port_available("127.0.0.1", 70000))

    def test_room_id_api(self):
        with tempfile.TemporaryDirectory() as td:
            spawner = self.make(td)
            spawner.seed_room_ids(7)
            self.assertEqual(spawner.new_room_id(), 8)
            a = spawner.reserve_lobby(owner_id=5, room_id=20, mode_id=0x2001, map_id=0x2F)
            self.assertEqual(a.room_id, 20)
            self.assertEqual(spawner.new_room_id(), 21)


if __name__ == "__main__":
    unittest.main()
