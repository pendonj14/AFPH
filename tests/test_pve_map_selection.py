from pathlib import Path
import tempfile
import unittest

from server.assaultfire_ds_spawner import (
    AFDEV_MODE_IDS,
    ROOM_TARGETS,
    DedicatedServerSpawner,
    SpawnerConfig,
    SpawnerError,
    resolve_room_target,
)

ROOT = Path(__file__).resolve().parents[1]


class PVEMapSelectionTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")

    def test_client_map_is_enabled_by_default(self):
        server = self.text("server/assaultfire_server_v143b.py")
        self.assertIn('AF_DS_USE_CLIENT_MAP", "1"', server)
        self.assertIn('client_map = str(create_req.get("map_string") or "").strip()', server)

    def test_a10a_seeds_full_ds_settings(self):
        server = self.text("server/assaultfire_server_v143b.py")
        for marker in (
            'map_name=map_name',
            'mode_id=int(create_req.get("mode_id", 0x00002001))',
            'map_id=int(create_req.get("map_id", 0x002F))',
            'sub_mode_id=int(create_req.get("sub_mode_id", 0x00001001))',
            'room_flags=int(create_req.get("flags", 0x00003008))',
        ):
            self.assertIn(marker, server)

    def test_a11e_updates_reserved_map_before_lazy_spawn(self):
        server = self.text("server/assaultfire_server_v143b.py")
        spawner = self.text("server/assaultfire_ds_spawner.py")
        self.assertIn('map_name=settings.get("map_string") or None', server)
        self.assertIn('map_name: Optional[str] = None', spawner)
        self.assertIn('resolve_room_target(', spawner)
        self.assertIn('"--map", allocation.map_name', spawner)
        self.assertIn('"--game", allocation.game_class', spawner)

    def test_start_room_alloc_replaces_stale_owner_map_before_spawning(self):
        with tempfile.TemporaryDirectory() as td:
            config = SpawnerConfig(
                enabled=True,
                max_instances=1,
                public_port_base=0,
                target_port_base=0,
                default_map="SV-Maya_3_Main",
                runtime_dir=Path(td) / "runtime",
                create_cooldown=0,
            )
            spawner = DedicatedServerSpawner(config)
            stale = spawner.reserve_lobby(
                owner_id=10001,
                map_name="SV-Maya_3_Main",
                mode_id=0x00002001,
                map_id=0x002F,
            )
            try:
                allocation = spawner.prepare_lobby_for_match(
                    owner_id=10001,
                    owner_nickname="LocalPlayer",
                    room_id=stale.room_id,
                    mode_id=0x00002001,
                    map_id=0x0007,
                    sub_mode_id=0x00001001,
                    room_flags=0x00003008,
                )
                self.assertEqual(allocation.room_id, stale.room_id)
                self.assertEqual(allocation.map_id, 0x0007)
                self.assertEqual(allocation.map_name, "SV-Factory_1_Main")
                self.assertEqual(allocation.game_class, "PVEGame.TGSVGame")
            finally:
                spawner.shutdown_all()

            new_spawner = DedicatedServerSpawner(
                SpawnerConfig(
                    enabled=True,
                    max_instances=1,
                    public_port_base=0,
                    target_port_base=0,
                    default_map="SV-Maya_3_Main",
                    runtime_dir=Path(td) / "new-runtime",
                    create_cooldown=0,
                )
            )
            try:
                new_owner_allocation = new_spawner.prepare_lobby_for_match(
                    owner_id=10002,
                    mode_id=0x00002001,
                    map_id=0x0007,
                    sub_mode_id=0x00001001,
                    room_flags=0x00003008,
                )
                self.assertEqual(new_owner_allocation.map_name, "SV-Factory_1_Main")
                self.assertEqual(new_owner_allocation.map_id, 0x0007)
            finally:
                new_spawner.shutdown_all()

    def test_start_room_alloc_handoff_uses_parsed_selection_and_authoritative_room(self):
        server = self.text("server/assaultfire_server_v143b.py")
        parser_start = server.index("def _v72_parse_start_room_alloc(")
        parser_end = server.index("def _v72_build_enter_room_alloc_success(", parser_start)
        parser = server[parser_start:parser_end]
        self.assertIn('struct.unpack_from(">I", match, 11)[0]', parser)
        self.assertIn('struct.unpack_from(">I", match, 15)[0]', parser)
        self.assertIn('"sub_mode_id": sub_mode_id', parser)
        self.assertIn('"room_flags": room_flags', parser)

        handler_start = server.index('elif app["cmd"] == TGAME_ZN_REQ_STARTROOMALLOC:')
        handler_end = server.index(
            'elif app["cmd"] == TGAME_ZN_REQ_CHANGE_NICKNAME:', handler_start
        )
        handler = server[handler_start:handler_end]
        self.assertIn("room=allocation_room", handler)
        self.assertIn("start_settings=ra", handler)

        handoff_start = server.index("def _v132_send_pve_afdev_handoff(")
        handoff_end = server.index("def _latejoin_v2_send_running_match_a11a(", handoff_start)
        handoff = server[handoff_start:handoff_end]
        self.assertIn("V143B_DS_SPAWNER.prepare_lobby_for_match(", handoff)
        self.assertIn('start_settings.get("match_map_id")', handoff)
        self.assertIn('room_for_handoff.get("map_id")', handoff)

        startmatch_start = server.index(
            'elif app["cmd"] == TGAME_ZN_REQ_STARTMATCH:'
        )
        startmatch_end = server.index(
            'elif app["cmd"] == TGAME_ZN_REQ_JOINMATCH:', startmatch_start
        )
        startmatch_handler = server[startmatch_start:startmatch_end]
        self.assertIn("room=room_for_start", startmatch_handler)

    def test_start_room_alloc_does_not_rewrite_an_active_server_map(self):
        with tempfile.TemporaryDirectory() as td:
            config = SpawnerConfig(
                enabled=True,
                max_instances=1,
                runtime_dir=Path(td) / "runtime",
                create_cooldown=0,
            )
            spawner = DedicatedServerSpawner(config)
            existing = spawner.reserve_lobby(
                owner_id=10001,
                map_name="SV-Maya_3_Main",
                mode_id=0x00002001,
                map_id=0x002F,
            )
            existing.state = "READY"
            try:
                with self.assertRaises(SpawnerError):
                    spawner.prepare_lobby_for_match(
                        owner_id=10001,
                        room_id=existing.room_id,
                        mode_id=0x00002001,
                        map_id=0x0007,
                        sub_mode_id=0x00001001,
                        room_flags=0x00003008,
                    )
                self.assertEqual(existing.map_id, 0x002F)
                self.assertEqual(existing.map_name, "SV-Maya_3_Main")
            finally:
                spawner.shutdown_all()

    def test_defense_steel_forest_empty_mapstring_uses_verified_target(self):
        self.assertIn(0x00002002, AFDEV_MODE_IDS)
        self.assertEqual(
            ROOM_TARGETS[(0x00002002, 0x0010)],
            ("IF-Factory_3_Main", "PVEGame.TGIFGame"),
        )
        self.assertEqual(
            resolve_room_target(0x00002002, 0x0010, "", "PVEGame.TGSVGame"),
            ("IF-Factory_3_Main", "PVEGame.TGIFGame"),
        )

    def test_server_routes_verified_afdev_modes_without_dead_legacy_fallback(self):
        server = self.text("server/assaultfire_server_v143b.py")
        self.assertIn("TGAME_AFDEV_MODE_IDS = frozenset(AFDEV_MODE_IDS)", server)
        self.assertIn("mode_now not in TGAME_AFDEV_MODE_IDS", server)
        self.assertNotIn("ZN2C_NTF_STARTMATCH legacy-non-PVE", server)

    def test_afdev_loader_accepts_defense_settings_family(self):
        loader = self.text(
            "tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py"
        )
        self.assertIn('0x00002001: "Survival"', loader)
        self.assertIn('0x00002002: "Defense"', loader)
        self.assertIn("unsupported AFDEV ModeId", loader)
        self.assertNotIn(
            'PvE loader expected ModeId 0x2001',
            loader,
        )

    def test_defense_does_not_require_survival_gri_difficulty_field(self):
        loader = self.text(
            "tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py"
        )
        self.assertIn(
            "if mode_id == 0x00002001:",
            loader,
        )
        self.assertIn(
            "Defense GRI difficulty write skipped",
            loader,
        )
        self.assertIn(
            '"difficulty_applied": difficulty_applied',
            loader,
        )



if __name__ == "__main__":
    unittest.main()
