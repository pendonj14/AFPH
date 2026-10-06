from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import assaultfire_preflight as preflight


class StartupPreflightTests(unittest.TestCase):
    def build_fixture(self, tmp: Path):
        client_root = tmp / "AF"
        tcls_dir = client_root / "TCLS" / "Tenio"
        config_dir = client_root / "TCLS" / "config"
        tcls_dir.mkdir(parents=True)
        config_dir.mkdir(parents=True)

        tcls_bytes = b"validated-test-tcls"
        tcls_path = tcls_dir / "TCLS.dll"
        tcls_path.write_bytes(tcls_bytes)
        validated_hash = hashlib.sha256(tcls_bytes).hexdigest()

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        private_path = tmp / "PRIVATE.PEM"
        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (config_dir / "APClient.dat").write_bytes(public_pem)

        hosts_path = tmp / "hosts"
        hosts_path.write_text(
            "\n".join(
                f"127.0.0.1 {name}" for name in preflight.REQUIRED_HOSTS
            ) + "\n",
            encoding="utf-8",
        )
        return client_root, private_path, hosts_path, validated_hash, public_pem

    def test_all_required_checks_pass(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            self.assertTrue(report.ok, report.errors)
            self.assertTrue(report.key_check.exact_bytes_match)
            self.assertTrue(report.key_check.same_rsa_key)
            self.assertEqual(report.key_check.rsa_key_size, 1024)
            self.assertEqual(report.key_check.apclient_length, 272)

    def test_same_rsa_key_is_not_enough_when_bytes_differ(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, public_pem = data
            apclient = client_root / "TCLS" / "config" / "APClient.dat"
            apclient.write_bytes(public_pem.replace(b"\n", b"\r\n"))
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            self.assertFalse(report.ok)
            self.assertFalse(report.key_check.exact_bytes_match)
            self.assertTrue(report.key_check.same_rsa_key)

    def test_bad_hosts_mapping_blocks_preflight(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            hosts_path.write_text(
                "127.0.0.1 tversion.levelupgames.ph\n"
                "10.0.0.5 tauthproxy.levelupgames.ph\n"
                "127.0.0.1 tdir.levelupgames.ph\n",
                encoding="utf-8",
            )
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda name: "10.0.0.5" if name.startswith("tauth") else "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            self.assertFalse(report.ok)
            self.assertTrue(any("tauthproxy.levelupgames.ph" in e for e in report.errors))

    def test_failed_preflight_is_written_to_server_log(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            report = preflight.evaluate_preflight(
                private_key_path=tmp / "PRIVATE.PEM",
                env={},
            )
            lines = preflight.preflight_report_lines(report)
            joined = "\n".join(lines)
            self.assertIn("[PREFLIGHT] client root             : None", joined)
            self.assertIn("[PREFLIGHT] TCLS validated build    : NO", joined)
            self.assertIn("[PREFLIGHT] APClient exact bytes    : NO", joined)
            self.assertIn("[PREFLIGHT] same RSA key            : NO", joined)
            self.assertIn("[PREFLIGHT] game launch gate         : LOCKED", joined)

            log_path = tmp / "af_server_live.log"
            preflight.print_preflight_report(report, log_path=log_path)
            logged = log_path.read_text(encoding="utf-8")
            self.assertIn("[PREFLIGHT] client root             : None", logged)
            self.assertIn("[PREFLIGHT] TCLS validated build    : NO", logged)
            self.assertIn("[PREFLIGHT] APClient exact bytes    : NO", logged)
            self.assertIn("[PREFLIGHT] same RSA key            : NO", logged)
            self.assertIn("[PREFLIGHT] game launch gate         : LOCKED", logged)

    def test_status_payload_contains_launch_gate_checks(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            status_path = Path(td) / "runtime" / "preflight_status.json"
            written = preflight.write_preflight_status(
                report,
                status_path,
                listeners_ready=True,
                log_written=True,
                log_path=Path(td) / "af_server_live.log",
            )
            self.assertEqual(written, status_path.resolve())

            import json
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertTrue(status["passed"])
            self.assertTrue(status["checks"]["client_root"])
            self.assertTrue(status["checks"]["tcls_validated_build"])
            self.assertTrue(status["checks"]["apclient_exact_bytes"])
            self.assertTrue(status["checks"]["same_rsa_key"])
            self.assertTrue(status["checks"]["hosts"])
            self.assertTrue(status["listeners_ready"])
            self.assertTrue(status["log_written"])
            self.assertTrue(status["launch_ready"])

    def test_non_rsa_public_key_never_reports_same_rsa_key(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, _hosts_path, _validated_hash, _ = data
            ec_private = ec.generate_private_key(ec.SECP256R1())
            ec_public = ec_private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            apclient = client_root / "TCLS" / "config" / "APClient.dat"
            apclient.write_bytes(ec_public)
            check = preflight.check_key_pair(private_path, apclient)
            self.assertFalse(check.same_rsa_key)

    def test_listener_gate_starts_locked_until_bind_success(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            status_path = Path(td) / "preflight_status.json"
            log_path = Path(td) / "server.log"
            preflight.write_preflight_status(
                report,
                status_path,
                listeners_ready=False,
                log_written=True,
                log_path=log_path,
            )
            import json
            before = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertTrue(before["passed"])
            self.assertFalse(before["launch_ready"])

    def test_preflight_log_falls_back_when_requested_path_is_unwritable(self):
        with tempfile.TemporaryDirectory() as td:
            requested = Path(td) / "bad" / "custom.log"
            calls = []

            def fake_append(lines, path):
                calls.append(path)
                if path == requested.resolve():
                    raise OSError("simulated write failure")
                return True

            with mock.patch.object(preflight, "_append_lines_to_log", side_effect=fake_append):
                written = preflight.persist_preflight_log(
                    ["[PREFLIGHT] test"],
                    log_path=requested,
                )

            self.assertIsNotNone(written)
            self.assertEqual(written, Path(preflight.__file__).resolve().with_name("af_server_live.log"))
            self.assertGreaterEqual(len(calls), 2)

    def test_launch_gate_unlocks_only_after_listener_ready_update(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            status_path = Path(td) / "preflight_status.json"
            log_path = Path(td) / "server.log"
            preflight.write_preflight_status(
                report,
                status_path,
                listeners_ready=False,
                log_written=True,
                log_path=log_path,
            )
            self.assertTrue(
                preflight.update_launch_gate_status(
                    ready=True,
                    status_path=status_path,
                    log_path=log_path,
                )
            )
            import json
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertTrue(status["listeners_ready"])
            self.assertTrue(status["launch_ready"])

    def test_server_calls_preflight_before_listener_threads(self):
        server = (ROOT / "server" / "assaultfire_server_v143b.py").read_text(
            encoding="utf-8", errors="replace"
        )
        main = server.index('if __name__ == "__main__":')
        gate = server.index("run_server_preflight(Path(PRIVATE_KEY_PATH))", main)
        spawner = server.index("_v143b_init_spawner()", gate)
        prebind = server.index("_prepare_listener_sockets()", spawner)
        unlock = server.index("update_launch_gate_status(ready=True)", prebind)
        listener = server.index("threading.Thread(", unlock)
        self.assertLess(gate, spawner)
        self.assertLess(spawner, prebind)
        self.assertLess(prebind, unlock)
        self.assertLess(unlock, listener)

    def test_parse_ipv4_setting_defaults_to_loopback_when_unset_or_blank(self):
        for value in (None, "", "  "):
            with self.subTest(value=value):
                self.assertEqual(
                    preflight.parse_ipv4_setting("AF_PUBLIC_HOST", value),
                    "127.0.0.1",
                )

    def test_parse_ipv4_setting_returns_stripped_valid_address(self):
        for value in ("100.64.1.2", " 100.64.1.2 "):
            with self.subTest(value=value):
                self.assertEqual(
                    preflight.parse_ipv4_setting("AF_PUBLIC_HOST", value),
                    "100.64.1.2",
                )

    def test_parse_ipv4_setting_rejects_non_ipv4_naming_setting_and_value(self):
        for value in ("not-an-ip", "127.1", "01.2.3.4", "::1", "tdir.levelupgames.ph"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as ctx:
                    preflight.parse_ipv4_setting("AF_PUBLIC_HOST", value)
                self.assertIn("AF_PUBLIC_HOST", str(ctx.exception))
                self.assertIn(repr(value), str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
