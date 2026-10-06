from pathlib import Path
import hashlib
import json
import os
import subprocess
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
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AF_PUBLIC_HOST", None)

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

    def test_expected_ip_accepts_hosts_and_resolver_at_that_address(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            hosts_path.write_text(
                "\n".join(
                    f"100.64.1.2 {name}" for name in preflight.REQUIRED_HOSTS
                ) + "\n",
                encoding="utf-8",
            )
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "100.64.1.2",
                validated_tcls_sha256=validated_hash,
                expected_ip="100.64.1.2",
            )
            self.assertTrue(report.ok, report.errors)
            self.assertTrue(preflight.preflight_check_flags(report)["hosts"])
            host_lines = [
                line
                for line in preflight.preflight_report_lines(report)
                if "[PREFLIGHT] hosts " in line and ".levelupgames.ph" in line
            ]
            self.assertEqual(len(host_lines), len(preflight.REQUIRED_HOSTS))
            for line in host_lines:
                self.assertIn(": YES (", line)

    def test_expected_ip_rejects_loopback_hosts_and_names_expected_address(self):
        with tempfile.TemporaryDirectory() as td:
            data = self.build_fixture(Path(td))
            client_root, private_path, hosts_path, validated_hash, _ = data
            report = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
                expected_ip="100.64.1.2",
            )
            self.assertFalse(report.ok)
            self.assertTrue(any("100.64.1.2" in e for e in report.errors), report.errors)

    def build_remote_fixture(self, tmp: Path, hosts_ip: str = "100.64.1.2"):
        client_root, private_path, hosts_path, validated_hash, public_pem = self.build_fixture(tmp)
        private_path.unlink()
        hosts_path.write_text(
            "\n".join(f"{hosts_ip} {name}" for name in preflight.REQUIRED_HOSTS) + "\n",
            encoding="utf-8",
        )
        return client_root, hosts_path, validated_hash, hashlib.sha256(public_pem).hexdigest()

    def remote_kwargs(self, client_root, hosts_path, validated_hash, resolved_ip="100.64.1.2"):
        return dict(
            client_root=client_root,
            hosts_path=hosts_path,
            resolver=lambda _name: resolved_ip,
            validated_tcls_sha256=validated_hash,
        )

    def run_remote(self, tmp: Path, hosts_ip: str = "100.64.1.2"):
        client_root, hosts_path, validated_hash, sha = self.build_remote_fixture(tmp, hosts_ip)
        status_path = tmp / "preflight_status.json"
        log_path = tmp / "server.log"
        ok = preflight.run_remote_preflight(
            "100.64.1.2",
            sha,
            status_path=status_path,
            log_path=log_path,
            **self.remote_kwargs(client_root, hosts_path, validated_hash, hosts_ip),
        )
        return ok, status_path, log_path

    def test_remote_preflight_passes_with_matching_apclient_hash_and_no_private_key(self):
        with tempfile.TemporaryDirectory() as td:
            client_root, hosts_path, validated_hash, sha = self.build_remote_fixture(Path(td))
            self.assertFalse((Path(td) / "PRIVATE.PEM").exists())
            for expected_sha in (sha, sha.upper()):
                with self.subTest(sha=expected_sha):
                    report = preflight.evaluate_preflight(
                        private_key_path=None,
                        apclient_sha256=expected_sha,
                        expected_ip="100.64.1.2",
                        **self.remote_kwargs(client_root, hosts_path, validated_hash),
                    )
                    self.assertTrue(report.ok, report.errors)
                    flags = preflight.preflight_check_flags(report)
                    self.assertTrue(all(flags.values()), flags)
                    self.assertFalse(any("PRIVATE.PEM" in e for e in report.errors), report.errors)

    def test_remote_preflight_rejects_wrong_apclient_hash(self):
        with tempfile.TemporaryDirectory() as td:
            client_root, hosts_path, validated_hash, _sha = self.build_remote_fixture(Path(td))
            report = preflight.evaluate_preflight(
                private_key_path=None,
                apclient_sha256=hashlib.sha256(b"another host's key").hexdigest(),
                expected_ip="100.64.1.2",
                **self.remote_kwargs(client_root, hosts_path, validated_hash),
            )
            self.assertFalse(report.ok)
            flags = preflight.preflight_check_flags(report)
            self.assertFalse(flags["apclient_exact_bytes"])
            self.assertFalse(flags["same_rsa_key"])
            self.assertTrue(any("APClient.dat SHA256" in e for e in report.errors), report.errors)
            self.assertFalse(any("PRIVATE.PEM" in e for e in report.errors), report.errors)

    def test_remote_preflight_rejects_non_key_apclient_even_when_hash_matches(self):
        with tempfile.TemporaryDirectory() as td:
            client_root, hosts_path, validated_hash, _sha = self.build_remote_fixture(Path(td))
            junk = b"x" * 288
            (client_root / "TCLS" / "config" / "APClient.dat").write_bytes(junk)
            report = preflight.evaluate_preflight(
                private_key_path=None,
                apclient_sha256=hashlib.sha256(junk).hexdigest(),
                expected_ip="100.64.1.2",
                **self.remote_kwargs(client_root, hosts_path, validated_hash),
            )
            self.assertFalse(report.ok)
            flags = preflight.preflight_check_flags(report)
            self.assertFalse(flags["apclient_272_bytes"])
            self.assertFalse(flags["rsa_1024"])

    def test_run_remote_preflight_writes_remote_status_and_returns_true(self):
        with tempfile.TemporaryDirectory() as td:
            ok, status_path, _log_path = self.run_remote(Path(td))
            self.assertIs(ok, True)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["mode"], "remote")
            self.assertEqual(status["remote_host"], "100.64.1.2")
            self.assertIsNone(status["server_pid"])
            self.assertIs(status["listeners_ready"], False)
            self.assertIs(status["launch_ready"], True)
            self.assertIs(status["checks"]["hosts"], True)

    def test_run_remote_preflight_fails_when_hosts_point_at_loopback(self):
        with tempfile.TemporaryDirectory() as td:
            ok, status_path, _log_path = self.run_remote(Path(td), hosts_ip="127.0.0.1")
            self.assertIs(ok, False)
            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["mode"], "remote")
            self.assertIs(status["checks"]["hosts"], False)
            self.assertIs(status["launch_ready"], False)

    def test_remote_cli_rejects_invalid_remote_host_without_writing_anything(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            env = os.environ.copy()
            for name in ("AF_PUBLIC_HOST", "AF_DS_PUBLIC_HOST"):
                env.pop(name, None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["AF_ACCOUNT_DB"] = str(tmp / "accounts.sqlite3")
            env["AF_LOG_PATH"] = str(tmp / "server.log")
            env["AF_PREFLIGHT_STATUS_PATH"] = str(tmp / "preflight_status.json")
            result = subprocess.run(
                [
                    sys.executable,
                    "server/assaultfire_preflight.py",
                    "--remote-host",
                    "127.1",
                    "--apclient-sha256",
                    hashlib.sha256(b"apclient").hexdigest(),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 2, output)
            self.assertIn("--remote-host", output)
            self.assertIn("'127.1'", output)
            self.assertFalse((tmp / "preflight_status.json").exists())
            self.assertFalse((tmp / "server.log").exists())

    def test_remote_report_lines_use_remote_pass_wording_without_listeners(self):
        with tempfile.TemporaryDirectory() as td:
            client_root, hosts_path, validated_hash, sha = self.build_remote_fixture(Path(td))
            report = preflight.evaluate_preflight(
                private_key_path=None,
                apclient_sha256=sha,
                expected_ip="100.64.1.2",
                **self.remote_kwargs(client_root, hosts_path, validated_hash),
            )
            self.assertTrue(report.ok, report.errors)
            lines = preflight.preflight_report_lines(report, listeners_ready=True, remote=True)
            self.assertIn(
                "[PREFLIGHT] PASS - remote client checks succeeded; "
                "supported game launch helpers are UNLOCKED.",
                lines,
            )
            self.assertFalse(any("FAILED" in line for line in lines), lines)
            self.assertNotIn("listeners", "\n".join(lines))

    def test_remote_report_lines_use_remote_failure_wording_without_listeners(self):
        with tempfile.TemporaryDirectory() as td:
            client_root, hosts_path, validated_hash, sha = self.build_remote_fixture(
                Path(td), hosts_ip="127.0.0.1"
            )
            report = preflight.evaluate_preflight(
                private_key_path=None,
                apclient_sha256=sha,
                expected_ip="100.64.1.2",
                **self.remote_kwargs(client_root, hosts_path, validated_hash, "127.0.0.1"),
            )
            self.assertFalse(report.ok)
            lines = preflight.preflight_report_lines(report, listeners_ready=True, remote=True)
            self.assertIn(
                "[PREFLIGHT] FAILED - remote client checks failed; "
                "supported game launch helpers remain LOCKED.",
                lines,
            )
            self.assertFalse(any("PASS" in line for line in lines), lines)
            self.assertNotIn("listeners", "\n".join(lines))

    def test_run_remote_preflight_log_has_remote_wording_without_listeners(self):
        with tempfile.TemporaryDirectory() as td:
            ok, _status_path, log_path = self.run_remote(Path(td))
            self.assertIs(ok, True)
            logged = log_path.read_text(encoding="utf-8")
            self.assertIn("[PREFLIGHT] PASS - remote client checks succeeded", logged)
            self.assertNotIn("listeners", logged)

    def test_report_lines_without_remote_keep_local_wording(self):
        with tempfile.TemporaryDirectory() as td:
            client_root, private_path, hosts_path, validated_hash, _ = self.build_fixture(Path(td))
            good = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "127.0.0.1",
                validated_tcls_sha256=validated_hash,
            )
            self.assertTrue(good.ok, good.errors)
            self.assertEqual(
                preflight.preflight_report_lines(good)[-1],
                "[PREFLIGHT] PASS - client checks succeeded; launch gate remains "
                "LOCKED until all required server listeners bind successfully.",
            )
            self.assertEqual(
                preflight.preflight_report_lines(good, listeners_ready=True)[-1],
                "[PREFLIGHT] PASS - all required checks and listeners succeeded; "
                "supported game launch helpers are UNLOCKED.",
            )
            bad = preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: "10.0.0.5",
                validated_tcls_sha256=validated_hash,
            )
            self.assertFalse(bad.ok)
            self.assertIn(
                "[PREFLIGHT] FAILED - server listeners will NOT start; "
                "supported game launch helpers remain LOCKED.",
                preflight.preflight_report_lines(bad),
            )

    def evaluate_with_env(self, env, hosts_ip="127.0.0.1", resolved_ip="127.0.0.1"):
        with tempfile.TemporaryDirectory() as td:
            client_root, private_path, hosts_path, validated_hash, _ = self.build_fixture(Path(td))
            hosts_path.write_text(
                "\n".join(f"{hosts_ip} {name}" for name in preflight.REQUIRED_HOSTS) + "\n",
                encoding="utf-8",
            )
            return preflight.evaluate_preflight(
                private_key_path=private_path,
                client_root=client_root,
                hosts_path=hosts_path,
                resolver=lambda _name: resolved_ip,
                validated_tcls_sha256=validated_hash,
                env=env,
            )

    def test_public_host_env_sets_expected_ip_when_hosts_and_resolver_match(self):
        report = self.evaluate_with_env(
            {"AF_PUBLIC_HOST": "100.64.1.2"}, hosts_ip="100.64.1.2", resolved_ip="100.64.1.2"
        )
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.expected_ip, "100.64.1.2")

    def test_public_host_env_rejects_loopback_hosts_and_names_public_host(self):
        report = self.evaluate_with_env({"AF_PUBLIC_HOST": "100.64.1.2"})
        self.assertFalse(report.ok)
        self.assertTrue(any("100.64.1.2" in e for e in report.errors), report.errors)

    def test_empty_env_keeps_loopback_expected_ip(self):
        report = self.evaluate_with_env({})
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.expected_ip, "127.0.0.1")

    def test_invalid_public_host_env_raises_value_error_naming_setting(self):
        with self.assertRaises(ValueError) as ctx:
            self.evaluate_with_env({"AF_PUBLIC_HOST": "bad"})
        self.assertIn("AF_PUBLIC_HOST", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
