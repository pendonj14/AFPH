import ast
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "tools" / "server_spawner" / "AFDevLoader_v48_spawner_multi_instance.py"


@unittest.skipUnless(os.name == "nt", "AFDEV loader is Windows-only")
class AfdevLoaderFixesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = LOADER.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)
        cls.main = next(
            n for n in cls.tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "main"
        )

    def test_unsupported_mode_id_rejected(self):
        proc = subprocess.run(
            [sys.executable, str(LOADER), "--game-dir", "C:/x", "--map", "M",
             "--mode-id", "0x101", "--no-uac"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unsupported AFDEV ModeId", proc.stderr)

    def test_wait_for_nonnull_gworld_raises_on_timeout(self):
        spec = importlib.util.spec_from_file_location("afdev_loader_under_test", LOADER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.safe_read_u32 = lambda hproc, addr: 0
        with self.assertRaises(RuntimeError):
            mod.wait_for_nonnull_gworld(0, timeout=0.2)

    def test_gameinfo_check_precedes_ready_file(self):
        src = ast.get_source_segment(self.source, self.main)
        self.assertIn("_gameinfo_is_a(", src)
        self.assertLess(src.index("_gameinfo_is_a("), src.index('"ready": True'))

    def test_pending_url_failure_raises(self):
        raises = [
            ast.get_source_segment(self.source, n)
            for n in ast.walk(self.main) if isinstance(n, ast.Raise)
        ]
        self.assertTrue(any("PendingURL did not clear" in r for r in raises))

    def test_outer_try_terminates_process_on_failure(self):
        tries = [n for n in self.main.body if isinstance(n, ast.Try) and n.finalbody]
        self.assertTrue(tries)
        # Exception + SystemExit, but NOT bare BaseException: Ctrl+C must only
        # stop monitoring and leave AFDEV running.
        handler = next(
            h for h in tries[-1].handlers
            if isinstance(h.type, ast.Tuple)
            and {e.id for e in h.type.elts if isinstance(e, ast.Name)} == {"Exception", "SystemExit"}
        )
        self.assertIn("TerminateProcess", ast.get_source_segment(self.source, handler))
        self.assertFalse(any(
            isinstance(h.type, ast.Name) and h.type.id in ("BaseException", "KeyboardInterrupt")
            for h in tries[-1].handlers
        ))

    def test_non_ds_branch_removed(self):
        self.assertNotIn("WaitForSingleObject", ast.get_source_segment(self.source, self.main))
        self.assertNotIn("monitor_travel_state(", ast.get_source_segment(self.source, self.main))


if __name__ == "__main__":
    unittest.main()
