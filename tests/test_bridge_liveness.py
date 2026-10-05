import ast
import unittest
from pathlib import Path

BRIDGE = Path(__file__).resolve().parents[1] / "tools" / "bridge" / "af_ds_udp_bridge_v9_multi_peer_latch.py"


def _poll_lazy_ready():
    tree = ast.parse(BRIDGE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "poll_lazy_ready":
            return node
    raise AssertionError("poll_lazy_ready not found")


class BridgeLivenessTest(unittest.TestCase):
    def test_loader_poll_checked_before_ready_return(self):
        fn = _poll_lazy_ready()
        poll_idx = ready_idx = None
        for i, stmt in enumerate(fn.body):
            if not isinstance(stmt, ast.If):
                continue
            test = ast.unparse(stmt.test)
            if "loader_proc.poll() is not None" in test and poll_idx is None:
                poll_idx = i
                src = ast.unparse(stmt)
                self.assertIn("state='FAILED'", src)
                self.assertTrue(any(isinstance(n, ast.Raise) for n in ast.walk(stmt)))
            if test == "afdev_ready" and ready_idx is None:
                ready_idx = i
        self.assertIsNotNone(poll_idx, "loader poll check missing")
        self.assertIsNotNone(ready_idx, "afdev_ready early return missing")
        self.assertLess(poll_idx, ready_idx)
        guard = [s for s in fn.body if isinstance(s, ast.If)][0]
        self.assertNotIn("afdev_ready", ast.unparse(guard.test))


if __name__ == "__main__":
    unittest.main()
