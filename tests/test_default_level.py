from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def _run(code, **extra_env):
    with tempfile.TemporaryDirectory() as td:
        env = os.environ.copy()
        env.update(AF_ACCOUNT_DB=str(Path(td) / 'accounts.sqlite3'),
                   AF_RUNTIME_MODE='production', AF_DEV_WEB='0')
        env.update(extra_env)
        return subprocess.run([sys.executable, '-c', code], cwd=ROOT / 'server',
                              env=env, capture_output=True, text=True, timeout=60)


class DefaultLevelTests(unittest.TestCase):
    def test_level_100_unlocks_every_skill_once(self):
        r = _run(r'''
import assaultfire_server_v143b as s
s._v140_select_player(10001)
assert s.V140_MALL_STATE["experience"] == 9574910, s.V140_MALL_STATE["experience"]
owned = [p["item_id"] for p in s.V111_INVENTORY]
missing = (set(s.V170_PVE_LEVEL_SKILL_IDS) | {100517, 100518}) - set(owned)
assert not missing, sorted(missing)
before = len(s.V111_INVENTORY)
s._v140_select_player(10001)
assert len(s.V111_INVENTORY) == before, "second login must not add rows"
assert all(owned.count(i) == 1 for i in (set(s.V170_PVE_LEVEL_SKILL_IDS) | {100517, 100518}))
print("OK")
''')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_switches_restore_level_one_without_event_skills(self):
        r = _run(r'''
import assaultfire_server_v143b as s
s._v140_select_player(10001)
assert s.V140_MALL_STATE["experience"] == 0, s.V140_MALL_STATE["experience"]
owned = {p["item_id"] for p in s.V111_INVENTORY}
assert 100518 not in owned
print("OK")
''', AF_DEFAULT_EXP='0', AF_UNLOCK_ALL_SKILLS='0')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main()
