from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GrantAllItemsTests(unittest.TestCase):
    def test_grant_is_complete_idempotent_and_keeps_bag_invariant(self):
        code = r'''
import assaultfire_server_v143b as s

s._v140_select_player(10001)
items = [p['item_id'] for p in s.V111_INVENTORY]
gids = [p['gid'] for p in s.V111_INVENTORY]
assert len(gids) == len(set(gids)), "duplicate GIDs"

bags = set(s._v141_catalog_bag_item_ids())
mounted = [p for p in s.V111_INVENTORY
           if s._v141_is_bag_item(p['item_id']) and p['owner_gid'] == s.V110_BAG_MOUNT_OWNER]
assert len(mounted) == 1, f"mounted bags: {len(mounted)}"
owned_bags = {p['item_id'] for p in s.V111_INVENTORY if s._v141_is_bag_item(p['item_id'])}
assert {100026, 100063, 100035, 100036, 100037} <= owned_bags, owned_bags
roots = {
    (list(s.V140_COMMODITY_BUNDLES.get(c) or ()) or [s.V140_SHOP_ITEM_MAP[c]])[0]
    for c in set(s.V140_SHOP_ITEM_MAP) | set(s.V140_COMMODITY_BUNDLES)
}
missing = {r for r in roots if r not in items}
assert not missing, f"missing roots: {sorted(missing)[:10]}"
assert all(items.count(r) == 1 for r in roots), "duplicate root"

before = len(s.V111_INVENTORY)
assert s._v160_grant_all_catalog_items() == 0
assert len(s.V111_INVENTORY) == before
print(s._v141_bag_invariant_text() if hasattr(s, '_v141_bag_invariant_text') else '')
print("OK", before)
'''
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env.update(AF_ACCOUNT_DB=str(Path(td) / 'accounts.sqlite3'),
                       AF_RUNTIME_MODE='production', AF_DEV_WEB='0')
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT / 'server',
                                    env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_switch_local_channel_response(self):
        code = r'''
import assaultfire_server_v143b as s
rsp = s._v160_build_switch_local_channel_response(1)
assert s._v160_parse_switch_local_channel_request(bytes.fromhex("00000001")) == 1
assert rsp[:2] == b"\x32\x43" or s.TGAME_ZN_RES_SWITCHLOCALCHANNEL.to_bytes(2, "big") in rsp
assert s.TGAME_ZN_REQ_SWITCHLOCALCHANNEL in s.V139_CURRENT_HANDLER_IDS
print("OK")
'''
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env.update(AF_ACCOUNT_DB=str(Path(td) / 'accounts.sqlite3'),
                       AF_RUNTIME_MODE='production', AF_DEV_WEB='0')
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT / 'server',
                                    env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
