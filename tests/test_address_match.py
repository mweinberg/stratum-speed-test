#!/usr/bin/env python3
"""
Tests for verify_address_in_outputs() in verify_pool.py.

A pool must only pass verification when a coinbase output actually pays the
miner's address. Writing the address as text into a script (for example a
zero-value OP_RETURN) while paying the reward elsewhere must fail.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import verify_pool as vp  # noqa: E402

USER_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
POOL_HASH = "11" * 20
REWARD = 312_500_000


def p2pkh_output(hash_hex, value):
    script = bytes.fromhex("76a914" + hash_hex + "88ac")
    addr_type, addr_data = vp.decode_script(script)
    return {"value_satoshis": value, "value_btc": value / 1e8, "script_hex": script.hex(),
            "address_type": addr_type, "address_data": addr_data}


def op_return_output(data):
    script = b"\x6a" + bytes([len(data)]) + data
    addr_type, addr_data = vp.decode_script(script)
    return {"value_satoshis": 0, "value_btc": 0.0, "script_hex": script.hex(),
            "address_type": addr_type, "address_data": addr_data}


class TestAddressMatch(unittest.TestCase):

    def test_real_payment_passes(self):
        user_hash = vp.base58_decode(USER_ADDRESS)
        found, _ = vp.verify_address_in_outputs([p2pkh_output(user_hash, REWARD)], USER_ADDRESS)
        self.assertTrue(found)

    def test_payment_to_someone_else_fails(self):
        found, _ = vp.verify_address_in_outputs([p2pkh_output(POOL_HASH, REWARD)], USER_ADDRESS)
        self.assertFalse(found)

    def test_address_as_text_does_not_pass(self):
        # Reward goes to the pool; the miner's address only appears as text
        outputs = [p2pkh_output(POOL_HASH, REWARD),
                   op_return_output(USER_ADDRESS.encode())]
        found, _ = vp.verify_address_in_outputs(outputs, USER_ADDRESS)
        self.assertFalse(found)


if __name__ == "__main__":
    unittest.main()
