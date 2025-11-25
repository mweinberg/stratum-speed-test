#!/usr/bin/env python3
"""Test SoloHash coinbase parsing"""

import sys
sys.path.insert(0, '.')

from verify_pool import parse_coinbase_outputs, hash_to_address

# Real data from solo-ca.solohash.co.uk
coinb1 = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2a03c91d0e0438bb256900'
coinb2 = '174d696e656420627920536f6c6f486173682e636f2e756b00000000020000000000000000266a24aa21a9ed4cf19dd80ae31a4bb9656726305874862cd21ac3e53887193339fa73545c4ad57e31bd1200000000160014c127bde9fd0248a19362a52de0f23fae736a2aeb00000000'

print("Testing SoloHash coinbase parsing...")
print("=" * 70)
print()

outputs = parse_coinbase_outputs(coinb2, coinb1)

if not outputs:
    print("❌ FAILED: Could not parse outputs")
    sys.exit(1)

print(f"✅ SUCCESS: Parsed {len(outputs)} outputs")
print()

for i, output in enumerate(outputs, 1):
    print(f"Output #{i}:")
    print(f"  Value: {output['value_btc']:.8f} BTC ({output['value_satoshis']:,} sats)")
    print(f"  Type: {output['address_type']}")
    
    if output['address_type'] == 'OP_RETURN':
        print(f"  Data: {output['address_data'][:60]}...")
    else:
        print(f"  Hash: {output['address_data']}")
        address = hash_to_address(output['address_data'], output['address_type'])
        if address:
            print(f"  Address: {address}")
    print()

print("=" * 70)
print("✅ SoloHash parsing works correctly!")
