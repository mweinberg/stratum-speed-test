#!/usr/bin/env python3
"""
Solo Mining Pool Verification Tool

Connects to a stratum pool as a worker and verifies that the block template
contains your Bitcoin address in the coinbase transaction. This helps ensure
the pool is actually solo mining (paying you directly) rather than pool mining.

Features:
  • Verifies your address appears in coinbase outputs
  • Shows block height and pool signature from coinbase script
  • Displays all coinbase outputs with full Bitcoin addresses
  • Shows payout percentages for each output (miner vs pool fee)
  • Decodes OP_RETURN witness commitments
  • Tests all 5 Bitcoin address types for compatibility
  • Validates extranonce1 (existence, size, uniqueness)
  • Analyzes pool architecture (detects proxying indicators)
  • Automatic retry logic for slow-responding pools
  • Connection timing metrics

Supported Address Types:
  • P2PKH (Legacy):     1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  • P2SH (Script Hash): 3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y
  • P2WPKH (SegWit):    bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
  • P2WSH (SegWit):     bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
  • P2TR (Taproot):     bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr

Supported Pool Formats:
  • Standard (CKPool, AtlasPool, most pools)
  • SoloHash (sequence marker early in coinb2)
  • Custom formats with automatic detection

Usage:
    # Test pool connectivity (uses random address)
    python3 verify_pool.py <pool_host> <pool_port>
    
    # Verify a specific address
    python3 verify_pool.py <pool_host> <pool_port> <your_btc_address>
    
    # Test all address types (-a flag)
    python3 verify_pool.py <pool_host> <pool_port> -a
    
    # Analyze pool architecture (detect proxying)
    python3 verify_pool.py <pool_host> <pool_port> --analyze

Examples:
    python3 verify_pool.py solo.atlaspool.io 3333
    python3 verify_pool.py solo.atlaspool.io 3333 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    python3 verify_pool.py solo.ckpool.org 3333 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    python3 verify_pool.py solo.ckpool.org 3333 -a
    python3 verify_pool.py solo-ca.solohash.co.uk 3333 --analyze

What You'll See:
    • Block height being mined
    • Pool signature (e.g., "ckpool", "/solo.ckpool.org/")
    • All coinbase outputs with amounts, types, hashes, and full addresses
    • Payout breakdown showing percentage split (e.g., 98% miner, 2% pool fee)
    • OP_RETURN witness commitment (SegWit metadata, 0 BTC)
    • Connection timing metrics (with --analyze)
    • Architecture analysis (with --analyze)
    • Verification result: ✅ Found, ⚠️ Unknown, or ❌ Not Found

Version: 1.2
"""

import socket
import json
import sys
import time
import binascii
import argparse
import statistics
from typing import Optional, Tuple, Dict, List


def connect_and_subscribe(host: str, port: int, timeout: int = 10) -> Tuple[Optional[socket.socket], Optional[dict]]:
    """
    Connect to stratum server and send mining.subscribe.
    Returns (socket, response) or (None, None) on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Send mining.subscribe
        subscribe_msg = json.dumps({
            "id": 1,
            "method": "mining.subscribe",
            "params": ["verify_pool/1.0"]
        }) + "\n"
        
        sock.sendall(subscribe_msg.encode('utf-8'))
        
        # Wait a moment for response to arrive
        time.sleep(0.2)
        
        # Receive response - may need multiple reads
        response_parts = []
        sock.settimeout(3)
        
        try:
            for _ in range(2):
                chunk = sock.recv(4096).decode('utf-8')
                if chunk:
                    response_parts.append(chunk)
                    if '\n' in chunk and '"id":1' in chunk:
                        break
                time.sleep(0.1)
        except socket.timeout:
            pass
        
        response = ''.join(response_parts).strip()
        
        if not response:
            return None, None
        
        # Parse response (may contain multiple lines)
        for line in response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('id') == 1:
                        return sock, data
                except json.JSONDecodeError:
                    continue
        
        return sock, None
        
    except Exception:
        return None, None


def authorize_worker(sock: socket.socket, username: str, password: str = "x") -> Tuple[bool, Optional[dict], Optional[float]]:
    """
    Send mining.authorize with username (typically your BTC address).
    Returns (authorized, mining_notify_params, difficulty) - notify and difficulty may be None.
    """
    try:
        # Ensure socket has a reasonable timeout
        sock.settimeout(10)
        
        authorize_msg = json.dumps({
            "id": 2,
            "method": "mining.authorize",
            "params": [username, password]
        }) + "\n"
        
        sock.sendall(authorize_msg.encode('utf-8'))
        
        # Receive response - may need multiple reads for slow connections
        # Wait a bit for the response to arrive
        time.sleep(0.3)
        
        response_parts = []
        sock.settimeout(2)  # Shorter timeout for subsequent reads
        
        try:
            # Try to read multiple times to get complete response
            for _ in range(3):
                chunk = sock.recv(8192).decode('utf-8')
                if chunk:
                    response_parts.append(chunk)
                    # If we got a complete response, break
                    if '\n' in chunk and '"id":2' in chunk:
                        break
                time.sleep(0.1)
        except socket.timeout:
            pass  # Normal - no more data
        
        response = ''.join(response_parts).strip()
        
        if not response:
            return False, None, None
        
        authorized = False
        notify_params = None
        difficulty = None
        
        for line in response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    
                    # Check authorization response
                    if data.get('id') == 2:
                        authorized = data.get('result', False)
                    
                    # Check for mining.notify
                    if data.get('method') == 'mining.notify':
                        notify_params = data.get('params')
                    
                    # Check for mining.set_difficulty
                    if data.get('method') == 'mining.set_difficulty':
                        diff = data.get('params', [None])[0]
                        if diff is not None:
                            difficulty = float(diff)
                except json.JSONDecodeError:
                    continue
        
        return authorized, notify_params, difficulty
        
    except Exception as e:
        return False, None, None


def wait_for_mining_notify(sock: socket.socket, timeout: int = 15, retry_count: int = 0) -> Tuple[Optional[dict], Optional[float]]:
    """
    Wait for mining.notify message containing the block template.
    Returns (notify_params, difficulty) or (None, None).
    
    Args:
        sock: Socket connection to pool
        timeout: Timeout in seconds
        retry_count: Current retry attempt (for display purposes)
    """
    try:
        sock.settimeout(timeout)
        
        if retry_count > 0:
            print(f"    Retry {retry_count}...")
        
        # May need to receive multiple messages
        buffer = ""
        start_time = time.time()
        difficulty = None
        notify_params = None
        
        while True:
            try:
                chunk = sock.recv(8192).decode('utf-8')
            except socket.timeout:
                elapsed = time.time() - start_time
                if not notify_params:
                    print(f"    Timeout after {elapsed:.1f}s - no mining.notify received")
                    return None, None
                else:
                    # We got notify but timed out waiting for more data
                    return notify_params, difficulty
                
            if not chunk:
                break
                
            buffer += chunk
            
            # Process complete lines
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line.strip():
                    try:
                        data = json.loads(line)
                        
                        # Look for mining.notify
                        if data.get('method') == 'mining.notify':
                            elapsed = time.time() - start_time
                            if retry_count > 0:
                                print(f"    ✓ Received after {elapsed:.1f}s (retry {retry_count})")
                            notify_params = data.get('params')
                            # Don't return immediately - keep reading for difficulty
                        
                        # Also check for mining.set_difficulty
                        if data.get('method') == 'mining.set_difficulty':
                            diff = data.get('params', [None])[0]
                            if diff is not None:
                                difficulty = float(diff)
                                print(f"    Received difficulty: {difficulty:,.0f}")
                        
                        # If we have both, we can return
                        if notify_params is not None:
                            # Give it a moment to see if difficulty comes through
                            if difficulty is not None:
                                return notify_params, difficulty
                            
                    except json.JSONDecodeError:
                        continue
            
            # If we got notify_params, wait a bit more for difficulty then return
            if notify_params is not None:
                elapsed = time.time() - start_time
                if elapsed > 1.0:  # Wait max 1 more second for difficulty
                    return notify_params, difficulty
        
        return notify_params, difficulty
        
    except Exception as e:
        print(f"    Error receiving notify: {e}")
        return None, None


def parse_coinbase_script(coinb1_hex: str) -> dict:
    """
    Parse the coinbase script (coinb1) to extract block height and pool signature.
    
    Coinbase script structure (coinb1 is partial, ends before extranonce):
    - Version (4 bytes)
    - Input count (1 byte, always 0x01)
    - Previous output hash (32 bytes, all zeros)
    - Previous output index (4 bytes, all 0xff)
    - Script length (varint)
    - Script data (partial):
      - Block height (BIP34, variable length)
      - Arbitrary data (pool signature, etc.)
      - [extranonce placeholder - not in coinb1]
    
    Returns dict with block_height, pool_signature, and raw script data.
    """
    try:
        coinb1_bytes = binascii.unhexlify(coinb1_hex)
        
        # Skip version (4 bytes) + input count (1 byte) + prev hash (32 bytes) + prev index (4 bytes)
        pos = 4 + 1 + 32 + 4  # = 41 bytes
        
        if pos >= len(coinb1_bytes):
            return {'error': f'Coinbase too short ({len(coinb1_bytes)} bytes, need at least {pos})'}
        
        # Read script length (varint - simplified for < 253)
        script_len = coinb1_bytes[pos]
        pos += 1
        
        # Note: coinb1 is partial, so we just read what's available
        # The script continues in coinb2 after the extranonce
        available_script = coinb1_bytes[pos:]
        
        # Parse block height (BIP34)
        # First byte indicates the length of the height value
        if len(available_script) == 0:
            return {
                'block_height': None,
                'pool_signature': '',
                'pool_signature_ascii': '',
                'script_hex': '',
                'script_ascii': '',
                'script_length': script_len
            }
        
        height_len = available_script[0]
        
        # Height length should be 1-4 bytes typically
        if height_len > 0 and height_len <= 4 and len(available_script) > height_len:
            # Extract height (little-endian)
            height_bytes = available_script[1:1 + height_len]
            block_height = int.from_bytes(height_bytes, 'little')
            
            # Everything after height is arbitrary data (pool signature)
            arbitrary_data = available_script[1 + height_len:]
        else:
            # Can't parse height, treat all as arbitrary
            block_height = None
            arbitrary_data = available_script
        
        # Try to decode arbitrary data as ASCII
        ascii_text = ''
        try:
            ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in arbitrary_data)
        except:
            pass
        
        # Full script ASCII (including height bytes)
        full_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in available_script)
        
        return {
            'block_height': block_height,
            'pool_signature': arbitrary_data.hex(),
            'pool_signature_ascii': ascii_text,
            'script_hex': available_script.hex(),
            'script_ascii': full_ascii,
            'script_length': script_len
        }
        
    except Exception as e:
        return {'error': str(e)}


def parse_coinbase_script_suffix(coinb2_hex: str) -> dict:
    """
    Parse the suffix of the coinbase script from coinb2.
    
    Coinb2 structure varies by pool:
    - Standard: [script_suffix][sequence 0xffffffff][output_count][outputs]
    - SoloHash: [script_suffix][sequence 0x00000000][output_count][outputs]
    
    The pool signature (like "ckpool", "Mined by SoloHash.co.uk") is typically 
    at the beginning of coinb2.
    """
    try:
        coinb2_bytes = binascii.unhexlify(coinb2_hex)
        
        # Find the sequence marker (0xffffffff or 0x00000000) which marks end of script
        sequence_pos = -1
        for i in range(len(coinb2_bytes) - 3):
            if coinb2_bytes[i:i+4] == b'\xff\xff\xff\xff' or coinb2_bytes[i:i+4] == b'\x00\x00\x00\x00':
                sequence_pos = i
                break
        
        if sequence_pos == -1:
            return {'error': 'Could not find sequence marker'}
        
        # Everything before sequence is the script suffix
        script_suffix = coinb2_bytes[:sequence_pos]
        
        # Try to decode as ASCII
        ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in script_suffix)
        
        # Extract readable strings (3+ consecutive printable chars)
        readable_strings = []
        current_string = ''
        for b in script_suffix:
            if 32 <= b < 127:
                current_string += chr(b)
            else:
                if len(current_string) >= 3:
                    readable_strings.append(current_string)
                current_string = ''
        if len(current_string) >= 3:
            readable_strings.append(current_string)
        
        return {
            'script_suffix_hex': script_suffix.hex(),
            'script_suffix_ascii': ascii_text,
            'readable_strings': readable_strings,
            'length': len(script_suffix)
        }
        
    except Exception as e:
        return {'error': str(e)}


def parse_coinbase_outputs(coinb2_hex: str, coinb1_hex: str = None) -> list:
    """
    Parse the outputs from coinbase transaction (coinb2).
    Returns list of output dictionaries.
    
    Coinb2 structure varies by pool:
    - Standard: [extranonce][sequence 4][output_count 1][outputs...][locktime 4]
    - SoloHash: sequence in coinb1, coinb2 = [extranonce][output_count][outputs...][locktime]
    
    Each output: [8 bytes value][1-9 bytes script_len][script]
    """
    try:
        coinb2_bytes = binascii.unhexlify(coinb2_hex)
        outputs = []
        
        # Method 0: Check for SoloHash format (sequence marker early in coinb2)
        # SoloHash format: coinb2 = [script_suffix][sequence 4][output_count 1][outputs][locktime 4]
        # The sequence marker appears early in coinb2 (after script suffix), not at the end of coinb1
        try:
            # Search for sequence marker in coinb2
            sequence_pos = -1
            for i in range(min(50, len(coinb2_bytes) - 4)):  # Check first 50 bytes
                if coinb2_bytes[i:i+4] == b'\x00\x00\x00\x00' or coinb2_bytes[i:i+4] == b'\xff\xff\xff\xff':
                    # Check if next byte looks like output count (1-20)
                    if i + 4 < len(coinb2_bytes):
                        potential_output_count = coinb2_bytes[i+4]
                        if 1 <= potential_output_count <= 20:
                            sequence_pos = i
                            break
            
            if sequence_pos != -1:
                # Found potential SoloHash format
                output_count = coinb2_bytes[sequence_pos + 4]
                pos = sequence_pos + 5  # Start of outputs
                test_pos = pos
                valid = True
                
                # Validate output structure
                for _ in range(output_count):
                    if test_pos + 8 > len(coinb2_bytes):
                        valid = False
                        break
                    
                    value = int.from_bytes(coinb2_bytes[test_pos:test_pos+8], 'little')
                    test_pos += 8
                    
                    if test_pos >= len(coinb2_bytes):
                        valid = False
                        break
                    
                    script_len = coinb2_bytes[test_pos]
                    test_pos += 1
                    
                    # Sanity check script length
                    if script_len > 200 or test_pos + script_len > len(coinb2_bytes):
                        valid = False
                        break
                    
                    test_pos += script_len
                
                # Check if we end at locktime (4 bytes remaining)
                if valid and len(coinb2_bytes) - test_pos == 4:
                    # This is SoloHash format! Parse the outputs
                    pos = sequence_pos + 5
                    
                    for _ in range(output_count):
                        if pos + 8 > len(coinb2_bytes):
                            break
                        
                        value = int.from_bytes(coinb2_bytes[pos:pos+8], 'little')
                        pos += 8
                        
                        if pos >= len(coinb2_bytes):
                            break
                        
                        script_len = coinb2_bytes[pos]
                        pos += 1
                        
                        if pos + script_len > len(coinb2_bytes):
                            break
                        
                        script = coinb2_bytes[pos:pos+script_len]
                        pos += script_len
                        
                        addr_type, addr_data = decode_script(script)
                        
                        outputs.append({
                            'value_satoshis': value,
                            'value_btc': value / 100000000,
                            'script_hex': script.hex(),
                            'address_type': addr_type,
                            'address_data': addr_data
                        })
                    
                    if outputs:
                        return outputs
        except:
            pass  # Fall through to other methods
        
        # Method 1: Standard format with sequence marker search
        # Try to find where outputs start by looking for sequence and testing positions
        if coinb1_hex:
            try:
                coinb1_bytes = binascii.unhexlify(coinb1_hex)
                
                if len(coinb1_bytes) >= 42:
                    script_len = coinb1_bytes[41]
                    script_in_coinb1 = len(coinb1_bytes) - 42
                    script_remaining = max(0, script_len - script_in_coinb1)
                    
                    # Try different extranonce sizes
                    for extranonce_size in [8, 4, 12, 16, 0]:
                        pos = script_remaining + extranonce_size + 4  # script + extranonce + sequence
                        
                        if pos >= len(coinb2_bytes):
                            continue
                        
                        output_count = coinb2_bytes[pos]
                        
                        if output_count > 0 and output_count <= 20:
                            test_pos = pos + 1
                            valid = True
                            
                            for _ in range(output_count):
                                if test_pos + 8 > len(coinb2_bytes):
                                    valid = False
                                    break
                                
                                value = int.from_bytes(coinb2_bytes[test_pos:test_pos+8], 'little')
                                test_pos += 8
                                
                                if test_pos >= len(coinb2_bytes):
                                    valid = False
                                    break
                                    
                                script_len_out = coinb2_bytes[test_pos]
                                test_pos += 1
                                
                                if script_len_out > 200 or test_pos + script_len_out > len(coinb2_bytes):
                                    valid = False
                                    break
                                
                                test_pos += script_len_out
                            
                            if valid and len(coinb2_bytes) - test_pos <= 4:
                                pos += 1
                                
                                for _ in range(output_count):
                                    if pos + 8 > len(coinb2_bytes):
                                        break
                                    
                                    value = int.from_bytes(coinb2_bytes[pos:pos+8], 'little')
                                    pos += 8
                                    
                                    if pos >= len(coinb2_bytes):
                                        break
                                    script_len_out = coinb2_bytes[pos]
                                    pos += 1
                                    
                                    if pos + script_len_out > len(coinb2_bytes):
                                        break
                                    
                                    script = coinb2_bytes[pos:pos+script_len_out]
                                    pos += script_len_out
                                    
                                    addr_type, addr_data = decode_script(script)
                                    
                                    outputs.append({
                                        'value_satoshis': value,
                                        'value_btc': value / 100000000,
                                        'script_hex': script.hex(),
                                        'address_type': addr_type,
                                        'address_data': addr_data
                                    })
                                
                                return outputs
            except:
                pass
        
        # Method 2: Search for standard sequence marker (0xffffffff)
        pos = 0
        found_sequence = False
        
        for i in range(len(coinb2_bytes) - 4):
            if coinb2_bytes[i:i+4] == b'\xff\xff\xff\xff':
                pos = i + 4  # Start after sequence
                found_sequence = True
                break
        
        if not found_sequence:
            return []
        
        # Read output count (varint)
        if pos >= len(coinb2_bytes):
            return []
            
        output_count = coinb2_bytes[pos]
        pos += 1
        
        for _ in range(output_count):
            if pos + 8 > len(coinb2_bytes):
                break
                
            # Read value (8 bytes, little-endian)
            value = int.from_bytes(coinb2_bytes[pos:pos+8], 'little')
            pos += 8
            
            # Read script length (varint - simplified, assumes < 253)
            if pos >= len(coinb2_bytes):
                break
            script_len = coinb2_bytes[pos]
            pos += 1
            
            if pos + script_len > len(coinb2_bytes):
                break
                
            # Read script
            script = coinb2_bytes[pos:pos+script_len]
            pos += script_len
            
            # Decode script type and address
            addr_type, addr_data = decode_script(script)
            
            outputs.append({
                'value_satoshis': value,
                'value_btc': value / 100000000,
                'script_hex': script.hex(),
                'address_type': addr_type,
                'address_data': addr_data
            })
        
        return outputs
        
    except Exception as e:
        return []


def decode_script(script: bytes) -> tuple:
    """
    Decode a Bitcoin script to determine address type and data.
    Returns (type, data) where data is the hash/witness program.
    """
    if len(script) == 0:
        return "empty", ""
    
    # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14:
        return "P2PKH", script[3:23].hex()
    
    # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14:
        return "P2SH", script[2:22].hex()
    
    # P2WPKH: OP_0 <20 bytes>
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "P2WPKH", script[2:22].hex()
    
    # P2WSH: OP_0 <32 bytes>
    if len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "P2WSH", script[2:34].hex()
    
    # P2TR: OP_1 <32 bytes>
    if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "P2TR", script[2:34].hex()
    
    # OP_RETURN (data output)
    if script[0] == 0x6a:
        return "OP_RETURN", script[1:].hex()
    
    return "unknown", script.hex()


def bech32_polymod(values):
    """Compute the Bech32 checksum polymod."""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP for Bech32 checksum."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data, spec):
    """Create Bech32/Bech32m checksum."""
    values = bech32_hrp_expand(hrp) + data
    const = 0x2bc830a3 if spec == 'bech32m' else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, witver, witprog, spec='bech32'):
    """Encode a segwit address (bech32 or bech32m)."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    
    # Convert 8-bit to 5-bit
    data = [witver] + convertbits(witprog, 8, 5)
    if data is None:
        return None
    
    # Create checksum
    checksum = bech32_create_checksum(hrp, data, spec)
    
    # Combine and encode
    combined = data + checksum
    return hrp + '1' + ''.join([charset[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    """Convert between bit groups."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def hash_to_address(hash_hex: str, addr_type: str) -> str:
    """
    Convert a hash to a readable Bitcoin address.
    Returns the address or the hash if encoding fails.
    """
    try:
        import hashlib
        
        if addr_type == "P2PKH":
            # Encode as legacy address (1...)
            version = bytes([0])
            hash_bytes = bytes.fromhex(hash_hex)
            data = version + hash_bytes
            checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
            
            # Base58 encode
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            num = int.from_bytes(data + checksum, 'big')
            encoded = ''
            while num > 0:
                num, remainder = divmod(num, 58)
                encoded = alphabet[remainder] + encoded
            
            # Add leading 1s for leading zeros
            for byte in data + checksum:
                if byte == 0:
                    encoded = '1' + encoded
                else:
                    break
            
            return encoded
            
        elif addr_type == "P2SH":
            # Encode as P2SH address (3...)
            version = bytes([5])
            hash_bytes = bytes.fromhex(hash_hex)
            data = version + hash_bytes
            checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
            
            # Base58 encode
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            num = int.from_bytes(data + checksum, 'big')
            encoded = ''
            while num > 0:
                num, remainder = divmod(num, 58)
                encoded = alphabet[remainder] + encoded
            
            for byte in data + checksum:
                if byte == 0:
                    encoded = '1' + encoded
                else:
                    break
            
            return encoded
            
        elif addr_type == "P2WPKH":
            # Encode as bech32 (bc1q...) - witness v0, 20 bytes
            hash_bytes = bytes.fromhex(hash_hex)
            return bech32_encode('bc', 0, hash_bytes, 'bech32')
            
        elif addr_type == "P2WSH":
            # Encode as bech32 (bc1q...) - witness v0, 32 bytes
            hash_bytes = bytes.fromhex(hash_hex)
            return bech32_encode('bc', 0, hash_bytes, 'bech32')
            
        elif addr_type == "P2TR":
            # Encode as bech32m (bc1p...) - witness v1, 32 bytes
            hash_bytes = bytes.fromhex(hash_hex)
            return bech32_encode('bc', 1, hash_bytes, 'bech32m')
            
        else:
            return hash_hex
            
    except:
        return hash_hex


def base58_decode(address: str) -> Optional[str]:
    """
    Decode a Base58Check address (legacy P2PKH or P2SH).
    Returns the hash160 (20 bytes) as hex, or None.
    """
    try:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        # Decode base58
        decoded = 0
        for char in address:
            decoded = decoded * 58 + alphabet.index(char)
        
        # Convert to bytes (25 bytes: 1 version + 20 hash + 4 checksum)
        decoded_bytes = decoded.to_bytes(25, 'big')
        
        # Extract hash160 (skip version byte, exclude checksum)
        hash160 = decoded_bytes[1:21]
        
        return hash160.hex()
        
    except:
        return None


def bech32_decode_simple(address: str) -> Optional[str]:
    """
    Simple bech32 decoder to extract witness program.
    Returns hex of witness program or None.
    """
    try:
        # Bech32 character set
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        
        # Remove prefix
        if not address.lower().startswith('bc1'):
            return None
        
        data_part = address[3:].lower()
        
        # Decode bech32 (simplified - just get the data)
        values = []
        for c in data_part[:-6]:  # Exclude checksum
            if c in charset:
                values.append(charset.index(c))
        
        # Convert from 5-bit to 8-bit
        bits = 0
        value = 0
        result = []
        
        for v in values[1:]:  # Skip witness version
            value = (value << 5) | v
            bits += 5
            
            if bits >= 8:
                bits -= 8
                result.append((value >> bits) & 0xff)
                value &= (1 << bits) - 1
        
        return bytes(result).hex()
        
    except:
        return None


def verify_address_in_outputs(outputs: list, btc_address: str) -> Tuple[bool, str]:
    """
    Check if the Bitcoin address matches any output in the coinbase.
    Returns (found, details).
    """
    try:
        # Decode the user's address to get hash
        user_hash = None
        addr_type_expected = None
        
        if btc_address.lower().startswith('bc1p'):
            # Taproot address (bech32m, witness v1)
            user_hash = bech32_decode_simple(btc_address)
            if not user_hash:
                return False, "Could not decode Taproot address"
            addr_type_expected = "P2TR"
            
        elif btc_address.lower().startswith('bc1'):
            # Bech32 address (P2WPKH or P2WSH)
            user_hash = bech32_decode_simple(btc_address)
            if not user_hash:
                return False, "Could not decode bech32 address"
            # P2WPKH = 20 bytes (40 hex chars), P2WSH = 32 bytes (64 hex chars)
            addr_type_expected = "P2WPKH" if len(user_hash) == 40 else "P2WSH"
            
        elif btc_address.startswith('1'):
            # Legacy P2PKH address
            user_hash = base58_decode(btc_address)
            if not user_hash:
                return False, "Could not decode P2PKH address"
            addr_type_expected = "P2PKH"
            
        elif btc_address.startswith('3'):
            # P2SH address
            user_hash = base58_decode(btc_address)
            if not user_hash:
                return False, "Could not decode P2SH address"
            addr_type_expected = "P2SH"
        else:
            return False, "Unrecognized address format"
        
        # Check each output
        for i, output in enumerate(outputs):
            addr_type = output['address_type']
            addr_data = output['address_data']
            value_btc = output['value_btc']
            
            # Compare hashes
            if addr_type == addr_type_expected and user_hash:
                if addr_data.lower() == user_hash.lower():
                    return True, f"Found in output #{i+1}: {value_btc:.8f} BTC to your {addr_type} address"
            
            # Check if address appears as ASCII (some pools do this)
            addr_ascii = btc_address.encode('utf-8').hex()
            if addr_ascii in output['script_hex'].lower():
                return True, f"Found in output #{i+1}: Address as ASCII in script"
        
        return False, "Address not found in any coinbase outputs"
        
    except Exception as e:
        return False, f"Error checking address: {e}"


def validate_bitcoin_address(address: str) -> Tuple[bool, str]:
    """
    Validate a Bitcoin address and return (is_valid, error_message).
    Returns (True, "") if valid, (False, error_message) if invalid.
    """
    import hashlib
    
    # Check basic format
    if not address or len(address) < 26:
        return False, "Address is too short (minimum 26 characters)"
    
    # P2PKH (1...) or P2SH (3...)
    if address.startswith('1') or address.startswith('3'):
        try:
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            
            # Check for invalid characters
            for char in address:
                if char not in alphabet:
                    return False, f"Invalid character '{char}' in address (not valid Base58)"
            
            # Decode
            decoded = 0
            for char in address:
                decoded = decoded * 58 + alphabet.index(char)
            
            decoded_bytes = decoded.to_bytes(25, 'big')
            
            # Verify checksum
            checksum = decoded_bytes[21:25]
            expected_checksum = hashlib.sha256(hashlib.sha256(decoded_bytes[:21]).digest()).digest()[:4]
            
            if checksum != expected_checksum:
                return False, f"Invalid checksum (address may have a typo)"
            
            # Verify version byte
            version = decoded_bytes[0]
            if address.startswith('1') and version != 0:
                return False, f"Invalid version byte for P2PKH address (expected 0, got {version})"
            if address.startswith('3') and version != 5:
                return False, f"Invalid version byte for P2SH address (expected 5, got {version})"
            
            return True, ""
            
        except Exception as e:
            return False, f"Failed to decode address: {str(e)}"
    
    # Bech32 (bc1...)
    elif address.lower().startswith('bc1'):
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        
        # Check for invalid characters
        data_part = address[3:].lower()
        for char in data_part:
            if char not in charset:
                return False, f"Invalid character '{char}' in bech32 address"
        
        # Check length
        if len(address) < 42:
            return False, f"Bech32 address too short (got {len(address)} chars, need at least 42)"
        
        if len(address) > 90:
            return False, f"Bech32 address too long (got {len(address)} chars, max 90)"
        
        # Basic validation passed
        return True, ""
    
    else:
        return False, f"Unrecognized address format (should start with 1, 3, or bc1)"


def generate_random_p2wpkh_address() -> str:
    """
    Generate a random P2WPKH (SegWit) address for testing.
    Returns a valid bc1q... address.
    """
    import hashlib
    import os
    
    # Generate random 20 bytes for the witness program
    random_bytes = os.urandom(20)
    
    # Encode as bech32
    hrp = 'bc'
    witver = 0
    
    # Convert to 5-bit groups
    data = [witver] + convertbits(random_bytes, 8, 5)
    
    # Create checksum
    checksum = bech32_create_checksum(hrp, data, 'bech32')
    
    # Encode
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    combined = data + checksum
    address = hrp + '1' + ''.join([charset[d] for d in combined])
    
    return address


def validate_extranonce1(subscribe_response: dict) -> Dict:
    """
    Validate and analyze extranonce1 from mining.subscribe response.
    
    Returns dict with:
        - exists: Boolean indicating if extranonce1 is present
        - value: Hex string of extranonce1 (or None)
        - size_bytes: Size in bytes (or None)
        - size_bits: Size in bits (or None)
        - as_integer: Integer representation (or None)
        - worker_capacity: Theoretical number of unique workers (or None)
        - warnings: List of warning messages
        - status: 'good', 'warning', or 'critical'
    """
    result = {
        'exists': False,
        'value': None,
        'size_bytes': None,
        'size_bits': None,
        'as_integer': None,
        'worker_capacity': None,
        'warnings': [],
        'status': 'critical'
    }
    
    # Check if extranonce1 exists in response
    if 'result' not in subscribe_response or not isinstance(subscribe_response['result'], list):
        result['warnings'].append("Invalid subscribe response format")
        return result
    
    if len(subscribe_response['result']) < 2:
        result['warnings'].append("Subscribe response missing extranonce1 (result array too short)")
        return result
    
    extranonce1 = subscribe_response['result'][1]
    
    if extranonce1 is None or extranonce1 == '':
        result['warnings'].append("Extranonce1 is empty or null")
        return result
    
    # Extranonce1 exists
    result['exists'] = True
    result['value'] = extranonce1
    result['size_bytes'] = len(extranonce1) // 2  # Hex string to bytes
    result['size_bits'] = result['size_bytes'] * 8
    
    # Convert to integer for analysis
    try:
        result['as_integer'] = int(extranonce1, 16)
    except ValueError:
        result['warnings'].append(f"Invalid hex format: {extranonce1}")
        return result
    
    # Calculate worker capacity (2^bits possible values)
    result['worker_capacity'] = 2 ** result['size_bits']
    
    # Analyze and set warnings/status
    if result['size_bytes'] < 4:
        result['status'] = 'warning'
        result['warnings'].append(f"Small extranonce1 ({result['size_bytes']} bytes) - limited to {result['worker_capacity']:,} unique workers")
        result['warnings'].append("This may indicate a proxy layer or limited infrastructure")
    elif result['size_bytes'] >= 8:
        result['status'] = 'good'
        # No warnings for good size
    else:  # 4-7 bytes
        result['status'] = 'good'
        # Acceptable size, no warnings
    
    return result


def test_extranonce1_uniqueness(host: str, port: int, timeout: int = 10, num_tests: int = 5) -> Dict:
    """
    Test if pool provides unique extranonce1 values for multiple connections.
    
    Returns dict with:
        - extranonce1_values: List of extranonce1 values received
        - unique_count: Number of unique values
        - total_count: Total number of successful connections
        - all_unique: Boolean indicating if all values were unique
        - duplicates: List of duplicate values (if any)
        - pattern: 'sequential', 'random', or 'unknown'
        - warnings: List of warning messages
        - status: 'good', 'warning', or 'critical'
    """
    print("\n" + "=" * 70)
    print("EXTRANONCE1 UNIQUENESS TEST")
    print("=" * 70)
    print(f"\nTesting {host}:{port} with {num_tests} connections...")
    print("This verifies that each connection receives a unique extranonce1 value.")
    print()
    
    extranonce1_values = []
    
    for i in range(num_tests):
        print(f"Connection {i+1}/{num_tests}...", end=" ")
        
        sock, subscribe_response = connect_and_subscribe(host, port, timeout)
        
        if not sock or not subscribe_response:
            print("❌ Failed")
            continue
        
        # Extract extranonce1
        validation = validate_extranonce1(subscribe_response)
        
        if validation['exists']:
            extranonce1_values.append(validation['value'])
            print(f"✓ {validation['value']} ({validation['size_bytes']} bytes)")
        else:
            print("❌ No extranonce1")
        
        sock.close()
        
        # Small delay between connections
        if i < num_tests - 1:
            time.sleep(0.3)
    
    # Analyze results
    result = {
        'extranonce1_values': extranonce1_values,
        'unique_count': len(set(extranonce1_values)),
        'total_count': len(extranonce1_values),
        'all_unique': False,
        'duplicates': [],
        'pattern': 'unknown',
        'warnings': [],
        'status': 'good'
    }
    
    if result['total_count'] == 0:
        result['status'] = 'critical'
        result['warnings'].append("Failed to receive any extranonce1 values")
        print("\n❌ CRITICAL: Could not retrieve extranonce1 from any connection")
        print("=" * 70)
        return result
    
    # Check for uniqueness
    result['all_unique'] = (result['unique_count'] == result['total_count'])
    
    if not result['all_unique']:
        # Find duplicates
        from collections import Counter
        counts = Counter(extranonce1_values)
        result['duplicates'] = [val for val, count in counts.items() if count > 1]
        result['status'] = 'critical'
        result['warnings'].append(f"Found {len(result['duplicates'])} duplicate extranonce1 value(s)")
        result['warnings'].append("CRITICAL: Duplicate extranonce1 can cause work collisions!")
    
    # Detect pattern (sequential vs random)
    if result['all_unique'] and len(extranonce1_values) >= 3:
        try:
            int_values = [int(val, 16) for val in extranonce1_values]
            differences = [int_values[i+1] - int_values[i] for i in range(len(int_values)-1)]
            
            # Check if differences are consistent (sequential)
            if len(set(differences)) == 1 and differences[0] > 0:
                result['pattern'] = 'sequential'
            elif all(d > 0 for d in differences) and max(differences) - min(differences) <= 10:
                result['pattern'] = 'sequential'
            else:
                result['pattern'] = 'random'
        except:
            result['pattern'] = 'unknown'
    
    # Print results
    print()
    print("Results:")
    print("-" * 70)
    print(f"Total connections:      {result['total_count']}")
    print(f"Unique extranonce1:     {result['unique_count']}")
    print(f"All unique:             {'✓ Yes' if result['all_unique'] else '❌ No'}")
    
    if result['duplicates']:
        print(f"Duplicate values:       {', '.join(result['duplicates'])}")
    
    if result['pattern'] != 'unknown':
        print(f"Pattern:                {result['pattern'].capitalize()}")
    
    print()
    
    if result['all_unique']:
        print("✓ PASSED: All extranonce1 values are unique")
        print("  Each connection receives a different extranonce1, which is correct.")
        if result['pattern'] == 'sequential':
            print("  Values are sequential, indicating a counter-based allocation.")
        elif result['pattern'] == 'random':
            print("  Values appear random, indicating random or hash-based allocation.")
    else:
        print("❌ FAILED: Duplicate extranonce1 values detected!")
        print()
        print("  CRITICAL ISSUE: Multiple connections received the same extranonce1.")
        print("  This can cause work collisions where different miners work on identical")
        print("  block candidates, wasting hashrate and potentially causing issues if a")
        print("  block is found.")
        print()
        print("  ⚠️  DO NOT MINE ON THIS POOL - Work collision risk!")
    
    print("=" * 70)
    
    return result


def analyze_pool_architecture(host: str, port: int, timeout: int = 15, num_tests: int = 3) -> Dict:
    """
    Analyze pool architecture to detect potential proxying or performance issues.
    
    Returns dict with:
        - response_times: List of connection response times
        - avg_response_time: Average response time in seconds
        - response_variance: Standard deviation of response times
        - extranonce_size: Size of extranonce1 in bytes
        - likely_proxied: Boolean indicating if pool appears to be proxying
        - indicators: List of strings describing detected indicators
    """
    print("\n" + "=" * 70)
    print("POOL ARCHITECTURE ANALYSIS")
    print("=" * 70)
    print(f"\nAnalyzing {host}:{port} with {num_tests} connection tests...")
    print()
    
    response_times = []
    extranonce_sizes = []
    indicators = []
    
    for i in range(num_tests):
        print(f"Test {i+1}/{num_tests}...", end=" ")
        
        start_time = time.time()
        sock, subscribe_response = connect_and_subscribe(host, port, timeout)
        
        if not sock or not subscribe_response:
            print("❌ Failed")
            continue
        
        elapsed = time.time() - start_time
        response_times.append(elapsed)
        
        # Get extranonce size
        if 'result' in subscribe_response and len(subscribe_response['result']) >= 2:
            extranonce1 = subscribe_response['result'][1]
            extranonce_size = len(extranonce1) // 2  # Hex string to bytes
            extranonce_sizes.append(extranonce_size)
        
        sock.close()
        print(f"✓ {elapsed:.3f}s")
        
        # Small delay between tests
        if i < num_tests - 1:
            time.sleep(0.5)
    
    if not response_times:
        return {
            'response_times': [],
            'avg_response_time': None,
            'response_variance': None,
            'extranonce_size': None,
            'likely_proxied': None,
            'indicators': ['Connection failed - could not analyze']
        }
    
    # Calculate statistics
    avg_time = statistics.mean(response_times)
    variance = statistics.stdev(response_times) if len(response_times) > 1 else 0
    avg_extranonce = statistics.mean(extranonce_sizes) if extranonce_sizes else None
    
    # Analyze indicators
    likely_proxied = False
    
    # Indicator 1: High response time variance
    if variance > 0.5:
        indicators.append(f"High response variance ({variance:.3f}s) - may indicate proxy layer")
        likely_proxied = True
    elif variance > 0.2:
        indicators.append(f"Moderate response variance ({variance:.3f}s)")
    else:
        indicators.append(f"Low response variance ({variance:.3f}s) - consistent performance")
    
    # Indicator 2: Slow average response time
    if avg_time > 1.0:
        indicators.append(f"Slow average response ({avg_time:.3f}s) - may indicate distant server or proxy")
        likely_proxied = True
    elif avg_time > 0.5:
        indicators.append(f"Moderate response time ({avg_time:.3f}s)")
    else:
        indicators.append(f"Fast response time ({avg_time:.3f}s) - direct connection likely")
    
    # Indicator 3: Small extranonce space
    if avg_extranonce and avg_extranonce < 4:
        indicators.append(f"Small extranonce space ({int(avg_extranonce)} bytes) - may indicate proxy")
        likely_proxied = True
    elif avg_extranonce:
        indicators.append(f"Standard extranonce space ({int(avg_extranonce)} bytes)")
    
    # Print results
    print()
    print("Results:")
    print("-" * 70)
    print(f"Average response time:  {avg_time:.3f}s")
    print(f"Response variance:      {variance:.3f}s")
    if avg_extranonce:
        print(f"Extranonce size:        {int(avg_extranonce)} bytes")
    print()
    print("Indicators:")
    for indicator in indicators:
        print(f"  • {indicator}")
    print()
    
    if likely_proxied:
        print("⚠️  ASSESSMENT: Pool may be using proxy layer or load balancer")
        print("   This doesn't necessarily mean they're proxying to another pool,")
        print("   but suggests a more complex infrastructure (multiple backend servers,")
        print("   load balancers, or geographic distribution).")
    else:
        print("✓ ASSESSMENT: Pool appears to be direct connection")
        print("  Fast, consistent responses suggest minimal infrastructure layers.")
    
    print("=" * 70)
    
    return {
        'response_times': response_times,
        'avg_response_time': avg_time,
        'response_variance': variance,
        'extranonce_size': int(avg_extranonce) if avg_extranonce else None,
        'likely_proxied': likely_proxied,
        'indicators': indicators
    }


def test_all_address_types(host: str, port: int, timeout: int, password: str) -> int:
    """
    Test all 5 Bitcoin address types to see which are supported by the pool.
    """
    # Sample addresses for each type (valid test addresses)
    test_addresses = [
        ("P2PKH (Legacy)", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1..."),
        ("P2SH", "3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y", "3..."),
        ("P2WPKH (SegWit)", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "bc1q..."),
        ("P2WSH (SegWit)", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "bc1q... (62 chars)"),
        ("P2TR (Taproot)", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "bc1p..."),
    ]
    
    print("=" * 70)
    print("SOLO MINING POOL VERIFICATION")
    print("=" * 70)
    print()
    print("This tool verifies that a solo mining pool is legitimate by:")
    print()
    print("1. CONNECTING as a mining worker to the pool's stratum server")
    print("2. AUTHORIZING with your Bitcoin address as the username")
    print("3. RECEIVING the block template (mining work) from the pool")
    print("4. PARSING the coinbase transaction to see where block rewards go")
    print("5. VERIFYING your address appears in the coinbase outputs")
    print()
    print("WHY THIS MATTERS:")
    print("In true solo mining, if you find a block, the reward (currently ~3.1 BTC)")
    print("should go directly to YOUR address - not the pool's address. This tool")
    print("confirms the pool is configured correctly by checking the actual block")
    print("template they send to miners.")
    print()
    print("WHAT WE CHECK:")
    print("- The coinbase transaction is the first transaction in every block")
    print("- It contains outputs that specify where the block reward is paid")
    print("- For legitimate solo mining, one output should pay to YOUR address")
    print("- We decode these outputs and verify your address is present")
    print()
    print("RESULTS:")
    print("✅ Address found     - Pool will pay YOU if you find a block (verified!)")
    print("⚠️  Unknown          - Could not verify (pool may require valid credentials)")
    print("❌ Address NOT found - WARNING: Pool may not be legitimate solo mining!")
    print("=" * 70)
    print()
    print("POOL ADDRESS TYPE COMPATIBILITY TEST")
    print(f"Pool: {host}:{port}")
    print()
    print("Testing which Bitcoin address types are supported by this pool...")
    print()
    
    results = []
    
    for addr_name, address, addr_format in test_addresses:
        print(f"Testing {addr_name} ({addr_format})...")
        
        # Longer delay between tests to avoid rate limiting (1 second instead of 0.5)
        if len(results) > 0:
            time.sleep(1.0)
        
        # Try to connect and authorize
        sock, subscribe_response = connect_and_subscribe(host, port, timeout)
        
        if not sock or not subscribe_response:
            print(f"  ❌ Connection failed")
            results.append((addr_name, addr_format, "Connection Failed", None))
            continue
        
        # Try to authorize with this address
        authorized, notify_params, difficulty = authorize_worker(sock, address, password)
        
        if not authorized:
            # Check if it's a connection issue or explicit rejection
            # If we got here, connection worked, so it's likely auth requirements
            print(f"  ⚠️  Authorization failed (may require valid credentials)")
            results.append((addr_name, addr_format, "Unknown ?", None))
            sock.close()
            continue
        
        # Get notify if not received
        if not notify_params:
            notify_params, difficulty = wait_for_mining_notify(sock, timeout)
        
        sock.close()
        
        if not notify_params or len(notify_params) < 9:
            print(f"  ⚠️  Authorized but no block template received")
            results.append((addr_name, addr_format, "Authorized (No Template)", None))
            continue
        
        # Parse outputs
        coinb1 = notify_params[2]
        coinb2 = notify_params[3]
        outputs = parse_coinbase_outputs(coinb2, coinb1)
        
        if not outputs:
            print(f"  ⚠️  Authorized but could not parse outputs")
            results.append((addr_name, addr_format, "Authorized (Parse Error)", None))
            continue
        
        # Verify address in outputs
        found, details = verify_address_in_outputs(outputs, address)
        
        if found:
            print(f"  ✅ Supported and verified in coinbase")
            results.append((addr_name, addr_format, "Supported ✓", details))
        else:
            print(f"  ❌ Address NOT found in coinbase")
            results.append((addr_name, addr_format, "Not Found X", outputs))
        
        print()
    
    # Print summary table
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    print(f"{'Address Type':<25} {'Format':<20} {'Result':<10}")
    print("-" * 70)
    
    for addr_name, addr_format, status, details in results:
        # Convert status to symbol
        if "Supported ✓" in status:
            symbol = "✓"
        elif "Not Found X" in status:
            symbol = "X"
        elif "Unknown ?" in status:
            symbol = "?"
        elif "Connection Failed" in status:
            symbol = "ERR"
        else:
            symbol = "?"
        
        print(f"{addr_name:<25} {addr_format:<20} {symbol:<10}")
    
    print()
    print("Legend:")
    print("  ✓   = Supported and verified in coinbase")
    print("  X   = Address NOT found in coinbase (WARNING: may not be legitimate!)")
    print("  ?   = Unknown (may require valid mining credentials)")
    print("  ERR = Connection error")
    print()
    
    # Count supported types
    supported_count = sum(1 for _, _, status, _ in results if "Supported ✓" in status)
    not_found_count = sum(1 for _, _, status, _ in results if "Not Found X" in status)
    unknown_count = sum(1 for _, _, status, _ in results if "Unknown ?" in status)
    
    # Show warnings for addresses not found in coinbase
    if not_found_count > 0:
        print("=" * 70)
        print("⚠️  WARNING: ADDRESS NOT FOUND IN COINBASE")
        print("=" * 70)
        print()
        print(f"{not_found_count} address type(s) were authorized but NOT found in the coinbase outputs.")
        print()
        print("This means:")
        print("  • The pool accepted your address for mining")
        print("  • BUT the block reward is NOT going to your address")
        print("  • The pool may be paying to their own address instead")
        print()
        print("⚠️  WARNING: This pool may not be legitimate solo mining!")
        print()
        print("Possible reasons:")
        print("  1. The pool is paying to their own address (not solo mining)")
        print("  2. The pool uses a different payout mechanism")
        print("  3. The test addresses don't match the pool's expected format")
        print()
        print("⚠️  Do NOT mine on this pool until you verify it's legitimate!")
        print("   Try testing with YOUR actual mining address to confirm.")
        print()
        print("Addresses NOT found in coinbase:")
        for addr_name, addr_format, status, outputs in results:
            if "Not Found X" in status:
                print(f"  • {addr_name} ({addr_format})")
                if outputs:
                    print(f"    Coinbase is paying to:")
                    for i, output in enumerate(outputs, 1):
                        if output['value_satoshis'] > 0:
                            addr = hash_to_address(output['address_data'], output['address_type'])
                            if addr and len(addr) > 40:
                                addr = addr[:20] + "..." + addr[-17:]
                            print(f"      Output #{i}: {output['address_type']} → {addr or output['address_type']}")
        print()
        print("=" * 70)
        print()
    
    if supported_count == 0 and unknown_count == 0 and not_found_count == 0:
        print("⚠️  WARNING: No address types were verified!")
        print("   This pool may not support solo mining or has connection issues.")
        return 1
    elif supported_count == 0 and unknown_count > 0:
        print(f"⚠️  Could not verify address types ({unknown_count} unknown).")
        print("   This pool may require valid mining credentials to test.")
        print("   Try testing with your actual mining address and credentials.")
        return 2
    elif supported_count == 0 and not_found_count > 0:
        print(f"⚠️  CRITICAL: {not_found_count} address type(s) NOT found in coinbase!")
        print("   This pool is likely NOT legitimate solo mining.")
        return 1
    elif supported_count < 3:
        print(f"✓ Pool supports {supported_count} address type(s).")
        if unknown_count > 0:
            print(f"  ({unknown_count} type(s) could not be verified)")
        if not_found_count > 0:
            print(f"  ⚠️  {not_found_count} type(s) NOT found in coinbase")
        return 0
    else:
        print(f"✓ Pool supports {supported_count} address type(s).")
        if unknown_count > 0:
            print(f"  ({unknown_count} type(s) could not be verified)")
        if not_found_count > 0:
            print(f"  ⚠️  {not_found_count} type(s) NOT found in coinbase")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description='Verify that a solo mining pool is paying to your address',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Test pool connectivity (uses random address):
    python3 verify_pool.py solo.atlaspool.io 3333
    python3 verify_pool.py solo.ckpool.org 3333
  
  Verify AtlasPool with your bech32 address (bc1q...):
    python3 verify_pool.py solo.atlaspool.io 3333 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
  
  Verify CKPool with your legacy address (1...):
    python3 verify_pool.py solo.ckpool.org 3333 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  
  Test which address types a pool supports:
    python3 verify_pool.py solo.atlaspool.io 3333 -a
    python3 verify_pool.py solo.ckpool.org 3333 --all-types
  
  Test extranonce1 uniqueness (detect work collisions):
    python3 verify_pool.py solo.atlaspool.io 3333 --test-extranonce
    python3 verify_pool.py solo.ckpool.org 3333 --test-extranonce
  
  Analyze pool architecture (detect proxying):
    python3 verify_pool.py solo-ca.solohash.co.uk 3333 --analyze
    python3 verify_pool.py solo.atlaspool.io 3333 --analyze
  
  Test slow pool with increased timeout and retries:
    python3 verify_pool.py slow-pool.example.com 3333 --timeout 60 --retries 3

Supported address types:
  • P2PKH (Legacy):     1...  (e.g., 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
  • P2SH:               3...  (e.g., 3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y)
  • P2WPKH (SegWit):    bc1q... (e.g., bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh)
  • P2WSH (SegWit):     bc1q... (longer, 62 chars)
  • P2TR (Taproot):     bc1p... (e.g., bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr)

Note: This tool performs a basic verification. For complete security, you should
      also verify the block template against Bitcoin Core's getblocktemplate.
        """
    )
    
    parser.add_argument('host', help='Pool hostname (e.g., solo.atlaspool.io)')
    parser.add_argument('port', type=int, help='Pool port (e.g., 3333)')
    parser.add_argument('address', nargs='?', default=None, 
                        help='Your Bitcoin address (optional - generates random P2WPKH if omitted)')
    parser.add_argument('-a', '--all-types', action='store_true', 
                        help='Test all 5 address types to see which are supported by the pool')
    parser.add_argument('--analyze', action='store_true',
                        help='Analyze pool architecture (detect proxying, measure performance)')
    parser.add_argument('--test-extranonce', action='store_true',
                        help='Test extranonce1 uniqueness across multiple connections')
    parser.add_argument('--username', help='Username (defaults to your address)')
    parser.add_argument('--password', default='x', help='Password (default: x)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds (default: 30)')
    parser.add_argument('--retries', type=int, default=2, help='Number of retries for slow pools (default: 2)')
    
    args = parser.parse_args()
    
    # Check for known scam pools
    scam_pools = ['zsolo.bid', 'luckymonster.pro']
    if any(scam in args.host.lower() for scam in scam_pools):
        print("="*70)
        print("⚠️  WARNING: KNOWN SCAM POOL DETECTED")
        print("="*70)
        print()
        print(f"The pool '{args.host}' is a confirmed scam operation.")
        print()
        print("EVIDENCE:")
        print("  • Mining Bitcoin Cash (BCH) while claiming to mine Bitcoin (BTC)")
        print("  • Stealing 100% of miners' hashrate for their own BCH rewards")
        print("  • Never updates to new Bitcoin blocks")
        print("  • Prevhash found on BCH blockchain, not BTC blockchain")
        print()
        print("DO NOT MINE ON THIS POOL!")
        print()
        print("For complete analysis and proof, see:")
        print("  https://github.com/mweinberg/stratum-speed-test/tree/main/findings")
        print()
        print("="*70)
        sys.exit(1)
    
    # Validate arguments
    if args.all_types and args.address:
        print("Error: Cannot use both --all-types and specify an address", file=sys.stderr)
        sys.exit(1)
    
    if args.analyze and args.all_types:
        print("Error: Cannot use both --analyze and --all-types", file=sys.stderr)
        sys.exit(1)
    
    if args.test_extranonce and args.all_types:
        print("Error: Cannot use both --test-extranonce and --all-types", file=sys.stderr)
        sys.exit(1)
    
    # Handle --test-extranonce mode
    if args.test_extranonce:
        result = test_extranonce1_uniqueness(args.host, args.port, args.timeout, num_tests=5)
        return 0 if result['status'] != 'critical' else 1
    
    # Handle --analyze mode
    if args.analyze:
        result = analyze_pool_architecture(args.host, args.port, args.timeout)
        return 0 if result['response_times'] else 1
    
    # Handle --all-types mode
    if args.all_types:
        return test_all_address_types(args.host, args.port, args.timeout, args.password)
    
    # Generate random address if none provided
    if not args.address:
        args.address = generate_random_p2wpkh_address()
        print("=" * 70)
        print("No address provided - using random P2WPKH address for testing")
        print("=" * 70)
        print(f"Generated address: {args.address}")
        print()
        print("Note: This is for testing pool connectivity and coinbase parsing.")
        print("      Use your actual address to verify it will receive payouts.")
        print()
    
    # Validate the Bitcoin address
    is_valid, error_msg = validate_bitcoin_address(args.address)
    if not is_valid:
        print("=" * 70)
        print("❌ INVALID BITCOIN ADDRESS")
        print("=" * 70)
        print()
        print(f"Address: {args.address}")
        print(f"Error:   {error_msg}")
        print()
        print("Please check your address and try again.")
        print()
        print("Valid address formats:")
        print("  • P2PKH (Legacy):  Starts with '1' (e.g., 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)")
        print("  • P2SH:            Starts with '3' (e.g., 3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y)")
        print("  • P2WPKH (SegWit): Starts with 'bc1q' (e.g., bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh)")
        print("  • P2WSH (SegWit):  Starts with 'bc1q' (longer)")
        print("  • P2TR (Taproot):  Starts with 'bc1p'")
        print()
        return 1
    
    username = args.username or args.address
    
    print("=" * 70)
    print("SOLO MINING POOL VERIFICATION")
    print("=" * 70)
    print()
    print("This tool verifies that a solo mining pool is legitimate by:")
    print()
    print("1. CONNECTING as a mining worker to the pool's stratum server")
    print("2. AUTHORIZING with your Bitcoin address as the username")
    print("3. RECEIVING the block template (mining work) from the pool")
    print("4. PARSING the coinbase transaction to see where block rewards go")
    print("5. VERIFYING your address appears in the coinbase outputs")
    print()
    print("WHY THIS MATTERS:")
    print("In true solo mining, if you find a block, the reward (currently ~3.1 BTC)")
    print("should go directly to YOUR address - not the pool's address. This tool")
    print("confirms the pool is configured correctly by checking the actual block")
    print("template they send to miners.")
    print()
    print("WHAT WE CHECK:")
    print("- The coinbase transaction is the first transaction in every block")
    print("- It contains outputs that specify where the block reward is paid")
    print("- For legitimate solo mining, one output should pay to YOUR address")
    print("- We decode these outputs and verify your address is present")
    print()
    print("RESULTS:")
    print("✅ Address found     - Pool will pay YOU if you find a block (verified!)")
    print("⚠️  Unknown          - Could not verify (pool may require valid credentials)")
    print("❌ Address NOT found - WARNING: Pool may not be legitimate solo mining!")
    print("=" * 70)
    print()
    print(f"Pool:    {args.host}:{args.port}")
    print(f"Address: {args.address}")
    print(f"Username: {username}")
    print()
    
    # Step 1: Connect and subscribe
    print("[1/4] Connecting to pool...")
    sock, subscribe_response = connect_and_subscribe(args.host, args.port, args.timeout)
    
    if not sock:
        print("❌ Failed to connect to pool")
        return 1
    
    if not subscribe_response or 'result' not in subscribe_response:
        print("❌ Invalid subscribe response")
        sock.close()
        return 1
    
    print("✓ Connected successfully")
    print(f"    Subscription ID: {subscribe_response.get('id')}")
    
    # Validate and display extranonce1
    print("\n[1.5/5] Validating extranonce1...")
    extranonce1_info = validate_extranonce1(subscribe_response)
    
    if not extranonce1_info['exists']:
        print("❌ Extranonce1 missing or invalid")
        for warning in extranonce1_info['warnings']:
            print(f"    ⚠️  {warning}")
        sock.close()
        return 1
    
    print("✓ Extranonce1 received")
    print(f"    Value (hex):     {extranonce1_info['value']}")
    print(f"    Value (int):     {extranonce1_info['as_integer']:,}")
    print(f"    Size:            {extranonce1_info['size_bytes']} bytes ({extranonce1_info['size_bits']} bits)")
    print(f"    Worker capacity: {extranonce1_info['worker_capacity']:,} unique workers")
    
    # Display warnings if any
    if extranonce1_info['warnings']:
        for warning in extranonce1_info['warnings']:
            print(f"    ⚠️  {warning}")
    
    # Status indicator
    if extranonce1_info['status'] == 'good':
        print(f"    Status:          ✓ Good")
    elif extranonce1_info['status'] == 'warning':
        print(f"    Status:          ⚠️  Warning")
    else:
        print(f"    Status:          ❌ Critical")
    
    # Step 2: Authorize
    print("\n[2/5] Authorizing worker...")
    authorized, notify_params, difficulty = authorize_worker(sock, username, args.password)
    
    if not authorized:
        print("❌ Authorization failed")
        sock.close()
        return 1
    
    print("✓ Worker authorized")
    
    # Step 3: Wait for mining.notify (if not already received)
    if notify_params:
        print("\n[3/5] Block template received with authorization ✓")
    else:
        print("\n[3/5] Waiting for block template (mining.notify)...")
        print(f"    (timeout: {args.timeout} seconds, retries: {args.retries})")
        
        # Try with retries for slow pools
        for retry in range(args.retries + 1):
            notify_params, diff = wait_for_mining_notify(sock, args.timeout, retry_count=retry)
            if diff is not None:
                difficulty = diff
            if notify_params:
                break
            
            # If not last retry, reconnect and try again
            if retry < args.retries:
                print(f"    Reconnecting for retry {retry + 1}...")
                sock.close()
                
                sock, subscribe_response = connect_and_subscribe(args.host, args.port, args.timeout)
                if not sock:
                    print("❌ Reconnection failed")
                    return 1
                
                authorized, notify_params, diff = authorize_worker(sock, username, args.password)
                if diff is not None:
                    difficulty = diff
                if notify_params:
                    print(f"    ✓ Received on reconnect (retry {retry + 1})")
                    break
    
    sock.close()
    
    if not notify_params:
        print(f"❌ Did not receive mining.notify after {args.retries + 1} attempts")
        print("    This pool may be very slow or not responding properly.")
        print("    Try increasing --timeout or --retries, or test a different pool.")
        return 1
    
    print("✓ Received block template")
    
    # Display difficulty if captured
    if difficulty is not None:
        print(f"    Pool difficulty: {difficulty:,.0f}")
    
    # Parse notify params
    # Format: [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
    if len(notify_params) < 9:
        print(f"❌ Invalid notify format (expected 9 params, got {len(notify_params)})")
        return 1
    
    job_id = notify_params[0]
    prevhash = notify_params[1]
    coinb1 = notify_params[2]
    coinb2 = notify_params[3]
    
    print(f"    Job ID: {job_id}")
    print(f"    Previous block: {prevhash[:16]}...{prevhash[-16:]}")
    print(f"    Coinbase part 1 length: {len(coinb1)} chars")
    print(f"    Coinbase part 2 length: {len(coinb2)} chars")
    
    # Parse coinbase script for block height and pool signature
    print("\n[4/5] Parsing coinbase script (block height & pool signature)...")
    
    # Parse coinb1 (beginning of script)
    script_info = parse_coinbase_script(coinb1)
    
    if 'error' in script_info:
        print(f"    ⚠️  Could not parse coinbase script prefix: {script_info['error']}")
    else:
        if script_info['block_height'] is not None:
            print(f"    Block height: {script_info['block_height']:,}")
    
    # Parse coinb2 (end of script - where pool signature usually is)
    script_suffix = parse_coinbase_script_suffix(coinb2)
    
    if 'error' not in script_suffix:
        if script_suffix['readable_strings']:
            print(f"    Pool signature: {', '.join(script_suffix['readable_strings'])}")
        
        # Show full script suffix if it has readable content
        if script_suffix['script_suffix_ascii'].strip('.'):
            ascii_text = script_suffix['script_suffix_ascii']
            # Only show if there's meaningful content
            readable_portion = ''.join(c for c in ascii_text if c.isprintable() and c not in '.')
            if len(readable_portion) >= 3:
                print(f"    Script suffix (ASCII): {ascii_text[:80]}")
                if len(ascii_text) > 80:
                    print(f"                           {ascii_text[80:160]}")
    
    # Step 5: Parse and verify coinbase outputs
    print("\n[5/5] Parsing coinbase transaction outputs...")
    
    # Parse the outputs from coinb2
    outputs = parse_coinbase_outputs(coinb2, coinb1)
    
    if not outputs:
        print("❌ Could not parse coinbase outputs")
        print("\nCoinbase hex (first 200 chars):")
        print(f"  {coinb1 + coinb2[:200]}...")
        return 1
    
    print(f"    Found {len(outputs)} output(s) in coinbase:")
    print()
    
    # Calculate total value (excluding OP_RETURN which has 0 value)
    total_value = sum(o['value_satoshis'] for o in outputs)
    
    for i, output in enumerate(outputs, 1):
        print(f"    Output #{i}:")
        
        # Show amount with percentage
        value_btc = output['value_btc']
        value_sats = output['value_satoshis']
        
        if total_value > 0 and value_sats > 0:
            percentage = (value_sats / total_value) * 100
            print(f"      Amount:  {value_btc:.8f} BTC ({value_sats:,} sats) - {percentage:.2f}%")
        else:
            print(f"      Amount:  {value_btc:.8f} BTC ({value_sats:,} sats)")
        
        print(f"      Type:    {output['address_type']}")
        
        if output['address_type'] == 'OP_RETURN':
            # Show OP_RETURN data (usually witness commitment or pool metadata)
            data_hex = output['address_data']
            print(f"      Purpose: Witness commitment (SegWit) or pool metadata")
            print(f"      Data:    {data_hex[:60]}{'...' if len(data_hex) > 60 else ''}")
            # Try to decode as ASCII
            try:
                data_bytes = bytes.fromhex(data_hex)
                ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_bytes)
                if ascii_text.strip('.'):
                    print(f"      ASCII:   {ascii_text[:60]}")
            except:
                pass
        elif output['address_type'] != 'unknown':
            # Show both hash and readable address
            print(f"      Hash:    {output['address_data']}")
            address = hash_to_address(output['address_data'], output['address_type'])
            if address and address != output['address_data']:
                print(f"      Address: {address}")
        else:
            # Unknown script type - show raw hex
            print(f"      Script:  {output['address_data'][:60]}{'...' if len(output['address_data']) > 60 else ''}")
        
        print()
    
    # Show summary if multiple paying outputs
    paying_outputs = [o for o in outputs if o['value_satoshis'] > 0]
    if len(paying_outputs) > 1:
        print("    " + "=" * 66)
        print("    PAYOUT BREAKDOWN:")
        for i, output in enumerate(outputs, 1):
            if output['value_satoshis'] > 0:
                percentage = (output['value_satoshis'] / total_value) * 100
                addr = hash_to_address(output['address_data'], output['address_type'])
                if addr and len(addr) > 40:
                    addr = addr[:20] + "..." + addr[-17:]
                print(f"      Output #{i}: {percentage:5.2f}% → {addr or output['address_type']}")
        print("    " + "=" * 66)
        print()
    
    # Verify if user's address is in the outputs
    found, details = verify_address_in_outputs(outputs, args.address)
    
    print("=" * 70)
    if found:
        print("✅ VERIFICATION PASSED - YOUR ADDRESS FOUND!")
        print("=" * 70)
        print(f"\n{details}")
        print(f"\nYour address ({args.address}) is in the coinbase outputs.")
        print("This pool is paying directly to your address.")
        print("\n✓ This is legitimate solo mining!")
        print("\n⚠️  Note: This verifies the block template. Always monitor actual")
        print("   payouts to ensure the pool is functioning correctly.")
        return 0
    else:
        print("❌ VERIFICATION FAILED - ADDRESS NOT FOUND")
        print("=" * 70)
        print(f"\n{details}")
        print(f"\nYour address ({args.address}) was NOT found in the coinbase outputs.")
        print("\nThe coinbase is paying to:")
        for i, output in enumerate(outputs, 1):
            if output['address_type'] not in ['OP_RETURN', 'unknown']:
                address = hash_to_address(output['address_data'], output['address_type'])
                if address and address != output['address_data']:
                    print(f"  Output #{i}: {output['address_type']} → {address}")
                else:
                    print(f"  Output #{i}: {output['address_type']} {output['address_data']}")
        print("\n⚠️  WARNING: This pool may not be legitimate solo mining!")
        print("\nPossible reasons:")
        print("  1. The pool is paying to their own address (not solo mining)")
        print("  2. You provided the wrong address or format")
        print("  3. The pool uses a different payout mechanism")
        print("\n⚠️  Do NOT mine on this pool until you verify it's legitimate!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
