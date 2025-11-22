#!/usr/bin/env python3
"""
Solo Mining Pool Verification Tool

Connects to a stratum pool as a worker and verifies that the block template
contains your Bitcoin address in the coinbase transaction. This helps ensure
the pool is actually solo mining (paying you directly) rather than pool mining.

The tool can verify a specific address or test all 5 Bitcoin address types:
  • P2PKH (Legacy):     1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  • P2SH (Script Hash): 3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y
  • P2WPKH (SegWit):    bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
  • P2WSH (SegWit):     bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
  • P2TR (Taproot):     bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr

Usage:
    # Verify a specific address
    python3 verify_pool.py <pool_host> <pool_port> <your_btc_address>
    
    # Test all address types (-a flag)
    python3 verify_pool.py <pool_host> <pool_port> -a

Examples:
    python3 verify_pool.py solo.atlaspool.io 3333 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    python3 verify_pool.py solo.ckpool.org 3333 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    python3 verify_pool.py solo.atlaspool.io 3333 -a

Version: 1.0
"""

import socket
import json
import sys
import time
import binascii
import argparse
from typing import Optional, Tuple


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


def authorize_worker(sock: socket.socket, username: str, password: str = "x") -> Tuple[bool, Optional[dict]]:
    """
    Send mining.authorize with username (typically your BTC address).
    Returns (authorized, mining_notify_params) - notify may be None.
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
            return False, None
        
        authorized = False
        notify_params = None
        
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
                except json.JSONDecodeError:
                    continue
        
        return authorized, notify_params
        
    except Exception as e:
        return False, None


def wait_for_mining_notify(sock: socket.socket, timeout: int = 15) -> Optional[dict]:
    """
    Wait for mining.notify message containing the block template.
    Returns the notify params or None.
    """
    try:
        sock.settimeout(timeout)
        
        # May need to receive multiple messages
        buffer = ""
        while True:
            try:
                chunk = sock.recv(8192).decode('utf-8')
            except socket.timeout:
                print("    Timeout - no mining.notify received")
                return None
                
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
                            return data.get('params')
                        
                        # Also check for mining.set_difficulty
                        if data.get('method') == 'mining.set_difficulty':
                            print(f"    Received difficulty: {data.get('params', [None])[0]}")
                            
                    except json.JSONDecodeError:
                        continue
        
        return None
        
    except Exception as e:
        print(f"Error receiving notify: {e}")
        return None


def parse_coinbase_outputs(coinb2_hex: str) -> list:
    """
    Parse the outputs from coinbase transaction (coinb2).
    Returns list of output dictionaries.
    
    Coinb2 structure: [extranonce_placeholder][sequence: 4 bytes][output_count][outputs...][locktime: 4 bytes]
    Each output: [8 bytes value][1-9 bytes script_len][script]
    """
    try:
        coinb2_bytes = binascii.unhexlify(coinb2_hex)
        outputs = []
        
        # Find the sequence number (ffffffff) which marks end of input
        # Then outputs start after that
        pos = 0
        found_sequence = False
        
        # Look for ffffffff (sequence number)
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


def witness_program_to_address(witness_program_hex: str, version: int = 0) -> str:
    """
    Convert witness program to bech32 address.
    Simplified - doesn't do full bech32 encoding.
    """
    # For comparison purposes, just return the hex
    return witness_program_hex


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
        authorized, notify_params = authorize_worker(sock, address, password)
        
        if not authorized:
            # Check if it's a connection issue or explicit rejection
            # If we got here, connection worked, so it's likely auth requirements
            print(f"  ⚠️  Authorization failed (may require valid credentials)")
            results.append((addr_name, addr_format, "Unknown ?", None))
            sock.close()
            continue
        
        # Get notify if not received
        if not notify_params:
            notify_params = wait_for_mining_notify(sock, timeout)
        
        sock.close()
        
        if not notify_params or len(notify_params) < 9:
            print(f"  ⚠️  Authorized but no block template received")
            results.append((addr_name, addr_format, "Authorized (No Template)", None))
            continue
        
        # Parse outputs
        coinb2 = notify_params[3]
        outputs = parse_coinbase_outputs(coinb2)
        
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
            print(f"  ⚠️  Authorized but address not in coinbase")
            results.append((addr_name, addr_format, "Authorized (Not in Coinbase)", None))
        
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
        elif "Unknown ?" in status:
            symbol = "?"
        elif "Connection Failed" in status:
            symbol = "ERR"
        elif "Not Supported" in status:
            symbol = "X"
        else:
            symbol = "?"
        
        print(f"{addr_name:<25} {addr_format:<20} {symbol:<10}")
    
    print()
    print("Legend:")
    print("  ✓   = Supported and verified in coinbase")
    print("  ?   = Unknown (may require valid mining credentials)")
    print("  X   = Not supported (pool rejected address type)")
    print("  ERR = Connection error")
    print()
    
    # Count supported types
    supported_count = sum(1 for _, _, status, _ in results if "Supported ✓" in status)
    unknown_count = sum(1 for _, _, status, _ in results if "Unknown ?" in status)
    
    if supported_count == 0 and unknown_count == 0:
        print("⚠️  WARNING: No address types were verified!")
        print("   This pool may not support solo mining or has connection issues.")
        return 1
    elif supported_count == 0 and unknown_count > 0:
        print(f"⚠️  Could not verify address types ({unknown_count} unknown).")
        print("   This pool may require valid mining credentials to test.")
        print("   Try testing with your actual mining address and credentials.")
        return 2
    elif supported_count < 3:
        print(f"✓ Pool supports {supported_count} address type(s).")
        if unknown_count > 0:
            print(f"  ({unknown_count} type(s) could not be verified)")
        return 0
    else:
        print(f"✓ Pool supports {supported_count} address type(s).")
        if unknown_count > 0:
            print(f"  ({unknown_count} type(s) could not be verified)")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description='Verify that a solo mining pool is paying to your address',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Verify AtlasPool with bech32 address (bc1q...):
    python3 verify_pool.py solo.atlaspool.io 3333 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
  
  Verify CKPool with legacy address (1...):
    python3 verify_pool.py solo.ckpool.org 3333 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  
  Test which address types a pool supports:
    python3 verify_pool.py solo.atlaspool.io 3333 -a
    python3 verify_pool.py solo.ckpool.org 3333 --all-types

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
    parser.add_argument('address', nargs='?', help='Your Bitcoin address')
    parser.add_argument('-a', '--all-types', action='store_true', 
                        help='Test all 5 address types to see which are supported by the pool')
    parser.add_argument('--username', help='Username (defaults to your address)')
    parser.add_argument('--password', default='x', help='Password (default: x)')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout in seconds (default: 15)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.all_types and args.address:
        print("Error: Cannot use both --all-types and specify an address", file=sys.stderr)
        sys.exit(1)
    
    if not args.all_types and not args.address:
        print("Error: Must provide either an address or use --all-types", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    # Handle --all-types mode
    if args.all_types:
        return test_all_address_types(args.host, args.port, args.timeout, args.password)
    
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
    
    # Step 2: Authorize
    print("\n[2/4] Authorizing worker...")
    authorized, notify_params = authorize_worker(sock, username, args.password)
    
    if not authorized:
        print("❌ Authorization failed")
        sock.close()
        return 1
    
    print("✓ Worker authorized")
    
    # Step 3: Wait for mining.notify (if not already received)
    if notify_params:
        print("\n[3/4] Block template received with authorization ✓")
    else:
        print("\n[3/4] Waiting for block template (mining.notify)...")
        print(f"    (timeout: {args.timeout} seconds)")
        
        notify_params = wait_for_mining_notify(sock, args.timeout)
    
    sock.close()
    
    if not notify_params:
        print("❌ Did not receive mining.notify")
        return 1
    
    print("✓ Received block template")
    
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
    
    # Step 4: Parse and verify coinbase outputs
    print("\n[4/4] Parsing coinbase transaction outputs...")
    
    # Parse the outputs from coinb2
    outputs = parse_coinbase_outputs(coinb2)
    
    if not outputs:
        print("❌ Could not parse coinbase outputs")
        print("\nCoinbase hex (first 200 chars):")
        print(f"  {coinb1 + coinb2[:200]}...")
        return 1
    
    print(f"    Found {len(outputs)} output(s) in coinbase:")
    print()
    
    for i, output in enumerate(outputs, 1):
        print(f"    Output #{i}:")
        print(f"      Amount: {output['value_btc']:.8f} BTC ({output['value_satoshis']:,} sats)")
        print(f"      Type:   {output['address_type']}")
        if output['address_type'] != 'OP_RETURN':
            print(f"      Data:   {output['address_data']}")
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
