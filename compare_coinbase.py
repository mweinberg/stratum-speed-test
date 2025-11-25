#!/usr/bin/env python3
"""
Compare Coinbase Structure Between Pools

This script connects to two mining pools and compares their coinbase
transaction structures to identify similarities or differences.
"""

import socket
import json
import sys
import time
import binascii
import argparse


def get_coinbase_from_pool(host, port, timeout=10):
    """
    Connect to a pool and retrieve the coinbase structure.
    Returns (coinb1, coinb2, notify_params) or (None, None, None) on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Subscribe
        subscribe_msg = json.dumps({
            "id": 1,
            "method": "mining.subscribe",
            "params": ["compare_coinbase/1.0"]
        }) + "\n"
        sock.sendall(subscribe_msg.encode('utf-8'))
        time.sleep(0.2)
        
        # Authorize with a Bitcoin address (some pools require this)
        auth_msg = json.dumps({
            "id": 2,
            "method": "mining.authorize",
            "params": ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "x"]
        }) + "\n"
        sock.sendall(auth_msg.encode('utf-8'))
        time.sleep(0.8)
        
        # Read responses
        response_parts = []
        sock.settimeout(3)
        
        try:
            for _ in range(3):
                chunk = sock.recv(8192).decode('utf-8')
                if chunk:
                    response_parts.append(chunk)
                time.sleep(0.1)
        except socket.timeout:
            pass
        
        sock.close()
        
        response = ''.join(response_parts)
        
        # Parse for mining.notify
        for line in response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('method') == 'mining.notify':
                        params = data.get('params')
                        if params and len(params) >= 9:
                            coinb1 = params[2]
                            coinb2 = params[3]
                            return coinb1, coinb2, params
                except json.JSONDecodeError:
                    continue
        
        return None, None, None
        
    except Exception as e:
        print(f"Error connecting to {host}:{port}: {e}", file=sys.stderr)
        return None, None, None


def analyze_coinbase_structure(coinb1_hex, coinb2_hex, pool_name):
    """
    Analyze the structure of a coinbase transaction.
    Returns a dict with structural information.
    """
    try:
        coinb1 = binascii.unhexlify(coinb1_hex)
        coinb2 = binascii.unhexlify(coinb2_hex)
        
        analysis = {
            'pool': pool_name,
            'coinb1_len': len(coinb1),
            'coinb2_len': len(coinb2),
            'coinb1_hex': coinb1_hex,
            'coinb2_hex': coinb2_hex,
        }
        
        # Parse coinb1 structure
        if len(coinb1) >= 42:
            analysis['version'] = coinb1[0:4].hex()
            analysis['input_count'] = coinb1[4]
            analysis['prev_hash'] = coinb1[5:37].hex()
            analysis['prev_index'] = coinb1[37:41].hex()
            analysis['script_len'] = coinb1[41]
            analysis['script_in_coinb1'] = len(coinb1) - 42
            analysis['coinb1_last_8_bytes'] = coinb1[-8:].hex()
            analysis['coinb1_last_4_bytes'] = coinb1[-4:].hex()
        
        # Analyze coinb2 structure
        analysis['coinb2_first_8_bytes'] = coinb2[:8].hex()
        analysis['coinb2_first_4_bytes'] = coinb2[:4].hex()
        analysis['coinb2_byte_0'] = coinb2[0]
        
        # Check for sequence marker (0xffffffff)
        has_sequence = False
        sequence_pos = -1
        for i in range(len(coinb2) - 3):
            if coinb2[i:i+4] == b'\xff\xff\xff\xff':
                has_sequence = True
                sequence_pos = i
                break
        
        analysis['has_standard_sequence'] = has_sequence
        analysis['sequence_position'] = sequence_pos
        
        # Try to identify format
        if coinb2[0] in range(1, 11):  # Looks like output_count
            # Possible zsolo format
            analysis['likely_format'] = 'zsolo-style'
            analysis['format_description'] = '[output_count][extranonce?][value][outputs]'
        elif has_sequence:
            # Standard format
            analysis['likely_format'] = 'standard'
            analysis['format_description'] = '[script?][extranonce][sequence][output_count][outputs]'
        else:
            analysis['likely_format'] = 'unknown'
            analysis['format_description'] = 'Non-standard format'
        
        return analysis
        
    except Exception as e:
        return {'error': str(e), 'pool': pool_name}


def compare_structures(analysis1, analysis2):
    """
    Compare two coinbase structures and report similarities/differences.
    """
    print("=" * 80)
    print("COINBASE STRUCTURE COMPARISON")
    print("=" * 80)
    print()
    
    # Basic info
    print(f"Pool 1: {analysis1['pool']}")
    print(f"Pool 2: {analysis2['pool']}")
    print()
    
    # Length comparison
    print("LENGTH COMPARISON:")
    print(f"  coinb1: {analysis1['coinb1_len']} bytes vs {analysis2['coinb1_len']} bytes", end="")
    if analysis1['coinb1_len'] == analysis2['coinb1_len']:
        print(" ✓ SAME")
    else:
        print(f" ✗ DIFFERENT (Δ{abs(analysis1['coinb1_len'] - analysis2['coinb1_len'])} bytes)")
    
    print(f"  coinb2: {analysis1['coinb2_len']} bytes vs {analysis2['coinb2_len']} bytes", end="")
    if analysis1['coinb2_len'] == analysis2['coinb2_len']:
        print(" ✓ SAME")
    else:
        print(f" ✗ DIFFERENT (Δ{abs(analysis1['coinb2_len'] - analysis2['coinb2_len'])} bytes)")
    print()
    
    # Format comparison
    print("FORMAT COMPARISON:")
    print(f"  Pool 1 format: {analysis1['likely_format']}")
    print(f"  Pool 2 format: {analysis2['likely_format']}")
    
    if analysis1['likely_format'] == analysis2['likely_format']:
        print("  ✓ SAME FORMAT TYPE")
    else:
        print("  ✗ DIFFERENT FORMAT TYPES")
    print()
    
    # Sequence marker
    print("SEQUENCE MARKER (0xffffffff):")
    print(f"  Pool 1: {'Found' if analysis1['has_standard_sequence'] else 'NOT FOUND'}", end="")
    if analysis1['has_standard_sequence']:
        print(f" at position {analysis1['sequence_position']}")
    else:
        print()
    
    print(f"  Pool 2: {'Found' if analysis2['has_standard_sequence'] else 'NOT FOUND'}", end="")
    if analysis2['has_standard_sequence']:
        print(f" at position {analysis2['sequence_position']}")
    else:
        print()
    
    if analysis1['has_standard_sequence'] == analysis2['has_standard_sequence']:
        print("  ✓ SAME")
    else:
        print("  ✗ DIFFERENT")
    print()
    
    # coinb2 first bytes
    print("COINB2 STRUCTURE:")
    print(f"  Pool 1 first 4 bytes: {analysis1['coinb2_first_4_bytes']}")
    print(f"  Pool 2 first 4 bytes: {analysis2['coinb2_first_4_bytes']}")
    
    if analysis1['coinb2_first_4_bytes'] == analysis2['coinb2_first_4_bytes']:
        print("  ✓ SAME")
    else:
        print("  ✗ DIFFERENT")
    print()
    
    print(f"  Pool 1 byte[0]: {analysis1['coinb2_byte_0']} (0x{analysis1['coinb2_byte_0']:02x})")
    print(f"  Pool 2 byte[0]: {analysis2['coinb2_byte_0']} (0x{analysis2['coinb2_byte_0']:02x})")
    
    if analysis1['coinb2_byte_0'] == analysis2['coinb2_byte_0']:
        print("  ✓ SAME")
    else:
        print("  ✗ DIFFERENT")
    print()
    
    # Overall verdict
    print("=" * 80)
    print("VERDICT:")
    print("=" * 80)
    
    matches = 0
    total = 5
    
    if analysis1['coinb1_len'] == analysis2['coinb1_len']:
        matches += 1
    if analysis1['coinb2_len'] == analysis2['coinb2_len']:
        matches += 1
    if analysis1['likely_format'] == analysis2['likely_format']:
        matches += 1
    if analysis1['has_standard_sequence'] == analysis2['has_standard_sequence']:
        matches += 1
    if analysis1['coinb2_first_4_bytes'] == analysis2['coinb2_first_4_bytes']:
        matches += 1
    
    similarity = (matches / total) * 100
    
    print(f"Similarity: {matches}/{total} metrics match ({similarity:.0f}%)")
    print()
    
    if similarity >= 80:
        print("✓ STRUCTURES ARE VERY SIMILAR")
        print("  These pools likely use the same stratum implementation or format.")
    elif similarity >= 60:
        print("~ STRUCTURES ARE SOMEWHAT SIMILAR")
        print("  These pools have some similarities but differ in key areas.")
    else:
        print("✗ STRUCTURES ARE DIFFERENT")
        print("  These pools use different coinbase formats.")
    print()
    
    # Detailed hex comparison
    print("=" * 80)
    print("DETAILED HEX DATA:")
    print("=" * 80)
    print()
    print(f"Pool 1 ({analysis1['pool']}):")
    print(f"  coinb1: {analysis1['coinb1_hex']}")
    print(f"  coinb2: {analysis1['coinb2_hex']}")
    print()
    print(f"Pool 2 ({analysis2['pool']}):")
    print(f"  coinb1: {analysis2['coinb1_hex']}")
    print(f"  coinb2: {analysis2['coinb2_hex']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Compare coinbase structures between two mining pools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Compare zsolo.bid with ckpool:
    python3 compare_coinbase.py btc.zsolo.bid 6057 solo.ckpool.org 3333
  
  Compare atlaspool with ckpool:
    python3 compare_coinbase.py solo.atlaspool.io 3333 solo.ckpool.org 3333
        """
    )
    
    parser.add_argument('host1', help='First pool hostname')
    parser.add_argument('port1', type=int, help='First pool port')
    parser.add_argument('host2', help='Second pool hostname')
    parser.add_argument('port2', type=int, help='Second pool port')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    
    args = parser.parse_args()
    
    print("Connecting to pools and retrieving coinbase structures...")
    print()
    
    # Get coinbase from pool 1
    print(f"[1/2] Connecting to {args.host1}:{args.port1}...")
    coinb1_1, coinb2_1, params1 = get_coinbase_from_pool(args.host1, args.port1, args.timeout)
    
    if not coinb1_1:
        print(f"✗ Failed to get coinbase from {args.host1}:{args.port1}")
        return 1
    
    print(f"✓ Retrieved coinbase from {args.host1}:{args.port1}")
    print()
    
    # Get coinbase from pool 2
    print(f"[2/2] Connecting to {args.host2}:{args.port2}...")
    coinb1_2, coinb2_2, params2 = get_coinbase_from_pool(args.host2, args.port2, args.timeout)
    
    if not coinb1_2:
        print(f"✗ Failed to get coinbase from {args.host2}:{args.port2}")
        return 1
    
    print(f"✓ Retrieved coinbase from {args.host2}:{args.port2}")
    print()
    
    # Analyze structures
    analysis1 = analyze_coinbase_structure(coinb1_1, coinb2_1, f"{args.host1}:{args.port1}")
    analysis2 = analyze_coinbase_structure(coinb1_2, coinb2_2, f"{args.host2}:{args.port2}")
    
    # Compare
    compare_structures(analysis1, analysis2)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
