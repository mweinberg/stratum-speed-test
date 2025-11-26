#!/usr/bin/env python3
"""
Prevhash Timeline Monitor

Captures prevhash from all pools at 30-second intervals for 11 minutes,
then displays a table showing how prevhashes changed over time.

This definitively shows which pools update to new blocks and which don't.
"""

import socket
import json
import time
import threading
from typing import Dict, List, Tuple
from datetime import datetime


def load_pools(filename: str = 'pools.txt') -> List[Tuple[str, int, str]]:
    """
    Load pools from file
    Returns list of (host, port, name) tuples
    """
    pools = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        host = parts[0]
                        port = int(parts[1])
                        name = f"{host}:{port}"
                        pools.append((host, port, name))
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        return []
    
    return pools


def get_prevhash(host: str, port: int, address: str, timeout: int = 10) -> Dict:
    """
    Connect to a pool and get the first prevhash
    """
    result = {
        'host': host,
        'port': port,
        'prevhash': None,
        'merkle_branches': None,
        'error': None
    }
    
    sock = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect
        sock.connect((host, port))
        
        # Subscribe
        subscribe_msg = json.dumps({
            'id': 1,
            'method': 'mining.subscribe',
            'params': ['PrevhashTimeline/1.0', None, host, port]
        }) + '\n'
        sock.sendall(subscribe_msg.encode('utf-8'))
        
        # Authorize
        authorize_msg = json.dumps({
            'id': 2,
            'method': 'mining.authorize',
            'params': [address, 'x']
        }) + '\n'
        sock.sendall(authorize_msg.encode('utf-8'))
        
        # Read responses
        buffer = ""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                chunk = sock.recv(4096).decode('utf-8')
                if not chunk:
                    break
                    
                buffer += chunk
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            data = json.loads(line)
                            
                            # Check for mining.notify (job with prevhash)
                            if data.get('method') == 'mining.notify':
                                params = data.get('params', [])
                                if len(params) >= 9:
                                    result['prevhash'] = params[1]
                                    result['merkle_branches'] = len(params[4])
                                    sock.close()
                                    return result
                        
                        except json.JSONDecodeError:
                            pass
            
            except socket.timeout:
                break
        
        if result['prevhash'] is None:
            result['error'] = 'No job'
    
    except socket.timeout:
        result['error'] = 'Timeout'
    except ConnectionRefusedError:
        result['error'] = 'Refused'
    except Exception as e:
        result['error'] = str(e)[:20]
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
    
    return result


def snapshot_all_pools(pools: List[Tuple[str, int, str]], address: str) -> Dict:
    """
    Connect to all pools simultaneously and capture prevhash
    """
    results = {}
    threads = []
    
    # Start all connections in parallel
    def worker(host, port, name):
        results[name] = get_prevhash(host, port, address)
    
    for host, port, name in pools:
        thread = threading.Thread(target=worker, args=(host, port, name))
        thread.start()
        threads.append(thread)
    
    # Wait for all to complete
    for thread in threads:
        thread.join()
    
    return results


def collect_timeline(pools: List[Tuple[str, int, str]], address: str, 
                     num_snapshots: int = 22, interval: int = 30) -> List[Dict]:
    """
    Collect prevhash snapshots over time
    """
    timeline = []
    
    print("="*80)
    print("PREVHASH TIMELINE MONITOR")
    print("="*80)
    print()
    print(f"Monitoring {len(pools)} pools")
    print(f"Snapshots: {num_snapshots} (every {interval} seconds)")
    print(f"Total duration: {num_snapshots * interval / 60:.1f} minutes")
    print(f"Address: {address}")
    print()
    
    start_time = time.time()
    
    for i in range(num_snapshots):
        snapshot_num = i + 1
        elapsed = time.time() - start_time
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print(f"[{timestamp}] Snapshot {snapshot_num}/{num_snapshots} (T+{elapsed:.0f}s)...", end='', flush=True)
        
        results = snapshot_all_pools(pools, address)
        
        # Count responses
        responding = sum(1 for r in results.values() if r['prevhash'])
        unique_prevhashes = len(set(r['prevhash'] for r in results.values() if r['prevhash']))
        
        print(f" {responding}/{len(pools)} pools, {unique_prevhashes} unique prevhash(es)")
        
        timeline.append({
            'snapshot': snapshot_num,
            'timestamp': timestamp,
            'elapsed': elapsed,
            'results': results
        })
        
        # Wait before next snapshot (except for last one)
        if snapshot_num < num_snapshots:
            time.sleep(interval)
    
    print()
    print("✓ Data collection complete!")
    print()
    
    return timeline


def display_timeline_table(timeline: List[Dict], pools: List[Tuple[str, int, str]]):
    """
    Display timeline as a table
    """
    # Order pools: scam pools first, then legitimate
    scam_keywords = ['luckymonster', 'zsolo']
    
    scam_pools = []
    legit_pools = []
    
    for host, port, name in pools:
        is_scam = any(keyword in name.lower() for keyword in scam_keywords)
        if is_scam:
            scam_pools.append(name)
        else:
            legit_pools.append(name)
    
    ordered_pools = sorted(scam_pools) + sorted(legit_pools)
    
    # Assign pool numbers
    pool_numbers = {name: i+1 for i, name in enumerate(ordered_pools)}
    
    # Create prevhash mapping (assign letters to unique prevhashes)
    all_prevhashes = set()
    for snapshot in timeline:
        for result in snapshot['results'].values():
            if result['prevhash']:
                all_prevhashes.add(result['prevhash'][:8])  # Use first 8 chars
    
    prevhash_letters = {}
    for i, ph in enumerate(sorted(all_prevhashes)):
        prevhash_letters[ph] = chr(65 + i)  # A, B, C, ...
    
    # Build table
    print("="*80)
    print("PREVHASH TIMELINE TABLE")
    print("="*80)
    print()
    
    # Header
    header = "Time    "
    for pool_name in ordered_pools:
        pool_num = pool_numbers[pool_name]
        header += f" {pool_num:2d}"
    print(header)
    print("-" * len(header))
    
    # Data rows
    for snapshot in timeline:
        row = f"{snapshot['timestamp']} "
        
        for pool_name in ordered_pools:
            result = snapshot['results'].get(pool_name, {})
            
            if result.get('prevhash'):
                ph_short = result['prevhash'][:8]
                letter = prevhash_letters.get(ph_short, '?')
                row += f"  {letter}"
            elif result.get('error'):
                row += f"  -"
            else:
                row += f"  ?"
        
        print(row)
    
    print()
    
    # Legend - Pool Numbers
    print("="*80)
    print("POOL LEGEND")
    print("="*80)
    print()
    
    # Scam pools first
    if scam_pools:
        print("⚠️  SUSPECTED SCAM POOLS:")
        for pool_name in sorted(scam_pools):
            pool_num = pool_numbers[pool_name]
            print(f"  [{pool_num:2d}] {pool_name}")
        print()
    
    # Legitimate pools
    print("✓ LEGITIMATE POOLS:")
    for pool_name in sorted(legit_pools):
        pool_num = pool_numbers[pool_name]
        print(f"  [{pool_num:2d}] {pool_name}")
    
    print()
    
    # Legend - Prevhash Letters
    print("="*80)
    print("PREVHASH LEGEND")
    print("="*80)
    print()
    
    for ph_short in sorted(all_prevhashes):
        letter = prevhash_letters[ph_short]
        
        # Find full prevhash
        full_prevhash = None
        for snapshot in timeline:
            for result in snapshot['results'].values():
                if result.get('prevhash', '')[:8] == ph_short:
                    full_prevhash = result['prevhash']
                    break
            if full_prevhash:
                break
        
        print(f"  [{letter}] {full_prevhash}")
    
    print()
    print("  [-] No response / Error")
    print()


def analyze_timeline(timeline: List[Dict], pools: List[Tuple[str, int, str]]):
    """
    Analyze the timeline data
    """
    print("="*80)
    print("ANALYSIS")
    print("="*80)
    print()
    
    # Track prevhash changes per pool
    pool_names = [name for _, _, name in pools]
    
    scam_keywords = ['luckymonster', 'zsolo']
    
    for pool_name in sorted(pool_names):
        is_scam = any(keyword in pool_name.lower() for keyword in scam_keywords)
        
        prevhashes = []
        for snapshot in timeline:
            result = snapshot['results'].get(pool_name, {})
            if result.get('prevhash'):
                prevhashes.append(result['prevhash'][:8])
            else:
                prevhashes.append(None)
        
        # Count unique prevhashes
        unique = len(set(ph for ph in prevhashes if ph))
        
        # Count changes
        changes = 0
        for i in range(1, len(prevhashes)):
            if prevhashes[i] and prevhashes[i-1] and prevhashes[i] != prevhashes[i-1]:
                changes += 1
        
        status = "⚠️ SCAM" if is_scam else "✓"
        
        if unique == 0:
            print(f"{status} {pool_name}: No data")
        elif unique == 1:
            print(f"{status} {pool_name}: STUCK on 1 prevhash (0 updates)")
        else:
            print(f"{status} {pool_name}: {unique} different prevhashes ({changes} updates)")
    
    print()
    
    # Detect block changes
    print("="*80)
    print("BLOCK CHANGES DETECTED")
    print("="*80)
    print()
    
    # Look at legitimate pools to see when blocks changed
    legit_pool = None
    for host, port, name in pools:
        if not any(keyword in name.lower() for keyword in scam_keywords):
            legit_pool = name
            break
    
    if legit_pool:
        prev_ph = None
        block_changes = []
        
        for snapshot in timeline:
            result = snapshot['results'].get(legit_pool, {})
            curr_ph = result.get('prevhash', '')[:8] if result.get('prevhash') else None
            
            if curr_ph and prev_ph and curr_ph != prev_ph:
                block_changes.append({
                    'snapshot': snapshot['snapshot'],
                    'timestamp': snapshot['timestamp'],
                    'from': prev_ph,
                    'to': curr_ph
                })
            
            prev_ph = curr_ph
        
        if block_changes:
            print(f"Detected {len(block_changes)} block change(s) (based on {legit_pool}):")
            for change in block_changes:
                print(f"  Snapshot {change['snapshot']} ({change['timestamp']}): {change['from']} → {change['to']}")
        else:
            print("No block changes detected during monitoring period")
            print("(Bitcoin blocks are found approximately every 10 minutes on average)")
    
    print()


def main():
    import sys
    
    # Parse arguments
    address = '3Ax2uht6S5Lh6V5HLNhxfaHnEZU7KaFvSZ'  # Default
    pools_file = 'pools.txt'  # Default
    num_snapshots = 22  # Default
    interval = 30  # Default (seconds)
    
    if len(sys.argv) > 1:
        address = sys.argv[1]
    if len(sys.argv) > 2:
        pools_file = sys.argv[2]
    if len(sys.argv) > 3:
        num_snapshots = int(sys.argv[3])
    if len(sys.argv) > 4:
        interval = int(sys.argv[4])
    
    # Load pools
    pools = load_pools(pools_file)
    
    if not pools:
        print(f"Error: No pools loaded from {pools_file}")
        return
    
    # Collect timeline data
    timeline = collect_timeline(pools, address, num_snapshots, interval)
    
    # Display results
    display_timeline_table(timeline, pools)
    analyze_timeline(timeline, pools)
    
    print("="*80)
    print("CONCLUSION")
    print("="*80)
    print()
    print("Legitimate pools should:")
    print("  • Update to new prevhashes when blocks are found")
    print("  • Show multiple different prevhashes over 11 minutes")
    print("  • All update together (within seconds)")
    print()
    print("Scam/fake pools will:")
    print("  • Stay stuck on the same prevhash")
    print("  • Not update when legitimate pools do")
    print("  • Show they're not on the real Bitcoin blockchain")
    print()


if __name__ == "__main__":
    main()
