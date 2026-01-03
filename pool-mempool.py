#!/usr/bin/env python3
"""
Pool Mempool Comparison Tool

Concurrently connects to multiple Bitcoin solo mining pools and compares
their mempool state by analyzing transaction fees in block templates.

This tool helps identify:
  • Which pools have the most up-to-date mempools
  • Which pools optimize for maximum transaction fees
  • Pool infrastructure quality and responsiveness
  • Stale block templates (outdated block heights)

Features:
  • Concurrent testing of all pools (~10-15 seconds)
  • Transaction fee calculation from coinbase outputs
  • Block height tracking to detect stale templates
  • Multiple runs for consistency analysis
  • JSON output for automation
  • Detailed timing metrics

Usage:
    # Single run
    python3 pool-mempool.py
    
    # Multiple runs for consistency
    python3 pool-mempool.py --runs 3
    
    # JSON output
    python3 pool-mempool.py --json
    
    # Verbose output with coinbase details
    python3 pool-mempool.py -v

Requirements:
  • Python 3.6+
  • No external dependencies

Version: 1.0
"""

import socket
import json
import time
import sys
import argparse
import binascii
from typing import Optional, Tuple, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean, median, stdev
from datetime import datetime

# Current block subsidy (after 2024 halving)
BLOCK_SUBSIDY_BTC = 3.125

# Pool configuration (from stratum_test.py)
POOLS = [
    ("solo.atlaspool.io", 3333, "AtlasPool.io", "*MANY*"),
    ("ausolo.ckpool.org", 3333, "AU CKPool", "AU"),
    ("eusolo.ckpool.org", 3333, "EU CKPool", "DE"),
    ("eu.findmyblock.xyz", 3335, "FindMyBlock", "FR"),
    ("pool.solomining.de", 3333, "SoloMining.de", "DE"),
    ("blitzpool.yourdevice.ch", 3333, "Blitzpool", "CH"),
    ("pool.sunnydecree.de", 3333, "Sunnydecree Pool", "DE"),
    ("pool.nerdminer.de", 3333, "Nerdminer.de", "DE"),
    ("pool.noderunners.network", 1337, "Noderunners", "DE"),
    ("pool.satoshiradio.nl", 3333, "Satoshi Radio", "NL"),
    ("solo.stratum.braiins.com", 3333, "Braiins Solo", "DE"),
    ("solo.ckpool.org", 3333, "US CKPool", "US"),
    ("parasite.wtf", 42069, "Parasite Pool", "US"),
    ("public-pool.io", 3333, "Public Pool", "US"),
    ("solo.cat", 3333, "solo.cat", "US"),
]


def connect_and_get_template(host: str, port: int, timeout: int = 10) -> Tuple[Optional[dict], Optional[float]]:
    """
    Connect to pool and get block template.
    Returns (notify_params, elapsed_time_ms) or (None, None) on failure.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        sock.connect((host, port))
        
        # Send mining.subscribe
        subscribe_msg = json.dumps({
            "id": 1,
            "method": "mining.subscribe",
            "params": ["pool-mempool/1.0"]
        }) + "\n"
        
        sock.sendall(subscribe_msg.encode('utf-8'))
        
        # Wait for response to arrive
        time.sleep(0.2)
        
        # Receive subscribe response
        response_parts = []
        sock.settimeout(2)
        
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
        
        # Parse subscribe response
        subscribe_ok = False
        for line in response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('id') == 1 and 'result' in data:
                        subscribe_ok = True
                        break
                except json.JSONDecodeError:
                    continue
        
        if not subscribe_ok:
            return None, None
        
        # Send mining.authorize
        authorize_msg = json.dumps({
            "id": 2,
            "method": "mining.authorize",
            "params": ["bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "x"]
        }) + "\n"
        
        sock.sendall(authorize_msg.encode('utf-8'))
        
        # Wait for response to arrive
        time.sleep(0.3)
        
        # Receive authorize response and mining.notify
        response_parts = []
        sock.settimeout(2)
        
        try:
            # Try to read multiple times to get complete response
            for _ in range(3):
                chunk = sock.recv(8192).decode('utf-8')
                if chunk:
                    response_parts.append(chunk)
                    # If we got authorize response, break
                    if '\n' in chunk and '"id":2' in chunk:
                        break
                time.sleep(0.1)
        except socket.timeout:
            pass  # Normal - no more data
        
        response = ''.join(response_parts).strip()
        
        elapsed_time = (time.time() - start_time) * 1000
        
        if not response:
            return None, None
        
        # Look for mining.notify in response
        notify_params = None
        for line in response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('method') == 'mining.notify':
                        notify_params = data.get('params')
                        break
                except json.JSONDecodeError:
                    continue
        
        return notify_params, elapsed_time
        
    except Exception as e:
        return None, None
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def parse_coinbase_outputs(coinb2_hex: str, coinb1_hex: str = None) -> list:
    """
    Parse coinbase outputs from coinb2.
    Simplified version from verify_pool.py - focuses on getting output values.
    """
    try:
        coinb2_bytes = binascii.unhexlify(coinb2_hex)
        outputs = []
        
        # Method 1: Look for sequence marker (0xffffffff) which marks end of script
        pos = 0
        found_sequence = False
        
        for i in range(len(coinb2_bytes) - 4):
            if coinb2_bytes[i:i+4] == b'\xff\xff\xff\xff':
                pos = i + 4
                found_sequence = True
                break
        
        # Method 2: Try SoloHash format (sequence early in coinb2)
        if not found_sequence:
            for i in range(min(50, len(coinb2_bytes) - 4)):
                if coinb2_bytes[i:i+4] == b'\x00\x00\x00\x00' or coinb2_bytes[i:i+4] == b'\xff\xff\xff\xff':
                    if i + 4 < len(coinb2_bytes):
                        potential_output_count = coinb2_bytes[i+4]
                        if 1 <= potential_output_count <= 20:
                            pos = i + 5
                            found_sequence = True
                            break
        
        if not found_sequence:
            return []
        
        # Read output count
        if pos >= len(coinb2_bytes):
            return []
        
        output_count = coinb2_bytes[pos]
        pos += 1
        
        # Parse each output
        for _ in range(output_count):
            if pos + 8 > len(coinb2_bytes):
                break
            
            # Read value (8 bytes, little-endian)
            value = int.from_bytes(coinb2_bytes[pos:pos+8], 'little')
            pos += 8
            
            # Read script length
            if pos >= len(coinb2_bytes):
                break
            script_len = coinb2_bytes[pos]
            pos += 1
            
            # Skip script
            if pos + script_len > len(coinb2_bytes):
                break
            pos += script_len
            
            outputs.append({
                'value_satoshis': value,
                'value_btc': value / 100000000
            })
        
        return outputs
        
    except Exception:
        return []


def parse_block_height(coinb1_hex: str) -> Optional[int]:
    """
    Parse block height from coinb1 (BIP34).
    """
    try:
        coinb1_bytes = binascii.unhexlify(coinb1_hex)
        
        # Skip: version (4) + input count (1) + prev hash (32) + prev index (4) = 41 bytes
        pos = 41
        
        if pos >= len(coinb1_bytes):
            return None
        
        # Read script length
        script_len = coinb1_bytes[pos]
        pos += 1
        
        # Read available script
        available_script = coinb1_bytes[pos:]
        
        if len(available_script) == 0:
            return None
        
        # First byte is height length
        height_len = available_script[0]
        
        if height_len > 0 and height_len <= 4 and len(available_script) > height_len:
            height_bytes = available_script[1:1 + height_len]
            block_height = int.from_bytes(height_bytes, 'little')
            return block_height
        
        return None
        
    except Exception:
        return None


def test_pool(hostname: str, port: int, display_name: str, country_code: str, timeout: int = 10) -> Dict:
    """
    Test a single pool and return mempool state.
    """
    result = {
        'hostname': hostname,
        'port': port,
        'display_name': display_name,
        'country_code': country_code,
        'success': False,
        'error': None,
        'response_time_ms': None,
        'block_height': None,
        'total_payout_btc': None,
        'transaction_fees_btc': None,
        'transaction_fees_sats': None,
        'output_count': None,
    }
    
    try:
        notify_params, elapsed_time = connect_and_get_template(hostname, port, timeout)
        
        if not notify_params or len(notify_params) < 9:
            result['error'] = 'No template received'
            return result
        
        result['response_time_ms'] = elapsed_time
        
        # Extract coinbase parts
        coinb1 = notify_params[2]
        coinb2 = notify_params[3]
        
        # Parse block height
        block_height = parse_block_height(coinb1)
        result['block_height'] = block_height
        
        # Parse outputs
        outputs = parse_coinbase_outputs(coinb2, coinb1)
        
        if not outputs:
            result['error'] = 'Could not parse outputs'
            return result
        
        result['output_count'] = len(outputs)
        
        # Calculate total payout (excluding OP_RETURN which has 0 value)
        total_payout_sats = sum(o['value_satoshis'] for o in outputs if o['value_satoshis'] > 0)
        total_payout_btc = total_payout_sats / 100000000
        
        result['total_payout_btc'] = total_payout_btc
        
        # Calculate transaction fees
        tx_fees_btc = total_payout_btc - BLOCK_SUBSIDY_BTC
        tx_fees_sats = int(tx_fees_btc * 100000000)
        
        result['transaction_fees_btc'] = tx_fees_btc
        result['transaction_fees_sats'] = tx_fees_sats
        result['success'] = True
        
        return result
        
    except Exception as e:
        result['error'] = str(e)
        return result


def test_all_pools(pools: List[Tuple], timeout: int = 10, max_workers: int = 20) -> List[Dict]:
    """
    Test all pools concurrently.
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all futures at once using dictionary comprehension
        futures = {
            executor.submit(test_pool, hostname, port, display_name, country_code, timeout): (hostname, display_name)
            for hostname, port, display_name, country_code in pools
        }
        
        # Collect results as they complete
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                # Should not happen since test_pool catches exceptions
                hostname, display_name = futures[future]
                print(f"  Error testing {display_name}: {e}")
    
    return results


def print_results_table(results: List[Dict], run_number: int = None, verbose: bool = False):
    """
    Print results in formatted table.
    """
    # Sort by transaction fees (descending)
    sorted_results = sorted(
        [r for r in results if r['success']],
        key=lambda x: x['transaction_fees_sats'] if x['transaction_fees_sats'] is not None else 0,
        reverse=True
    )
    
    # Add failed results at the end
    failed_results = [r for r in results if not r['success']]
    sorted_results.extend(failed_results)
    
    if not sorted_results:
        print("No results to display")
        return
    
    # Calculate column widths
    max_name_len = max(len(r['display_name']) for r in sorted_results)
    max_name_len = max(max_name_len, len("Pool Name"))
    
    # CC column needs to fit "*MANY*" (6 chars) + padding
    max_cc_len = max(len(r['country_code']) for r in sorted_results)
    cc_width = max(max_cc_len, 2) + 2  # At least "CC" + padding
    
    # Print header
    if run_number is not None:
        print(f"\n{'=' * 100}")
        print(f"RUN #{run_number} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 100}")
    else:
        print(f"\n{'=' * 100}")
        print(f"POOL MEMPOOL COMPARISON - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 100}")
    
    print()
    
    # Table header
    separator = f"+{'-' * (max_name_len + 2)}+{'-' * (cc_width + 2)}+{'-' * 12}+{'-' * 18}+{'-' * 12}+{'-' * 10}+"
    print(separator)
    
    header = f"| {'Pool Name'.ljust(max_name_len)} | {'CC'.ljust(cc_width)} | {'Height'.ljust(10)} | {'TX Fees (BTC)'.ljust(16)} | {'Fees (sats)'.ljust(10)} | {'Time (ms)'.ljust(8)} |"
    print(header)
    print(separator)
    
    # Data rows
    for result in sorted_results:
        name = result['display_name'].ljust(max_name_len)
        cc = result['country_code'].ljust(cc_width)
        
        if result['success']:
            height = str(result['block_height']).ljust(10) if result['block_height'] else 'N/A'.ljust(10)
            
            if result['transaction_fees_btc'] is not None:
                fees_btc = f"{result['transaction_fees_btc']:.8f}".ljust(16)
            else:
                fees_btc = 'N/A'.ljust(16)
            
            if result['transaction_fees_sats'] is not None:
                fees_sats = f"{result['transaction_fees_sats']:,}".ljust(10)
            else:
                fees_sats = 'N/A'.ljust(10)
            
            time_ms = f"{int(result['response_time_ms'])}".ljust(8) if result['response_time_ms'] else 'N/A'.ljust(8)
        else:
            height = 'FAILED'.ljust(10)
            fees_btc = (result['error'][:14] if result['error'] else 'Error').ljust(16)
            fees_sats = '-'.ljust(10)
            time_ms = '-'.ljust(8)
        
        row = f"| {name} | {cc} | {height} | {fees_btc} | {fees_sats} | {time_ms} |"
        print(row)
        
        # Verbose output
        if verbose and result['success']:
            print(f"|   Total Payout: {result['total_payout_btc']:.8f} BTC = {BLOCK_SUBSIDY_BTC:.3f} subsidy + {result['transaction_fees_btc']:.8f} fees")
            print(f"|   Outputs: {result['output_count']}")
    
    print(separator)
    
    # Statistics
    successful = [r for r in sorted_results if r['success'] and r['transaction_fees_sats'] is not None]
    
    if successful:
        fees_list = [r['transaction_fees_sats'] for r in successful]
        heights_list = [r['block_height'] for r in successful if r['block_height'] is not None]
        
        print()
        print("STATISTICS:")
        print(f"  Successful pools: {len(successful)}/{len(sorted_results)}")
        print(f"  Highest fees:     {max(fees_list):,} sats ({max(fees_list)/100000000:.8f} BTC)")
        print(f"  Lowest fees:      {min(fees_list):,} sats ({min(fees_list)/100000000:.8f} BTC)")
        print(f"  Average fees:     {int(mean(fees_list)):,} sats ({mean(fees_list)/100000000:.8f} BTC)")
        print(f"  Median fees:      {int(median(fees_list)):,} sats ({median(fees_list)/100000000:.8f} BTC)")
        
        if len(fees_list) > 1:
            print(f"  Std deviation:    {int(stdev(fees_list)):,} sats")
            print(f"  Fee range:        {max(fees_list) - min(fees_list):,} sats difference")
        
        if heights_list:
            max_height = max(heights_list)
            min_height = min(heights_list)
            print(f"  Block heights:    {min_height} - {max_height}")
            
            if max_height > min_height:
                stale_pools = [r for r in successful if r['block_height'] and r['block_height'] < max_height]
                print(f"  ⚠️  Stale templates: {len(stale_pools)} pool(s) on old block")
                for pool in stale_pools:
                    blocks_behind = max_height - pool['block_height']
                    print(f"      • {pool['display_name']}: {blocks_behind} block(s) behind")


def print_json_output(all_runs: List[List[Dict]]):
    """
    Print results in JSON format.
    """
    output = {
        'timestamp': datetime.now().isoformat(),
        'block_subsidy_btc': BLOCK_SUBSIDY_BTC,
        'runs': []
    }
    
    for run_idx, results in enumerate(all_runs, 1):
        run_data = {
            'run_number': run_idx,
            'pools': []
        }
        
        for result in results:
            pool_data = {
                'hostname': result['hostname'],
                'port': result['port'],
                'display_name': result['display_name'],
                'country_code': result['country_code'],
                'success': result['success'],
                'error': result['error'],
                'response_time_ms': result['response_time_ms'],
                'block_height': result['block_height'],
                'total_payout_btc': result['total_payout_btc'],
                'transaction_fees_btc': result['transaction_fees_btc'],
                'transaction_fees_sats': result['transaction_fees_sats'],
                'output_count': result['output_count'],
            }
            run_data['pools'].append(pool_data)
        
        output['runs'].append(run_data)
    
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Compare mempool state across Bitcoin solo mining pools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single run:
    python3 pool-mempool.py
  
  Multiple runs for consistency:
    python3 pool-mempool.py --runs 3
  
  JSON output:
    python3 pool-mempool.py --json
  
  Verbose output:
    python3 pool-mempool.py -v

What This Shows:
  • Transaction fees indicate mempool freshness and optimization
  • Higher fees suggest better-connected or better-optimized pools
  • Block height differences indicate stale templates
  • Response time shows pool infrastructure speed
  • Consistency across runs indicates stable infrastructure

Note: Small fee differences (0.001-0.005 BTC) are normal due to:
  • Different mempool views across the network
  • Different template generation times
  • Different transaction selection algorithms
        """
    )
    
    parser.add_argument('--runs', type=int, default=1, help='Number of test runs (default: 1)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output with additional details')
    
    args = parser.parse_args()
    
    if args.runs < 1:
        print("Error: --runs must be at least 1", file=sys.stderr)
        return 1
    
    if args.runs > 10:
        print("Warning: Running more than 10 times may take a while...")
    
    all_runs = []
    
    for run in range(args.runs):
        if not args.json:
            if run > 0:
                print(f"\nWaiting 5 seconds before next run...")
                time.sleep(5)
            
            if args.runs > 1:
                print(f"\nStarting run {run + 1}/{args.runs}...")
            else:
                print(f"\nTesting {len(POOLS)} pools concurrently...")
        
        results = test_all_pools(POOLS, timeout=args.timeout)
        all_runs.append(results)
        
        if not args.json:
            print_results_table(results, run_number=(run + 1) if args.runs > 1 else None, verbose=args.verbose)
    
    # Print JSON output if requested
    if args.json:
        print_json_output(all_runs)
    
    # Print summary if multiple runs
    if args.runs > 1 and not args.json:
        print(f"\n{'=' * 100}")
        print(f"MULTI-RUN SUMMARY ({args.runs} runs)")
        print(f"{'=' * 100}")
        print()
        
        # Aggregate statistics across all runs
        all_successful = []
        for results in all_runs:
            all_successful.extend([r for r in results if r['success'] and r['transaction_fees_sats'] is not None])
        
        if all_successful:
            # Group by pool
            pool_stats = {}
            for result in all_successful:
                pool_name = result['display_name']
                if pool_name not in pool_stats:
                    pool_stats[pool_name] = {
                        'display_name': pool_name,
                        'country_code': result['country_code'],
                        'fees': [],
                        'heights': [],
                        'response_times': []
                    }
                pool_stats[pool_name]['fees'].append(result['transaction_fees_sats'])
                if result['block_height']:
                    pool_stats[pool_name]['heights'].append(result['block_height'])
                if result['response_time_ms']:
                    pool_stats[pool_name]['response_times'].append(result['response_time_ms'])
            
            # Calculate statistics for each pool
            pool_summary = []
            for pool_name, stats in pool_stats.items():
                fees = stats['fees']
                if len(fees) >= 1:
                    summary = {
                        'display_name': stats['display_name'],
                        'country_code': stats['country_code'],
                        'runs': len(fees),
                        'avg_fees': mean(fees),
                        'min_fees': min(fees),
                        'max_fees': max(fees),
                        'std_fees': stdev(fees) if len(fees) > 1 else 0,
                        'avg_height': mean(stats['heights']) if stats['heights'] else None,
                        'avg_response_time': mean(stats['response_times']) if stats['response_times'] else None,
                    }
                    pool_summary.append(summary)
            
            # Sort by average fees (descending)
            pool_summary.sort(key=lambda x: x['avg_fees'], reverse=True)
            
            # Find best values for highlighting
            best_avg_fees = max(p['avg_fees'] for p in pool_summary)
            best_max_fees = max(p['max_fees'] for p in pool_summary)
            best_avg_time = min(p['avg_response_time'] for p in pool_summary if p['avg_response_time'])
            
            # Print summary table
            print("POOL SUMMARY (sorted by average transaction fees):")
            print()
            
            # Calculate column widths
            max_name_len = max(len(p['display_name']) for p in pool_summary)
            max_name_len = max(max_name_len, len("Pool Name"))
            
            # CC column needs to fit "*MANY*" (6 chars) + padding
            max_cc_len = max(len(p['country_code']) for p in pool_summary)
            cc_width = max(max_cc_len, 2) + 2  # At least "CC" + padding
            
            separator = f"+{'-' * (max_name_len + 2)}+{'-' * (cc_width + 2)}+{'-' * 7}+{'-' * 18}+{'-' * 18}+{'-' * 18}+{'-' * 12}+{'-' * 12}+"
            print(separator)
            
            header = f"| {'Pool Name'.ljust(max_name_len)} | {'CC'.ljust(cc_width)} | {'Runs'.ljust(5)} | {'Avg Fees (sats)'.ljust(16)} | {'Min Fees (sats)'.ljust(16)} | {'Max Fees (sats)'.ljust(16)} | {'Std Dev'.ljust(10)} | {'Avg Time'.ljust(10)} |"
            print(header)
            print(separator)
            
            for pool in pool_summary:
                name = pool['display_name'].ljust(max_name_len)
                cc = pool['country_code'].ljust(cc_width)
                runs = str(pool['runs']).ljust(5)
                
                # Highlight best avg fees
                avg_fees_str = f"{int(pool['avg_fees']):,}"
                if pool['avg_fees'] == best_avg_fees:
                    avg_fees_str = f"*{avg_fees_str}"
                avg_fees = avg_fees_str.ljust(16)
                
                min_fees = f"{int(pool['min_fees']):,}".ljust(16)
                
                # Highlight best max fees
                max_fees_str = f"{int(pool['max_fees']):,}"
                if pool['max_fees'] == best_max_fees:
                    max_fees_str = f"*{max_fees_str}"
                max_fees = max_fees_str.ljust(16)
                
                std_dev = f"{int(pool['std_fees']):,}".ljust(10) if pool['std_fees'] > 0 else '-'.ljust(10)
                
                # Highlight best avg time
                if pool['avg_response_time']:
                    avg_time_str = f"{int(pool['avg_response_time'])}ms"
                    if pool['avg_response_time'] == best_avg_time:
                        avg_time_str = f"*{avg_time_str}"
                    avg_time = avg_time_str.ljust(10)
                else:
                    avg_time = '-'.ljust(10)
                
                row = f"| {name} | {cc} | {runs} | {avg_fees} | {min_fees} | {max_fees} | {std_dev} | {avg_time} |"
                print(row)
            
            print(separator)
            print()
            
            # Overall statistics
            all_avg_fees = [p['avg_fees'] for p in pool_summary]
            print("OVERALL STATISTICS:")
            print(f"  Pools tested:     {len(pool_summary)}")
            print(f"  Highest avg fees: {int(max(all_avg_fees)):,} sats ({max(all_avg_fees)/100000000:.8f} BTC)")
            print(f"  Lowest avg fees:  {int(min(all_avg_fees)):,} sats ({min(all_avg_fees)/100000000:.8f} BTC)")
            print(f"  Overall avg:      {int(mean(all_avg_fees)):,} sats ({mean(all_avg_fees)/100000000:.8f} BTC)")
            print(f"  Fee range:        {int(max(all_avg_fees) - min(all_avg_fees)):,} sats difference")
            print()
            
            # Consistency analysis
            print("CONSISTENCY ANALYSIS:")
            print()
            most_consistent = min(pool_summary, key=lambda x: x['std_fees'] if x['runs'] > 1 else float('inf'))
            least_consistent = max(pool_summary, key=lambda x: x['std_fees'] if x['runs'] > 1 else 0)
            
            if most_consistent['runs'] > 1:
                print(f"  Most consistent:  {most_consistent['display_name']}")
                print(f"    Std deviation:  {int(most_consistent['std_fees']):,} sats")
                print(f"    Fee range:      {int(most_consistent['min_fees']):,} - {int(most_consistent['max_fees']):,} sats")
                print()
            
            if least_consistent['runs'] > 1 and least_consistent['std_fees'] > 0:
                print(f"  Least consistent: {least_consistent['display_name']}")
                print(f"    Std deviation:  {int(least_consistent['std_fees']):,} sats")
                print(f"    Fee range:      {int(least_consistent['min_fees']):,} - {int(least_consistent['max_fees']):,} sats")
                print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
