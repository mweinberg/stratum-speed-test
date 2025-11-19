#!/usr/bin/env python3
"""
Stratum Server Connection Tester
Tests connectivity and response time to Bitcoin mining stratum servers
"""

import socket
import json
import time
import sys
import argparse
import subprocess
import platform
import urllib.request
import urllib.error
from typing import Optional, Tuple, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean, median

# Predefined servers for auto mode
# Format: (hostname, port, display_name, location)
# Location codes: AU=Australia, DE=Germany, RU=Russia, US=United States, *MANY*=Anycast (multiple locations)
PREDEFINED_SERVERS = [
    ("solo.atlaspool.io", 3333, "AtlasPool.io", "*MANY*"),  # Anycast - Global edge network
    ("ausolo.ckpool.org", 3333, "AU CKPool", "AU"),      # Australia
    ("stratum.kano.is", 3333, "KanoPool", "US"),          # United States
    ("eusolo.ckpool.org", 3333, "EU CKPool", "DE"),      # Germany
    ("eu.findmyblock.xyz", 3335, "FindMyBlock", "FR"),    # France
    ("solo-de.solohash.co.uk", 3333, "DE SoloHash", "DE"),    # Germany
    ("solo.solohash.co.uk", 3333, "UK SoloHash", "UK"),    # UK
    ("pool.solomining.de", 3333, "SoloMining.de", "DE"),    # Germany
    
 
 
    ("btc-eu.luckymonster.pro", 7112, "EU LuckyMonster", "FR"), # France
    ("btc.zsolo.bid", 6057, "zSolo", "FR"),              # France
    ("solo.ckpool.org", 3333, "US CKPool", "US"),          # United States
    ("parasite.wtf", 42069, "Parasite Pool", "US"),          # United States
    ("public-pool.io", 21496, "Public Pool", "US"),           # United States
    ("solo.cat", 3333, "solo.cat", "US"),                        # United States
    ("solo-ca.solohash.co.uk", 3333, "US SoloHash", "US"),                        # United States
    ("btc.luckymonster.pro", 7112, "LuckyMiner", "US"), # United States
]

def ping_host(hostname: str, timeout: int = 2) -> Optional[float]:
    """
    Perform ICMP ping to hostname and return response time in milliseconds.
    Returns None if ping fails or is not supported.
    """
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            # Windows: ping -n 1 -w 2000 hostname
            command = ['ping', '-4', '-n', '1', '-w', str(timeout * 1000), hostname]
        else:
            # macOS/Linux
            if system == 'darwin':  # macOS
                command = ['ping', '-c', '1', '-W', str(timeout * 1000), hostname]
            else:  # Linux
                command = ['ping', '-c', '1', '-W', str(timeout), hostname]
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1,
            text=True
        )
        
        if result.returncode != 0:
            return None
            
        output = result.stdout
        
        if system == 'windows':
            import re
            matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', output.lower())
            if matches:
                time_str = matches[-1]
            else:
                return None
        else:
            if 'time=' in output:
                time_part = output.split('time=')[1]
                time_str = time_part.split('ms')[0].strip().split()[0]
            else:
                return None
                
        return float(time_str)
    except:
        return None

def test_stratum_connection(hostname: str, port: int, timeout: int = 5) -> Optional[float]:
    """
    Test stratum server connection and return response time in milliseconds.
    Returns None if connection fails.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        sock.connect((hostname, port))
        
        subscribe_msg = json.dumps({
            "id": 1,
            "method": "mining.subscribe",
            "params": []
        }) + "\n"
        
        sock.sendall(subscribe_msg.encode('utf-8'))
        response = sock.recv(4096)
        elapsed_time = (time.time() - start_time) * 1000
        
        sock.close()
        
        if response:
            try:
                json.loads(response.decode('utf-8'))
            except json.JSONDecodeError:
                pass
        
        return elapsed_time
        
    except:
        return None

def get_public_ip() -> Optional[str]:
    """Get the public IPv4 address"""
    try:
        req = urllib.request.Request(
            'https://api.ipify.org?format=text',
            headers={'User-Agent': 'StratumTester/2.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            ip = response.read().decode('utf-8').strip()
            return ip if ip else None
    except:
        return None

def get_asn_info(ip: str) -> Optional[Dict[str, str]]:
    """Get ASN information for an IP address"""
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,as,isp,city,regionName,country'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'StratumTester/2.0'}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                as_info = data.get('as', '')
                isp = data.get('isp', '')
                city = data.get('city', '')
                region = data.get('regionName', '')
                country = data.get('country', '')
                
                asn = ''
                if as_info.startswith('AS'):
                    asn = as_info.split()[0]
                
                location = ', '.join(filter(None, [city, country]))
                
                return {
                    'asn': asn,
                    'provider': isp,
                    'location': location
                }
            return None
    except:
        return None

def test_server_multiple_runs(hostname: str, port: int, display_name: str, 
                               runs: int, country_code: str = "??") -> Dict:
    """Test a server multiple times and return statistics"""
    ping_times = []
    stratum_times = []
    
    for _ in range(runs):
        ping_time = ping_host(hostname)
        stratum_time = test_stratum_connection(hostname, port)
        
        if ping_time is not None:
            ping_times.append(ping_time)
        if stratum_time is not None:
            stratum_times.append(stratum_time)
        
        # Small delay between runs
        if runs > 1:
            time.sleep(0.1)
    
    return {
        'hostname': hostname,
        'port': port,
        'display_name': display_name,
        'country_code': country_code,
        'ping_times': ping_times,
        'stratum_times': stratum_times
    }

def format_time_single(time_ms: Optional[float]) -> str:
    """Format single time value for display"""
    if time_ms is None:
        return "N/A"
    return f"{int(round(time_ms))}"

def format_time_multi(times: List[float]) -> str:
    """Format multiple time values with statistics"""
    if not times:
        return "N/A"
    
    avg = mean(times)
    min_t = min(times)
    max_t = max(times)
    
    if len(times) == 1:
        return f"{int(round(avg))}"
    else:
        return f"{int(round(avg))} ({int(round(min_t))}-{int(round(max_t))})"

def format_time_for_result(result: Dict, use_ping: bool = False) -> str:
    """Format time from result dict"""
    times = result['ping_times'] if use_ping else result['stratum_times']
    
    if not times:
        # If ping failed but stratum succeeded, ICMP is blocked
        if use_ping and result['stratum_times']:
            return "BLOCKED"
        return "N/A"
    
    if len(times) == 1:
        return format_time_single(times[0])
    else:
        return format_time_multi(times)

def print_table(results: List[Dict], runs: int):
    """Print results in a formatted ASCII table"""
    if not results:
        return
    
    # Calculate column widths
    max_name_len = max(len(r['display_name']) for r in results)
    max_name_len = max(max_name_len, len("Pool Name"))
    
    country_width = max(len(r.get('country_code', '??')) for r in results)
    country_width = max(country_width, len("CC"))
    
    max_host_len = max(len(r['hostname']) for r in results)
    max_host_len = max(max_host_len, len("Host"))
    
    port_width = max(len(str(r['port'])) for r in results)
    port_width = max(port_width, len("Port"))
    
    ping_values = [format_time_for_result(r, use_ping=True) for r in results]
    ping_width = max(len(v) for v in ping_values)
    ping_width = max(ping_width, len("Ping (ms)"))
    
    stratum_values = [format_time_for_result(r, use_ping=False) for r in results]
    stratum_width = max(len(v) for v in stratum_values)
    stratum_width = max(stratum_width, len("Stratum (ms)"))
    
    # Print table
    separator = f"+{'-' * (max_name_len + 2)}+{'-' * (country_width + 2)}+{'-' * (max_host_len + 2)}+{'-' * (port_width + 2)}+{'-' * (ping_width + 2)}+{'-' * (stratum_width + 2)}+"
    
    print(separator)
    
    # Header
    if runs > 1:
        print(f"| {'Pool Name'.ljust(max_name_len)} | {'CC'.ljust(country_width)} | {'Host'.ljust(max_host_len)} | {'Port'.ljust(port_width)} | {'Ping (ms)'.ljust(ping_width)} | {'Stratum (ms)'.ljust(stratum_width)} |")
        print(f"| {' '.ljust(max_name_len)} | {' '.ljust(country_width)} | {' '.ljust(max_host_len)} | {' '.ljust(port_width)} | {'Avg (Min-Max)'.ljust(ping_width)} | {'Avg (Min-Max)'.ljust(stratum_width)} |")
    else:
        print(f"| {'Pool Name'.ljust(max_name_len)} | {'CC'.ljust(country_width)} | {'Host'.ljust(max_host_len)} | {'Port'.ljust(port_width)} | {'Ping (ms)'.ljust(ping_width)} | {'Stratum (ms)'.ljust(stratum_width)} |")
    
    print(separator)
    
    # Data rows
    for i, result in enumerate(results):
        country_code = result.get('country_code', '??').ljust(country_width)
        ping_str = ping_values[i].ljust(ping_width)
        stratum_str = stratum_values[i].ljust(stratum_width)
        print(f"| {result['display_name'].ljust(max_name_len)} | {country_code} | {result['hostname'].ljust(max_host_len)} | {str(result['port']).ljust(port_width)} | {ping_str} | {stratum_str} |")
    
    print(separator)

def print_summary(results: List[Dict]):
    """Print summary of fastest servers"""
    # Filter out failed results
    valid_ping = [r for r in results if r['ping_times']]
    valid_stratum = [r for r in results if r['stratum_times']]
    
    if not valid_ping and not valid_stratum:
        return
    
    print(f"\nSummary:")
    print("-" * 60)
    
    if valid_ping:
        fastest_ping = min(valid_ping, key=lambda x: mean(x['ping_times']))
        ping_time = mean(fastest_ping['ping_times'])
        print(f"Fastest Ping:    {fastest_ping['display_name']} ({int(round(ping_time))} ms)")
    
    if valid_stratum:
        # Find fastest and all within 3ms
        fastest_stratum = min(valid_stratum, key=lambda x: mean(x['stratum_times']))
        fastest_time = mean(fastest_stratum['stratum_times'])
        threshold = fastest_time + 3  # 3ms threshold
        
        # Get all servers within 3ms of fastest
        competitive_servers = [
            r for r in valid_stratum 
            if mean(r['stratum_times']) <= threshold
        ]
        
        # Sort by stratum time
        competitive_servers.sort(key=lambda x: mean(x['stratum_times']))
        
        print(f"Fastest Stratum: {fastest_stratum['display_name']} ({int(round(fastest_time))} ms)")
        print()
        
        if len(competitive_servers) == 1:
            print(f"RECOMMENDATION: Consider using {fastest_stratum['display_name']} ({fastest_stratum['hostname']}:{fastest_stratum['port']})")
            print(f"                for optimal mining performance from your location.")
        else:
            print(f"RECOMMENDED POOLS (within 3ms of fastest):")
            for i, server in enumerate(competitive_servers, 1):
                server_time = mean(server['stratum_times'])
                # Show actual time with decimal for transparency
                print(f"  {i}. {server['display_name']} - {server['hostname']}:{server['port']} ({server_time:.1f} ms)")
            print()
            print(f"All {len(competitive_servers)} pools above offer similar performance from your location.")

def print_intro():
    """Print introductory text"""
    print("\n" + "=" * 80)
    print("BITCOIN SOLO MINING POOL SPEED TEST")
    print("=" * 80)
    print()
    print("This script helps Bitcoin solo miners find the fastest stratum mining pool")
    print("server from their location. When solo mining, even small differences in")
    print("connection speed can affect your mining efficiency. The script tests")
    print("connectivity to major solo mining pools worldwide, measuring both network")
    print("latency (ping) and full stratum protocol response times.")
    print()
    print("The script performs two tests for each pool:")
    print("  1. PING TEST - Measures basic network latency using ICMP")
    print("  2. STRATUM HANDSHAKE - Measures complete connection time including the")
    print("     mining.subscribe protocol handshake (this is what your miner experiences)")
    print()
    print("By running this test from your own network, you'll get accurate results that")
    print("reflect the actual performance your mining hardware would experience, helping")
    print("you choose the optimal pool server for maximum efficiency.")
    print()
    print("IMPORTANT: For the most accurate results, run this test from the same network")
    print("           connection your miners use.")
    print("=" * 80)

def print_network_info(ipv4: Optional[str], asn_info: Optional[Dict]):
    """Print network information"""
    print("\n" + "=" * 60)
    print("Testing from:", end=" ")
    
    if asn_info and asn_info.get('location'):
        print(asn_info['location'])
    else:
        print("Unknown location")
    
    print("(Note: Location based on IP geolocation - may differ if using VPN/proxy)")
    
    if ipv4:
        print(f"Your IP: {ipv4}")
    
    if asn_info:
        if asn_info.get('provider'):
            print(f"Network: {asn_info['asn']} {asn_info['provider']}")
        elif asn_info.get('asn'):
            print(f"Network: {asn_info['asn']}")

def test_all_servers(runs: int = 1):
    """Test all predefined servers with concurrent execution"""
    # Print intro
    print_intro()
    
    # Get network info
    ipv4 = get_public_ip()
    asn_info = get_asn_info(ipv4) if ipv4 else None
    
    # Print network info
    print_network_info(ipv4, asn_info)
    
    # Test servers
    print(f"\nTesting {len(PREDEFINED_SERVERS)} servers (runs: {runs})...")
    
    results = []
    with ThreadPoolExecutor(max_workers=len(PREDEFINED_SERVERS)) as executor:
        futures = {
            executor.submit(test_server_multiple_runs, host, port, name, runs, cc): (host, port, name, cc)
            for host, port, name, cc in PREDEFINED_SERVERS
        }
        
        completed = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            completed += 1
            print(f"  Progress: {completed}/{len(PREDEFINED_SERVERS)}", end='\r')
    
    print()  # New line after progress
    
    # Sort by stratum time
    results.sort(key=lambda x: (
        not x['stratum_times'],  # No results last
        mean(x['stratum_times']) if x['stratum_times'] else float('inf'),
        x['display_name'] != 'AtlasPool.io'  # AtlasPool first in ties
    ))
    
    print("\nResults:")
    print_table(results, runs)
    print_summary(results)
    
    print()

def test_single_server(hostname: str, port: int, runs: int = 1):
    """Test a single server"""
    # Print intro
    print_intro()
    
    # Get network info
    ipv4 = get_public_ip()
    asn_info = get_asn_info(ipv4) if ipv4 else None
    
    print_network_info(ipv4, asn_info)
    
    # Test server
    print(f"\nTesting {hostname}:{port} (runs: {runs})...")
    result = test_server_multiple_runs(hostname, port, hostname, runs)
    print("\nResults:")
    print_table([result], runs)
    
    print()

def output_json(runs: int = 1):
    """Output results in JSON format"""
    # Get network info
    ipv4 = get_public_ip()
    asn_info = get_asn_info(ipv4) if ipv4 else None
    
    output = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'client': {
            'ipv4': ipv4,
            'location': asn_info.get('location') if asn_info else None,
            'asn': asn_info.get('asn') if asn_info else None,
            'provider': asn_info.get('provider') if asn_info else None
        },
        'runs': runs,
        'results': []
    }
    
    # Test servers
    with ThreadPoolExecutor(max_workers=len(PREDEFINED_SERVERS)) as executor:
        futures = [
            executor.submit(test_server_multiple_runs, host, port, name, runs, cc)
            for host, port, name, cc in PREDEFINED_SERVERS
        ]
        for future in as_completed(futures):
            result = future.result()
            output['results'].append({
                'host': result['hostname'],
                'port': result['port'],
                'display_name': result['display_name'],
                'country_code': result.get('country_code', '??'),
                'ping_ms': result['ping_times'],
                'stratum_ms': result['stratum_times'],
                'ping_avg': mean(result['ping_times']) if result['ping_times'] else None,
                'stratum_avg': mean(result['stratum_times']) if result['stratum_times'] else None
            })
    
    print(json.dumps(output, indent=2))

def main():
    parser = argparse.ArgumentParser(
        description='Test Bitcoin mining stratum server connectivity and response time',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Test all servers (default, 1 run):
    python stratum_test.py
  
  Test with 3 runs for accuracy:
    python stratum_test.py --runs 3
  
  Output JSON format:
    python stratum_test.py --json
  
  Test single server:
    python stratum_test.py solo.atlaspool.io 3333
  
  Test single server with 2 runs:
    python stratum_test.py solo.atlaspool.io 3333 --runs 2
        """
    )
    
    parser.add_argument('hostname', nargs='?',
                        help='Stratum server hostname (optional)')
    parser.add_argument('port', nargs='?', type=int,
                        help='Stratum server port (optional)')
    parser.add_argument('--runs', type=int, choices=[1, 2, 3], default=1,
                        help='Number of test runs per server (default: 1)')
    parser.add_argument('--json', action='store_true',
                        help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.json and (args.hostname or args.port):
        print("Error: --json cannot be used with single server test", file=sys.stderr)
        sys.exit(1)
    
    # Single server test
    if args.hostname and args.port:
        test_single_server(args.hostname, args.port, args.runs)
    elif args.hostname or args.port:
        print("Error: Both hostname and port must be provided for single server test", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    # JSON output
    elif args.json:
        output_json(args.runs)
    # Default: test all servers
    else:
        test_all_servers(args.runs)

if __name__ == "__main__":
    main()
