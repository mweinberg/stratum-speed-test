#!/usr/bin/env python3
"""
Bitcoin Solo Mining Pool Speed Test

Tests connectivity and response time to Bitcoin solo mining stratum servers
to help you find the fastest pool from your location. Measures both network
latency (ping) and actual stratum protocol handshake times.

Features:
  • Tests 16 popular solo mining pools worldwide
  • Concurrent testing for fast results (~10 seconds)
  • Multiple runs for accuracy (--runs 1-3)
  • Address type verification (-v flag) tests all 5 Bitcoin address formats:
    - P2PKH (Legacy): 1...
    - P2SH (Script Hash): 3...
    - P2WPKH (SegWit): bc1q...
    - P2WSH (SegWit Script): bc1q... (longer)
    - P2TR (Taproot): bc1p...
  • JSON output for automation (--json)
  • Single server testing mode

Usage:
    # Test all pools
    python3 stratum_test.py
    
    # Test with verification
    python3 stratum_test.py -v
    
    # Test with multiple runs
    python3 stratum_test.py --runs 3
    
    # Test single pool
    python3 stratum_test.py solo.atlaspool.io 3333

Version: 1.2
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
import binascii
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

# Global flag to track if ping is available
_ping_available = None

def check_ping_available() -> bool:
    """
    Check if ping command is available on the system.
    Returns True if available, False otherwise.
    """
    global _ping_available
    
    # Return cached result if already checked
    if _ping_available is not None:
        return _ping_available
    
    try:
        # Try to run ping with help flag
        result = subprocess.run(
            ['ping', '-h'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2
        )
        _ping_available = True
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        _ping_available = False
        return False


def show_ping_warning():
    """
    Show warning message with OS-specific instructions for installing ping.
    """
    system = platform.system().lower()
    
    print()
    print("=" * 70)
    print("⚠️  WARNING: 'ping' command not found on your system")
    print("=" * 70)
    print()
    print("Ping tests will show as 'BLOCKED' but stratum tests will work normally.")
    print()
    print("To install ping:")
    
    if system == 'linux':
        print("  • Debian/Ubuntu/Termux: sudo apt install iputils-ping")
        print("  • Fedora/RHEL:          sudo dnf install iputils")
        print("  • Arch Linux:           sudo pacman -S iputils")
    elif system == 'darwin':
        print("  • macOS: ping is built-in (check your PATH)")
    elif system == 'windows':
        print("  • Windows: ping is built-in (check your PATH)")
    else:
        print("  • Install iputils or iputils-ping package for your system")
    
    print()
    print("Press Enter to continue without ping, or Ctrl+C to exit...")
    print("=" * 70)
    
    try:
        input()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
    print()


def ping_host(hostname: str, timeout: int = 2) -> Optional[float]:
    """
    Perform ICMP ping to hostname and return response time in milliseconds.
    Returns None if ping fails or is not supported.
    
    Note: Uses TCP connection test as fallback for systems where ICMP ping
    has subprocess issues (e.g., Python 3.9 on macOS).
    """
    # Check if ping is available (cached after first check)
    if not check_ping_available():
        return None
    
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            command = ['ping', '-n', '1', '-w', str(timeout * 1000), hostname]
        else:
            # Unix-like systems (macOS, Linux)
            command = ['ping', '-c', '1', hostname]
        
        # Try using os.system as a workaround for Python 3.9 subprocess issues
        import tempfile
        import os
        import random
        
        # Add small random delay to avoid concurrent temp file collisions
        time.sleep(random.uniform(0, 0.1))
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as f:
            temp_file = f.name
        
        try:
            # Redirect output to temp file with timeout
            if system == 'windows':
                cmd = f'ping -n 1 -w {timeout * 1000} {hostname} > "{temp_file}" 2>&1'
            else:
                # Unix-like systems - don't use -W flag due to inconsistencies
                # Let the subprocess timeout handle it
                cmd = f'ping -c 1 {hostname} > "{temp_file}" 2>&1'
            
            ret = os.system(cmd)
            
            # Check if file exists and has content
            if not os.path.exists(temp_file):
                return None
            
            # Non-zero return code usually means ping failed
            if ret != 0:
                return None
            
            with open(temp_file, 'r') as f:
                output = f.read()
            
            if not output or len(output) < 10:
                return None
            
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
        finally:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except:
                pass
                
    except:
        # Silently fail for ping - it's not critical
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

def verify_address_type(hostname: str, port: int, address: str, timeout: int = 5) -> Optional[bool]:
    """
    Verify if a pool supports a specific address type.
    Returns True if supported, False if rejected, None if unknown/error.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            sock.connect((hostname, port))
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None  # Connection failed
        
        # Subscribe
        subscribe_msg = json.dumps({
            "id": 1,
            "method": "mining.subscribe",
            "params": []
        }) + "\n"
        
        try:
            sock.sendall(subscribe_msg.encode('utf-8'))
            # Wait for response to arrive
            time.sleep(0.2)
            
            # Read response in chunks
            response_parts = []
            sock.settimeout(3)
            for _ in range(2):
                chunk = sock.recv(4096).decode('utf-8')
                if chunk:
                    response_parts.append(chunk)
                    if '\n' in chunk and '"id":1' in chunk:
                        break
                time.sleep(0.1)
            
            subscribe_response = ''.join(response_parts)
        except (socket.timeout, OSError):
            return None  # Network error
        
        if not subscribe_response:
            return None
        
        # Check if subscribe succeeded
        subscribe_ok = False
        for line in subscribe_response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('id') == 1 and 'result' in data:
                        subscribe_ok = True
                        break
                except json.JSONDecodeError:
                    continue
        
        if not subscribe_ok:
            return None  # Can't connect properly
        
        # Authorize
        authorize_msg = json.dumps({
            "id": 2,
            "method": "mining.authorize",
            "params": [address, "x"]
        }) + "\n"
        
        try:
            sock.sendall(authorize_msg.encode('utf-8'))
            # Wait for response
            time.sleep(0.3)
            
            # Read response in chunks
            response_parts = []
            sock.settimeout(2)
            for _ in range(3):
                chunk = sock.recv(8192).decode('utf-8')
                if chunk:
                    response_parts.append(chunk)
                    if '\n' in chunk and '"id":2' in chunk:
                        break
                time.sleep(0.1)
            
            response = ''.join(response_parts)
        except (socket.timeout, OSError):
            return None  # Network error
        
        if not response:
            return None
        
        # Check authorization result
        for line in response.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('id') == 2:
                        result = data.get('result')
                        error = data.get('error')
                        
                        # If there's an error, it's rejected
                        if error:
                            return False
                        
                        # If result is True, it's supported
                        if result == True:
                            return True
                        
                        # If result is False but no error, unclear
                        return None
                except json.JSONDecodeError:
                    continue
        
        # No clear response
        return None
        
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def test_address_types(hostname: str, port: int) -> Dict[str, Optional[bool]]:
    """
    Test all 5 Bitcoin address types against a pool.
    Returns dict with address type names as keys and support status as values.
    Values: True = supported, False = not supported, None = unknown
    """
    test_addresses = {
        'P2PKH': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'P2SH': '3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y',
        'P2WPKH': 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
        'P2WSH': 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',
        'P2TR': 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
    }
    
    results = {}
    for addr_type, address in test_addresses.items():
        # Use longer timeout for verification (8 seconds instead of 5)
        results[addr_type] = verify_address_type(hostname, port, address, timeout=8)
        # Longer delay between tests to avoid rate limiting (0.5s instead of 0.2s)
        time.sleep(0.5)
    
    return results


def test_server_multiple_runs(hostname: str, port: int, display_name: str, 
                               runs: int, country_code: str = "??", verify: bool = False) -> Dict:
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
    
    result = {
        'hostname': hostname,
        'port': port,
        'display_name': display_name,
        'country_code': country_code,
        'ping_times': ping_times,
        'stratum_times': stratum_times
    }
    
    # Optionally test address type compatibility
    if verify:
        result['address_types'] = test_address_types(hostname, port)
    
    return result

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

def print_table(results: List[Dict], runs: int, verify: bool = False):
    """Print results in a formatted ASCII table"""
    if not results:
        return
    
    # Check if verification was performed
    has_verification = verify and any('address_types' in r for r in results)
    
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
    
    # Address type column widths (if verification enabled)
    addr_widths = {}
    if has_verification:
        addr_types = ['P2PKH', 'P2SH', 'P2WPKH', 'P2WSH', 'P2TR']
        for addr_type in addr_types:
            addr_widths[addr_type] = max(len(addr_type), 3)  # At least 3 for checkmark/X
    
    # Build separator
    separator = f"+{'-' * (max_name_len + 2)}+{'-' * (country_width + 2)}+{'-' * (max_host_len + 2)}+{'-' * (port_width + 2)}+{'-' * (ping_width + 2)}+{'-' * (stratum_width + 2)}+"
    if has_verification:
        for addr_type in addr_types:
            separator += f"+{'-' * (addr_widths[addr_type] + 2)}+"
    
    print(separator)
    
    # Header
    header_line = f"| {'Pool Name'.ljust(max_name_len)} | {'CC'.ljust(country_width)} | {'Host'.ljust(max_host_len)} | {'Port'.ljust(port_width)} | {'Ping (ms)'.ljust(ping_width)} | {'Stratum (ms)'.ljust(stratum_width)} |"
    if has_verification:
        for addr_type in addr_types:
            header_line += f" {addr_type.ljust(addr_widths[addr_type])} |"
    print(header_line)
    
    if runs > 1:
        subheader = f"| {' '.ljust(max_name_len)} | {' '.ljust(country_width)} | {' '.ljust(max_host_len)} | {' '.ljust(port_width)} | {'Avg (Min-Max)'.ljust(ping_width)} | {'Avg (Min-Max)'.ljust(stratum_width)} |"
        if has_verification:
            for addr_type in addr_types:
                subheader += f" {' '.ljust(addr_widths[addr_type])} |"
        print(subheader)
    
    print(separator)
    
    # Data rows
    for i, result in enumerate(results):
        country_code = result.get('country_code', '??').ljust(country_width)
        ping_str = ping_values[i].ljust(ping_width)
        stratum_str = stratum_values[i].ljust(stratum_width)
        
        row = f"| {result['display_name'].ljust(max_name_len)} | {country_code} | {result['hostname'].ljust(max_host_len)} | {str(result['port']).ljust(port_width)} | {ping_str} | {stratum_str} |"
        
        # Add verification columns
        if has_verification:
            addr_types_result = result.get('address_types', {})
            for addr_type in addr_types:
                supported = addr_types_result.get(addr_type, None)
                if supported is True:
                    symbol = '✓'
                elif supported is False:
                    symbol = 'X'
                else:  # None or missing
                    symbol = '?'
                row += f" {symbol.ljust(addr_widths[addr_type])} |"
        
        print(row)
    
    print(separator)
    
    # Print legend if verification was performed
    if has_verification:
        print("\nAddress Type Legend: ✓ = Supported, X = Not Supported, ? = Unknown/Requires Auth")
        print("  P2PKH = Legacy (1...), P2SH = Script Hash (3...)")
        print("  P2WPKH = SegWit (bc1q...), P2WSH = SegWit Script (bc1q... long)")
        print("  P2TR = Taproot (bc1p...)")

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

def test_all_servers(runs: int = 1, verify: bool = False):
    """Test all predefined servers with concurrent execution"""
    # Print intro
    print_intro()
    
    # Check if ping is available and warn if not
    if not check_ping_available():
        show_ping_warning()
    
    # Get network info
    ipv4 = get_public_ip()
    asn_info = get_asn_info(ipv4) if ipv4 else None
    
    # Print network info
    print_network_info(ipv4, asn_info)
    
    # Test servers
    verify_msg = " with address type verification" if verify else ""
    print(f"\nTesting {len(PREDEFINED_SERVERS)} servers (runs: {runs}){verify_msg}...")
    if verify:
        print("  Note: Verification adds ~10 seconds per server")
        print("  Using reduced concurrency (4 servers at a time) for reliability")
    
    results = []
    # Reduce concurrency when doing verification to avoid overwhelming pools
    max_workers = 4 if verify else len(PREDEFINED_SERVERS)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(test_server_multiple_runs, host, port, name, runs, cc, verify): (host, port, name, cc)
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
    print_table(results, runs, verify)
    print_summary(results)
    
    print()

def test_single_server(hostname: str, port: int, runs: int = 1):
    """Test a single server"""
    # Print intro
    print_intro()
    
    # Check if ping is available and warn if not
    if not check_ping_available():
        show_ping_warning()
    
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
    parser.add_argument('-v', '--verify', action='store_true',
                        help='Test all 5 Bitcoin address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) to verify '
                             'which formats each pool accepts. This confirms the pool will pay block rewards '
                             'to your address type. See verify_pool.py for detailed verification. (adds ~10s per server)')
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
        test_all_servers(args.runs, args.verify)

if __name__ == "__main__":
    main()
