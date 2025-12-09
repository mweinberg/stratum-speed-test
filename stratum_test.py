#!/usr/bin/env python3
"""
Bitcoin Solo Mining Pool Speed Test

Tests connectivity and response time to Bitcoin solo mining stratum servers
to help you find the fastest pool from your location. Measures both network
latency (ping) and actual stratum protocol handshake times.

Features:
  • Tests 20 popular solo mining pools worldwide
  • Concurrent testing for fast results (~10 seconds)
  • Multiple runs for accuracy (--runs 1-3)
  • TLS connection testing (-t/--tls flag) for secure stratum connections
    - Supports TLS 1.3 (Python 3.7+) and TLS 1.2 (Python 3.6+)
    - Detailed error reporting for TLS failures
    - Optional certificate verification bypass (--no-verify-cert)
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
    
    # Test with TLS support (requires Python 3.6+)
    python3 stratum_test.py -t
    
    # Test with TLS, skip certificate verification (for IP addresses)
    python3 stratum_test.py -t --no-verify-cert
    
    # Test with verification
    python3 stratum_test.py -v
    
    # Test with multiple runs
    python3 stratum_test.py --runs 3
    
    # Test single pool
    python3 stratum_test.py solo.atlaspool.io 3333
    
    # Test single pool with TLS
    python3 stratum_test.py solo.atlaspool.io 3333 -t

Requirements:
  • Python 3.6+ (Python 3.7+ recommended for TLS 1.3 support)
  • No external dependencies (uses only standard library)

Version: 1.4
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
import threading
from typing import Optional, Tuple, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean, median

# Predefined servers for auto mode
# Each entry is a tuple with the following fields:
#   1. hostname (str): The server's hostname or IP address
#   2. port (int): The standard stratum port (typically 3333)
#   3. tls_port (int): The TLS-enabled stratum port (0 = no TLS support)
#   4. display_name (str): Human-readable name shown in results
#   5. location (str): Country code (ISO 3166-1 alpha-2) or "*MANY*" for Anycast
#
# Location codes: AU=Australia, CH=Switzerland, DE=Germany, FR=France, NL=Netherlands,
#                 RU=Russia, UK=United Kingdom, US=United States, *MANY*=Anycast (multiple locations)
PREDEFINED_SERVERS = [
    ("solo.atlaspool.io", 3333, 4333, "AtlasPool.io", "*MANY*"),  # Anycast - Global edge network
    ("ausolo.ckpool.org", 3333, 0, "AU CKPool", "AU"),      # Australia
    ("stratum.kano.is", 3333, 0, "KanoPool", "US"),          # United States
    ("eusolo.ckpool.org", 3333, 0, "EU CKPool", "DE"),      # Germany
    ("eu.findmyblock.xyz", 3335, 0, "FindMyBlock", "FR"),    # France
    ("solo-de.solohash.co.uk", 3333, 0, "DE SoloHash", "DE"),    # Germany
    ("solo.solohash.co.uk", 3333, 0, "UK SoloHash", "UK"),    # UK
    ("pool.solomining.de", 3333, 0, "SoloMining.de", "DE"),    # Germany
    
    ("blitzpool.yourdevice.ch", 3333, 0, "Blitzpool", "CH"),  # Switzerland
    ("pool.sunnydecree.de", 3333, 0, "Sunnydecree Pool", "DE"),  # Germany
    ("pool.nerdminer.de", 3333, 0, "Nerdminer.de", "DE"),  # Germany
    ("pool.noderunners.network", 1337, 1336, "Noderunners", "DE"),  # Germany
    ("pool.satoshiradio.nl", 3333, 0, "Satoshi Radio", "NL"),  # Netherlands
    ("solo.stratum.braiins.com", 3333, 0, "Braiins Solo", "DE"),  # Germany
    ("de.kano.is", 3333, 0, "KanoPool DE", "DE"),  # Germany
 
    ("solo.ckpool.org", 3333, 0, "US CKPool", "US"),          # United States
    ("parasite.wtf", 42069, 0, "Parasite Pool", "US"),          # United States
    ("public-pool.io", 3333, 4333, "Public Pool", "US"),           # United States
    ("solo.cat", 3333, 0, "solo.cat", "US"),                        # United States
    ("solo-ca.solohash.co.uk", 3333, 0, "US SoloHash", "US"),                        # United States
]

# Global flag to track if ping is available
_ping_available = None

# Global lock to synchronize ping operations
_ping_lock = threading.Lock()

def lookup_predefined_server(hostname: str) -> Optional[Tuple[int, int, str, str]]:
    """
    Look up server info from PREDEFINED_SERVERS by hostname.
    Returns (port, tls_port, display_name, country_code) if found, None otherwise.
    """
    for host, port, tls_port, display_name, country_code in PREDEFINED_SERVERS:
        if host == hostname:
            return (port, tls_port, display_name, country_code)
    return None

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

    # Use global lock to prevent concurrent ping operations
    with _ping_lock:
        # Retry ping up to 3 times for reliability
        for attempt in range(3):
            try:
                system = platform.system().lower()

                if system == 'windows':
                    command = ['ping', '-n', '1', '-w', str(timeout * 1000), hostname]
                else:
                    # Unix-like systems (macOS, Linux)
                    command = ['ping', '-c', '1', '-W', str(timeout), hostname]

                # Use subprocess.run with proper capture to avoid temp file issues
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout + 1,  # Add 1 second buffer
                    text=True
                )

                # Check return code - non-zero usually means ping failed
                if result.returncode != 0:
                    # If this is not the last attempt, continue to retry
                    if attempt < 2:
                        time.sleep(0.1)  # Small delay before retry
                        continue
                    return None

                output = result.stdout
                if not output or len(output) < 10:
                    # If this is not the last attempt, continue to retry
                    if attempt < 2:
                        time.sleep(0.1)  # Small delay before retry
                        continue
                    return None

                if system == 'windows':
                    import re
                    matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', output.lower())
                    if matches:
                        time_str = matches[-1]
                    else:
                        # If this is not the last attempt, continue to retry
                        if attempt < 2:
                            time.sleep(0.1)  # Small delay before retry
                            continue
                        return None
                else:
                    if 'time=' in output:
                        time_part = output.split('time=')[1]
                        time_str = time_part.split('ms')[0].strip().split()[0]
                    else:
                        # If this is not the last attempt, continue to retry
                        if attempt < 2:
                            time.sleep(0.1)  # Small delay before retry
                            continue
                        return None

                return float(time_str)

            except subprocess.TimeoutExpired:
                # Ping timed out - if not last attempt, retry
                if attempt < 2:
                    continue
                return None
            except (OSError, ValueError):
                # System call failed or parsing error - if not last attempt, retry
                if attempt < 2:
                    continue
                return None

        # All attempts failed
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

def test_stratum_tls_connection(hostname: str, port: int, timeout: int = 5, verify_cert: bool = True) -> Tuple[Optional[float], Optional[str]]:
    """
    Test stratum server TLS connection and return response time in milliseconds.
    Returns (elapsed_time, error_message) tuple.
    
    Args:
        hostname: Server hostname or IP address
        port: TLS port number
        timeout: Connection timeout in seconds
        verify_cert: If False, disables certificate verification (useful for IP addresses)
    
    Returns:
        Tuple of (elapsed_time_ms, error_message)
        - elapsed_time_ms: Time in milliseconds if successful, None if failed
        - error_message: None if successful, error description if failed
    """
    try:
        import ssl
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Disable certificate verification if requested
        if not verify_cert:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        # Create socket and wrap with TLS
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        
        # For certificate verification, we need a hostname (not IP)
        # If verify_cert is False, we can use None for server_hostname
        server_hostname = hostname if verify_cert else None
        
        # Connect and perform TLS handshake
        with context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
            tls_sock.connect((hostname, port))
            
            subscribe_msg = json.dumps({
                "id": 1,
                "method": "mining.subscribe",
                "params": []
            }) + "\n"
            
            tls_sock.sendall(subscribe_msg.encode('utf-8'))
            response = tls_sock.recv(4096)
            elapsed_time = (time.time() - start_time) * 1000
            
            if response:
                try:
                    json.loads(response.decode('utf-8'))
                except json.JSONDecodeError:
                    pass
        
        return (elapsed_time, None)
        
    except Exception as e:
        import ssl
        error_type = type(e).__name__
        error_msg = str(e)
        
        # Categorize common TLS errors
        if isinstance(e, ssl.SSLCertVerificationError):
            return (None, f"Certificate verification failed: {error_msg}")
        elif isinstance(e, ssl.SSLError):
            if "CERTIFICATE_VERIFY_FAILED" in error_msg:
                return (None, "Certificate verification failed")
            elif "certificate verify failed" in error_msg.lower():
                return (None, "Certificate verification failed")
            else:
                return (None, f"SSL error: {error_msg}")
        elif isinstance(e, socket.timeout):
            return (None, "Connection timeout")
        elif isinstance(e, ConnectionRefusedError):
            return (None, "Connection refused")
        elif isinstance(e, OSError):
            if "Name or service not known" in error_msg or "nodename nor servname provided" in error_msg:
                return (None, "DNS resolution failed")
            else:
                return (None, f"Network error: {error_msg}")
        else:
            return (None, f"{error_type}: {error_msg}")

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
                               runs: int, country_code: str = "??", verify: bool = False,
                               tls_port: int = 0, test_tls: bool = False, verify_cert: bool = True) -> Dict:
    """Test a server multiple times and return statistics"""
    ping_times = []
    stratum_times = []
    tls_times = []
    tls_errors = []
    
    for _ in range(runs):
        ping_time = ping_host(hostname)
        stratum_time = test_stratum_connection(hostname, port)
        
        if ping_time is not None:
            ping_times.append(ping_time)
        if stratum_time is not None:
            stratum_times.append(stratum_time)
        
        # Test TLS if requested and port is available
        if test_tls and tls_port > 0:
            tls_time, tls_error = test_stratum_tls_connection(hostname, tls_port, verify_cert=verify_cert)
            if tls_time is not None:
                tls_times.append(tls_time)
            if tls_error is not None:
                tls_errors.append(tls_error)
        
        # Small delay between runs
        if runs > 1:
            time.sleep(0.1)
    
    result = {
        'hostname': hostname,
        'port': port,
        'tls_port': tls_port,
        'display_name': display_name,
        'country_code': country_code,
        'ping_times': ping_times,
        'stratum_times': stratum_times,
        'tls_times': tls_times,
        'tls_errors': tls_errors
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

def format_time_for_tls(result: Dict) -> str:
    """Format TLS time from result dict"""
    tls_port = result.get('tls_port', 0)
    tls_times = result.get('tls_times', [])
    
    # If no TLS port configured
    if tls_port == 0:
        return "-"
    
    # If TLS port exists but no successful times
    if not tls_times:
        return "FAILED"
    
    if len(tls_times) == 1:
        return format_time_single(tls_times[0])
    else:
        return format_time_multi(tls_times)

def print_table(results: List[Dict], runs: int, verify: bool = False, show_tls: bool = False):
    """Print results in a formatted ASCII table"""
    if not results:
        return
    
    # Check if verification was performed
    has_verification = verify and any('address_types' in r for r in results)
    
    # Check if TLS testing was performed (show column if TLS testing is enabled, regardless of results)
    has_tls = show_tls
    
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
    
    # TLS column width
    tls_width = 0
    tls_values = []
    if has_tls:
        tls_values = [format_time_for_tls(r) for r in results]
        if tls_values:  # Only calculate width if we have values
            tls_width = max(len(v) for v in tls_values)
            tls_width = max(tls_width, len("TLS (ms)"))
        else:
            tls_width = len("TLS (ms)")
    
    # Address type column widths (if verification enabled)
    addr_widths = {}
    if has_verification:
        addr_types = ['P2PKH', 'P2SH', 'P2WPKH', 'P2WSH', 'P2TR']
        for addr_type in addr_types:
            addr_widths[addr_type] = max(len(addr_type), 3)  # At least 3 for checkmark/X
    
    # Build separator
    separator = f"+{'-' * (max_name_len + 2)}+{'-' * (country_width + 2)}+{'-' * (max_host_len + 2)}+{'-' * (port_width + 2)}+{'-' * (ping_width + 2)}+{'-' * (stratum_width + 2)}"
    if has_tls:
        separator += f"+{'-' * (tls_width + 2)}"
    if has_verification:
        for addr_type in addr_types:
            separator += f"+{'-' * (addr_widths[addr_type] + 2)}"
    separator += "+"
    
    print(separator)
    
    # Header
    header_line = f"| {'Pool Name'.ljust(max_name_len)} | {'CC'.ljust(country_width)} | {'Host'.ljust(max_host_len)} | {'Port'.ljust(port_width)} | {'Ping (ms)'.ljust(ping_width)} | {'Stratum (ms)'.ljust(stratum_width)} |"
    if has_tls:
        header_line += f" {'TLS (ms)'.ljust(tls_width)} |"
    if has_verification:
        for addr_type in addr_types:
            header_line += f" {addr_type.ljust(addr_widths[addr_type])} |"
    print(header_line)
    
    if runs > 1:
        subheader = f"| {' '.ljust(max_name_len)} | {' '.ljust(country_width)} | {' '.ljust(max_host_len)} | {' '.ljust(port_width)} | {'Avg (Min-Max)'.ljust(ping_width)} | {'Avg (Min-Max)'.ljust(stratum_width)} |"
        if has_tls:
            subheader += f" {'Avg (Min-Max)'.ljust(tls_width)} |"
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
        
        # Add TLS column
        if has_tls:
            tls_str = tls_values[i].ljust(tls_width)
            row += f" {tls_str} |"
        
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

def print_tls_errors(results: List[Dict]):
    """Print TLS error details for failed connections"""
    # Collect all TLS failures with errors
    tls_failures = []
    for r in results:
        tls_port = r.get('tls_port', 0)
        tls_errors = r.get('tls_errors', [])
        
        # Only report if TLS was attempted (port > 0) and there are errors
        if tls_port > 0 and tls_errors:
            # Get the most common error (in case of multiple runs)
            error_msg = tls_errors[0] if tls_errors else "Unknown error"
            tls_failures.append({
                'display_name': r['display_name'],
                'hostname': r['hostname'],
                'tls_port': tls_port,
                'error': error_msg
            })
    
    if not tls_failures:
        return
    
    print("\nTLS Connection Failures:")
    print("-" * 80)
    
    for failure in tls_failures:
        print(f"  • {failure['display_name']} ({failure['hostname']}:{failure['tls_port']})")
        print(f"    Error: {failure['error']}")
    
    # Add helpful hint about certificate verification
    cert_errors = [f for f in tls_failures if 'certificate' in f['error'].lower() or 'verification' in f['error'].lower()]
    if cert_errors:
        print()
        print("  💡 Tip: If testing IP addresses, use --no-verify-cert to skip certificate validation")
        print("     Example: python3 stratum_test.py -t --no-verify-cert")

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

def test_all_servers(runs: int = 1, verify: bool = False, test_tls: bool = False, verify_cert: bool = True):
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
    tls_msg = " with TLS testing" if test_tls else ""
    print(f"\nTesting {len(PREDEFINED_SERVERS)} servers (runs: {runs}){verify_msg}{tls_msg}...")
    if verify:
        print("  Note: Verification adds ~10 seconds per server")
        print("  Using reduced concurrency (4 servers at a time) for reliability")
    
    results = []
    # Reduce concurrency when doing verification to avoid overwhelming pools
    max_workers = 4 if verify else len(PREDEFINED_SERVERS)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(test_server_multiple_runs, host, port, name, runs, cc, verify, tls_port, test_tls, verify_cert): (host, port, tls_port, name, cc)
            for host, port, tls_port, name, cc in PREDEFINED_SERVERS
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
    print_table(results, runs, verify, test_tls)
    print_summary(results)
    print_tls_errors(results)
    
    print()

def test_single_server(hostname: str, port: int, runs: int = 1, test_tls: bool = False, tls_port: int = 0, verify_cert: bool = True):
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
    
    # Look up server info from predefined list
    server_info = lookup_predefined_server(hostname)
    if server_info:
        _, predefined_tls_port, display_name, country_code = server_info
        # Use predefined TLS port if not explicitly specified
        if test_tls and tls_port == 0:
            tls_port = predefined_tls_port
    else:
        display_name = hostname
        country_code = "??"
    
    # Test server
    tls_msg = f" with TLS on port {tls_port}" if test_tls and tls_port > 0 else ""
    cert_msg = " (no cert verification)" if test_tls and not verify_cert else ""
    print(f"\nTesting {hostname}:{port} (runs: {runs}){tls_msg}{cert_msg}...")
    result = test_server_multiple_runs(hostname, port, display_name, runs, country_code, False, tls_port, test_tls, verify_cert)
    print("\nResults:")
    print_table([result], runs, False, test_tls)
    print_tls_errors([result])
    
    print()

def output_json(runs: int = 1, test_tls: bool = False, verify_cert: bool = True):
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
        'tls_tested': test_tls,
        'results': []
    }
    
    # Test servers
    with ThreadPoolExecutor(max_workers=len(PREDEFINED_SERVERS)) as executor:
        futures = [
            executor.submit(test_server_multiple_runs, host, port, name, runs, cc, False, tls_port, test_tls, verify_cert)
            for host, port, tls_port, name, cc in PREDEFINED_SERVERS
        ]
        for future in as_completed(futures):
            result = future.result()
            result_data = {
                'host': result['hostname'],
                'port': result['port'],
                'tls_port': result.get('tls_port', 0),
                'display_name': result['display_name'],
                'country_code': result.get('country_code', '??'),
                'ping_ms': result['ping_times'],
                'stratum_ms': result['stratum_times'],
                'ping_avg': mean(result['ping_times']) if result['ping_times'] else None,
                'stratum_avg': mean(result['stratum_times']) if result['stratum_times'] else None
            }
            if test_tls:
                result_data['tls_ms'] = result.get('tls_times', [])
                result_data['tls_avg'] = mean(result['tls_times']) if result.get('tls_times') else None
            output['results'].append(result_data)
    
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
  
  Test with TLS support (requires Python 3.6+):
    python stratum_test.py -t
    python stratum_test.py --tls
  
  Test with TLS, skip certificate verification (for IP addresses):
    python stratum_test.py -t --no-verify-cert
  
  Output JSON format:
    python stratum_test.py --json
  
  Test single server:
    python stratum_test.py solo.atlaspool.io 3333
  
  Test single server with TLS:
    python stratum_test.py solo.atlaspool.io 3333 -t 4333
  
  Test single server with TLS, no cert verification:
    python stratum_test.py 3.76.213.107 3333 -t 4333 --no-verify-cert
  
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
    parser.add_argument('-t', '--tls', nargs='?', type=int, const=0, metavar='TLS_PORT',
                        help='Test TLS stratum connections. Requires Python 3.6+ (Python 3.7+ for TLS 1.3). '
                             'For predefined servers, uses configured TLS ports. '
                             'For single server test, specify TLS port number (e.g., -t 4333)')
    parser.add_argument('--no-verify-cert', action='store_true',
                        help='Disable TLS certificate verification (useful for testing IP addresses with TLS). '
                             'WARNING: Only use for testing - disables security checks!')
    parser.add_argument('--json', action='store_true',
                        help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.json and (args.hostname or args.port):
        print("Error: --json cannot be used with single server test", file=sys.stderr)
        sys.exit(1)
    
    # Determine if TLS testing is enabled
    test_tls = args.tls is not None
    tls_port = args.tls if args.tls else 0
    verify_cert = not args.no_verify_cert
    
    # Check Python version for TLS support
    if test_tls:
        python_version = sys.version_info
        if python_version < (3, 6):
            print("Error: TLS testing requires Python 3.6 or higher", file=sys.stderr)
            print(f"Current version: Python {python_version.major}.{python_version.minor}.{python_version.micro}", file=sys.stderr)
            sys.exit(1)
        elif python_version < (3, 7):
            print("Warning: Python 3.6 detected - TLS 1.2 will be used (TLS 1.3 requires Python 3.7+)", file=sys.stderr)
            print()
    
    # Single server test
    if args.hostname and args.port:
        # Check if TLS port is needed
        if test_tls and tls_port == 0:
            # Look up if this is a predefined server with TLS support
            server_info = lookup_predefined_server(args.hostname)
            if not server_info or server_info[1] == 0:
                # Not in predefined list or no TLS support configured
                print("Error: TLS port must be specified for single server TLS test (e.g., -t 4333)", file=sys.stderr)
                sys.exit(1)
        test_single_server(args.hostname, args.port, args.runs, test_tls, tls_port, verify_cert)
    elif args.hostname or args.port:
        print("Error: Both hostname and port must be provided for single server test", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    # JSON output
    elif args.json:
        output_json(args.runs, test_tls, verify_cert)
    # Default: test all servers
    else:
        test_all_servers(args.runs, args.verify, test_tls, verify_cert)

if __name__ == "__main__":
    main()
