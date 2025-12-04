# Bitcoin Solo Mining Pool Speed Test

A cross-platform Python tool to help Bitcoin solo miners find the fastest public stratum mining pool server from their location.

## Why Use This Tool?

When solo mining Bitcoin, even small differences in connection speed can affect your mining efficiency (particularly noticeable with rejected share count). This script tests connectivity to major solo mining pools worldwide, measuring both network latency and full stratum protocol response times to help you choose the optimal pool server.

## How It Works

The script performs two tests for each pool:

1. **PING TEST** - Measures basic network latency using ICMP
2. **STRATUM HANDSHAKE** - Measures complete connection time including the mining.subscribe protocol handshake (this is what your miner actually experiences)

All servers are tested concurrently for fast results (~5-10 seconds total).

## Requirements

- Python 3.6 or higher (Python 3.11+ recommended for best performance)
- No external dependencies (uses only standard library)
- Works on Windows, macOS, and Linux

**Note**: Use `python3` if `python` is not available on your system.

**macOS Users**: If using the system Python 3.9.6 (from Command Line Tools), the script includes workarounds for subprocess issues. For best results, consider upgrading to Python 3.11+ via Homebrew: `brew install python@3.11`

## Installation

Clone the repository from GitHub:

```bash
git clone https://github.com/mweinberg/stratum-speed-test.git
cd stratum-speed-test
```

Make it executable (Linux/macOS):

```bash
chmod +x stratum_test.py
```

## Usage

### Quick Test (Default)

Test all preconfigured pools with 1 run each:

```bash
python3 stratum_test.py  # or just 'python' on some systems
```

### TLS Connection Testing (New in v1.3)

Test secure TLS stratum connections for pools that support it:

```bash
python stratum_test.py -t
```

This tests both regular and TLS connections, showing response times for each. TLS results appear in an additional column:
- **Number** = TLS connection time in milliseconds
- **N/A** = Pool doesn't support TLS
- **FAILED** = TLS connection failed

**TLS-enabled pools:**
- AtlasPool.io (port 4333)
- Public Pool (port 4333)
- Noderunners (port 1336)

### Address Type Verification (New in v1.1)

Test which Bitcoin address types each pool supports:

```bash
python stratum_test.py -v
```

This tests all 5 address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and shows which formats each pool accepts. Results appear as additional columns in the output table:
- ✓ = Supported
- X = Not Supported  
- ? = Unknown (may require valid credentials)

**Note**: Verification adds ~10 seconds per server and uses reduced concurrency for reliability.

### Multiple Runs for Accuracy

Run multiple tests per server and get average with min-max range:

```bash
python stratum_test.py --runs 3
```

Valid options: `--runs 1`, `--runs 2`, or `--runs 3`

You can combine with verification:

```bash
python stratum_test.py --runs 3 -v
```

### Test a Specific Pool

Test a single pool server by providing the hostname and port as arguments:

```bash
python stratum_test.py <hostname> <port>
```

**Examples:**

```bash
# Test AtlasPool (note: use solo.atlaspool.io, not atlaspool.io)
python stratum_test.py solo.atlaspool.io 3333

# Test CKPool
python stratum_test.py solo.ckpool.org 3333

# Test with multiple runs for better accuracy
python stratum_test.py solo.atlaspool.io 3333 --runs 3

# Test with TLS (for predefined servers, TLS port is auto-detected)
python stratum_test.py public-pool.io 3333 -t

# Test with TLS on custom port
python stratum_test.py solo.atlaspool.io 3333 -t 4333
```

**Important:** Both hostname and port must be provided. The script will show an error if only one is specified.

### Pool Verification Tool (New in v1.1)

Use `verify_pool.py` to verify a solo mining pool will pay block rewards to YOUR address:

```bash
# Verify a specific address
python3 verify_pool.py solo.atlaspool.io 3333 bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Test all 5 address types
python3 verify_pool.py solo.atlaspool.io 3333 -a
```

**What it does:**
1. Connects to the pool as a mining worker
2. Requests a block template (mining work)
3. Parses the coinbase transaction
4. Verifies YOUR address appears in the payout outputs

**Results:**
- ✅ Address found - Pool will pay YOU if you find a block
- ⚠️ Unknown - Could not verify (may require valid credentials)
- ❌ Address NOT found - WARNING: Pool may not be legitimate!

This tool helps ensure you're using a legitimate solo mining pool that will actually pay you if you find a block, rather than paying the pool operator.

### JSON Output

Get machine-readable output for automation:

```bash
python stratum_test.py --json
python stratum_test.py --runs 3 --json > results.json
```

## Preconfigured Mining Pools

The script includes 20 popular Bitcoin solo mining pools.  This list is not exhaustive, and the author intends no slight to any missing pools!  Feel free to submit a pull request or comment on other solo mining pools which should be considered for inclusion.

### Global/Anycast
- **AtlasPool.io** - `solo.atlaspool.io:3333` (TLS: 4333) - Global edge network

### Australia (AU)
- **AU CKPool** - `ausolo.ckpool.org:3333`

### Switzerland (CH)
- **Blitzpool** - `blitzpool.yourdevice.ch:3333`

### Germany (DE)
- **EU CKPool** - `eusolo.ckpool.org:3333`
- **DE SoloHash** - `solo-de.solohash.co.uk:3333`
- **SoloMining.de** - `pool.solomining.de:3333`
- **Sunnydecree Pool** - `pool.sunnydecree.de:3333`
- **Nerdminer.de** - `pool.nerdminer.de:3333`
- **Noderunners** - `pool.noderunners.network:1337` (TLS: 1336)
- **Braiins Solo** - `solo.stratum.braiins.com:3333`
- **KanoPool DE** - `de.kano.is:3333`

### France (FR)
- **FindMyBlock** - `eu.findmyblock.xyz:3335`

### Netherlands (NL)
- **Satoshi Radio** - `pool.satoshiradio.nl:3333`

### United Kingdom (UK)
- **UK SoloHash** - `solo.solohash.co.uk:3333`

### United States (US)
- **US CKPool** - `solo.ckpool.org:3333`
- **KanoPool** - `stratum.kano.is:3333`
- **Parasite Pool** - `parasite.wtf:42069`
- **Public Pool** - `public-pool.io:3333` (TLS: 4333)
- **solo.cat** - `solo.cat:3333`
- **US SoloHash** - `solo-ca.solohash.co.uk:3333`

## Example Output

```
================================================================================
BITCOIN SOLO MINING POOL SPEED TEST
================================================================================

This script helps Bitcoin solo miners find the fastest stratum mining pool
server from their location...

============================================================
Testing from: Baltimore, United States
(Note: Location based on IP geolocation - may differ if using VPN/proxy)
Your IP: 203.0.113.42
Network: AS12345 Example ISP

Testing 16 servers (runs: 1)...
  Progress: 16/16

Results:
+-----------------+--------+-------------------------+-------+-----------+--------------+
| Pool Name       | CC     | Host                    | Port  | Ping (ms) | Stratum (ms) |
+-----------------+--------+-------------------------+-------+-----------+--------------+
| AtlasPool.io    | *MANY* | solo.atlaspool.io       | 3333  | 12        | 32           |
| US SoloHash     | US     | solo-ca.solohash.co.uk  | 3333  | 22        | 55           |
| LuckyMiner      | US     | btc.luckymonster.pro    | 7112  | 31        | 64           |
| Public Pool     | US     | public-pool.io          | 21496 | BLOCKED   | 119          |
| Parasite Pool   | US     | parasite.wtf            | 42069 | 52        | 121          |
| KanoPool        | US     | stratum.kano.is         | 3333  | 76        | 142          |
| US CKPool       | US     | solo.ckpool.org         | 3333  | 75        | 148          |
| solo.cat        | US     | solo.cat                | 3333  | 71        | 149          |
| zSolo           | FR     | btc.zsolo.bid           | 6057  | 100       | 203          |
| UK SoloHash     | UK     | solo.solohash.co.uk     | 3333  | 93        | 204          |
| SoloMining.de   | DE     | pool.solomining.de      | 3333  | 105       | 205          |
| EU LuckyMonster | FR     | btc-eu.luckymonster.pro | 7112  | 98        | 205          |
| EU CKPool       | DE     | eusolo.ckpool.org       | 3333  | 111       | 211          |
| DE SoloHash     | DE     | solo-de.solohash.co.uk  | 3333  | 108       | 211          |
| AU CKPool       | AU     | ausolo.ckpool.org       | 3333  | 304       | 3814         |
| FindMyBlock     | FR     | eu.findmyblock.xyz      | 3335  | 103       | N/A          |
+-----------------+--------+-------------------------+-------+-----------+--------------+

Summary:
------------------------------------------------------------
Fastest Ping:    AtlasPool.io (12 ms)
Fastest Stratum: AtlasPool.io (32 ms)

RECOMMENDATION: Consider using AtlasPool.io (solo.atlaspool.io:3333)
                for optimal mining performance from your location.
```

## Understanding the Results

### Status Messages

- **Number (e.g., 52)** - Response time in milliseconds
- **BLOCKED** - Ping failed but stratum succeeded (ICMP blocked by firewall).
- **N/A** - Connection failed or timed out (server unreachable or down)

### Which Metric Matters?

**Stratum (ms)** is the most important metric - this is the actual time your mining hardware experiences when connecting to the pool. Lower is better.

**Ping (ms)** shows basic network latency. If ping shows "BLOCKED" but stratum works, the pool is still usable (some pools block ICMP for security).

### Recommendations

The script recommends all pools within **3ms** of the fastest stratum time. If multiple pools are recommended, they all offer similar performance from your location.

## Tips for Best Results

1. **Run from your mining network** - Test from the same network connection your miners use
2. **Run multiple times** - Use `--runs 3` for more accurate results
3. **Test at different times** - Network conditions vary throughout the day
4. **Consider geographic location** - Pools closer to you typically have lower latency
5. **VPN affects results** - Location detection is based on IP geolocation

## Adding Custom Pools

To test pools not in the preconfigured list, use the single server test:

```bash
python stratum_test.py your.pool.com 3333
```

To permanently add a pool, edit the `PREDEFINED_SERVERS` list in the script:

```python
PREDEFINED_SERVERS = [
    ("your.pool.com", 3333, 4333, "Your Pool Name", "US"),
    # ... other servers
]
```

Format: `(hostname, port, tls_port, display_name, country_code)`
- Set `tls_port` to `0` if the pool doesn't support TLS

## Troubleshooting

### "N/A" for both ping and stratum
- Server might be down
- Port might be blocked by firewall
- DNS resolution might have failed
- Check if you can reach the server: `ping hostname`

### "BLOCKED" for ping
- Normal - some pools block ICMP ping for security
- As long as stratum works, the pool is usable

### Script hangs or is slow
- Some servers might be timing out (5 second timeout per server)
- Try testing a specific server to isolate the issue
- Check your internet connection

### All pings show "BLOCKED" (macOS)
- If using system Python 3.9.6, upgrade to Python 3.11+: `brew install python@3.11`
- Or the script should now work with the v1.1 fix

### Permission errors on Linux/macOS
- Make the script executable: `chmod +x stratum_test.py`
- Or run with: `python3 stratum_test.py`

## Technical Details

### Concurrency
- Tests all servers simultaneously using 16 concurrent threads
- Total test time: ~5-10 seconds (limited by slowest server)
- Thread-safe and works on all platforms

### Timeouts
- Ping timeout: 2 seconds
- Stratum connection timeout: 5 seconds
- Multiple runs have 0.1 second delay between attempts

### Network Requirements
- Outbound TCP connections to pool ports (typically 3333, 7112, etc.)
- Outbound ICMP for ping tests (optional - script works without it)
- HTTPS access to ipify.org and ip-api.com for IP/location lookup

## JSON Output Format

```json
{
  "timestamp": "2025-11-19T10:30:00Z",
  "client": {
    "ipv4": "203.0.113.42",
    "location": "São Paulo, Brazil",
    "asn": "AS12345",
    "provider": "Example ISP"
  },
  "runs": 3,
  "results": [
    {
      "host": "solo.atlaspool.io",
      "port": 3333,
      "display_name": "AtlasPool.io",
      "country_code": "*MANY*",
      "ping_ms": [45, 46, 44],
      "stratum_ms": [52, 51, 53],
      "ping_avg": 45.0,
      "stratum_avg": 52.0
    }
  ]
}
```

## Privacy & Security

- The script only connects to pool servers you're testing
- IP geolocation uses public APIs (ipify.org, ip-api.com)
- No data is collected or sent to third parties
- All connections are outbound only
- Source code is open and auditable

## Contributing

Found a bug or want to add a pool? Contributions welcome!

## License

GPL-3.0 License - Free to use and modify under the terms of the GNU General Public License v3.0

## Support

For issues or questions:
- GitHub Issues: [Create an issue]
- Pool operators: Contact to be added to the preconfigured list

## Changelog

### Version 1.3 - December 2025

**New Features:**
- Added: TLS connection testing with `-t`/`--tls` flag
- Added: `test_stratum_tls_connection()` function for secure stratum connections
- Added: TLS port field to PREDEFINED_SERVERS configuration
- Added: TLS column in results table showing secure connection times
- Added: `lookup_predefined_server()` for automatic metadata extraction
- Added: Auto-detection of TLS ports for predefined servers

**Pool Updates:**
- Updated: public-pool.io default port from 21496 to 3333
- Added: pool.noderunners.network with TLS support (port 1337, TLS 1336)
- Added: 4 new pools (Blitzpool, Sunnydecree, Nerdminer.de, Satoshi Radio)
- Updated: Total pool count from 16 to 20

**TLS-Enabled Pools:**
- AtlasPool.io (TLS port 4333)
- Public Pool (TLS port 4333)
- Noderunners (TLS port 1336)

**Improvements:**
- Enhanced: PREDEFINED_SERVERS documentation with detailed field descriptions
- Improved: Single server testing now extracts country code from predefined list
- Improved: Better error handling for TLS port validation

### Version 1.2 - November 2025

**Improvements:**
- Added: Ping availability detection at startup
- Added: OS-specific installation instructions when ping is missing
- Added: Clear warning message for systems without ping command
- Improved: Better user experience on Android/Termux and minimal Linux systems
- Improved: Script continues to work (stratum tests) even without ping

**User Experience:**
- Users on systems without ping (Android, minimal containers) now get helpful guidance
- Installation instructions provided for Debian/Ubuntu/Termux, Fedora, Arch Linux
- Option to continue without ping or exit to install it first

**Thanks:**
- Special thanks to Reddit user alex262414 from r/BitAxe who reported the issue on Android and helped test the fix!

### Version 1.1 - November 2025

**New Features:**
- Added: Address type verification (`-v` flag) - Tests all 5 Bitcoin address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- Added: `verify_pool.py` - Standalone tool to verify solo mining pools pay to your address
- Added: Comprehensive address validation with helpful error messages
- Added: Three-state verification results (✓ Supported, X Not Supported, ? Unknown)

**Improvements:**
- Improved: Verification reliability with better timeout handling and retry logic
- Improved: Reduced concurrency during verification (4 workers) to avoid rate limiting
- Improved: Multiple recv() calls to handle fragmented responses from pools
- Improved: Added delays between address type tests (1 second) for consistency
- Improved: Expanded table output shows address type compatibility at a glance

**Bug Fixes:**
- Fixed: Ping tests now work correctly on macOS with Python 3.9.6
- Fixed: Resolved subprocess segfault issue causing "BLOCKED" for all hosts
- Fixed: Invalid P2SH test address replaced with valid one
- Fixed: Socket timeout issues causing inconsistent verification results
- Changed: Improved ping implementation using `os.system()` for better compatibility

**Documentation:**
- Added: Comprehensive preamble explaining verification process
- Added: Address validation with specific error messages for invalid addresses
- Updated: Help text explains all 5 address types with examples
- Updated: README with detailed changelog and new features

### Version 1.0 - November 2025
- Initial release

---

**Note**: This tool is for testing connectivity only. Actual mining performance depends on many factors including hardware, network stability, and pool luck. Always do your own research before choosing a mining pool.
