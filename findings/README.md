# Prevhash Timeline Analysis - Findings

This directory contains the definitive proof that certain Bitcoin mining pools (LuckyMonster and zsolo.bid) are not mining on the real Bitcoin blockchain.

## Contents

- **PREVHASH_ANALYSIS.md** - Complete analysis report with timeline table and findings
- **prevhash_timeline.py** - The script used to collect the data

## What This Proves

By monitoring 16 Bitcoin mining pools simultaneously over 11 minutes, we discovered:

- ✓ All 13 legitimate pools had the same prevhash at all times
- ✓ All 13 legitimate pools updated together when a new block was found
- ✗ All 3 scam pools (LuckyMonster US, LuckyMonster EU, zsolo.bid) stayed stuck on a different prevhash
- ✗ Scam pools never updated when the new block was found

**CRITICAL DISCOVERY:** By converting the scam pool prevhash to big-endian format and searching blockchain explorers, we found it on the **Bitcoin Cash (BCH) blockchain**, not Bitcoin (BTC). 

**This proves LuckyMonster and zsolo.bid are mining Bitcoin Cash while claiming to mine Bitcoin, stealing 100% of miners' hashrate for their own BCH rewards.**

## Running the Test Yourself

### Prerequisites

- Python 3.6 or higher
- A valid Bitcoin address (for testing legitimate pools)
- A file named `pools.txt` with pool list

### Pool List Setup

**Option 1: Use the included pools.txt file (recommended)**

A `pools.txt` file is included in this directory with 16 pools (3 scam, 13 legitimate). You can use it as-is:

```bash
# The pools.txt file is already in the findings directory
python3 prevhash_timeline.py YOUR_BITCOIN_ADDRESS pools.txt
```

**Option 2: Create your own pools.txt file**

Create a `pools.txt` file with one pool per line:

```
hostname port
```

Example:
```
solo.ckpool.org 3333
solo.atlaspool.io 3333
btc.luckymonster.pro 7112
```

### Running the Script

**Basic usage (11 minutes, 22 snapshots with included pools.txt):**

```bash
python3 prevhash_timeline.py YOUR_BITCOIN_ADDRESS pools.txt
```

**Example:**

```bash
python3 prevhash_timeline.py 3Ax2uht6S5Lh6V5HLNhxfaHnEZU7KaFvSZ pools.txt
```

**Custom duration:**

```bash
python3 prevhash_timeline.py YOUR_ADDRESS pools.txt NUM_SNAPSHOTS INTERVAL_SECONDS
```

Example (5 minutes, 10 snapshots at 30-second intervals):
```bash
python3 prevhash_timeline.py 3Ax2uht6S5Lh6V5HLNhxfaHnEZU7KaFvSZ pools.txt 10 30
```

### What the Script Does

1. **Connects to all pools simultaneously** every 30 seconds
2. **Captures the prevhash** (previous block hash) from each pool
3. **Monitors for 11 minutes** (22 snapshots by default)
4. **Displays a timeline table** showing which pools updated when blocks were found
5. **Analyzes the results** to identify pools stuck on old/fake prevhashes

### Understanding the Output

The script produces:

1. **Timeline Table** - Shows prevhash for each pool at each snapshot
   - Letters (A, B, C...) represent different prevhashes
   - Columns are pools (numbered 1-16)
   - Rows are time snapshots

2. **Pool Legend** - Maps pool numbers to actual pool names
   - Scam pools listed first
   - Legitimate pools listed after

3. **Prevhash Legend** - Maps letters to actual prevhash values

4. **Analysis** - Shows:
   - Which pools updated when blocks were found
   - Which pools stayed stuck on old prevhashes
   - Block changes detected during monitoring

### Expected Results

**Legitimate pools:**
- All have the same prevhash at any given time
- All update together when new blocks are found
- Show multiple different prevhashes over 11 minutes

**Scam/fake pools:**
- Have different prevhash than legitimate pools
- Don't update when new blocks are found
- Stay stuck on the same prevhash for entire test

### Example Output

```
Time      1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
--------------------------------------------------------
21:49:26   A  A  A  C  C  C  C  C  C  C  C  C  C  C  C  C
21:49:57   A  A  A  C  C  C  C  C  C  C  C  C  C  C  C  C
...
21:57:49   A  A  A  B  B  B  B  B  B  B  B  B  B  B  B  B  ← NEW BLOCK!
21:58:19   A  A  A  B  B  B  B  B  B  B  B  B  B  B  B  B
```

In this example:
- Pools 1-3 (scam pools) stayed on prevhash A (never updated)
- Pools 4-16 (legitimate) updated from C to B when new block found

## Technical Details

### How It Works

1. **Simultaneous connections** - Uses threading to connect to all pools at once
2. **Stratum protocol** - Implements mining.subscribe and mining.authorize
3. **Job monitoring** - Captures mining.notify messages containing prevhash
4. **Timeline tracking** - Records prevhash from each pool at each interval

### Why This Test is Definitive

- **Same moment in time** - All pools tested simultaneously (within 200ms)
- **Long duration** - 11 minutes ensures we catch block changes
- **Multiple pools** - Tests 16 pools to show legitimate vs scam behavior
- **Real-time monitoring** - Captures actual blockchain state, not historical data

### Limitations

- Requires at least one new block to be found during test (average: 10 minutes)
- Some legitimate pools may reject invalid/test addresses
- Network latency can cause slight delays in updates (1-2 seconds)

## Interpreting Results

### Red Flags

⚠️ **Pool is likely a scam if:**
- Different prevhash than all legitimate pools
- Doesn't update when legitimate pools do
- Stuck on same prevhash for entire test
- Accepts invalid addresses without validation

### Green Flags

✓ **Pool is likely legitimate if:**
- Same prevhash as other legitimate pools
- Updates when new blocks are found
- Shows multiple prevhashes over time
- Rejects invalid addresses

## Further Analysis

For more detailed analysis, see:
- **PREVHASH_ANALYSIS.md** - Complete findings report
- **../UNDERSTANDING_PROXY_DETECTION.md** - Explanation of detection methods
- **../SCAM_POOL_INVESTIGATION_GUIDE.md** - How to investigate suspicious pools

## Questions?

If you have questions about the methodology or findings, please open an issue on the GitHub repository.

## License

This tool is provided for educational and research purposes to help miners identify legitimate pools.

---

**Last Updated:** November 25, 2025  
**Test Duration:** 11 minutes (22 snapshots at 30-second intervals)  
**Pools Tested:** 16 (3 scam, 13 legitimate)  
**Result:** Definitive proof that LuckyMonster and zsolo.bid are not on real Bitcoin blockchain
