#!/usr/bin/env python3
"""Measure PIE base entropy for 32-bit telnetd behind ASLR."""

import socket
import subprocess
import time
import sys

NUM_SAMPLES = 30

bases = []

for i in range(NUM_SAMPLES):
    # Connect to spawn a new telnetd process
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('127.0.0.1', 2325))
        time.sleep(0.15)
    except Exception as e:
        print(f"[{i}] Connection failed: {e}", file=sys.stderr)
        continue

    # Read maps for the newest telnetd process
    result = subprocess.run(
        ['docker', 'exec', 'autohack-telnetd-32bit', 'bash', '-c',
         'cat /proc/$(pgrep -n in.telnetd)/maps 2>/dev/null | grep telnetd | head -1'],
        capture_output=True, text=True, timeout=5
    )

    s.close()

    line = result.stdout.strip()
    if line:
        # Extract the base address (start of first mapping)
        base_hex = line.split('-')[0]
        base = int(base_hex, 16)
        bases.append(base)
        print(f"[{i:2d}] base=0x{base:08x}  {line[:60]}")
    else:
        print(f"[{i:2d}] no output (stderr: {result.stderr.strip()[:80]})", file=sys.stderr)

print(f"\n{'='*60}")
print(f"Collected {len(bases)} samples")

if not bases:
    print("No bases collected - cannot analyze.")
    sys.exit(1)

unique = sorted(set(bases))
print(f"Unique bases: {len(unique)}")
print(f"Min:  0x{min(unique):08x}")
print(f"Max:  0x{max(unique):08x}")
print(f"Range: 0x{max(unique) - min(unique):08x} ({(max(unique) - min(unique)) // 4096} pages)")

print(f"\nAll unique bases:")
for b in unique:
    count = bases.count(b)
    print(f"  0x{b:08x}  (seen {count}x)")

# Entropy analysis
import math
num_unique = len(unique)
if num_unique > 1:
    # The range in pages
    page_range = (max(unique) - min(unique)) // 4096
    # Check alignment - what's the stride?
    if len(unique) >= 2:
        diffs = sorted(set(unique[i+1] - unique[i] for i in range(len(unique)-1) if unique[i+1] != unique[i]))
        min_stride = min(diffs) if diffs else 0
        print(f"\nSmallest stride between bases: 0x{min_stride:x} ({min_stride // 4096} pages)")
        if min_stride > 0:
            theoretical_positions = page_range // (min_stride // 4096) + 1 if min_stride else page_range
            print(f"Theoretical positions in range: ~{theoretical_positions}")

    bits = math.log2(num_unique)
    print(f"\nObserved entropy: {bits:.1f} bits ({num_unique} unique values from {len(bases)} samples)")
    print(f"Average brute-force attempts (50% success): ~{num_unique // 2}")
    print(f"Worst case brute-force attempts: {num_unique}")

    # Extrapolate: if we saw N unique in S samples, estimate total
    # Using capture-recapture: if all samples were unique, there are likely more
    all_unique = (num_unique == len(bases))
    if all_unique:
        print(f"\nWARNING: All {len(bases)} samples were unique - true entropy may be higher.")
        print(f"Consider collecting more samples for better estimate.")
    else:
        # Good-Turing estimate
        singletons = sum(1 for b in unique if bases.count(b) == 1)
        estimated_total = num_unique / (1 - singletons / len(bases)) if singletons < len(bases) else num_unique * 2
        est_bits = math.log2(estimated_total)
        print(f"\nEstimated total positions (Good-Turing): ~{int(estimated_total)}")
        print(f"Estimated entropy: ~{est_bits:.1f} bits")
        print(f"Estimated avg brute-force: ~{int(estimated_total) // 2} attempts")
else:
    print("\nOnly 1 unique base - ASLR may be disabled for this binary!")
    print("Brute force: 1 attempt (deterministic)")
