#!/usr/bin/env python3
"""Test: Send SLC subneg before WILL LINEMODE"""
import socket, time, sys

IAC=0xFF; SB=0xFA; SE=0xF0; DO=0xFD; WILL=0xFB; WONT=0xFC; DONT=0xFE
OPT_LINEMODE=0x22; OPT_TTYPE=0x18; OPT_NAWS=0x1F; LM_SLC=0x03

def recv_all(s, timeout=2):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            chunks.append(c)
    except: pass
    return b''.join(chunks)

def test():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(("127.0.0.1", 2325))

    # Get initial DOs
    time.sleep(0.3)
    data = recv_all(s, 1)
    print(f"Initial: {len(data)} bytes")
    print(f"Hex: {data.hex()}")

    # Parse DOs
    i = 0
    while i < len(data):
        if data[i] == IAC and i+2 < len(data):
            cmd = data[i+1]
            opt = data[i+2]
            names = {0xFD:'DO', 0xFB:'WILL', 0xFC:'WONT', 0xFE:'DONT'}
            optnames = {0x18:'TTYPE', 0x1F:'NAWS', 0x20:'TSPEED', 0x22:'LINEMODE', 0x23:'XDISPLOC', 0x24:'OLD_ENVIRON', 0x27:'NEW_ENVIRON'}
            print(f"  {names.get(cmd,'?')} {optnames.get(opt, hex(opt))}")
            i += 3
        else:
            i += 1

    # NOW: Send SLC subneg WITHOUT sending WILL LINEMODE first
    # The server sent DO LINEMODE, setting options[LINEMODE] = OPT_HIS (0x08?)
    # But we haven't sent WILL LINEMODE, so OPT_HIM_ACK (0x04?) is not set
    slc_data = bytearray()
    for func in range(0x13, 0x30):  # ~30 triplets
        slc_data.extend([func, 0x02, 0x00])

    pkt = bytearray([IAC, SB, OPT_LINEMODE, LM_SLC])
    pkt.extend(slc_data)
    pkt.extend([IAC, SE])

    print(f"\nSending SLC subneg ({len(slc_data)} bytes, {len(slc_data)//3} triplets) BEFORE WILL LINEMODE")
    s.send(bytes(pkt))

    time.sleep(0.5)
    resp = recv_all(s, 1)
    print(f"Response after SLC: {len(resp)} bytes")
    if resp:
        print(f"Hex: {resp[:100].hex()}")
        # Check for SLC response
        if bytes([IAC, SB, OPT_LINEMODE, LM_SLC]) in resp:
            print("*** GOT SLC RESPONSE - Server processed our SLC! ***")
        else:
            print("No SLC response in data")
    else:
        print("No response (may have been silently deferred or ignored)")

    # Now send WILL LINEMODE and see if deferred SLC gets processed
    print(f"\nNow sending WILL LINEMODE...")
    s.send(bytes([IAC, WILL, OPT_LINEMODE]))

    time.sleep(0.5)
    resp2 = recv_all(s, 1)
    print(f"Response after WILL LINEMODE: {len(resp2)} bytes")
    if resp2:
        print(f"Hex: {resp2[:200].hex()}")
        if bytes([IAC, SB, OPT_LINEMODE, LM_SLC]) in resp2:
            print("*** GOT SLC RESPONSE after WILL LINEMODE - Deferred SLC was processed! ***")
            # Find the SLC data
            idx = resp2.find(bytes([IAC, SB, OPT_LINEMODE, LM_SLC]))
            end_idx = resp2.find(bytes([IAC, SE]), idx+4)
            if end_idx > idx:
                slc_resp = resp2[idx+4:end_idx]
                print(f"SLC response body: {len(slc_resp)} bytes")
                print(f"Hex: {slc_resp[:60].hex()}")
        else:
            print("No SLC response")

    # Also try: send WILLs for other options + TTYPE to trigger terminit
    print(f"\nSending remaining WILLs + TTYPE...")
    resp3_pkt = bytearray()
    resp3_pkt.extend([IAC, WILL, OPT_NAWS])
    resp3_pkt.extend([IAC, WILL, 0x20])  # TSPEED
    resp3_pkt.extend([IAC, WILL, OPT_TTYPE])
    resp3_pkt.extend([IAC, SB, OPT_TTYPE, 0x00])
    resp3_pkt.extend(b'xterm')
    resp3_pkt.extend([IAC, SE])
    resp3_pkt.extend([IAC, SB, OPT_NAWS, 0x00, 0x50, 0x00, 0x18, IAC, SE])
    s.send(bytes(resp3_pkt))

    time.sleep(1)
    resp3 = recv_all(s, 2)
    print(f"Response after TTYPE: {len(resp3)} bytes")
    if resp3:
        print(f"Hex first 200: {resp3[:200].hex()}")
        if bytes([IAC, SB, OPT_LINEMODE, LM_SLC]) in resp3:
            print("*** GOT SLC RESPONSE after TTYPE - This is the deferslc path! ***")
            idx = resp3.find(bytes([IAC, SB, OPT_LINEMODE, LM_SLC]))
            end_idx = resp3.find(bytes([IAC, SE]), idx+4)
            if end_idx > idx:
                slc_resp = resp3[idx+4:end_idx]
                print(f"SLC response body: {len(slc_resp)} bytes ({len(slc_resp)//3} triplets)")
                if len(slc_resp) > 54:
                    print(f"*** OVERFLOW DATA in deferred response: {len(slc_resp)-54} bytes ***")

    s.close()

if __name__ == "__main__":
    test()
