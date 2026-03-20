# CVE-2026-32746 - 32-bit Exploitation via def_slcbuf/free() Primitive

## Target
GNU InetUtils telnetd 2.4, compiled as 32-bit i386 on Debian bookworm.
Container: `autohack-telnetd-32bit` on port 2325.

## Background
CVE-2026-32746 is a BSS buffer overflow in the SLC (Set Local Characters) handler. `add_slc()` writes 3 bytes per triplet into a 108-byte buffer (`slcbuf`) without bounds checking. With 40+ triplets, adjacent BSS variables are corrupted.

Previous work on 64-bit proved the overflow is real (verified via SLC response analysis showing leaked BSS data including PIE pointers) but could NOT achieve code execution due to:
- Full RELRO (read-only GOT)
- 64-bit pointer NULL byte constraints (can't represent consecutive NULLs in triplets)
- Forward-only overflow (critical targets like auth_user, login_invocation are before slcbuf in BSS)

## New Attack Path: WatchTowr's Research
Source: https://labs.watchtowr.com/a-32-year-old-bug-walks-into-a-telnet-server-gnu-inetutils-telnetd-cve-2026-32746/

### The Defer Trick (Critical - New Ordering)
By responding to LINEMODE *before* TTYPE during negotiation, the SLC data is deferred:
1. Server sends DO TTYPE and DO LINEMODE
2. Client responds to LINEMODE first (WILL LINEMODE), then TTYPE (WILL TTYPE)
3. Server receives SLC data before terminit() is true, so it saves to `def_slcbuf` via malloc()
4. Client sends TTYPE suboption -> terminit() becomes true
5. Server calls deferslc() which processes the saved SLC (triggering our overflow) then calls free(def_slcbuf)

### The Primitive: Arbitrary free()
On 32-bit Debian bookworm, `def_slcbuf` is a heap pointer located within the overflow range after slcbuf. By corrupting it with overflow data, we control the pointer passed to `free()`. This is a powerful exploitation primitive.

### Why 32-bit Works
- 4-byte pointers avoid the NULL byte problem (no consecutive NULLs needed)
- Partial pointer overwrites are more practical
- Legacy systems most likely to run telnet are 32-bit

### Triplet Byte Constraints
- func > NSLC (0x1E): remaining bytes forced to (func, SLC_NOSUPPORT=0, 0)
- func == 0: triplet doesn't reach buffer
- func <= NSLC: flag gets SLC_ACK (0x80) OR'd if bottom 2 bits are 0
- Any byte == 0xFF: doubled to 0xFF 0xFF in buffer (IAC escaping)
- Total subnegotiation packet limit: 0x200 bytes -> ~0x190 bytes of overflow

### IAC Doubling Alignment Table
| 0xFF in   | Bytes written | Alignment shift |
|-----------|---------------|-----------------|
| None      | 3             | +0              |
| func      | 4 (0xFF 0xFF flag val) | +1     |
| val       | 4 (func flag 0xFF 0xFF) | +1    |
| func+val  | 5             | +2              |

## Tools Available on Cinder

### pwntools (v4.15.0)
Installed at `/home/jeffaf/.local/bin`. Use for exploit development.

```python
from pwn import *

# Load binary - auto-parses GOT, PLT, symbols, gadgets
elf = ELF('./telnetd-32')
print(elf.got)        # GOT entries
print(elf.plt)        # PLT entries  
print(elf.symbols)    # All symbols
print(elf.checksec()) # Protections summary

# ROP chain building
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])

# Managed connections
r = remote('localhost', 2325)
r.send(payload)
data = r.recv(1024)

# Shellcode generation (32-bit Linux)
shellcode = asm(shellcraft.i386.linux.sh())

# Pack/unpack helpers
addr = p32(0xdeadbeef)  # pack 32-bit
val = u32(data[:4])     # unpack 32-bit

# Pattern generation for offset finding
payload = cyclic(200)
offset = cyclic_find(u32(crash_addr))

# Remote symbol resolution (no libc needed)
d = DynELF(leak_func, elf=elf)
system_addr = d.lookup('system', 'libc')

# Format string exploitation
payload = fmtstr_payload(offset, {target: value})
```

### Radare2 (r2 v6.0.5)
Available on Cinder for static binary analysis.

```bash
# Quick binary info + protections
r2 -q -c "iI" telnetd-32

# Find BSS section
r2 -q -c "iS~bss" telnetd-32

# Find SLC-related symbols
r2 -q -c "is~slcbuf,slcptr,def_slc,slcchange,add_slc,end_slc,deferslc,process_slc,change_slc" telnetd-32

# Disassemble add_slc to see the overflow
r2 -q -c "aa; pdf @ sym.add_slc" telnetd-32

# Disassemble deferslc to see the free() call
r2 -q -c "aa; pdf @ sym.deferslc" telnetd-32

# Check RELRO
r2 -q -c "iI~relro" telnetd-32

# Map all globals in BSS after slcbuf (get offsets)
r2 -q -c "is~type=OBJECT | sort" telnetd-32

# ROP gadget search
r2 -q -c "aa; /R pop" telnetd-32

# Via r2pipe from Python (combine with pwntools)
import r2pipe
r2 = r2pipe.open("telnetd-32")
print(r2.cmd("iS~bss"))
print(r2.cmd("is~slcbuf"))
```

### GDB
Available inside the container for dynamic analysis.
```bash
# Attach to running telnetd inside container
docker exec -it autohack-telnetd-32bit bash
gdb -p $(pgrep in.telnetd-32)

# Or use ltrace for malloc/free tracing
ltrace -f -e malloc+free+memmove -o /tmp/trace.log /usr/sbin/in.telnetd-32
```

## Your Mission

### Phase 1: Setup and Recon
1. Verify the container is running and telnetd-32 is a 32-bit ELF
2. Map the BSS layout: find slcbuf, slcptr, slcchange, def_slclen, def_slcbuf offsets
3. Check binary protections (RELRO, PIE, stack canaries, NX) - use `ELF('./telnetd-32').checksec()`
4. Identify the exact offset from slcbuf to def_slcbuf

### Phase 2: Implement the Defer Trick
1. Modify the exploit to respond to LINEMODE before TTYPE
2. Verify that deferslc() is called and free(def_slcbuf) executes
3. Confirm the overflow corrupts def_slcbuf with controlled data

### Phase 3: Exploit the free() Primitive
1. Determine what value def_slcbuf gets corrupted to (based on triplet data at that offset)
2. Use IAC doubling alignment to control the corrupted pointer value
3. Research libc 2.36 (Debian bookworm) heap exploitation techniques for fake chunk attacks via corrupted free()
4. Attempt to turn the arbitrary free() into a write-what-where or code execution

### Phase 4: Verify
- If you achieve code execution, create /tmp/pwned with proof
- Log all experiments to results/experiments.jsonl
- Update results/status.md with findings

## Scoring
- CRASH (10): Process crashes
- CONTROLLED_WRITE (30): Controlled memory corruption
- FREE_PRIMITIVE (40): Controlled free() on attacker-chosen address
- CODE_EXEC (60): Arbitrary code execution
- SHELL (100): Interactive shell

## Key Files
- exploit.py: Current exploit (64-bit, response-based verification)
- prepare.py: Lab setup script
- program.md: This file
- results/: Experiment logs

## Important Notes
- The server does NOT crash from the overflow on 64-bit. 32-bit behavior may differ.
- The SLC response leaks BSS data including PIE pointers (ASLR defeat confirmed on 64-bit).
- CVE-2005-0469 was the client-side twin of this bug, fixed 20 years earlier.
- WatchTowr did NOT publish a complete exploit chain. Closing that gap is the goal.
