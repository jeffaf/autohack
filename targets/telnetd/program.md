# autohack: CVE-2026-32746 Research Program

You are an autonomous security researcher. Your goal is to evolve a crash PoC into a working remote code execution exploit for CVE-2026-32746.

## The Vulnerability

GNU InetUtils telnetd has a buffer overflow in the LINEMODE SLC handler (`slc.c`). The `add_slc()` function appends 3 bytes per SLC triplet to a 108-byte buffer (`slcbuf`, 104 usable) without bounds checking. After ~35 triplets with function codes > 18 (NSLC), the buffer overflows, corrupting `slcptr` (a `char*` pointer in BSS immediately after `slcbuf`). When `end_slc()` runs, it writes `IAC SE` (0xFF 0xF0) at the address in `slcptr`.

**This gives you an arbitrary 2-byte write primitive.**

## Current State

`exploit.py` currently achieves: **CRASH** (score: 10/100)

## Scoring Ladder

| Score | Primitive | What It Means |
|-------|-----------|---------------|
| 0 | None | No crash, no effect |
| 10 | CRASH | Target process dies (current) |
| 30 | CONTROLLED_WRITE | You control WHERE the write goes |
| 60 | CODE_EXEC | Arbitrary code runs on target |
| 100 | SHELL | Interactive shell or reverse shell |

## Your Task

Modify ONLY `exploit.py` to climb the scoring ladder. Each experiment:

1. Modify `exploit.py`
2. Run it: `python3 targets/telnetd/exploit.py`
3. Read the KEY=VALUE metrics from stdout
4. Log the result (see Logging below)
5. Decide what to try next. Repeat.

## Logging

**This is critical.** Log every experiment to `targets/telnetd/results/experiments.jsonl` (create if missing). Each line is one JSON object:

```json
{"exp": 1, "ts": "2026-03-18T12:00:00Z", "change": "increased triplets to 70", "metrics": {"CRASH": true, "LEVEL": "crash", "SCORE": 10}, "kept": true, "notes": "baseline confirmed"}
```

Fields:
- `exp` - experiment number (incrementing)
- `ts` - ISO timestamp
- `change` - what you modified (brief)
- `metrics` - the KEY=VALUE output from exploit.py
- `kept` - did you keep this change or revert?
- `notes` - observations, hypotheses, what you learned

Also update `targets/telnetd/results/status.md` after each significant finding with a human-readable summary of progress, current best score, and next research direction.

If you revert a change, say why in the log. Failed experiments are valuable data.

## Research Directions

### Phase 1: Understand the overflow (CRASH → CONTROLLED_WRITE)
- Map exactly which overflow bytes land on `slcptr`
- The bytes in triplets 35-38 should overwrite `slcptr`
- Vary the func/flag/value bytes in those positions
- Print `CONTROLLED_WRITE=true` when you can predict the write target
- Print `WRITE_ADDR=0x...` with the address you wrote to

### Phase 2: Weaponize the write (CONTROLLED_WRITE → CODE_EXEC)
- Find the GOT (Global Offset Table) address for a function called after `end_slc()`
- Overwrite that GOT entry to redirect execution
- Common targets: `printf`, `write`, `strlen`, or any libc function called post-overflow
- Consider: ASLR may be off in the container (check), stack canaries, RELRO status
- Print `CODE_EXEC=true` when you achieve arbitrary code execution

### Phase 3: Get a shell (CODE_EXEC → SHELL)
- Execute a reverse shell or bind shell
- Or: write a marker file inside the container as proof
- Print `SHELL=true` when you have command execution

## Constraints

- Modify ONLY `exploit.py`
- Target runs at 127.0.0.1:2324 (Docker container)
- Time budget: 120 seconds per experiment
- The target auto-restarts between experiments (xinetd spawns fresh telnetd)
- Output metrics as KEY=VALUE to stdout
- Use stderr for debug/notes

## Useful Information

- Architecture: ARM64 (Apple Silicon Docker) or x86_64 (depends on host)
- OS: Debian bookworm-slim
- Binary: `/usr/sbin/telnetd` (inetutils 2.4)
- ASLR: Check with `docker exec autohack-telnetd cat /proc/sys/kernel/randomize_va_space`
- You can inspect the binary: `docker exec autohack-telnetd readelf -a /usr/sbin/telnetd`
- You can check protections: NX, RELRO, stack canaries, PIE

## Tips

- Start by varying overflow bytes systematically, not randomly
- Check dmesg/coredumps in the container for crash details
- The 2-byte write (IAC SE = 0xFF 0xF0) is limited but may be enough
- Consider: what if you trigger the overflow multiple times in one connection?
- Multiple SLC suboptions in sequence = multiple writes = more control
