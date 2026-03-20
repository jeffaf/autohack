# autohack

Autonomous exploit research, inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch). Same idea: give an AI agent a target and let it iterate. But instead of training an LLM, it's developing an exploit.

## How It Works

Same loop as autoresearch, adapted for offensive security:

1. Agent reads `program.md` (research directives + tool docs)
2. Agent modifies exploit scripts (the mutable files)
3. Agent runs exploit against isolated Docker target
4. Agent reads metrics, decides what to try next. Repeat.

## Structure

```
autohack/
├── targets/
│   ├── telnetd/              # CVE-2026-32746 (64-bit)
│   │   ├── Dockerfile
│   │   ├── prepare.py        # Lab setup (Docker build + start)
│   │   ├── exploit.py        # Agent modifies this
│   │   ├── program.md        # Research directives
│   │   └── results/          # Experiment logs
│   └── telnetd-32bit/        # CVE-2026-32746 (32-bit, primary target)
│       ├── Dockerfile        # Compiles inetutils 2.4 from source with -m32
│       ├── program.md        # Research directives + tool docs
│       ├── exploit.py        # Base exploit
│       ├── exploit_defer.py  # Defer trick implementation
│       ├── exploit_defer2.py # Refined defer trick
│       ├── HEAP_EXPLOITATION_GUIDE.md  # Technique reference
│       ├── telnetd-32        # Extracted 32-bit binary for analysis
│       └── results/          # Experiment logs + status
├── README.md
└── LICENSE
```

## Quick Start

```bash
# 1. Set up the 32-bit target lab
cd targets/telnetd-32bit
docker build -t autohack-telnetd-32bit-img .
docker run -d --name autohack-telnetd-32bit -p 2325:23 autohack-telnetd-32bit-img

# 2. Extract binary for static analysis
docker cp autohack-telnetd-32bit:/usr/sbin/in.telnetd-32 ./telnetd-32

# 3. Point your agent at the target
claude --permission-mode bypassPermissions --print \
  "Read program.md and start experimenting. Target is localhost:2325."
```

## Targets

| Target | CVE | Arch | Best Score | Experiments |
|--------|-----|------|------------|-------------|
| telnetd | CVE-2026-32746 | x86-64 | 30 (CONTROLLED_WRITE) | 10 |
| telnetd-32bit | CVE-2026-32746 | i386 | 40 (FREE_PRIMITIVE) | 82 |

## Scoring

| Score | Level | Description |
|-------|-------|-------------|
| 10 | CRASH | Process crashes from overflow |
| 30 | CONTROLLED_WRITE | Controlled memory corruption confirmed |
| 40 | FREE_PRIMITIVE | Controlled free() on attacker-influenced data |
| 60 | CODE_EXEC | Arbitrary code execution |
| 100 | SHELL | Interactive shell (unauthenticated) |

## Tools

The 32-bit target is designed for use with:

- **[pwntools](https://github.com/Gallopsled/pwntools)** - ELF parsing, ROP chains, shellcraft, remote connections
- **[pwndbg](https://github.com/pwndbg/pwndbg)** - GDB plugin for heap visualization (bins, top_chunk, vis_heap_chunks)
- **[radare2](https://github.com/radareorg/radare2)** - Static binary analysis, disassembly, gadget search

See `program.md` in each target directory for tool-specific commands and usage.

## Results: CVE-2026-32746 (32-bit)

Five rounds of autonomous exploitation research:

**Round 1-3 (Score 30):** Mapped BSS layout, confirmed overflow reaches 286 bytes past BSS into heap. Overflow pattern: `(func, 0x00, 0x00)` triplets. Agent concluded defer trick was impossible due to localstat() setting terminit early.

**Round 4 (Score 40):** Agent self-corrected. Found that localstat() is only called from telnetd_run(), not during getterminaltype. Defer trick works: SLC data deferred to heap, deferslc() fires, free(def_slcbuf) executes.

**Round 5 (Score 40):** Full toolkit deployed (pwntools + pwndbg + r2). Memory layout mapped (PIE ~0x565xx000, heap ~0x56bxx000, libc ~0xf7dxx000). Every heap technique attempted. Heap is ~5MB from BSS, making House of Force, tcache poisoning, and all heap metadata attacks physically unreachable.

**Escalation barriers:**
- `def_slcbuf` is before `slcbuf` in BSS (linker layout) - forward overflow can't corrupt it
- GOT is also before slcbuf - unreachable
- Triplet byte constraints prevent constructing valid 32-bit addresses
- All function pointers in overflow range are startup-only

WatchTowr described the theoretical primitive but also did not publish a working exploit for this build.

## Adding Targets

Create a directory in `targets/` with:
- `Dockerfile` - builds the isolated lab environment
- `prepare.py` (optional) - setup script
- `exploit.py` - starting PoC (agent modifies this)
- `program.md` - research instructions, tool docs, scoring criteria

## Lessons Learned

1. **Scoring systems are security boundaries.** The agent will find every shortcut. Our first run "achieved SHELL" by logging in with test credentials baked into the Docker lab. Define success precisely.
2. **Agents self-correct across rounds.** Round 4 proved Round 3's analysis wrong. Give agents fresh context and they can revisit assumptions.
3. **Systematic beats creative for recon, not exploitation.** The agent excels at binary analysis, protocol implementation, and methodical testing. It struggles with creative leaps that connect unrelated primitives.
4. **tmux > background SSH.** Long-running Claude Code sessions over SSH die after ~30 minutes. Run in tmux or screen.

## Credits

- Pattern: [Andrej Karpathy](https://github.com/karpathy/autoresearch)
- CVE-2026-32746: [DREAM Security Research Team](https://dreamgroup.com/vulnerability-advisory-pre-auth-remote-code-execution-via-buffer-overflow-in-telnetd-linemode-slc-handler/)
- WatchTowr research: [labs.watchtowr.com](https://labs.watchtowr.com/a-32-year-old-bug-walks-into-a-telnet-server-gnu-inetutils-telnetd-cve-2026-32746/)

## License

MIT
