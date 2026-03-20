# autohack

Autonomous exploit research, inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch). Same idea: give an AI agent a target and let it iterate. But instead of training an LLM, it's developing an exploit.

## How It Works

Same loop as autoresearch, adapted for offensive security:

1. Agent reads `program.md` (research directives + constraints)
2. Agent modifies `exploit.py` (the starting PoC)
3. Agent runs exploit against isolated Docker target
4. Agent reads metrics, decides what to try next. Repeat.

## Structure

```
autohack/
├── targets/
│   ├── telnetd/              # CVE-2026-32746 (64-bit)
│   │   ├── Dockerfile
│   │   ├── prepare.py        # One-command lab setup
│   │   ├── exploit.py        # Starting PoC (agent modifies this)
│   │   └── program.md        # Research directives for agent
│   └── telnetd-32bit/        # CVE-2026-32746 (32-bit)
│       ├── Dockerfile        # Compiles inetutils 2.4 from source with -m32
│       ├── prepare.py
│       ├── exploit.py
│       └── program.md
├── README.md
└── LICENSE
```

## Quick Start

```bash
# 1. Set up a target lab
cd targets/telnetd-32bit
python3 prepare.py

# 2. Point your agent at the target
claude --permission-mode bypassPermissions --print \
  "Read program.md and start experimenting. Target is localhost:2325."
```

## Targets

| Target | CVE | Arch | Description |
|--------|-----|------|-------------|
| telnetd | CVE-2026-32746 | x86-64 | Pre-auth BSS buffer overflow in SLC handler |
| telnetd-32bit | CVE-2026-32746 | i386 | Same vuln, 32-bit build (closer to real deployments) |

## Scoring

Each target uses a scoring rubric in `program.md`. Default levels:

| Score | Level | Description |
|-------|-------|-------------|
| 10 | CRASH | Process crashes from overflow |
| 30 | CONTROLLED_WRITE | Controlled memory corruption confirmed |
| 40 | FREE_PRIMITIVE | Controlled free() on attacker-influenced data |
| 60 | CODE_EXEC | Arbitrary code execution |
| 100 | SHELL | Interactive shell (unauthenticated) |

## Recommended Tools

The `program.md` for each target documents tool-specific commands. Recommended stack:

- **[pwntools](https://github.com/Gallopsled/pwntools)** - ELF parsing, ROP chains, shellcraft, remote connections
- **[pwndbg](https://github.com/pwndbg/pwndbg)** - GDB plugin for heap visualization
- **[radare2](https://github.com/radareorg/radare2)** - Static binary analysis and gadget search

## Adding Targets

Create a directory in `targets/` with:
- `Dockerfile` - builds the isolated lab environment
- `prepare.py` - one-command setup (build + start + extract binary)
- `exploit.py` - starting PoC (the file the agent modifies)
- `program.md` - research instructions, tool docs, scoring criteria

## Lessons Learned

1. **Scoring systems are security boundaries.** The agent will find every shortcut. Our first run "achieved SHELL" by logging in with test credentials baked into the Docker lab. Define success precisely.
2. **Agents self-correct across rounds.** Give agents fresh context and they can revisit wrong assumptions from previous sessions.
3. **Systematic beats creative.** Agents excel at recon, binary analysis, and methodical testing. They struggle with the creative leaps that connect unrelated primitives into novel exploitation chains.
4. **Use tmux/screen.** Long-running agent sessions over SSH die after ~30 minutes. Always run inside a terminal multiplexer.

## Credits

- Pattern: [Andrej Karpathy](https://github.com/karpathy/autoresearch)
- CVE-2026-32746: [DREAM Security Research Team](https://dreamgroup.com/vulnerability-advisory-pre-auth-remote-code-execution-via-buffer-overflow-in-telnetd-linemode-slc-handler/)

## License

MIT
