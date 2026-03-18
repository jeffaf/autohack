# autohack

Autonomous security research framework. Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch).

Give an AI agent a target, a PoC, and a goal. Let it iterate overnight. Wake up to results.

## How It Works

Same loop as autoresearch, adapted for offensive security:

1. Agent reads `program.md` (research directives)
2. Agent modifies `exploit.py` (the only mutable file)
3. Agent runs exploit against isolated Docker target
4. Agent reads metrics, decides what to try next. Repeat.

## Structure

```
autohack/
├── targets/            # Target-specific labs
│   └── telnetd/        # CVE-2026-32746 (first target)
│       ├── prepare.py  # Lab setup (Docker build + start)
│       ├── exploit.py  # Agent modifies this
│       └── program.md  # Research directives for agent
├── README.md
└── LICENSE
```

## Quick Start

```bash
# 1. Set up a target lab
python3 targets/telnetd/prepare.py

# 2. Point your agent at the target
cd /path/to/autohack
claude  # or codex
# Then: "Read targets/telnetd/program.md and start experimenting"
```

## Targets

| Target | CVE | Starting Point | Goal |
|--------|-----|----------------|------|
| telnetd | CVE-2026-32746 | Crash PoC (buffer overflow) | Arbitrary write → RCE |

## Adding Targets

Create a directory in `targets/` with:
- `prepare.py` - builds and starts the isolated lab
- `exploit.py` - starting PoC (agent modifies this)
- `program.md` - research instructions for the agent

## Safety

- All targets run in Docker containers (fully isolated)
- Experiment log captures everything for review

## Credits

- Pattern: [Andrej Karpathy](https://github.com/karpathy/autoresearch)
- CVE-2026-32746: DREAM Security Research Team

## License

MIT
