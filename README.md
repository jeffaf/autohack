# autohack

Autonomous security research framework. Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch).

Give an AI agent a target, a PoC, and a goal. Let it iterate overnight. Wake up to results.

## How It Works

Same loop as autoresearch, adapted for offensive security:

1. Agent modifies `exploit.py` (the only mutable file)
2. `harness.py` runs the exploit against an isolated target
3. Results are measured against defined success criteria
4. If improved: keep. If not: revert. Repeat.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  program.md │────▶│  AI Agent    │────▶│ exploit.py  │
│ (research   │     │  (Claude,    │     │ (modified)  │
│  directives)│     │   Codex)     │     │             │
└─────────────┘     └──────┬───────┘     └──────┬──────┘
                           │                     │
                           │              ┌──────▼──────┐
                    ┌──────▼───────┐      │  harness.py │
                    │  Experiment  │◀─────│  (run +     │
                    │  Log         │      │   measure)  │
                    └──────────────┘      └──────┬──────┘
                                                 │
                                          ┌──────▼──────┐
                                          │   Docker    │
                                          │   Target    │
                                          └─────────────┘
```

## Structure

```
autohack/
├── harness.py          # Run loop: execute, measure, log (DO NOT MODIFY)
├── targets/            # Target-specific labs
│   └── telnetd/        # CVE-2026-32746 (first target)
│       ├── prepare.py  # Lab setup (Docker build + start)
│       ├── exploit.py  # Agent modifies this
│       ├── program.md  # Research directives for agent
│       ├── Dockerfile
│       └── results/    # Experiment logs
├── README.md
└── LICENSE
```

## Quick Start

```bash
# 1. Set up a target lab
python3 targets/telnetd/prepare.py

# 2. Point your agent at the target
# In Claude Code / Codex, open this repo and say:
#   "Read targets/telnetd/program.md and start experimenting"

# 3. Or run the harness directly for manual iteration
python3 harness.py --target telnetd --iterations 20
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
- Harness enforces time budgets per experiment
- Experiment log captures everything for review

## Credits

- Pattern: [Andrej Karpathy](https://github.com/karpathy/autoresearch)
- CVE-2026-32746: DREAM Security Research Team

## License

MIT
