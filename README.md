# autohack

I gave Claude a crash PoC and 8 hours. Here's what it built.

Autonomous exploit research, inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch). Same idea: give an AI agent a target and let it iterate overnight. But instead of training an LLM, it's developing an exploit.

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
# 1. Clone and set up the lab
git clone https://github.com/jeffaf/autohack.git
cd autohack
python3 targets/telnetd/prepare.py

# 2. Run Claude Code in autonomous mode
claude --print --permission-mode bypassPermissions \
  "Read targets/telnetd/program.md. This is your research directive. \
   Begin autonomous experimentation on CVE-2026-32746. \
   Modify only targets/telnetd/exploit.py. \
   After each modification, run it and evaluate the KEY=VALUE metrics. \
   Log every experiment to targets/telnetd/results/experiments.jsonl. \
   Update targets/telnetd/results/status.md with your progress. \
   Keep iterating until you reach CONTROLLED_WRITE (score 30) or higher. \
   If stuck for 10 experiments, pivot your strategy entirely."
```

The agent reads program.md, modifies exploit.py, runs it, reads the metrics, logs results, and decides what to try next. You walk away, it iterates. Check `results/status.md` and `results/experiments.jsonl` to see what it tried.

## Targets

| Target | CVE | Starting Point | Goal |
|--------|-----|----------------|------|
| telnetd | CVE-2026-32746 | Crash PoC (buffer overflow) | Arbitrary write → RCE |

## Adding Targets

Create a directory in `targets/` with:
- `prepare.py` - builds and starts the isolated lab
- `exploit.py` - starting PoC (agent modifies this)
- `program.md` - research instructions for the agent

## Credits

- Pattern: [Andrej Karpathy](https://github.com/karpathy/autoresearch)
- CVE-2026-32746: DREAM Security Research Team

## License

MIT
