#!/usr/bin/env python3
"""
autohack harness - autonomous security research loop

Runs exploit.py against an isolated target, measures results,
logs experiments, and manages the keep/discard cycle.

DO NOT MODIFY - this is the fixed evaluation framework.
The agent modifies exploit.py, not this file.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


class ExperimentResult:
    """Captures the outcome of a single experiment run."""

    def __init__(self):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.iteration = 0
        self.duration_s = 0.0
        self.exit_code = None
        self.stdout = ""
        self.stderr = ""
        self.metrics = {}
        self.diff = ""
        self.kept = False
        self.notes = ""

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "iteration": self.iteration,
            "duration_s": round(self.duration_s, 2),
            "exit_code": self.exit_code,
            "stdout_tail": self.stdout[-2000:] if self.stdout else "",
            "stderr_tail": self.stderr[-1000:] if self.stderr else "",
            "metrics": self.metrics,
            "diff_lines": self.diff.count("\n"),
            "kept": self.kept,
            "notes": self.notes,
        }


def parse_metrics(stdout):
    """Extract metrics from exploit output.

    Exploits should print metrics as KEY=VALUE lines to stdout.
    Recognized metrics:
      CRASH=true/false       - did the target crash?
      CONTROLLED_WRITE=true  - achieved controlled arbitrary write?
      CODE_EXEC=true         - achieved code execution?
      SHELL=true             - got a shell?
      WRITE_ADDR=0x...       - address written to
      WRITE_VALUE=0x...      - value written
      SIGNAL=11              - signal that killed the target
      OVERFLOW_BYTES=76      - bytes past buffer end
      LEVEL=crash|write|exec|shell  - highest primitive achieved
    """
    metrics = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            key = key.strip().upper()
            value = value.strip()
            # Only capture recognized metric keys
            recognized = {
                "CRASH", "CONTROLLED_WRITE", "CODE_EXEC", "SHELL",
                "WRITE_ADDR", "WRITE_VALUE", "SIGNAL", "OVERFLOW_BYTES",
                "LEVEL", "PRIMITIVE", "SCORE",
            }
            if key in recognized:
                # Parse booleans
                if value.lower() in ("true", "1", "yes"):
                    metrics[key] = True
                elif value.lower() in ("false", "0", "no"):
                    metrics[key] = False
                else:
                    metrics[key] = value
    return metrics


def score_result(metrics):
    """Score an experiment result. Higher is better.

    Scoring ladder:
      0  - no crash
      10 - crash (DoS)
      30 - controlled write (can choose where/what to write)
      60 - code execution
      100 - shell
    """
    if metrics.get("SHELL"):
        return 100
    if metrics.get("CODE_EXEC"):
        return 60
    if metrics.get("CONTROLLED_WRITE"):
        return 30
    if metrics.get("CRASH"):
        return 10
    return 0


def get_diff(target_dir):
    """Get git diff of exploit.py changes."""
    try:
        result = subprocess.run(
            ["git", "diff", "exploit.py"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout
    except Exception:
        return ""


def run_experiment(target_dir, timeout_s=120):
    """Run a single experiment: execute exploit.py and capture results."""
    result = ExperimentResult()
    exploit_path = target_dir / "exploit.py"

    if not exploit_path.exists():
        result.notes = "exploit.py not found"
        return result

    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(exploit_path)],
            cwd=target_dir,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        result.exit_code = proc.returncode
        result.stdout = proc.stdout
        result.stderr = proc.stderr
    except subprocess.TimeoutExpired:
        result.notes = f"Timed out after {timeout_s}s"
        result.exit_code = -1
    except Exception as e:
        result.notes = f"Error: {e}"
        result.exit_code = -2

    result.duration_s = time.time() - start
    result.metrics = parse_metrics(result.stdout)
    result.metrics["SCORE"] = score_result(result.metrics)
    result.diff = get_diff(target_dir)

    return result


def run_loop(target_name, iterations, timeout_s, results_dir):
    """Main experiment loop."""
    target_dir = Path(__file__).parent / "targets" / target_name

    if not target_dir.exists():
        print(f"[-] Target directory not found: {target_dir}")
        sys.exit(1)

    results_dir = target_dir / "results"
    results_dir.mkdir(exist_ok=True)

    # Backup original exploit
    exploit_path = target_dir / "exploit.py"
    backup_path = target_dir / "exploit.py.orig"
    if not backup_path.exists():
        shutil.copy2(exploit_path, backup_path)

    # Load previous best score
    best_score = 0
    log_path = results_dir / "experiment_log.jsonl"

    if log_path.exists():
        with open(log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    s = entry.get("metrics", {}).get("SCORE", 0)
                    if s > best_score:
                        best_score = s
                except json.JSONDecodeError:
                    pass

    print(f"\n{'='*60}")
    print(f"  autohack - autonomous security research")
    print(f"{'='*60}")
    print(f"  Target:     {target_name}")
    print(f"  Iterations: {iterations}")
    print(f"  Timeout:    {timeout_s}s per run")
    print(f"  Best score: {best_score}")
    print(f"{'='*60}\n")

    for i in range(1, iterations + 1):
        print(f"[{i}/{iterations}] Running experiment...")

        result = run_experiment(target_dir, timeout_s)
        result.iteration = i
        score = result.metrics.get("SCORE", 0)

        # Decide: keep or revert
        if score > best_score:
            result.kept = True
            best_score = score
            # Save this version as the new best
            shutil.copy2(exploit_path, target_dir / "exploit.py.best")
            print(f"  ✅ IMPROVED: score {score} (was {best_score - score + score})")
            print(f"     Metrics: {result.metrics}")
        elif score == best_score and score > 0:
            result.kept = True  # Keep ties (different approach, same level)
            print(f"  ➡️  TIED: score {score}")
        else:
            result.kept = False
            # Revert to best version
            best_path = target_dir / "exploit.py.best"
            if best_path.exists():
                shutil.copy2(best_path, exploit_path)
            print(f"  ❌ REVERTED: score {score} (best: {best_score})")

        # Log result
        with open(log_path, "a") as f:
            f.write(json.dumps(result.to_dict()) + "\n")

        # Save individual result
        result_file = results_dir / f"exp_{i:04d}.json"
        with open(result_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        # Check for victory
        if score >= 100:
            print(f"\n🎉 SHELL ACHIEVED on iteration {i}!")
            break

    # Summary
    print(f"\n{'='*60}")
    print(f"  Completed {i} experiments")
    print(f"  Best score: {best_score}")
    level = "none"
    if best_score >= 100:
        level = "SHELL"
    elif best_score >= 60:
        level = "CODE_EXEC"
    elif best_score >= 30:
        level = "CONTROLLED_WRITE"
    elif best_score >= 10:
        level = "CRASH"
    print(f"  Highest primitive: {level}")
    print(f"  Log: {log_path}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="autohack - autonomous security research harness"
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target name (directory under targets/)")
    parser.add_argument("--iterations", "-n", type=int, default=20,
                        help="Number of experiments to run (default: 20)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Timeout per experiment in seconds (default: 120)")
    parser.add_argument("--results-dir", default=None,
                        help="Results directory (default: targets/<name>/results/)")
    args = parser.parse_args()

    run_loop(args.target, args.iterations, args.timeout, args.results_dir)


if __name__ == "__main__":
    main()
