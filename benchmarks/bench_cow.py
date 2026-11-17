#!/usr/bin/env python3
"""Benchmark `cp -r` vs `git worktree add` vs `agentfork run` (APFS clonefile CoW)."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = REPO_ROOT / "zig-out" / "bin" / "agentfork"


def build_realistic_repo(repo_dir: Path, num_files: int = 500) -> int:
    """Create a realistic git-initialized repository with `num_files` files."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    dirs = [f"pkg_{i:02d}/src" for i in range(10)] + [f"pkg_{i:02d}/tests" for i in range(10)]
    for d in dirs:
        (repo_dir / d).mkdir(parents=True, exist_ok=True)

    payload = (
        "// Realistic module fixture for CoW sandbox benchmarking\n"
        + ("const std = @import(\"std\");\n" * 16)
        + "pub fn compute(x: u64) u64 { return x *% 6364136223846793005 +% 1; }\n"
    )
    payload_bytes = payload.encode("utf-8")

    for idx in range(num_files):
        rel_dir = dirs[idx % len(dirs)]
        file_path = repo_dir / rel_dir / f"mod_{idx:04d}.zig"
        data = f"// module {idx}\n".encode("utf-8") + payload_bytes
        file_path.write_bytes(data)
        total_bytes += len(data)

    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "bench@agentfork.local"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "agentfork-bench"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init 500-file fixture"], cwd=repo_dir, check=True)
    return total_bytes


def summarize(samples_ms: list[float]) -> dict[str, float]:
    return {
        "mean_ms": round(statistics.mean(samples_ms), 3),
        "median_ms": round(statistics.median(samples_ms), 3),
        "min_ms": round(min(samples_ms), 3),
        "max_ms": round(max(samples_ms), 3),
    }


def run_benchmark(agentfork_bin: Path, num_files: int = 500, iterations: int = 10) -> dict:
    if not agentfork_bin.exists():
        raise FileNotFoundError(f"agentfork binary not found at {agentfork_bin}")

    with tempfile.TemporaryDirectory(prefix="agentfork-bench-") as tmp:
        tmp_path = Path(tmp)
        src_repo = tmp_path / "repo"
        repo_bytes = build_realistic_repo(src_repo, num_files=num_files)

        cp_times_ms: list[float] = []
        wt_times_ms: list[float] = []
        af_wall_ms: list[float] = []
        af_clone_us: list[float] = []
        used_cow_flags: list[bool] = []

        # Warmup one iteration for filesystem caches
        warm_cp = tmp_path / "warm_cp"
        subprocess.run(["cp", "-r", str(src_repo), str(warm_cp)], check=True)
        shutil.rmtree(warm_cp)

        for i in range(iterations):
            # 1. cp -r
            cp_dst = tmp_path / f"cp_{i}"
            t0 = time.perf_counter()
            subprocess.run(["cp", "-r", str(src_repo), str(cp_dst)], check=True)
            cp_times_ms.append((time.perf_counter() - t0) * 1000.0)
            shutil.rmtree(cp_dst)

            # 2. git worktree add
            wt_dst = tmp_path / f"wt_{i}"
            t0 = time.perf_counter()
            subprocess.run(
                ["git", "-C", str(src_repo), "worktree", "add", "-q", "--detach", str(wt_dst)],
                check=True,
            )
            wt_times_ms.append((time.perf_counter() - t0) * 1000.0)
            subprocess.run(
                ["git", "-C", str(src_repo), "worktree", "remove", "--force", str(wt_dst)],
                check=True,
            )

            # 3. agentfork run (APFS clonefile CoW)
            af_dst = tmp_path / f"af_{i}"
            t0 = time.perf_counter()
            proc = subprocess.run(
                [str(agentfork_bin), "run", str(src_repo), str(af_dst), "--", "/usr/bin/true"],
                capture_output=True,
                text=True,
                check=True,
            )
            af_wall_ms.append((time.perf_counter() - t0) * 1000.0)
            first_line = proc.stdout.strip().splitlines()[0]
            meta = json.loads(first_line)
            af_clone_us.append(float(meta["clone_us"]))
            used_cow_flags.append(bool(meta["used_cow_clonefile"]))
            shutil.rmtree(af_dst, ignore_errors=True)

        cp_mean = statistics.mean(cp_times_ms)
        wt_mean = statistics.mean(wt_times_ms)
        af_wall_mean = statistics.mean(af_wall_ms)
        af_clone_mean_ms = statistics.mean(af_clone_us) / 1000.0

        return {
            "platform": platform.platform(),
            "file_count": num_files,
            "repo_bytes": repo_bytes,
            "iterations": iterations,
            "used_cow_clonefile": all(used_cow_flags),
            "cp_r": summarize(cp_times_ms),
            "git_worktree_add": summarize(wt_times_ms),
            "agentfork_run_wall": summarize(af_wall_ms),
            "agentfork_clone_only": {
                "mean_us": round(statistics.mean(af_clone_us), 2),
                "median_us": round(statistics.median(af_clone_us), 2),
                "min_us": round(min(af_clone_us), 2),
                "max_us": round(max(af_clone_us), 2),
            },
            "speedups": {
                "agentfork_clone_vs_cp_r": round(cp_mean / af_clone_mean_ms, 2) if af_clone_mean_ms > 0 else None,
                "agentfork_clone_vs_git_worktree": round(wt_mean / af_clone_mean_ms, 2) if af_clone_mean_ms > 0 else None,
                "agentfork_wall_vs_cp_r": round(cp_mean / af_wall_mean, 2) if af_wall_mean > 0 else None,
                "agentfork_wall_vs_git_worktree": round(wt_mean / af_wall_mean, 2) if af_wall_mean > 0 else None,
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark CoW workspace fork vs cp -r and git worktree add")
    parser.add_argument("--bin", type=Path, default=DEFAULT_BIN, help="Path to agentfork binary")
    parser.add_argument("--files", type=int, default=500, help="Number of files in temp repo")
    parser.add_argument("--iterations", type=int, default=10, help="Benchmark iterations")
    args = parser.parse_args()

    result = run_benchmark(args.bin, num_files=args.files, iterations=args.iterations)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
