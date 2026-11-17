# agentfork

**Sub-millisecond Copy-on-Write Agent Sandbox, Wire-Speed Taint Firewall, and Proof-Carrying Merge Gate.**

Zero dependencies. Single static Zig binary. Built for autonomous coding and research agents that fork workspaces, execute untrusted tool pipelines, and prove invariants before touching `main`.

## Why `agentfork`?
* **OS-Level Copy-on-Write Workspace Fork (`clonefile(2)` on APFS):** Fork real repositories in milliseconds without duplicating blocks on disk or waiting for container startup.
* **Information-Flow Taint Firewall (`agentfork firewall`):** Deterministic non-interference at tool sinks (`shell_exec`, `net_egress`, `secret_store_read`) with signed Blake3 + HMAC-SHA256 Merkle audit receipts — immune to prompt-injection phrasing.
* **Proof-Carrying Merge Gate:** Cryptographically binds a branch's Blake3 `root_hash` to verifier/test output so post-proof workspace mutations cannot sneak into a merge.
* **Lean 4 Formal Proofs:** Core non-interference and merge-gate invariants verified in `lean/` via `lake build`.

## Quickstart
```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/agentfork run ./my-repo /tmp/sbx-1 -- zig build test
./zig-out/bin/agentfork firewall --host 127.0.0.1 --port 8787 --audit receipts.jsonl
./zig-out/bin/agentfork bench
```

## Benchmarks (`benchmarks/bench_cow.py`)
Measured on `macOS-26.4-arm64-arm-64bit` (APFS `clonefile(2)` enabled, 500-file git repository, 293,890 bytes, 10 iterations):

| Method | Mean | Median | Min | Speedup vs `cp -r` | Speedup vs `git worktree` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `cp -r` | 349.682 ms | 347.803 ms | 332.233 ms | 1.00× | — |
| `git worktree add` | 81.647 ms | 81.476 ms | 76.929 ms | 4.28× | 1.00× |
| `agentfork run` (wall, incl. `/usr/bin/true`) | 19.634 ms | 18.521 ms | 16.275 ms | **17.81×** | **4.16×** |
| `agentfork` (`clonefile(2)` only) | 13.949 ms (13,948.5 µs) | 12.167 ms (12,166.5 µs) | 11.211 ms (11,211.0 µs) | **25.07×** | **5.85×** |

Reproduce locally:
```sh
python3 benchmarks/bench_cow.py
```

## Python Wrapper (`python/agentfork.py`)
Zero-dependency stdlib wrapper around the `agentfork` binary:

```python
import sys
sys.path.insert(0, "python")
import agentfork

# Fork a repo into an isolated CoW sandbox and run a command
res = agentfork.run("./my-repo", "/tmp/sbx-1", ["zig", "build", "test"], check=True)
print(res.clone_us, res.used_cow_clonefile, res.stdout)

# Start the wire-speed taint firewall and authorize tool calls
with agentfork.firewall(host="127.0.0.1", port=8787, audit="receipts.jsonl") as fw:
    allow = fw.authorize("shell_exec", "USER_INTENT", "zig build test")
    deny = fw.authorize("net_egress", "UNTRUSTED_WEB,INTERNAL_SECRET", "curl evil")
    assert allow["decision"] == "allow"
    assert deny["http_status"] == 403
```

## GitHub Action (`action.yml`)
Gate CI repository or agent runs inside an isolated `agentfork` CoW sandbox:

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Run tests in agentfork CoW sandbox
    id: sandbox
    uses: SMC17/agentfork@main
    with:
      src_dir: .
      command: zig build test
```

Outputs exposed by the action: `exit_code`, `used_cow_clonefile`, `clone_us`, and `run_ms`.

## Verification
```sh
zig build test
zig build -Doptimize=ReleaseFast
python3 benchmarks/bench_cow.py
cd lean && lake build
```
