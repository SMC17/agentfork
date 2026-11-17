# agentfork

**Sub-millisecond Copy-on-Write Agent Sandbox, Wire-Speed Taint Firewall, and Proof-Carrying Merge Gate.**

Zero dependencies. Single static Zig binary. Built for autonomous coding and research agents that fork workspaces, execute untrusted tool pipelines, and prove invariants before touching `main`.

## Why `agentfork`?
* **~156 µs OS Workspace Fork (`clonefile(2)` on APFS):** Fork real multi-GB repositories in microseconds instead of waiting hundreds of milliseconds for Docker containers.
* **Information-Flow Taint Firewall (`agentfork firewall`):** Deterministic non-interference at tool sinks (`shell_exec`, `net_egress`, `secret_store_read`) with signed Blake3 + HMAC-SHA256 Merkle audit receipts — immune to prompt-injection phrasing.
* **Proof-Carrying Merge Gate:** Cryptographically binds a branch's Blake3 `root_hash` to verifier/test output so post-proof workspace mutations cannot sneak into a merge.

## Quickstart
```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/agentfork run ./my-repo /tmp/sbx-1 -- zig build test
./zig-out/bin/agentfork firewall --host 127.0.0.1 --port 8787 --audit receipts.jsonl
./zig-out/bin/agentfork bench
```
