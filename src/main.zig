const std = @import("std");
pub const cow_sandbox = @import("cow_sandbox.zig");
pub const fork = @import("fork.zig");
pub const proof_gate = @import("proof_gate.zig");
pub const taint_receipt = @import("taint_receipt.zig");
pub const firewall_proxy = @import("firewall_proxy.zig");

const usage =
    \\agentfork — copy-on-write clones for agent runs, a taint-label policy check, and a merge-gate model
    \\
    \\Usage:
    \\  agentfork run <src_dir> <sandbox_dir> -- <cmd...>   Clone src_dir (APFS clonefile, else copy) and run cmd in the clone.
    \\                                                      The clone is a working directory, not an isolation boundary.
    \\  agentfork firewall (--key-file <path> | env AGENTFORK_RECEIPT_KEY) [--host 127.0.0.1] [--port 8787]
    \\                     [--audit <jsonl>] [--max-requests <n>]
    \\                                                      HTTP allow/deny service for labelled tool calls; HMAC receipts.
    \\                                                      The key is 64 hex characters (32 bytes). There is no default key.
    \\  agentfork bench                                     In-memory branch fork and policy-decision latency
    \\
;

/// Reads the receipt key: 64 hex characters, from `--key-file` or from the
/// AGENTFORK_RECEIPT_KEY environment variable. There is no built-in key, because
/// a key that ships in the binary lets anyone mint a receipt that verifies.
fn loadReceiptKey(io: std.Io, alloc: std.mem.Allocator, key_file: ?[]const u8, env_value: ?[]const u8) ![32]u8 {
    const raw = if (key_file) |path|
        try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(4096))
    else if (env_value) |v|
        v
    else
        return error.MissingReceiptKey;
    const hex = std.mem.trim(u8, raw, " \t\r\n");
    if (hex.len != 64) return error.ReceiptKeyNot64Hex;
    var key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, hex) catch return error.ReceiptKeyNot64Hex;
    return key;
}

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const io = init.io;
    const stdout = std.Io.File.stdout();

    const args = try init.minimal.args.toSlice(alloc);
    if (args.len < 2) {
        try stdout.writeStreamingAll(io, usage);
        return;
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "run")) {
        if (args.len < 5) {
            try stdout.writeStreamingAll(io, "usage: agentfork run <src_dir> <sandbox_dir> -- <cmd...>\n");
            return;
        }
        var sep: ?usize = null;
        for (args[4..], 4..) |a, idx| {
            if (std.mem.eql(u8, a, "--")) {
                sep = idx;
                break;
            }
        }
        const s = sep orelse return error.MissingSeparator;
        var argv = try alloc.alloc([]const u8, args.len - (s + 1));
        for (args[s + 1 ..], 0..) |a, i| argv[i] = a;

        const res = try cow_sandbox.runInCowSandbox(alloc, io, args[2], args[3], argv);
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"exit_code\":{d},\"used_cow_clonefile\":{},\"clone_us\":{d},\"run_ms\":{d}}}\n", .{
            res.exit_code,
            res.used_cow_clonefile,
            res.clone_ns / 1000,
            res.run_ns / 1_000_000,
        });
        try stdout.writeStreamingAll(io, msg);
        if (res.stdout.len > 0) try stdout.writeStreamingAll(io, res.stdout);
    } else if (std.mem.eql(u8, cmd, "firewall")) {
        var host: []const u8 = "127.0.0.1";
        var port: u16 = 8787;
        var audit: ?[]const u8 = null;
        var max_req: ?usize = null;
        var key_file: ?[]const u8 = null;
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--host") and i + 1 < args.len) {
                i += 1;
                host = args[i];
            } else if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
                i += 1;
                port = try std.fmt.parseInt(u16, args[i], 10);
            } else if (std.mem.eql(u8, args[i], "--audit") and i + 1 < args.len) {
                i += 1;
                audit = args[i];
            } else if (std.mem.eql(u8, args[i], "--key-file") and i + 1 < args.len) {
                i += 1;
                key_file = args[i];
            } else if (std.mem.eql(u8, args[i], "--max-requests") and i + 1 < args.len) {
                i += 1;
                max_req = try std.fmt.parseInt(usize, args[i], 10);
            }
        }
        const key = loadReceiptKey(io, alloc, key_file, init.environ_map.get("AGENTFORK_RECEIPT_KEY")) catch |err| {
            const stderr = std.Io.File.stderr();
            var eb: [256]u8 = undefined;
            const m = std.fmt.bufPrint(&eb, "agentfork firewall: no usable receipt key ({s}). Pass --key-file <path> or set AGENTFORK_RECEIPT_KEY to 64 hex characters, for example from `openssl rand -hex 32`.\n", .{@errorName(err)}) catch "agentfork firewall: no usable receipt key\n";
            try stderr.writeStreamingAll(io, m);
            std.process.exit(2);
        };
        var fw = firewall_proxy.FirewallServer.init(alloc, io, key, audit);
        defer fw.deinit();
        var buf: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "agentfork firewall listening on {s}:{d}\n", .{ host, port });
        try stdout.writeStreamingAll(io, line);
        try fw.listenAndServe(host, port, max_req);
    } else if (std.mem.eql(u8, cmd, "bench")) {
        var fk = try fork.AgentForkKernel.init(alloc);
        defer fk.deinit();
        _ = try fk.writeFile(0, "src/app.zig", "pub fn main() void {}\n", 1);
        const fork_start = std.Io.Clock.Timestamp.now(io, .awake);
        var i: usize = 0;
        while (i < 1000) : (i += 1) _ = try fk.forkBranch(0, "spec");
        const fork_ns: u64 = @intCast(@divTrunc(fork_start.untilNow(io).raw.toNanoseconds(), 1000));

        var tk = taint_receipt.TaintKernel.init(alloc, [_]u8{0x77} ** 32);
        defer tk.deinit();
        const taint_start = std.Io.Clock.Timestamp.now(io, .awake);
        i = 0;
        while (i < 2000) : (i += 1) {
            _ = try tk.authorizeAndRecord(.shell_exec, "bash", &.{.{ .bytes = "zig build test", .taint = taint_receipt.Taint.USER_INTENT }}, null, @intCast(i));
        }
        const taint_ns: u64 = @intCast(@divTrunc(taint_start.untilNow(io).raw.toNanoseconds(), 2000));

        var buf: [160]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"fork_ns_per_branch\":{d},\"taint_ns_per_receipt\":{d}}}\n", .{ fork_ns, taint_ns });
        try stdout.writeStreamingAll(io, msg);
    } else {
        try stdout.writeStreamingAll(io, usage);
    }
}

test "loadReceiptKey refuses a missing or malformed key" {
    const io = std.testing.io;
    const a = std.testing.allocator;
    try std.testing.expectError(error.MissingReceiptKey, loadReceiptKey(io, a, null, null));
    try std.testing.expectError(error.ReceiptKeyNot64Hex, loadReceiptKey(io, a, null, "abcd"));
    try std.testing.expectError(error.ReceiptKeyNot64Hex, loadReceiptKey(io, a, null, "zz" ** 32));
    const k = try loadReceiptKey(io, a, null, "00" ** 31 ++ "ff");
    try std.testing.expectEqual(@as(u8, 0xff), k[31]);
}

test {
    std.testing.refAllDecls(@This());
}
