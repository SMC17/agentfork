const std = @import("std");
pub const cow_sandbox = @import("cow_sandbox.zig");
pub const fork = @import("fork.zig");
pub const proof_gate = @import("proof_gate.zig");
pub const taint_receipt = @import("taint_receipt.zig");
pub const firewall_proxy = @import("firewall_proxy.zig");

const usage =
    \\agentfork — Sub-millisecond CoW Agent Sandbox, Taint Firewall & Proof-Carrying Merge Gate
    \\
    \\Usage:
    \\  agentfork run <src_dir> <sandbox_dir> -- <cmd...>   Fork repo via APFS clonefile(2) CoW & run isolated command
    \\  agentfork firewall [--host 127.0.0.1] [--port 8787] [--audit <jsonl>]
    \\                                                      Run wire-speed HTTP Taint & Merkle Receipt Firewall
    \\  agentfork bench                                     Benchmark CoW branch fork & IFC Merkle receipt latency
    \\
;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    if (args.len < 2) {
        try std.fs.File.stdout().writeAll(usage);
        return;
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "run")) {
        if (args.len < 5) {
            try std.fs.File.stdout().writeAll("usage: agentfork run <src_dir> <sandbox_dir> -- <cmd...>\n");
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

        const res = try cow_sandbox.runInCowSandbox(alloc, args[2], args[3], argv);
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"exit_code\":{d},\"used_cow_clonefile\":{},\"clone_us\":{d},\"run_ms\":{d}}}\n", .{
            res.exit_code,
            res.used_cow_clonefile,
            res.clone_ns / 1000,
            res.run_ns / 1_000_000,
        });
        try std.fs.File.stdout().writeAll(msg);
        if (res.stdout.len > 0) try std.fs.File.stdout().writeAll(res.stdout);
    } else if (std.mem.eql(u8, cmd, "firewall")) {
        var host: []const u8 = "127.0.0.1";
        var port: u16 = 8787;
        var audit: ?[]const u8 = null;
        var max_req: ?usize = null;
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
            } else if (std.mem.eql(u8, args[i], "--max-requests") and i + 1 < args.len) {
                i += 1;
                max_req = try std.fmt.parseInt(usize, args[i], 10);
            }
        }
        const key = [_]u8{0x5A} ** 32;
        var fw = firewall_proxy.FirewallServer.init(alloc, key, audit);
        defer fw.deinit();
        var buf: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "agentfork firewall listening on {s}:{d}\n", .{ host, port });
        try std.fs.File.stdout().writeAll(line);
        try fw.listenAndServe(host, port, max_req);
    } else if (std.mem.eql(u8, cmd, "bench")) {
        var timer = try std.time.Timer.start();
        var fk = try fork.AgentForkKernel.init(alloc);
        defer fk.deinit();
        _ = try fk.writeFile(0, "src/app.zig", "pub fn main() void {}\n", 1);
        timer.reset();
        var i: usize = 0;
        while (i < 1000) : (i += 1) _ = try fk.forkBranch(0, "spec");
        const fork_ns = timer.read() / 1000;

        var tk = taint_receipt.TaintKernel.init(alloc, [_]u8{0x77} ** 32);
        defer tk.deinit();
        timer.reset();
        i = 0;
        while (i < 2000) : (i += 1) {
            _ = try tk.authorizeAndRecord(.shell_exec, "bash", &.{.{ .bytes = "zig build test", .taint = taint_receipt.Taint.USER_INTENT }}, null, @intCast(i));
        }
        const taint_ns = timer.read() / 2000;

        var buf: [160]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"fork_ns_per_branch\":{d},\"taint_ns_per_receipt\":{d}}}\n", .{ fork_ns, taint_ns });
        try std.fs.File.stdout().writeAll(msg);
    } else {
        try std.fs.File.stdout().writeAll(usage);
    }
}

test {
    std.testing.refAllDecls(@This());
}
