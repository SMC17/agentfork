const std = @import("std");
const Io = std.Io;
const taint_receipt = @import("taint_receipt.zig");

/// Live wire-speed HTTP Taint & Capability Firewall Proxy.
/// Accepts HTTP requests (e.g., `POST /authorize` with `X-Sink` and `X-Taint` headers),
/// enforces non-interference policies via `TaintKernel`, returns 200/403 with signed receipt metadata,
/// and optionally persists signed Merkle receipts to disk.
pub const FirewallServer = struct {
    allocator: std.mem.Allocator,
    io: Io,
    kernel: taint_receipt.TaintKernel,
    audit_log_path: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, io: Io, signing_key: [32]u8, audit_log_path: ?[]const u8) FirewallServer {
        return .{
            .allocator = allocator,
            .io = io,
            .kernel = taint_receipt.TaintKernel.init(allocator, signing_key),
            .audit_log_path = audit_log_path,
        };
    }

    pub fn deinit(self: *FirewallServer) void {
        self.kernel.deinit();
    }

    /// Names the five sinks. Anything else is not a sink this firewall knows,
    /// and the request is refused rather than treated as a harmless read.
    pub fn parseSink(s: []const u8) ?taint_receipt.SinkKind {
        if (std.mem.eql(u8, s, "read_public")) return .read_public;
        if (std.mem.eql(u8, s, "shell_exec")) return .shell_exec;
        if (std.mem.eql(u8, s, "net_egress")) return .net_egress;
        if (std.mem.eql(u8, s, "file_write_workspace")) return .file_write_workspace;
        if (std.mem.eql(u8, s, "secret_store_read")) return .secret_store_read;
        return null;
    }

    /// Parses a comma-separated label list. Returns null when the list is empty
    /// or names a label this firewall does not know: an unreadable label must not
    /// silently drop taint.
    pub fn parseTaintMask(csv: []const u8) ?taint_receipt.TaintMask {
        var mask: taint_receipt.TaintMask = 0;
        var any = false;
        var it = std.mem.splitScalar(u8, csv, ',');
        while (it.next()) |raw| {
            const tok = std.mem.trim(u8, raw, " \t\r\n");
            if (tok.len == 0) continue;
            any = true;
            if (std.mem.eql(u8, tok, "USER_INTENT")) {
                mask |= taint_receipt.Taint.USER_INTENT;
            } else if (std.mem.eql(u8, tok, "UNTRUSTED_WEB")) {
                mask |= taint_receipt.Taint.UNTRUSTED_WEB;
            } else if (std.mem.eql(u8, tok, "UNTRUSTED_EMAIL")) {
                mask |= taint_receipt.Taint.UNTRUSTED_EMAIL;
            } else if (std.mem.eql(u8, tok, "INTERNAL_SECRET")) {
                mask |= taint_receipt.Taint.INTERNAL_SECRET;
            } else if (std.mem.eql(u8, tok, "CREDENTIAL")) {
                mask |= taint_receipt.Taint.CREDENTIAL;
            } else if (std.mem.eql(u8, tok, "PII")) {
                mask |= taint_receipt.Taint.PII;
            } else return null;
        }
        return if (any) mask else null;
    }

    pub fn handleConnection(self: *FirewallServer, stream: Io.net.Stream) !void {
        const io = self.io;
        defer stream.close(io);
        var buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(io, &buf);
        stream_reader.interface.fillMore() catch |err| switch (err) {
            error.EndOfStream => return,
            error.ReadFailed => return stream_reader.err.?,
        };
        const req = stream_reader.interface.buffered();

        // No defaults: a request must say which sink it targets and what its
        // input carries. Missing or unknown labels are refused (fail closed).
        var sink_str: ?[]const u8 = null;
        var taint_str: ?[]const u8 = null;
        var tool_str: []const u8 = "http_tool";

        // Split headers & body
        const split_idx = std.mem.indexOf(u8, req, "\r\n\r\n") orelse req.len;
        const headers = req[0..split_idx];
        const body = if (split_idx + 4 <= req.len) req[split_idx + 4 ..] else "";

        var lines = std.mem.splitSequence(u8, headers, "\r\n");
        while (lines.next()) |line| {
            if (std.ascii.startsWithIgnoreCase(line, "X-Sink:")) {
                sink_str = std.mem.trim(u8, line["X-Sink:".len..], " \t");
            } else if (std.ascii.startsWithIgnoreCase(line, "X-Taint:")) {
                taint_str = std.mem.trim(u8, line["X-Taint:".len..], " \t");
            } else if (std.ascii.startsWithIgnoreCase(line, "X-Tool:")) {
                tool_str = std.mem.trim(u8, line["X-Tool:".len..], " \t");
            }
        }

        const sink = if (sink_str) |v| parseSink(v) else null;
        const mask = if (taint_str) |v| parseTaintMask(v) else null;
        if (sink == null or mask == null) {
            const reason = if (sink_str == null)
                "missing X-Sink"
            else if (sink == null)
                "unknown X-Sink"
            else if (taint_str == null)
                "missing X-Taint"
            else
                "unknown or empty X-Taint label";
            var jb: [256]u8 = undefined;
            const body_json = try std.fmt.bufPrint(&jb, "{{\"decision\":\"deny_unlabelled\",\"reason\":\"{s}\"}}\n", .{reason});
            self.appendAudit(body_json);
            var rb: [512]u8 = undefined;
            const r = try std.fmt.bufPrint(&rb, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body_json.len, body_json });
            try streamWriteAll(io, stream, r);
            return;
        }
        const now_ns: i128 = Io.Clock.real.now(io).toNanoseconds();
        const receipt = try self.kernel.authorizeAndRecord(
            sink.?,
            tool_str,
            &.{.{ .bytes = body, .taint = mask.? }},
            null,
            now_ns,
        );

        const hex_mac = std.fmt.bytesToHex(receipt.mac, .lower);
        const hex_prev = std.fmt.bytesToHex(receipt.prev_chain_hash, .lower);
        const hex_chain = std.fmt.bytesToHex(receipt.chain_hash, .lower);
        const allowed = receipt.decision == .allow;
        const status_line = if (allowed) "HTTP/1.1 200 OK" else "HTTP/1.1 403 Forbidden";

        var json_buf: [512]u8 = undefined;
        const json_body = try std.fmt.bufPrint(
            &json_buf,
            "{{\"seq\":{d},\"decision\":\"{s}\",\"taint_in\":{d},\"prev_chain_hash\":\"{s}\",\"chain_hash\":\"{s}\",\"mac\":\"{s}\"}}\n",
            .{ receipt.seq, @tagName(receipt.decision), receipt.taint_in, hex_prev, hex_chain, hex_mac },
        );

        self.appendAudit(json_body);

        var resp_buf: [1024]u8 = undefined;
        const resp = try std.fmt.bufPrint(
            &resp_buf,
            "{s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ status_line, json_body.len, json_body },
        );
        try streamWriteAll(io, stream, resp);
    }

    fn appendAudit(self: *FirewallServer, line: []const u8) void {
        const p = self.audit_log_path orelse return;
        const io = self.io;
        const file = Io.Dir.cwd().createFile(io, p, .{ .truncate = false }) catch return;
        defer file.close(io);
        const end = file.length(io) catch 0;
        file.writePositionalAll(io, line, end) catch {};
    }

    pub fn listenAndServe(self: *FirewallServer, host: []const u8, port: u16, max_requests: ?usize) !void {
        const addr = try Io.net.IpAddress.parse(host, port);
        var server = try addr.listen(self.io, .{ .reuse_address = true });
        defer server.deinit(self.io);

        var count: usize = 0;
        while (max_requests == null or count < max_requests.?) : (count += 1) {
            const stream = try server.accept(self.io);
            try self.handleConnection(stream);
        }
    }
};

fn streamWriteAll(io: Io, stream: Io.net.Stream, bytes: []const u8) !void {
    var stream_writer = stream.writer(io, &.{});
    stream_writer.interface.writeAll(bytes) catch |err| switch (err) {
        error.WriteFailed => return stream_writer.err.?,
    };
}

test "FirewallServer blocks tainted shell_exec, refuses unlabelled requests, and chains receipts" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const key = [_]u8{0x55} ** 32;
    var fw = FirewallServer.init(alloc, io, key, null);
    defer fw.deinit();

    const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var tcp_server = try addr.listen(io, .{ .reuse_address = true });
    defer tcp_server.deinit(io);
    const port = tcp_server.socket.address.getPort();

    const ThreadCtx = struct {
        srv: *Io.net.Server,
        fw: *FirewallServer,
        fn run(ctx: @This()) void {
            var i: usize = 0;
            while (i < 5) : (i += 1) {
                const stream = ctx.srv.accept(ctx.fw.io) catch return;
                ctx.fw.handleConnection(stream) catch return;
            }
        }
    };

    const thr = try std.Thread.spawn(.{}, ThreadCtx.run, .{ThreadCtx{ .srv = &tcp_server, .fw = &fw }});
    defer thr.join();

    // 1. Clean request -> 200 OK
    {
        const c1_addr = try Io.net.IpAddress.parse("127.0.0.1", port);
        const c1 = try c1_addr.connect(io, .{ .mode = .stream });
        defer c1.close(io);
        try streamWriteAll(io, c1, "POST /authorize HTTP/1.1\r\nHost: localhost\r\nX-Sink: shell_exec\r\nX-Taint: USER_INTENT\r\nContent-Length: 4\r\n\r\nls\n");
        var resp: [1024]u8 = undefined;
        var c1_reader = c1.reader(io, &resp);
        try c1_reader.interface.fillMore();
        const n = c1_reader.interface.bufferedLen();
        try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "200 OK") != null);
    }

    // 2. Indirect prompt injection -> 403 Forbidden
    {
        const c2_addr = try Io.net.IpAddress.parse("127.0.0.1", port);
        const c2 = try c2_addr.connect(io, .{ .mode = .stream });
        defer c2.close(io);
        try streamWriteAll(io, c2, "POST /authorize HTTP/1.1\r\nHost: localhost\r\nX-Sink: shell_exec\r\nX-Taint: USER_INTENT,UNTRUSTED_WEB\r\nContent-Length: 9\r\n\r\nrm -rf /\n");
        var resp: [1024]u8 = undefined;
        var c2_reader = c2.reader(io, &resp);
        try c2_reader.interface.fillMore();
        const n = c2_reader.interface.bufferedLen();
        try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "403 Forbidden") != null);
    }

    // 3-5. Missing or unknown labels are refused, not allowed.
    const refused = [_][]const u8{
        "POST /authorize HTTP/1.1\r\nHost: localhost\r\nX-Sink: shell_exec\r\nContent-Length: 3\r\n\r\nls\n",
        "POST /authorize HTTP/1.1\r\nHost: localhost\r\nX-Sink: shel_exec\r\nX-Taint: USER_INTENT\r\nContent-Length: 3\r\n\r\nls\n",
        "POST /authorize HTTP/1.1\r\nHost: localhost\r\nX-Sink: shell_exec\r\nX-Taint: USER_INTENT,UNTRUSTED_WBE\r\nContent-Length: 3\r\n\r\nls\n",
    };
    for (refused) |req| {
        const c_addr = try Io.net.IpAddress.parse("127.0.0.1", port);
        const c = try c_addr.connect(io, .{ .mode = .stream });
        defer c.close(io);
        try streamWriteAll(io, c, req);
        var resp: [1024]u8 = undefined;
        var c_reader = c.reader(io, &resp);
        try c_reader.interface.fillMore();
        const n = c_reader.interface.bufferedLen();
        try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "400 Bad Request") != null);
        try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "deny_unlabelled") != null);
    }

    try std.testing.expect(fw.kernel.verifyChain());
}

