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

    pub fn parseSink(s: []const u8) taint_receipt.SinkKind {
        if (std.mem.eql(u8, s, "shell_exec")) return .shell_exec;
        if (std.mem.eql(u8, s, "net_egress")) return .net_egress;
        if (std.mem.eql(u8, s, "file_write_workspace")) return .file_write_workspace;
        if (std.mem.eql(u8, s, "secret_store_read")) return .secret_store_read;
        return .read_public;
    }

    pub fn parseTaintMask(csv: []const u8) taint_receipt.TaintMask {
        var mask: taint_receipt.TaintMask = 0;
        var it = std.mem.splitScalar(u8, csv, ',');
        while (it.next()) |raw| {
            const tok = std.mem.trim(u8, raw, " \t\r\n");
            if (std.mem.eql(u8, tok, "USER_INTENT")) mask |= taint_receipt.Taint.USER_INTENT;
            if (std.mem.eql(u8, tok, "UNTRUSTED_WEB")) mask |= taint_receipt.Taint.UNTRUSTED_WEB;
            if (std.mem.eql(u8, tok, "UNTRUSTED_EMAIL")) mask |= taint_receipt.Taint.UNTRUSTED_EMAIL;
            if (std.mem.eql(u8, tok, "INTERNAL_SECRET")) mask |= taint_receipt.Taint.INTERNAL_SECRET;
            if (std.mem.eql(u8, tok, "CREDENTIAL")) mask |= taint_receipt.Taint.CREDENTIAL;
            if (std.mem.eql(u8, tok, "PII")) mask |= taint_receipt.Taint.PII;
        }
        return mask;
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

        var sink_str: []const u8 = "read_public";
        var taint_str: []const u8 = "USER_INTENT";
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

        const sink = parseSink(sink_str);
        const mask = parseTaintMask(taint_str);
        const now_ns: i128 = Io.Clock.real.now(io).toNanoseconds();
        const receipt = try self.kernel.authorizeAndRecord(
            sink,
            tool_str,
            &.{.{ .bytes = body, .taint = mask }},
            null,
            now_ns,
        );

        const hex_mac = std.fmt.bytesToHex(receipt.mac, .lower);
        const allowed = receipt.decision == .allow;
        const status_line = if (allowed) "HTTP/1.1 200 OK" else "HTTP/1.1 403 Forbidden";

        var json_buf: [512]u8 = undefined;
        const json_body = try std.fmt.bufPrint(
            &json_buf,
            "{{\"seq\":{d},\"decision\":\"{s}\",\"taint_in\":{d},\"mac\":\"{s}\"}}\n",
            .{ receipt.seq, @tagName(receipt.decision), receipt.taint_in, hex_mac },
        );

        if (self.audit_log_path) |p| {
            const file = Io.Dir.cwd().createFile(io, p, .{ .truncate = false }) catch null;
            if (file) |f| {
                defer f.close(io);
                const end = f.length(io) catch 0;
                f.writePositionalAll(io, json_body, end) catch {};
            }
        }

        var resp_buf: [1024]u8 = undefined;
        const resp = try std.fmt.bufPrint(
            &resp_buf,
            "{s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ status_line, json_body.len, json_body },
        );
        try streamWriteAll(io, stream, resp);
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

test "FirewallServer live TCP HTTP proxy blocks tainted shell_exec and logs signed receipt" {
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
            while (i < 2) : (i += 1) {
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

    try std.testing.expect(fw.kernel.verifyChain());
}
