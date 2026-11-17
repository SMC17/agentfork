const std = @import("std");
const fork = @import("fork.zig");

/// Proof-Carrying Agent Merge Gate.
/// Cryptographically binds a branch snapshot's Blake3 `root_hash` to a verified
/// invariant / Lean / test-suite execution output and HMAC-SHA256 certificate,
/// guaranteeing no post-verification workspace mutation can sneak into a merge.
pub const ProofCertificate = struct {
    branch_id: u32,
    snapshot_id: u32,
    snapshot_root_hash: fork.Hash256,
    verifier_cmd: []const u8,
    verifier_output_hash: fork.Hash256,
    exit_code: u8,
    issued_ns: i128,
    mac: [32]u8,
};

pub fn issueCertificate(
    kernel: *const fork.AgentForkKernel,
    branch_id: u32,
    verifier_cmd: []const u8,
    verifier_stdout: []const u8,
    exit_code: u8,
    issued_ns: i128,
    signing_key: [32]u8,
) !ProofCertificate {
    if (branch_id >= kernel.branches.items.len) return error.InvalidBranch;
    if (exit_code != 0) return error.VerificationFailed;
    const snap_id = kernel.branches.items[branch_id].head_snapshot;
    const root_hash = kernel.snapshots.items[snap_id].root_hash;

    var out_hash: fork.Hash256 = undefined;
    std.crypto.hash.Blake3.hash(verifier_stdout, &out_hash, .{});

    const mac = computeCertMac(branch_id, snap_id, &root_hash, verifier_cmd, &out_hash, exit_code, issued_ns, &signing_key);
    return .{
        .branch_id = branch_id,
        .snapshot_id = snap_id,
        .snapshot_root_hash = root_hash,
        .verifier_cmd = verifier_cmd,
        .verifier_output_hash = out_hash,
        .exit_code = exit_code,
        .issued_ns = issued_ns,
        .mac = mac,
    };
}

pub fn verifyAndMerge(
    kernel: *fork.AgentForkKernel,
    cert: ProofCertificate,
    target_branch: u32,
    signing_key: [32]u8,
) !void {
    if (cert.branch_id >= kernel.branches.items.len or target_branch >= kernel.branches.items.len) {
        return error.InvalidBranch;
    }
    if (cert.exit_code != 0) return error.VerificationFailed;

    const br = &kernel.branches.items[cert.branch_id];
    if (br.head_snapshot != cert.snapshot_id) return error.SnapshotMutatedAfterProof;
    const cur_root = kernel.snapshots.items[br.head_snapshot].root_hash;
    if (!std.mem.eql(u8, &cur_root, &cert.snapshot_root_hash)) return error.SnapshotMutatedAfterProof;

    const expected = computeCertMac(
        cert.branch_id,
        cert.snapshot_id,
        &cert.snapshot_root_hash,
        cert.verifier_cmd,
        &cert.verifier_output_hash,
        cert.exit_code,
        cert.issued_ns,
        &signing_key,
    );
    if (!std.crypto.timing_safe.eql([32]u8, cert.mac, expected)) return error.InvalidProofSignature;

    br.verified = true;
    try kernel.mergeVerified(cert.branch_id, target_branch);
}

fn computeCertMac(
    branch_id: u32,
    snapshot_id: u32,
    root_hash: *const fork.Hash256,
    verifier_cmd: []const u8,
    output_hash: *const fork.Hash256,
    exit_code: u8,
    issued_ns: i128,
    key: *const [32]u8,
) [32]u8 {
    var h = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    h.update(std.mem.asBytes(&branch_id));
    h.update(std.mem.asBytes(&snapshot_id));
    h.update(root_hash);
    h.update(verifier_cmd);
    h.update(output_hash);
    h.update(&.{exit_code});
    h.update(std.mem.asBytes(&issued_ns));
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

test "proof_gate binds snapshot root hash to verifier certificate and blocks post-proof mutation" {
    const alloc = std.testing.allocator;
    var k = try fork.AgentForkKernel.init(alloc);
    defer k.deinit();

    _ = try k.writeFile(0, "proof.lean", "theorem t : 1 = 1 := rfl\n", 10);
    const b1 = try k.forkBranch(0, "verified-branch");
    _ = try k.writeFile(b1, "proof.lean", "theorem t : 2 = 2 := rfl\n", 20);

    const key = [_]u8{0x99} ** 32;
    const cert = try issueCertificate(&k, b1, "lake build", "Build completed successfully.", 0, 30, key);

    // Mutate branch after certificate issuance -> merge MUST fail!
    _ = try k.writeFile(b1, "proof.lean", "theorem t : 2 = 3 := sorry\n", 40);
    try std.testing.expectError(error.SnapshotMutatedAfterProof, verifyAndMerge(&k, cert, 0, key));

    // Re-certify clean branch -> merge succeeds
    _ = try k.writeFile(b1, "proof.lean", "theorem t : 2 = 2 := rfl\n", 50);
    const cert2 = try issueCertificate(&k, b1, "lake build", "Build completed successfully.", 0, 60, key);
    try verifyAndMerge(&k, cert2, 0, key);
    try std.testing.expectEqualStrings("theorem t : 2 = 2 := rfl\n", k.readFile(k.branches.items[0].head_snapshot, "proof.lean").?);
}
