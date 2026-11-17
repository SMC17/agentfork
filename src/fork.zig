const std = @import("std");

/// Content-addressed Copy-on-Write state & deterministic agent trajectory kernel.
/// Enables sub-microsecond branch forking, structural file-tree sharing,
/// deterministic tool-call replay, and verified atomic merges.
pub const Hash256 = [32]u8;

pub const FileEntry = struct {
    path_hash: u64,
    path: []const u8,
    content_hash: Hash256,
    size: usize,
};

pub const Snapshot = struct {
    id: u32,
    parent_id: ?u32,
    entries: []const FileEntry,
    root_hash: Hash256,
    created_ns: i128,
};

pub const ToolStep = struct {
    step_idx: u32,
    branch_id: u32,
    tool_name: []const u8,
    input_hash: Hash256,
    output_hash: Hash256,
    output_bytes: []const u8,
    snapshot_before: u32,
    snapshot_after: u32,
    virtual_clock_ns: i128,
};

pub const Branch = struct {
    id: u32,
    name: []const u8,
    head_snapshot: u32,
    parent_branch: ?u32,
    steps: std.ArrayListUnmanaged(ToolStep),
    verified: bool,
};

pub const DiffKind = enum {
    added,
    modified,
    deleted,
};

pub const DiffEntry = struct {
    path: []const u8,
    kind: DiffKind,
    old_size: usize,
    new_size: usize,
};

pub const AgentForkKernel = struct {
    allocator: std.mem.Allocator,
    blobs: std.AutoHashMapUnmanaged(Hash256, []const u8) = .{},
    snapshots: std.ArrayListUnmanaged(Snapshot) = .{},
    branches: std.ArrayListUnmanaged(Branch) = .{},
    interned_paths: std.StringHashMapUnmanaged([]const u8) = .{},

    pub fn init(allocator: std.mem.Allocator) !AgentForkKernel {
        var self = AgentForkKernel{ .allocator = allocator };
        const empty_root = computeRootHash(&.{});
        try self.snapshots.append(allocator, .{
            .id = 0,
            .parent_id = null,
            .entries = &.{},
            .root_hash = empty_root,
            .created_ns = 0,
        });
        try self.branches.append(allocator, .{
            .id = 0,
            .name = try allocator.dupe(u8, "main"),
            .head_snapshot = 0,
            .parent_branch = null,
            .steps = .{},
            .verified = false,
        });
        return self;
    }

    pub fn deinit(self: *AgentForkKernel) void {
        var blob_it = self.blobs.valueIterator();
        while (blob_it.next()) |v| {
            self.allocator.free(v.*);
        }
        self.blobs.deinit(self.allocator);

        for (self.snapshots.items) |snap| {
            if (snap.entries.len > 0) self.allocator.free(snap.entries);
        }
        self.snapshots.deinit(self.allocator);

        for (self.branches.items) |*br| {
            self.allocator.free(br.name);
            for (br.steps.items) |st| {
                self.allocator.free(st.tool_name);
                self.allocator.free(st.output_bytes);
            }
            br.steps.deinit(self.allocator);
        }
        self.branches.deinit(self.allocator);

        var path_it = self.interned_paths.keyIterator();
        while (path_it.next()) |k| {
            self.allocator.free(k.*);
        }
        self.interned_paths.deinit(self.allocator);
    }

    fn internPath(self: *AgentForkKernel, path: []const u8) ![]const u8 {
        if (self.interned_paths.get(path)) |existing| return existing;
        const owned = try self.allocator.dupe(u8, path);
        try self.interned_paths.put(self.allocator, owned, owned);
        return owned;
    }

    fn storeBlob(self: *AgentForkKernel, data: []const u8) !Hash256 {
        var h: Hash256 = undefined;
        std.crypto.hash.Blake3.hash(data, &h, .{});
        if (!self.blobs.contains(h)) {
            const owned = try self.allocator.dupe(u8, data);
            try self.blobs.put(self.allocator, h, owned);
        }
        return h;
    }

    pub fn readFile(self: *const AgentForkKernel, snap_id: u32, path: []const u8) ?[]const u8 {
        if (snap_id >= self.snapshots.items.len) return null;
        const ph = std.hash.Wyhash.hash(0, path);
        for (self.snapshots.items[snap_id].entries) |e| {
            if (e.path_hash == ph and std.mem.eql(u8, e.path, path)) {
                return self.blobs.get(e.content_hash);
            }
        }
        return null;
    }

    pub fn writeFile(self: *AgentForkKernel, branch_id: u32, path: []const u8, data: []const u8, clock_ns: i128) !u32 {
        if (branch_id >= self.branches.items.len) return error.InvalidBranch;
        const br = &self.branches.items[branch_id];
        const base = self.snapshots.items[br.head_snapshot];

        const content_hash = try self.storeBlob(data);
        const ipath = try self.internPath(path);
        const ph = std.hash.Wyhash.hash(0, ipath);

        var list = std.ArrayListUnmanaged(FileEntry){};
        defer list.deinit(self.allocator);

        var replaced = false;
        for (base.entries) |e| {
            if (e.path_hash == ph and std.mem.eql(u8, e.path, ipath)) {
                try list.append(self.allocator, .{
                    .path_hash = ph,
                    .path = ipath,
                    .content_hash = content_hash,
                    .size = data.len,
                });
                replaced = true;
            } else {
                try list.append(self.allocator, e);
            }
        }
        if (!replaced) {
            try list.append(self.allocator, .{
                .path_hash = ph,
                .path = ipath,
                .content_hash = content_hash,
                .size = data.len,
            });
        }

        const owned_entries = try list.toOwnedSlice(self.allocator);
        std.mem.sort(FileEntry, owned_entries, {}, struct {
            fn lessThan(_: void, a: FileEntry, b: FileEntry) bool {
                return std.mem.order(u8, a.path, b.path) == .lt;
            }
        }.lessThan);

        const new_id: u32 = @intCast(self.snapshots.items.len);
        const root_hash = computeRootHash(owned_entries);
        try self.snapshots.append(self.allocator, .{
            .id = new_id,
            .parent_id = br.head_snapshot,
            .entries = owned_entries,
            .root_hash = root_hash,
            .created_ns = clock_ns,
        });
        br.head_snapshot = new_id;
        return new_id;
    }

    pub fn deleteFile(self: *AgentForkKernel, branch_id: u32, path: []const u8, clock_ns: i128) !u32 {
        if (branch_id >= self.branches.items.len) return error.InvalidBranch;
        const br = &self.branches.items[branch_id];
        const base = self.snapshots.items[br.head_snapshot];
        const ph = std.hash.Wyhash.hash(0, path);

        var list = std.ArrayListUnmanaged(FileEntry){};
        defer list.deinit(self.allocator);
        for (base.entries) |e| {
            if (!(e.path_hash == ph and std.mem.eql(u8, e.path, path))) {
                try list.append(self.allocator, e);
            }
        }
        const owned_entries = try list.toOwnedSlice(self.allocator);
        const new_id: u32 = @intCast(self.snapshots.items.len);
        try self.snapshots.append(self.allocator, .{
            .id = new_id,
            .parent_id = br.head_snapshot,
            .entries = owned_entries,
            .root_hash = computeRootHash(owned_entries),
            .created_ns = clock_ns,
        });
        br.head_snapshot = new_id;
        return new_id;
    }

    /// O(1) speculative branch fork: clones only the head snapshot pointer, zero blob copying.
    pub fn forkBranch(self: *AgentForkKernel, source_branch: u32, name: []const u8) !u32 {
        if (source_branch >= self.branches.items.len) return error.InvalidBranch;
        const src = self.branches.items[source_branch];
        const new_id: u32 = @intCast(self.branches.items.len);
        try self.branches.append(self.allocator, .{
            .id = new_id,
            .name = try self.allocator.dupe(u8, name),
            .head_snapshot = src.head_snapshot,
            .parent_branch = source_branch,
            .steps = .{},
            .verified = false,
        });
        return new_id;
    }

    pub fn recordToolStep(
        self: *AgentForkKernel,
        branch_id: u32,
        tool_name: []const u8,
        input_bytes: []const u8,
        output_bytes: []const u8,
        snap_before: u32,
        snap_after: u32,
        virtual_clock_ns: i128,
    ) !u32 {
        if (branch_id >= self.branches.items.len) return error.InvalidBranch;
        const br = &self.branches.items[branch_id];
        var in_h: Hash256 = undefined;
        var out_h: Hash256 = undefined;
        std.crypto.hash.Blake3.hash(input_bytes, &in_h, .{});
        std.crypto.hash.Blake3.hash(output_bytes, &out_h, .{});

        const idx: u32 = @intCast(br.steps.items.len);
        try br.steps.append(self.allocator, .{
            .step_idx = idx,
            .branch_id = branch_id,
            .tool_name = try self.allocator.dupe(u8, tool_name),
            .input_hash = in_h,
            .output_hash = out_h,
            .output_bytes = try self.allocator.dupe(u8, output_bytes),
            .snapshot_before = snap_before,
            .snapshot_after = snap_after,
            .virtual_clock_ns = virtual_clock_ns,
        });
        return idx;
    }

    /// Deterministic offline replay lookup: returns recorded output bytes if tool + input match.
    pub fn replayLookup(self: *const AgentForkKernel, branch_id: u32, step_idx: u32, tool_name: []const u8, input_bytes: []const u8) ?[]const u8 {
        if (branch_id >= self.branches.items.len) return null;
        const br = self.branches.items[branch_id];
        if (step_idx >= br.steps.items.len) return null;
        const st = br.steps.items[step_idx];
        var in_h: Hash256 = undefined;
        std.crypto.hash.Blake3.hash(input_bytes, &in_h, .{});
        if (std.mem.eql(u8, st.tool_name, tool_name) and std.mem.eql(u8, &st.input_hash, &in_h)) {
            return st.output_bytes;
        }
        return null;
    }

    /// Time-travel rollback of a branch head to any prior snapshot.
    pub fn rollbackBranch(self: *AgentForkKernel, branch_id: u32, target_snap: u32) !void {
        if (branch_id >= self.branches.items.len) return error.InvalidBranch;
        if (target_snap >= self.snapshots.items.len) return error.InvalidSnapshot;
        self.branches.items[branch_id].head_snapshot = target_snap;
    }

    pub fn mergeVerified(self: *AgentForkKernel, winner_branch: u32, target_branch: u32) !void {
        if (winner_branch >= self.branches.items.len or target_branch >= self.branches.items.len) {
            return error.InvalidBranch;
        }
        if (!self.branches.items[winner_branch].verified) return error.UnverifiedBranch;
        self.branches.items[target_branch].head_snapshot = self.branches.items[winner_branch].head_snapshot;
    }

    pub fn diffSnapshots(self: *const AgentForkKernel, allocator: std.mem.Allocator, snap_a: u32, snap_b: u32) ![]DiffEntry {
        if (snap_a >= self.snapshots.items.len or snap_b >= self.snapshots.items.len) {
            return error.InvalidSnapshot;
        }
        const a = self.snapshots.items[snap_a].entries;
        const b = self.snapshots.items[snap_b].entries;
        var out = std.ArrayListUnmanaged(DiffEntry){};
        errdefer out.deinit(allocator);

        var i: usize = 0;
        var j: usize = 0;
        while (i < a.len and j < b.len) {
            const ord = std.mem.order(u8, a[i].path, b[j].path);
            switch (ord) {
                .lt => {
                    try out.append(allocator, .{ .path = a[i].path, .kind = .deleted, .old_size = a[i].size, .new_size = 0 });
                    i += 1;
                },
                .gt => {
                    try out.append(allocator, .{ .path = b[j].path, .kind = .added, .old_size = 0, .new_size = b[j].size });
                    j += 1;
                },
                .eq => {
                    if (!std.mem.eql(u8, &a[i].content_hash, &b[j].content_hash)) {
                        try out.append(allocator, .{ .path = b[j].path, .kind = .modified, .old_size = a[i].size, .new_size = b[j].size });
                    }
                    i += 1;
                    j += 1;
                },
            }
        }
        while (i < a.len) : (i += 1) {
            try out.append(allocator, .{ .path = a[i].path, .kind = .deleted, .old_size = a[i].size, .new_size = 0 });
        }
        while (j < b.len) : (j += 1) {
            try out.append(allocator, .{ .path = b[j].path, .kind = .added, .old_size = 0, .new_size = b[j].size });
        }
        return out.toOwnedSlice(allocator);
    }
};

fn computeRootHash(entries: []const FileEntry) Hash256 {
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (entries) |e| {
        hasher.update(e.path);
        hasher.update(&.{0});
        hasher.update(&e.content_hash);
    }
    var out: Hash256 = undefined;
    hasher.final(&out);
    return out;
}

test "AgentForkKernel speculative fork, replay, diff, and verified merge" {
    const alloc = std.testing.allocator;
    var k = try AgentForkKernel.init(alloc);
    defer k.deinit();

    const s1 = try k.writeFile(0, "src/app.zig", "pub fn x() i32 { return 1; }\n", 100);
    const s2 = try k.writeFile(0, "README.md", "# app\n", 200);
    try std.testing.expectEqual(@as(u32, 1), s1);
    try std.testing.expectEqual(@as(u32, 2), s2);

    const b1 = try k.forkBranch(0, "fix-a");
    const b2 = try k.forkBranch(0, "fix-b");

    const b1_snap_before = k.branches.items[b1].head_snapshot;
    const b1_snap_after = try k.writeFile(b1, "src/app.zig", "pub fn x() i32 { return 42; }\n", 300);
    _ = try k.writeFile(b2, "src/app.zig", "pub fn x() i32 { return -1; }\n", 301);

    _ = try k.recordToolStep(b1, "zig_test", "{\"target\":\"test\"}", "{\"passed\":true}", b1_snap_before, b1_snap_after, 350);
    const replayed = k.replayLookup(b1, 0, "zig_test", "{\"target\":\"test\"}");
    try std.testing.expect(replayed != null);
    try std.testing.expectEqualStrings("{\"passed\":true}", replayed.?);

    // Unverified merge must fail
    try std.testing.expectError(error.UnverifiedBranch, k.mergeVerified(b1, 0));

    // Verify b1 and merge to main
    k.branches.items[b1].verified = true;
    try k.mergeVerified(b1, 0);
    try std.testing.expectEqualStrings("pub fn x() i32 { return 42; }\n", k.readFile(k.branches.items[0].head_snapshot, "src/app.zig").?);

    // Snapshot diff between s2 (before fork) and merged main head
    const diffs = try k.diffSnapshots(alloc, s2, k.branches.items[0].head_snapshot);
    defer alloc.free(diffs);
    try std.testing.expectEqual(@as(usize, 1), diffs.len);
    try std.testing.expectEqual(DiffKind.modified, diffs[0].kind);
    try std.testing.expectEqualStrings("src/app.zig", diffs[0].path);
}
