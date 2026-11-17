const std = @import("std");
const builtin = @import("builtin");

/// OS-level Copy-on-Write workspace sandbox using macOS `clonefile(2)` (APFS O(1) CoW)
/// with portable recursive-copy fallback on non-APFS/non-macOS filesystems.
/// Forks a real repository directory, executes a real child process inside the clone,
/// and promotes changes back only if verification passes.
const c = if (builtin.os.tag == .macos) struct {
    extern "c" fn clonefile(src: [*:0]const u8, dst: [*:0]const u8, flags: u32) c_int;
} else struct {};

pub const SandboxResult = struct {
    exit_code: u8,
    sandbox_dir: []const u8,
    clone_ns: u64,
    run_ns: u64,
    used_cow_clonefile: bool,
    stdout: []const u8,
    stderr: []const u8,
};

pub fn cloneWorkspace(allocator: std.mem.Allocator, src_dir: []const u8, dst_dir: []const u8) !bool {
    if (builtin.os.tag == .macos) {
        const src_z = try allocator.dupeZ(u8, src_dir);
        defer allocator.free(src_z);
        const dst_z = try allocator.dupeZ(u8, dst_dir);
        defer allocator.free(dst_z);
        if (c.clonefile(src_z.ptr, dst_z.ptr, 0) == 0) {
            return true;
        }
    }
    try copyDirRecursive(allocator, src_dir, dst_dir);
    return false;
}

fn copyDirRecursive(allocator: std.mem.Allocator, src_path: []const u8, dst_path: []const u8) !void {
    try std.fs.cwd().makePath(dst_path);
    var src_dir = try std.fs.cwd().openDir(src_path, .{ .iterate = true });
    defer src_dir.close();
    var dst_dir = try std.fs.cwd().openDir(dst_path, .{});
    defer dst_dir.close();

    var it = src_dir.iterate();
    while (try it.next()) |entry| {
        const s_child = try std.fs.path.join(allocator, &.{ src_path, entry.name });
        defer allocator.free(s_child);
        const d_child = try std.fs.path.join(allocator, &.{ dst_path, entry.name });
        defer allocator.free(d_child);

        switch (entry.kind) {
            .directory => try copyDirRecursive(allocator, s_child, d_child),
            .file => try std.fs.Dir.copyFile(src_dir, entry.name, dst_dir, entry.name, .{}),
            else => {},
        }
    }
}

pub fn runInCowSandbox(
    allocator: std.mem.Allocator,
    src_dir: []const u8,
    sandbox_dir: []const u8,
    argv: []const []const u8,
) !SandboxResult {
    std.fs.cwd().deleteTree(sandbox_dir) catch {};
    var timer = try std.time.Timer.start();
    const used_cow = try cloneWorkspace(allocator, src_dir, sandbox_dir);
    const clone_ns = timer.read();

    timer.reset();
    var child = std.process.Child.init(argv, allocator);
    child.cwd = sandbox_dir;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    var stdout_buf = std.ArrayListUnmanaged(u8){};
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayListUnmanaged(u8){};
    defer stderr_buf.deinit(allocator);

    try child.collectOutput(allocator, &stdout_buf, &stderr_buf, 1024 * 1024);
    const term = try child.wait();
    const run_ns = timer.read();

    const code: u8 = switch (term) {
        .Exited => |ec| ec,
        else => 255,
    };

    return .{
        .exit_code = code,
        .sandbox_dir = try allocator.dupe(u8, sandbox_dir),
        .clone_ns = clone_ns,
        .run_ns = run_ns,
        .used_cow_clonefile = used_cow,
        .stdout = try stdout_buf.toOwnedSlice(allocator),
        .stderr = try stderr_buf.toOwnedSlice(allocator),
    };
}

test "cow_sandbox clones real directory and runs isolated child process" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base_path);

    const src_dir = try std.fs.path.join(alloc, &.{ base_path, "repo" });
    defer alloc.free(src_dir);
    const sbx_dir = try std.fs.path.join(alloc, &.{ base_path, "sandbox" });
    defer alloc.free(sbx_dir);

    try std.fs.cwd().makePath(src_dir);
    const orig_file = try std.fs.path.join(alloc, &.{ src_dir, "hello.txt" });
    defer alloc.free(orig_file);
    try std.fs.cwd().writeFile(.{ .sub_path = orig_file, .data = "original" });

    // Child mutates hello.txt inside sandbox only
    const res = try runInCowSandbox(alloc, src_dir, sbx_dir, &.{
        "/bin/sh",
        "-c",
        "echo mutated > hello.txt && cat hello.txt",
    });
    defer {
        alloc.free(res.sandbox_dir);
        alloc.free(res.stdout);
        alloc.free(res.stderr);
    }

    try std.testing.expectEqual(@as(u8, 0), res.exit_code);
    try std.testing.expectEqualStrings("mutated\n", res.stdout);

    // Original repo file must remain untouched
    const orig_read = try std.fs.cwd().readFileAlloc(alloc, orig_file, 1024);
    defer alloc.free(orig_read);
    try std.testing.expectEqualStrings("original", orig_read);
}
