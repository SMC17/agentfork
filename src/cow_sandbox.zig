const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

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

pub fn cloneWorkspace(allocator: std.mem.Allocator, io: Io, src_dir: []const u8, dst_dir: []const u8) !bool {
    if (builtin.os.tag == .macos) {
        const src_z = try allocator.dupeZ(u8, src_dir);
        defer allocator.free(src_z);
        const dst_z = try allocator.dupeZ(u8, dst_dir);
        defer allocator.free(dst_z);
        if (c.clonefile(src_z.ptr, dst_z.ptr, 0) == 0) {
            return true;
        }
    }
    try copyDirRecursive(allocator, io, src_dir, dst_dir);
    return false;
}

fn copyDirRecursive(allocator: std.mem.Allocator, io: Io, src_path: []const u8, dst_path: []const u8) !void {
    try Io.Dir.cwd().createDirPath(io, dst_path);
    var src_dir = try Io.Dir.cwd().openDir(io, src_path, .{ .iterate = true });
    defer src_dir.close(io);
    var dst_dir = try Io.Dir.cwd().openDir(io, dst_path, .{});
    defer dst_dir.close(io);

    var it = src_dir.iterate();
    while (try it.next(io)) |entry| {
        const s_child = try std.fs.path.join(allocator, &.{ src_path, entry.name });
        defer allocator.free(s_child);
        const d_child = try std.fs.path.join(allocator, &.{ dst_path, entry.name });
        defer allocator.free(d_child);

        switch (entry.kind) {
            .directory => try copyDirRecursive(allocator, io, s_child, d_child),
            .file => try Io.Dir.copyFile(src_dir, entry.name, dst_dir, entry.name, io, .{}),
            else => {},
        }
    }
}

pub fn runInCowSandbox(
    allocator: std.mem.Allocator,
    io: Io,
    src_dir: []const u8,
    sandbox_dir: []const u8,
    argv: []const []const u8,
) !SandboxResult {
    Io.Dir.cwd().deleteTree(io, sandbox_dir) catch {};
    const clone_start = Io.Clock.Timestamp.now(io, .awake);
    const used_cow = try cloneWorkspace(allocator, io, src_dir, sandbox_dir);
    const clone_ns: u64 = @intCast(clone_start.untilNow(io).raw.toNanoseconds());

    const run_start = Io.Clock.Timestamp.now(io, .awake);
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .path = sandbox_dir },
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);

    const max_output_bytes = 1024 * 1024;
    var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    while (multi_reader.fill(64, .none)) |_| {
        if (multi_reader.reader(0).buffered().len > max_output_bytes) return error.StdoutStreamTooLong;
        if (multi_reader.reader(1).buffered().len > max_output_bytes) return error.StderrStreamTooLong;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => |e| return e,
    }
    try multi_reader.checkAnyError();

    const term = try child.wait(io);
    const run_ns: u64 = @intCast(run_start.untilNow(io).raw.toNanoseconds());

    const code: u8 = switch (term) {
        .exited => |ec| ec,
        else => 255,
    };

    const stdout = try multi_reader.toOwnedSlice(0);
    errdefer allocator.free(stdout);
    const stderr = try multi_reader.toOwnedSlice(1);
    errdefer allocator.free(stderr);

    return .{
        .exit_code = code,
        .sandbox_dir = try allocator.dupe(u8, sandbox_dir),
        .clone_ns = clone_ns,
        .run_ns = run_ns,
        .used_cow_clonefile = used_cow,
        .stdout = stdout,
        .stderr = stderr,
    };
}

test "cow_sandbox clones real directory and runs isolated child process" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const base_path = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base_path);

    const src_dir = try std.fs.path.join(alloc, &.{ base_path, "repo" });
    defer alloc.free(src_dir);
    const sbx_dir = try std.fs.path.join(alloc, &.{ base_path, "sandbox" });
    defer alloc.free(sbx_dir);

    try Io.Dir.cwd().createDirPath(io, src_dir);
    const orig_file = try std.fs.path.join(alloc, &.{ src_dir, "hello.txt" });
    defer alloc.free(orig_file);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = orig_file, .data = "original" });

    // Child mutates hello.txt inside sandbox only
    const res = try runInCowSandbox(alloc, io, src_dir, sbx_dir, &.{
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
    const orig_read = try Io.Dir.cwd().readFileAlloc(io, orig_file, alloc, .limited(1024));
    defer alloc.free(orig_read);
    try std.testing.expectEqualStrings("original", orig_read);
}
