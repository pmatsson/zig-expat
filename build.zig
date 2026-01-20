const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const expat_dep = b.dependency("expat", .{});
    const expat_path = expat_dep.path("expat/lib");

    const lib = b.addLibrary(.{
        .name = "expat",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    lib.addCSourceFiles(.{
        .root = expat_path,
        .files = &.{
            "xmlparse.c",
            "xmlrole.c",
            "xmltok.c",
        },
        .flags = &.{
            "-DHAVE_EXPAT_CONFIG_H",
            "-DXML_GE=1",
            "-DXML_DTD",
            "-DXML_NS",
            "-DXML_CONTEXT_BYTES=1024",
        },
    });

    lib.addIncludePath(expat_path);
    lib.addIncludePath(b.path("src"));

    const mod = b.addModule("expat", .{
        .root_source_file = b.path("src/expat.zig"),
        .target = target,
        .optimize = optimize,
    });

    mod.linkLibrary(lib);
    mod.addIncludePath(expat_path);

    // Tests
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/expat.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.linkLibrary(lib);
    tests.root_module.addIncludePath(expat_path);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
