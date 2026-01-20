# zig-expat 

Zig bindings for [libexpat](https://libexpat.github.io/), the fast streaming XML parser.

## Usage

Fetch the dependency:

```sh
zig fetch --save git+https://github.com/pmatsson/zig-expat
```

In your `build.zig`:

```zig
const expat = b.dependency("expat", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("expat", expat.module("expat"));
```

## Version

Tracks libexpat 2.7.3

## Status

WIP. Covers core parsing, handlers, errors, and buffer APIs. DTD/namespace declarations not yet covered. Use `expat.c.*` to access the raw C API directly.
