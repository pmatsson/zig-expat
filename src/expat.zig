//! Zig bindings for libexpat.

const std = @import("std");

pub const c = @cImport({
    @cInclude("expat.h");
});

pub const AttrIterator = struct {
    ptr: ?[*:null]const ?[*:0]const u8,

    pub const Attr = struct { name: [:0]const u8, value: [:0]const u8 };

    pub fn next(self: *AttrIterator) ?Attr {
        const p = self.ptr orelse return null;
        const name_ptr = p[0] orelse return null;
        const value_ptr = p[1] orelse return null;
        self.ptr = p + 2;
        return .{
            .name = std.mem.sliceTo(name_ptr, 0),
            .value = std.mem.sliceTo(value_ptr, 0),
        };
    }

    pub fn count(self: AttrIterator) usize {
        var it = self;
        var n: usize = 0;
        while (it.next()) |_| n += 1;
        return n;
    }
};

pub const Status = enum { ok, suspended, failed };

pub const Parsing = enum(c_int) {
    initialized = c.XML_INITIALIZED,
    parsing = c.XML_PARSING,
    finished = c.XML_FINISHED,
    suspended = c.XML_SUSPENDED,
};

pub const ParsingStatus = struct {
    parsing: Parsing,
    final_buffer: bool,
};

pub const Error = enum(c_int) {
    none = c.XML_ERROR_NONE,
    no_memory = c.XML_ERROR_NO_MEMORY,
    syntax = c.XML_ERROR_SYNTAX,
    no_elements = c.XML_ERROR_NO_ELEMENTS,
    invalid_token = c.XML_ERROR_INVALID_TOKEN,
    unclosed_token = c.XML_ERROR_UNCLOSED_TOKEN,
    partial_char = c.XML_ERROR_PARTIAL_CHAR,
    tag_mismatch = c.XML_ERROR_TAG_MISMATCH,
    duplicate_attribute = c.XML_ERROR_DUPLICATE_ATTRIBUTE,
    junk_after_doc_element = c.XML_ERROR_JUNK_AFTER_DOC_ELEMENT,
    param_entity_ref = c.XML_ERROR_PARAM_ENTITY_REF,
    undefined_entity = c.XML_ERROR_UNDEFINED_ENTITY,
    recursive_entity_ref = c.XML_ERROR_RECURSIVE_ENTITY_REF,
    async_entity = c.XML_ERROR_ASYNC_ENTITY,
    bad_char_ref = c.XML_ERROR_BAD_CHAR_REF,
    binary_entity_ref = c.XML_ERROR_BINARY_ENTITY_REF,
    attribute_external_entity_ref = c.XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF,
    misplaced_xml_pi = c.XML_ERROR_MISPLACED_XML_PI,
    unknown_encoding = c.XML_ERROR_UNKNOWN_ENCODING,
    incorrect_encoding = c.XML_ERROR_INCORRECT_ENCODING,
    unclosed_cdata_section = c.XML_ERROR_UNCLOSED_CDATA_SECTION,
    external_entity_handling = c.XML_ERROR_EXTERNAL_ENTITY_HANDLING,
    not_standalone = c.XML_ERROR_NOT_STANDALONE,
    unexpected_state = c.XML_ERROR_UNEXPECTED_STATE,
    entity_declared_in_pe = c.XML_ERROR_ENTITY_DECLARED_IN_PE,
    feature_requires_xml_dtd = c.XML_ERROR_FEATURE_REQUIRES_XML_DTD,
    cant_change_feature_once_parsing = c.XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING,
    unbound_prefix = c.XML_ERROR_UNBOUND_PREFIX,
    undeclaring_prefix = c.XML_ERROR_UNDECLARING_PREFIX,
    incomplete_pe = c.XML_ERROR_INCOMPLETE_PE,
    xml_decl = c.XML_ERROR_XML_DECL,
    text_decl = c.XML_ERROR_TEXT_DECL,
    publicid = c.XML_ERROR_PUBLICID,
    suspended = c.XML_ERROR_SUSPENDED,
    not_suspended = c.XML_ERROR_NOT_SUSPENDED,
    aborted = c.XML_ERROR_ABORTED,
    finished = c.XML_ERROR_FINISHED,
    suspend_pe = c.XML_ERROR_SUSPEND_PE,
    reserved_prefix_xml = c.XML_ERROR_RESERVED_PREFIX_XML,
    reserved_prefix_xmlns = c.XML_ERROR_RESERVED_PREFIX_XMLNS,
    reserved_namespace_uri = c.XML_ERROR_RESERVED_NAMESPACE_URI,
    invalid_argument = c.XML_ERROR_INVALID_ARGUMENT,
    no_buffer = c.XML_ERROR_NO_BUFFER,
    amplification_limit_breach = c.XML_ERROR_AMPLIFICATION_LIMIT_BREACH,
    _,
};

pub fn errorString(code: Error) [*:0]const u8 {
    return c.XML_ErrorString(@intCast(@intFromEnum(code)));
}

fn toStatus(s: c.XML_Status) Status {
    return switch (s) {
        c.XML_STATUS_OK => .ok,
        c.XML_STATUS_SUSPENDED => .suspended,
        else => .failed,
    };
}

/// XML Parser with optional userdata. Pass `void` if you don't need it.
pub fn Parser(comptime UserData: type) type {
    return struct {
        raw: c.XML_Parser,

        const Self = @This();
        const has_userdata = UserData != void;
        const Ud = if (has_userdata) *UserData else void;

        pub const StartElementFn = if (has_userdata) fn (Ud, [:0]const u8, AttrIterator) void else fn ([:0]const u8, AttrIterator) void;
        pub const EndElementFn = if (has_userdata) fn (Ud, [:0]const u8) void else fn ([:0]const u8) void;
        pub const CharacterDataFn = if (has_userdata) fn (Ud, []const u8) void else fn ([]const u8) void;
        pub const CdataSectionFn = if (has_userdata) fn (Ud) void else fn () void;
        pub const CommentFn = if (has_userdata) fn (Ud, [:0]const u8) void else fn ([:0]const u8) void;
        pub const ProcessingInstructionFn = if (has_userdata) fn (Ud, [:0]const u8, [:0]const u8) void else fn ([:0]const u8, [:0]const u8) void;
        pub const DefaultFn = if (has_userdata) fn (Ud, []const u8) void else fn ([]const u8) void;

        inline fn ud(raw_ud: ?*anyopaque) Ud {
            return if (has_userdata) @ptrCast(@alignCast(raw_ud)) else {};
        }

        pub fn init(encoding: ?[*:0]const u8, user_data: Ud) ?Self {
            const p = c.XML_ParserCreate(encoding) orelse return null;
            if (has_userdata) c.XML_SetUserData(p, user_data);
            return .{ .raw = p };
        }

        pub fn initNs(encoding: ?[*:0]const u8, sep: u8, user_data: Ud) ?Self {
            const p = c.XML_ParserCreateNS(encoding, sep) orelse return null;
            if (has_userdata) c.XML_SetUserData(p, user_data);
            return .{ .raw = p };
        }

        pub fn deinit(self: *Self) void {
            c.XML_ParserFree(self.raw);
            self.raw = undefined;
        }

        pub fn reset(self: *Self, encoding: ?[*:0]const u8, user_data: Ud) bool {
            const ok = c.XML_ParserReset(self.raw, encoding) == c.XML_TRUE;
            if (ok and has_userdata) c.XML_SetUserData(self.raw, user_data);
            return ok;
        }

        pub fn setElementHandler(self: *Self, comptime start: ?*const StartElementFn, comptime end: ?*const EndElementFn) void {
            c.XML_SetElementHandler(
                self.raw,
                if (start) |h| comptime wrap.startElement(h) else null,
                if (end) |h| comptime wrap.endElement(h) else null,
            );
        }

        pub fn setStartElementHandler(self: *Self, comptime h: ?*const StartElementFn) void {
            c.XML_SetStartElementHandler(self.raw, if (h) |f| comptime wrap.startElement(f) else null);
        }

        pub fn setEndElementHandler(self: *Self, comptime h: ?*const EndElementFn) void {
            c.XML_SetEndElementHandler(self.raw, if (h) |f| comptime wrap.endElement(f) else null);
        }

        pub fn setCharacterDataHandler(self: *Self, comptime h: ?*const CharacterDataFn) void {
            c.XML_SetCharacterDataHandler(self.raw, if (h) |f| comptime wrap.charData(f) else null);
        }

        pub fn setCdataSectionHandler(self: *Self, comptime start: ?*const CdataSectionFn, comptime end: ?*const CdataSectionFn) void {
            c.XML_SetCdataSectionHandler(
                self.raw,
                if (start) |h| comptime wrap.cdata(h) else null,
                if (end) |h| comptime wrap.cdata(h) else null,
            );
        }

        pub fn setStartCdataSectionHandler(self: *Self, comptime h: ?*const CdataSectionFn) void {
            c.XML_SetStartCdataSectionHandler(self.raw, if (h) |f| comptime wrap.cdata(f) else null);
        }

        pub fn setEndCdataSectionHandler(self: *Self, comptime h: ?*const CdataSectionFn) void {
            c.XML_SetEndCdataSectionHandler(self.raw, if (h) |f| comptime wrap.cdata(f) else null);
        }

        pub fn setCommentHandler(self: *Self, comptime h: ?*const CommentFn) void {
            c.XML_SetCommentHandler(self.raw, if (h) |f| comptime wrap.comment(f) else null);
        }

        pub fn setProcessingInstructionHandler(self: *Self, comptime h: ?*const ProcessingInstructionFn) void {
            c.XML_SetProcessingInstructionHandler(self.raw, if (h) |f| comptime wrap.pi(f) else null);
        }

        pub fn setDefaultHandler(self: *Self, comptime h: ?*const DefaultFn) void {
            c.XML_SetDefaultHandler(self.raw, if (h) |f| comptime wrap.default(f) else null);
        }

        pub fn setDefaultHandlerExpand(self: *Self, comptime h: ?*const DefaultFn) void {
            c.XML_SetDefaultHandlerExpand(self.raw, if (h) |f| comptime wrap.default(f) else null);
        }

        pub fn parse(self: *Self, data: []const u8, is_final: bool) Status {
            return toStatus(c.XML_Parse(self.raw, data.ptr, @intCast(data.len), @intFromBool(is_final)));
        }

        pub fn getBuffer(self: *Self, len: usize) ?[*]u8 {
            return @ptrCast(c.XML_GetBuffer(self.raw, @intCast(len)));
        }

        pub fn parseBuffer(self: *Self, len: usize, is_final: bool) Status {
            return toStatus(c.XML_ParseBuffer(self.raw, @intCast(len), @intFromBool(is_final)));
        }

        pub fn stopParser(self: *Self, resumable: bool) Status {
            return toStatus(c.XML_StopParser(self.raw, if (resumable) c.XML_TRUE else c.XML_FALSE));
        }

        pub fn resumeParser(self: *Self) Status {
            return toStatus(c.XML_ResumeParser(self.raw));
        }

        pub fn getParsingStatus(self: *Self) ParsingStatus {
            var s: c.XML_ParsingStatus = undefined;
            c.XML_GetParsingStatus(self.raw, &s);
            return .{ .parsing = @enumFromInt(s.parsing), .final_buffer = s.finalBuffer == c.XML_TRUE };
        }

        pub fn setEncoding(self: *Self, encoding: ?[*:0]const u8) bool {
            return c.XML_SetEncoding(self.raw, encoding) == c.XML_STATUS_OK;
        }

        pub fn getErrorCode(self: *Self) Error {
            return @enumFromInt(c.XML_GetErrorCode(self.raw));
        }

        pub fn line(self: *Self) usize {
            return @intCast(c.XML_GetCurrentLineNumber(self.raw));
        }

        pub fn column(self: *Self) usize {
            return @intCast(c.XML_GetCurrentColumnNumber(self.raw));
        }

        pub fn byteIndex(self: *Self) isize {
            return @intCast(c.XML_GetCurrentByteIndex(self.raw));
        }

        pub fn byteCount(self: *Self) usize {
            return @intCast(c.XML_GetCurrentByteCount(self.raw));
        }

        pub fn specifiedAttrCount(self: *Self) usize {
            const n = c.XML_GetSpecifiedAttributeCount(self.raw);
            return if (n >= 0) @intCast(n) else 0;
        }

        pub fn idAttrIndex(self: *Self) ?usize {
            const idx = c.XML_GetIdAttributeIndex(self.raw);
            return if (idx >= 0) @intCast(idx) else null;
        }

        fn sliceTo(ptr: [*c]const u8) [:0]const u8 {
            return std.mem.sliceTo(@as([*:0]const u8, @ptrCast(ptr)), 0);
        }

        fn slice(ptr: [*c]const u8, len: c_int) []const u8 {
            return @as([*]const u8, @ptrCast(ptr))[0..@intCast(len)];
        }

        const wrap = struct {
            fn startElement(comptime h: *const StartElementFn) c.XML_StartElementHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque, name: [*c]const u8, attrs: [*c][*c]const u8) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud), sliceTo(name), .{ .ptr = @ptrCast(attrs) }) else h(sliceTo(name), .{ .ptr = @ptrCast(attrs) });
                    }
                }.cb;
            }

            fn endElement(comptime h: *const EndElementFn) c.XML_EndElementHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque, name: [*c]const u8) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud), sliceTo(name)) else h(sliceTo(name));
                    }
                }.cb;
            }

            fn charData(comptime h: *const CharacterDataFn) c.XML_CharacterDataHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque, s: [*c]const u8, len: c_int) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud), slice(s, len)) else h(slice(s, len));
                    }
                }.cb;
            }

            fn cdata(comptime h: *const CdataSectionFn) c.XML_StartCdataSectionHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud)) else h();
                    }
                }.cb;
            }

            fn comment(comptime h: *const CommentFn) c.XML_CommentHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque, text: [*c]const u8) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud), sliceTo(text)) else h(sliceTo(text));
                    }
                }.cb;
            }

            fn pi(comptime h: *const ProcessingInstructionFn) c.XML_ProcessingInstructionHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque, target: [*c]const u8, data: [*c]const u8) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud), sliceTo(target), sliceTo(data)) else h(sliceTo(target), sliceTo(data));
                    }
                }.cb;
            }

            fn default(comptime h: *const DefaultFn) c.XML_DefaultHandler {
                return struct {
                    fn cb(raw_ud: ?*anyopaque, s: [*c]const u8, len: c_int) callconv(.c) void {
                        if (has_userdata) h(ud(raw_ud), slice(s, len)) else h(slice(s, len));
                    }
                }.cb;
            }
        };
    };
}

pub fn version() [*:0]const u8 {
    return c.XML_ExpatVersion();
}

pub fn versionInfo() struct { major: c_int, minor: c_int, micro: c_int } {
    const info = c.XML_ExpatVersionInfo();
    return .{ .major = info.major, .minor = info.minor, .micro = info.micro };
}

const testing = std.testing;

const VoidParser = Parser(void);

test "basic parsing" {
    var p = VoidParser.init(null, {}) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expectEqual(.ok, p.parse("<root><child/></root>", true));
}

test "version" {
    try testing.expect(version()[0] != 0);
    try testing.expect(versionInfo().major >= 2);
}

test "cdata" {
    const Context = struct {
        in_cdata: bool = false,
        content: []const u8 = "",

        fn start(self: *@This()) void {
            self.in_cdata = true;
        }
        fn end(self: *@This()) void {
            self.in_cdata = false;
        }
        fn chars(self: *@This(), data: []const u8) void {
            if (self.in_cdata) self.content = data;
        }
    };

    var ctx = Context{};
    var p = Parser(Context).init(null, &ctx) orelse return error.InitFailed;
    defer p.deinit();
    p.setCdataSectionHandler(&Context.start, &Context.end);
    p.setCharacterDataHandler(&Context.chars);
    try testing.expectEqual(.ok, p.parse("<r><![CDATA[<stuff>]]></r>", true));
    try testing.expectEqualStrings("<stuff>", ctx.content);
}

test "default handler" {
    const Context = struct {
        chunks: [16][]const u8 = undefined,
        len: usize = 0,

        fn cb(self: *@This(), data: []const u8) void {
            if (self.len < 16) {
                self.chunks[self.len] = data;
                self.len += 1;
            }
        }
    };

    var ctx = Context{};
    var p = Parser(Context).init(null, &ctx) orelse return error.InitFailed;
    defer p.deinit();
    p.setDefaultHandler(&Context.cb);
    try testing.expectEqual(.ok, p.parse("<r>x</r>", true));
    try testing.expect(ctx.len >= 3);
    try testing.expectEqualStrings("<r>", ctx.chunks[0]);
    try testing.expectEqualStrings("x", ctx.chunks[1]);
    try testing.expectEqualStrings("</r>", ctx.chunks[2]);
}

test "buffer parsing" {
    var p = VoidParser.init(null, {}) orelse return error.InitFailed;
    defer p.deinit();
    const xml = "<r/>";
    const buf = p.getBuffer(xml.len) orelse return error.NoBuffer;
    @memcpy(buf[0..xml.len], xml);
    try testing.expectEqual(.ok, p.parseBuffer(xml.len, true));
}

test "parsing status" {
    var p = VoidParser.init(null, {}) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expectEqual(Parsing.initialized, p.getParsingStatus().parsing);
    _ = p.parse("<r>", false);
    try testing.expectEqual(Parsing.parsing, p.getParsingStatus().parsing);
    _ = p.parse("</r>", true);
    try testing.expectEqual(Parsing.finished, p.getParsingStatus().parsing);
}

test "encoding" {
    var p = VoidParser.init(null, {}) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expect(p.setEncoding("UTF-8"));
    _ = p.parse("<r/>", true);
    try testing.expect(p.reset(null, {}));
    try testing.expect(p.setEncoding("ISO-8859-1"));
}

test "attribute iterator" {
    const Context = struct {
        attr_count: usize = 0,
        first_name: [:0]const u8 = "",
        first_value: [:0]const u8 = "",

        fn cb(self: *@This(), _: [:0]const u8, attrs: AttrIterator) void {
            var it = attrs;
            if (it.next()) |attr| {
                self.first_name = attr.name;
                self.first_value = attr.value;
                self.attr_count = 1 + it.count();
            }
        }
    };

    var ctx = Context{};
    var p = Parser(Context).init(null, &ctx) orelse return error.InitFailed;
    defer p.deinit();
    p.setStartElementHandler(&Context.cb);
    try testing.expectEqual(.ok, p.parse("<r a='1' b='2'/>", true));
    try testing.expectEqual(@as(usize, 2), ctx.attr_count);
    try testing.expectEqualStrings("a", ctx.first_name);
    try testing.expectEqualStrings("1", ctx.first_value);
}

test "error handling" {
    var p = VoidParser.init(null, {}) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expectEqual(Status.failed, p.parse("<r><unclosed>", true));
    const err = p.getErrorCode();
    try testing.expect(err != .none);
    try testing.expect(errorString(err)[0] != 0);
}

test "namespace parsing" {
    const Context = struct {
        name: [:0]const u8 = "",

        fn cb(self: *@This(), n: [:0]const u8, _: AttrIterator) void {
            self.name = n;
        }
    };

    var ctx = Context{};
    var p = Parser(Context).initNs(null, '|', &ctx) orelse return error.InitFailed;
    defer p.deinit();
    p.setStartElementHandler(&Context.cb);
    try testing.expectEqual(.ok, p.parse("<r xmlns='http://example.com'><child/></r>", true));
    try testing.expect(std.mem.indexOf(u8, ctx.name, "http://example.com") != null);
}

test "comment handler" {
    const Context = struct {
        comment: [:0]const u8 = "",

        fn cb(self: *@This(), text: [:0]const u8) void {
            self.comment = text;
        }
    };

    var ctx = Context{};
    var p = Parser(Context).init(null, &ctx) orelse return error.InitFailed;
    defer p.deinit();
    p.setCommentHandler(&Context.cb);
    try testing.expectEqual(.ok, p.parse("<r><!-- hello world --></r>", true));
    try testing.expectEqualStrings(" hello world ", ctx.comment);
}

test "userdata support" {
    const Context = struct {
        depth: usize = 0,
        max_depth: usize = 0,
        element_count: usize = 0,

        fn onStart(self: *@This(), _: [:0]const u8, _: AttrIterator) void {
            self.depth += 1;
            self.element_count += 1;
            if (self.depth > self.max_depth) {
                self.max_depth = self.depth;
            }
        }

        fn onEnd(self: *@This(), _: [:0]const u8) void {
            self.depth -= 1;
        }
    };

    var ctx = Context{};
    var p = Parser(Context).init(null, &ctx) orelse return error.InitFailed;
    defer p.deinit();

    p.setElementHandler(&Context.onStart, &Context.onEnd);
    try testing.expectEqual(.ok, p.parse("<root><a><b/></a><c/></root>", true));

    try testing.expectEqual(@as(usize, 0), ctx.depth);
    try testing.expectEqual(@as(usize, 3), ctx.max_depth);
    try testing.expectEqual(@as(usize, 4), ctx.element_count);
}

test "userdata with character data" {
    const Context = struct {
        text: std.ArrayListUnmanaged(u8) = .{},

        fn onChars(self: *@This(), data: []const u8) void {
            self.text.appendSlice(testing.allocator, data) catch {};
        }
    };

    var ctx = Context{};
    defer ctx.text.deinit(testing.allocator);

    var p = Parser(Context).init(null, &ctx) orelse return error.InitFailed;
    defer p.deinit();

    p.setCharacterDataHandler(&Context.onChars);
    try testing.expectEqual(.ok, p.parse("<r>Hello, World!</r>", true));

    try testing.expectEqualStrings("Hello, World!", ctx.text.items);
}
