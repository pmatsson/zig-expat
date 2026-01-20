//! Zig bindings for libexpat.

const std = @import("std");

pub const c = @cImport({
    @cInclude("expat.h");
});

pub const Parser = struct {
    raw: c.XML_Parser,

    // Handler types
    pub const StartElementHandler = *const fn (?*anyopaque, [*:0]const u8, ?[*:null]const ?[*:0]const u8) callconv(.c) void;
    pub const EndElementHandler = *const fn (?*anyopaque, [*:0]const u8) callconv(.c) void;
    pub const CharacterDataHandler = *const fn (?*anyopaque, [*]const u8, c_int) callconv(.c) void;
    pub const CdataSectionHandler = *const fn (?*anyopaque) callconv(.c) void;
    pub const CommentHandler = *const fn (?*anyopaque, [*:0]const u8) callconv(.c) void;
    pub const ProcessingInstructionHandler = *const fn (?*anyopaque, [*:0]const u8, [*:0]const u8) callconv(.c) void;
    pub const DefaultHandler = *const fn (?*anyopaque, [*]const u8, c_int) callconv(.c) void;

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

    pub fn init(encoding: ?[*:0]const u8) ?Parser {
        return if (c.XML_ParserCreate(encoding)) |p| .{ .raw = p } else null;
    }

    /// Create parser with namespace support; `sep` is inserted between URI and local name.
    pub fn initNs(encoding: ?[*:0]const u8, sep: u8) ?Parser {
        return if (c.XML_ParserCreateNS(encoding, sep)) |p| .{ .raw = p } else null;
    }

    pub fn deinit(self: *Parser) void {
        c.XML_ParserFree(self.raw);
        self.raw = undefined;
    }

    pub fn reset(self: *Parser, encoding: ?[*:0]const u8) bool {
        return c.XML_ParserReset(self.raw, encoding) == c.XML_TRUE;
    }

    // User data

    pub fn setUserData(self: *Parser, user_data: ?*anyopaque) void {
        c.XML_SetUserData(self.raw, user_data);
    }

    pub fn getUserData(self: *Parser) ?*anyopaque {
        return c.XML_GetUserData(self.raw);
    }

    // Handlers

    pub fn setElementHandler(self: *Parser, start: ?StartElementHandler, end: ?EndElementHandler) void {
        c.XML_SetElementHandler(self.raw, @ptrCast(start), @ptrCast(end));
    }

    pub fn setStartElementHandler(self: *Parser, h: ?StartElementHandler) void {
        c.XML_SetStartElementHandler(self.raw, @ptrCast(h));
    }

    pub fn setEndElementHandler(self: *Parser, h: ?EndElementHandler) void {
        c.XML_SetEndElementHandler(self.raw, @ptrCast(h));
    }

    pub fn setCharacterDataHandler(self: *Parser, h: ?CharacterDataHandler) void {
        c.XML_SetCharacterDataHandler(self.raw, @ptrCast(h));
    }

    pub fn setCdataSectionHandler(self: *Parser, start: ?CdataSectionHandler, end: ?CdataSectionHandler) void {
        c.XML_SetCdataSectionHandler(self.raw, @ptrCast(start), @ptrCast(end));
    }

    pub fn setStartCdataSectionHandler(self: *Parser, h: ?CdataSectionHandler) void {
        c.XML_SetStartCdataSectionHandler(self.raw, @ptrCast(h));
    }

    pub fn setEndCdataSectionHandler(self: *Parser, h: ?CdataSectionHandler) void {
        c.XML_SetEndCdataSectionHandler(self.raw, @ptrCast(h));
    }

    pub fn setCommentHandler(self: *Parser, h: ?CommentHandler) void {
        c.XML_SetCommentHandler(self.raw, @ptrCast(h));
    }

    pub fn setProcessingInstructionHandler(self: *Parser, h: ?ProcessingInstructionHandler) void {
        c.XML_SetProcessingInstructionHandler(self.raw, @ptrCast(h));
    }

    /// Catch-all for content not handled elsewhere. Inhibits internal entity expansion.
    pub fn setDefaultHandler(self: *Parser, h: ?DefaultHandler) void {
        c.XML_SetDefaultHandler(self.raw, @ptrCast(h));
    }

    /// Like setDefaultHandler but allows internal entity expansion.
    pub fn setDefaultHandlerExpand(self: *Parser, h: ?DefaultHandler) void {
        c.XML_SetDefaultHandlerExpand(self.raw, @ptrCast(h));
    }

    // Parsing

    pub fn parse(self: *Parser, data: []const u8, is_final: bool) Status {
        return toStatus(c.XML_Parse(self.raw, data.ptr, @intCast(data.len), if (is_final) 1 else 0));
    }

    /// Get internal buffer for zero-copy parsing. Call parseBuffer after filling it.
    pub fn getBuffer(self: *Parser, len: usize) ?[*]u8 {
        return @ptrCast(c.XML_GetBuffer(self.raw, @intCast(len)));
    }

    pub fn parseBuffer(self: *Parser, len: usize, is_final: bool) Status {
        return toStatus(c.XML_ParseBuffer(self.raw, @intCast(len), if (is_final) 1 else 0));
    }

    pub fn stopParser(self: *Parser, resumable: bool) Status {
        return toStatus(c.XML_StopParser(self.raw, if (resumable) c.XML_TRUE else c.XML_FALSE));
    }

    pub fn resumeParser(self: *Parser) Status {
        return toStatus(c.XML_ResumeParser(self.raw));
    }

    pub fn getParsingStatus(self: *Parser) ParsingStatus {
        var s: c.XML_ParsingStatus = undefined;
        c.XML_GetParsingStatus(self.raw, &s);
        return .{ .parsing = @enumFromInt(s.parsing), .final_buffer = s.finalBuffer == c.XML_TRUE };
    }

    /// Must be called before parse(). Returns false if parsing already started.
    pub fn setEncoding(self: *Parser, encoding: ?[*:0]const u8) bool {
        return c.XML_SetEncoding(self.raw, encoding) == c.XML_STATUS_OK;
    }

    // Error handling

    pub fn getErrorCode(self: *Parser) Error {
        return @enumFromInt(c.XML_GetErrorCode(self.raw));
    }

    pub fn errorString(code: Error) [*:0]const u8 {
        return c.XML_ErrorString(@intCast(@intFromEnum(code)));
    }

    // Position info

    pub fn getCurrentLineNumber(self: *Parser) usize {
        return @intCast(c.XML_GetCurrentLineNumber(self.raw));
    }

    pub fn getCurrentColumnNumber(self: *Parser) usize {
        return @intCast(c.XML_GetCurrentColumnNumber(self.raw));
    }

    pub fn getCurrentByteIndex(self: *Parser) isize {
        return @intCast(c.XML_GetCurrentByteIndex(self.raw));
    }

    /// Bytes in current event. Only meaningful inside a handler.
    pub fn getCurrentByteCount(self: *Parser) usize {
        return @intCast(c.XML_GetCurrentByteCount(self.raw));
    }

    // Attribute info (valid inside start element handler)

    /// Number of name/value pairs. Divide by 2 for attribute count.
    pub fn getSpecifiedAttributeCount(self: *Parser) usize {
        const n = c.XML_GetSpecifiedAttributeCount(self.raw);
        return if (n >= 0) @intCast(n) else 0;
    }

    pub fn getIdAttributeIndex(self: *Parser) ?usize {
        const idx = c.XML_GetIdAttributeIndex(self.raw);
        return if (idx >= 0) @intCast(idx) else null;
    }

    fn toStatus(result: c.XML_Status) Status {
        return switch (result) {
            c.XML_STATUS_OK => .ok,
            c.XML_STATUS_SUSPENDED => .suspended,
            else => .failed,
        };
    }
};

pub fn expatVersion() [*:0]const u8 {
    return c.XML_ExpatVersion();
}

pub fn expatVersionInfo() struct { major: c_int, minor: c_int, micro: c_int } {
    const info = c.XML_ExpatVersionInfo();
    return .{ .major = info.major, .minor = info.minor, .micro = info.micro };
}

// Tests

const testing = std.testing;

test "basic parsing" {
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expectEqual(.ok, p.parse("<root><child/></root>", true));
}

test "version" {
    try testing.expect(expatVersion()[0] != 0);
    try testing.expect(expatVersionInfo().major >= 2);
}

test "cdata" {
    const H = struct {
        in_cdata: bool = false,
        content: []const u8 = "",
        fn start(ud: ?*anyopaque) callconv(.c) void {
            cast(ud).in_cdata = true;
        }
        fn end(ud: ?*anyopaque) callconv(.c) void {
            cast(ud).in_cdata = false;
        }
        fn chars(ud: ?*anyopaque, s: [*]const u8, len: c_int) callconv(.c) void {
            const self = cast(ud);
            if (self.in_cdata) self.content = s[0..@intCast(len)];
        }
        fn cast(ud: ?*anyopaque) *@This() {
            return @ptrCast(@alignCast(ud));
        }
    };
    var h = H{};
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    p.setUserData(&h);
    p.setCdataSectionHandler(&H.start, &H.end);
    p.setCharacterDataHandler(&H.chars);
    try testing.expectEqual(.ok, p.parse("<r><![CDATA[<stuff>]]></r>", true));
    try testing.expectEqualStrings("<stuff>", h.content);
}

test "default handler" {
    const H = struct {
        chunks: [16][]const u8 = undefined,
        len: usize = 0,
        fn cb(ud: ?*anyopaque, s: [*]const u8, slen: c_int) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ud));
            if (self.len < 16) {
                self.chunks[self.len] = s[0..@intCast(slen)];
                self.len += 1;
            }
        }
    };
    var h = H{};
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    p.setUserData(&h);
    p.setDefaultHandler(&H.cb);
    try testing.expectEqual(.ok, p.parse("<r>x</r>", true));
    // Should see: "<r>", "x", "</r>"
    try testing.expect(h.len >= 3);
    try testing.expectEqualStrings("<r>", h.chunks[0]);
    try testing.expectEqualStrings("x", h.chunks[1]);
    try testing.expectEqualStrings("</r>", h.chunks[2]);
}

test "buffer parsing" {
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    const xml = "<r/>";
    const buf = p.getBuffer(xml.len) orelse return error.NoBuffer;
    @memcpy(buf[0..xml.len], xml);
    try testing.expectEqual(.ok, p.parseBuffer(xml.len, true));
}

test "parsing status" {
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expectEqual(Parser.Parsing.initialized, p.getParsingStatus().parsing);
    _ = p.parse("<r>", false);
    try testing.expectEqual(Parser.Parsing.parsing, p.getParsingStatus().parsing);
    _ = p.parse("</r>", true);
    try testing.expectEqual(Parser.Parsing.finished, p.getParsingStatus().parsing);
}

test "encoding" {
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    try testing.expect(p.setEncoding("UTF-8"));
    _ = p.parse("<r/>", true);
    try testing.expect(p.reset(null));
    try testing.expect(p.setEncoding("ISO-8859-1"));
}

test "attribute count" {
    const H = struct {
        count: usize = 0,
        p: *Parser = undefined,
        fn cb(ud: ?*anyopaque, _: [*:0]const u8, _: ?[*:null]const ?[*:0]const u8) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ud));
            self.count = self.p.getSpecifiedAttributeCount();
        }
    };
    var h = H{};
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    h.p = &p;
    p.setUserData(&h);
    p.setStartElementHandler(&H.cb);
    try testing.expectEqual(.ok, p.parse("<r a='1' b='2'/>", true));
    try testing.expectEqual(@as(usize, 4), h.count); // 2 attrs = 4 entries
}

test "error handling" {
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    const result = p.parse("<r><unclosed>", true);
    try testing.expectEqual(Parser.Status.failed, result);
    const err = p.getErrorCode();
    try testing.expect(err != .none);
    const msg = Parser.errorString(err);
    try testing.expect(msg[0] != 0);
}

test "position info" {
    const H = struct {
        line: usize = 0,
        col: usize = 0,
        p: *Parser = undefined,
        fn cb(ud: ?*anyopaque, _: [*:0]const u8, _: ?[*:null]const ?[*:0]const u8) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ud));
            self.line = self.p.getCurrentLineNumber();
            self.col = self.p.getCurrentColumnNumber();
        }
    };
    var h = H{};
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    h.p = &p;
    p.setUserData(&h);
    p.setStartElementHandler(&H.cb);
    try testing.expectEqual(.ok, p.parse("<r>\n  <elem/>\n</r>", true));
    try testing.expectEqual(@as(usize, 2), h.line);
    try testing.expectEqual(@as(usize, 2), h.col); // 0-indexed, "  <elem" -> col 2
}

test "namespace parsing" {
    const H = struct {
        name: []const u8 = "",
        fn cb(ud: ?*anyopaque, name: [*:0]const u8, _: ?[*:null]const ?[*:0]const u8) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ud));
            self.name = std.mem.sliceTo(name, 0);
        }
    };
    var h = H{};
    var p = Parser.initNs(null, '|') orelse return error.InitFailed;
    defer p.deinit();
    p.setUserData(&h);
    p.setStartElementHandler(&H.cb);
    try testing.expectEqual(.ok, p.parse("<r xmlns='http://example.com'><child/></r>", true));
    // child element should have namespace URI prefixed
    try testing.expect(std.mem.indexOf(u8, h.name, "http://example.com") != null);
}

test "stop and resume" {
    const H = struct {
        count: usize = 0,
        p: *Parser = undefined,
        fn cb(ud: ?*anyopaque, _: [*:0]const u8, _: ?[*:null]const ?[*:0]const u8) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ud));
            self.count += 1;
            if (self.count == 1) _ = self.p.stopParser(true); // suspend after first element
        }
    };
    var h = H{};
    var p = Parser.init(null) orelse return error.InitFailed;
    defer p.deinit();
    h.p = &p;
    p.setUserData(&h);
    p.setStartElementHandler(&H.cb);

    const result = p.parse("<r><a/><b/></r>", true);
    try testing.expectEqual(Parser.Status.suspended, result);
    try testing.expectEqual(@as(usize, 1), h.count);

    // Resume and finish
    const resumed = p.resumeParser();
    try testing.expect(resumed == .ok or resumed == .suspended);
}
