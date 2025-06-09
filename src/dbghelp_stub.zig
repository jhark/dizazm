// Stub implementation for dbghelp on non-Windows platforms.

pub fn init() !void {
    return error.PlatformNotSupported;
}

pub fn deinit() void {}

pub fn loadModule(image_path: []const u8) !u64 {
    _ = image_path;
    return error.PlatformNotSupported;
}

pub const SymbolInfo = struct {
    image_rva: u64 = 0, // RVA in the image when mapped.
    size: u64 = 0,
    displacement: u64 = 0, // Offset from start of symbol.
    name_len: u16 = 0,
    name_buf: [0]u8 = undefined,

    pub fn name(self: *const @This()) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub fn findSymbolInfo(
    mod_base: u64,
    symbol_name: []const u8,
) !?SymbolInfo {
    _ = mod_base;
    _ = symbol_name;
    return error.PlatformNotSupported;
}

pub fn findSymbolInfoW(
    mod_base: u64,
    symbol_name: [:0]const u16,
) !?SymbolInfo {
    _ = mod_base;
    _ = symbol_name;
    return error.PlatformNotSupported;
}

pub fn findSymbolInfoFromAddress(
    mod_base: u64,
    address: u64,
) !?SymbolInfo {
    _ = mod_base;
    _ = address;
    return error.PlatformNotSupported;
}
