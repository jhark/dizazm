const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const windows = std.os.windows;

const LoadLibraryW = windows.kernel32.LoadLibraryW;
const GetProcAddress = windows.kernel32.GetProcAddress;
const FreeLibrary = windows.kernel32.FreeLibrary;

const HANDLE = windows.HANDLE;
const HMODULE = windows.HMODULE;
const BOOL = windows.BOOL;

const FALSE = windows.FALSE;
const TRUE = windows.TRUE;
const SYMOPT_DEFERRED_LOADS = 0x00000004;
const SYMOPT_DEBUG = 0x80000000;
const SYMFLAG_FUNCTION = 0x00000800;

const SYMBOL_INFOW = extern struct {
    SizeOfStruct: u32,
    TypeIndex: u32,
    Reserved: [2]u64,
    Index: u32,
    Size: u32,
    ModBase: u64,
    Flags: u32,
    Value: u64,
    Address: u64,
    Register: u32,
    Scope: u32,
    Tag: u32,
    NameLen: u32,
    MaxNameLen: u32,
    Name: [1]u16, // Note: This is a flexible length array.
};

// The API just wants a unique identifier even though it takes a HANDLE.
const g_handle: HANDLE = @ptrFromInt(0x6e82cae787e463c7); // Chosen by fair dice roll.

var g_dbghelp_dll: HMODULE = undefined;
// var g_symsrv_dll: HMODULE = undefined;

var g_symInitialize: *const fn (
    hProcess: HANDLE,
    UserSearchPath: ?[*:0]const u8,
    fInvadeProcess: BOOL,
) callconv(.winapi) BOOL = undefined;

var g_symCleanup: *const fn (hProcess: HANDLE) callconv(.winapi) BOOL = undefined;

var g_symSetOptions: *const fn (SymOptions: u32) callconv(.winapi) u32 = undefined;

var g_symLoadModuleExW: *const fn (
    hProcess: HANDLE,
    hFile: ?HANDLE,
    ImageName: ?[*:0]const u16,
    ModuleName: ?[*:0]const u16,
    BaseOfDll: u64,
    DllSize: u32,
    Data: ?*anyopaque, // MODLOAD_DATA
    Flags: u32,
) callconv(.winapi) u64 = undefined;

var g_symFromNameW: *const fn (
    hProcess: HANDLE,
    Name: [*:0]const u16,
    Symbol: *SYMBOL_INFOW,
) callconv(.winapi) BOOL = undefined;

fn loadProcAddress(ptr: anytype, name: [:0]const u8) !void {
    const p = GetProcAddress(g_dbghelp_dll, name) orelse return error.GetProcAddress;
    ptr.* = @ptrCast(@alignCast(p));
}

pub fn init() !void {
    const dbghelp_dll_name = comptime std.unicode.utf8ToUtf16LeStringLiteral("dbghelp.dll");
    g_dbghelp_dll = LoadLibraryW(dbghelp_dll_name) orelse return error.LoadLibraryW;
    errdefer _ = FreeLibrary(g_dbghelp_dll);

    // Doesn't seem to help dbghelp.dll find symsrv.dll.
    // const symsrv_dll_name = comptime std.unicode.utf8ToUtf16LeStringLiteral("symsrv.dll");
    // g_symsrv_dll = LoadLibraryW(symsrv_dll_name) orelse return error.LoadLibraryW;
    // errdefer _ = FreeLibrary(g_symsrv_dll);

    try loadProcAddress(&g_symInitialize, "SymInitialize");
    try loadProcAddress(&g_symCleanup, "SymCleanup");
    try loadProcAddress(&g_symSetOptions, "SymSetOptions");
    try loadProcAddress(&g_symLoadModuleExW, "SymLoadModuleExW");
    try loadProcAddress(&g_symFromNameW, "SymFromNameW");

    _ = g_symSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

    if (g_symInitialize(g_handle, null, FALSE) == FALSE) {
        std.log.err("SymInitialize: {}\n", .{windows.GetLastError()});
        return error.SymInitializeFailed;
    }
}

pub fn deinit() void {
    if (g_symCleanup(g_handle) == FALSE) {
        std.log.debug("SymCleanup: {}", .{windows.GetLastError()});
    }
    if (FreeLibrary(g_dbghelp_dll) == FALSE) {
        std.log.debug("FreeLibrary: {}", .{windows.GetLastError()});
    }
}

pub fn findSymbolInfo(
    image_path: []const u8,
    symbol_name: []const u8,
) !?SymbolLocation {
    var buf: [16384]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = stack_allocator.allocator();

    const image_path_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, image_path);
    defer allocator.free(image_path_wtf16);

    const symbol_name_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, symbol_name);
    defer allocator.free(symbol_name_wtf16);

    return findSymbolInfoW(image_path_wtf16, symbol_name_wtf16);
}

pub fn findSymbolInfoW(
    image_path: [:0]const u16,
    symbol_name: [:0]const u16,
) !?SymbolLocation {
    const mod_base = g_symLoadModuleExW(
        g_handle,
        null,
        image_path.ptr,
        null,
        0,
        0,
        null,
        0,
    );

    if (mod_base == 0) {
        std.log.err("SymLoadModuleEx: {}\n", .{windows.GetLastError()});
        return error.SymLoadModuleExFailed;
    }

    var symbol_info: SYMBOL_INFOW = std.mem.zeroes(SYMBOL_INFOW);
    symbol_info.SizeOfStruct = @sizeOf(SYMBOL_INFOW);

    if (g_symFromNameW(g_handle, symbol_name, &symbol_info) == FALSE) {
        const err = windows.GetLastError();
        std.log.warn("SymFromNameW: {}\n", .{err});
        if (err == windows.Win32Error.MOD_NOT_FOUND) {
            // TODO -- This seems like a misleading error code being unable to find the symbol.
            return null;
        }
        return error.SymFromNameFailed;
    }

    // Sometimes the base address isn't set for some reason.
    if (symbol_info.ModBase == 0) {
        symbol_info.ModBase = mod_base;
    }

    return SymbolLocation{
        .image_rva = symbol_info.Address - symbol_info.ModBase,
        .size = symbol_info.Size,
    };
}

pub const SymbolLocation = struct {
    image_rva: u64, // RVA in the image when mapped.
    size: u64,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        const program_name_slice: []const u8 = if (args.len > 0) args[0] else "program";
        try stdout.print("Usage: {s} <executable_path> <symbol_name>\n", .{program_name_slice});
        try stdout.print("Example: {s} C:\\Windows\\System32\\kernel32.dll CreateFileA\n", .{program_name_slice});
        return;
    }

    const exe_path: [:0]const u8 = args[1];
    const symbol_name: [:0]const u8 = args[2];

    try init();
    defer deinit();

    const location = findSymbolInfo(exe_path, symbol_name) catch |err| {
        try stdout.print("Error getting symbol info: {}\n", .{err});
        return; // Exit main if there was an error
    };

    try stdout.print("address: 0x{x}, size: {}\n", .{ location.image_rva, location.size });
}
