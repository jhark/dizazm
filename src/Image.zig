const std = @import("std");
const pe = @import("pe.zig");
const windows = std.os.windows;

const FILE_MAP_READ = 0x0004;

extern "kernel32" fn CreateFileW(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: windows.DWORD,
    dwShareMode: windows.DWORD,
    lpSecurityAttributes: ?*windows.SECURITY_ATTRIBUTES,
    dwCreationDisposition: windows.DWORD,
    dwFlagsAndAttributes: windows.DWORD,
    hTemplateFile: ?windows.HANDLE,
) callconv(windows.WINAPI) windows.HANDLE;

extern "kernel32" fn CreateFileMappingW(
    hFile: windows.HANDLE,
    lpFileMappingAttributes: ?*windows.SECURITY_ATTRIBUTES,
    flProtect: windows.DWORD,
    dwMaximumSizeHigh: windows.DWORD,
    dwMaximumSizeLow: windows.DWORD,
    lpName: ?[*:0]const u16,
) callconv(windows.WINAPI) ?windows.HANDLE;

extern "kernel32" fn MapViewOfFile(
    hFileMappingObject: windows.HANDLE,
    dwDesiredAccess: windows.DWORD,
    dwFileOffsetHigh: windows.DWORD,
    dwFileOffsetLow: windows.DWORD,
    dwNumberOfBytesToMap: usize,
) callconv(windows.WINAPI) ?*anyopaque;

extern "kernel32" fn UnmapViewOfFile(
    lpBaseAddress: *const anyopaque,
) callconv(windows.WINAPI) windows.BOOL;

fn file_rva(comptime T: type, data: []const u8, rva_: anytype) [*]const T {
    const rva_u: usize = @intCast(rva_);
    return @ptrCast(@alignCast(data.ptr + rva_u));
}

fn file_rva_slice(comptime T: type, data: []const u8, rva_: anytype, len_: anytype) []const T {
    const len_u: usize = @intCast(len_);
    const t = file_rva(T, data, rva_);
    return t[0..len_u];
}

mapping: Mapping,
image_data: []const u8,
dos_header: *const pe.IMAGE_DOS_HEADER,
file_header: *const pe.IMAGE_FILE_HEADER,
optional_header: *const pe.IMAGE_OPTIONAL_HEADER64,
export_dir: ?*const pe.IMAGE_EXPORT_DIRECTORY,
text_section: *const pe.IMAGE_SECTION_HEADER,
rdata_section: *const pe.IMAGE_SECTION_HEADER,
idata_range: ?RvaRange, // Not a real section, contained within .rdata.

const RvaRange = struct {
    begin: u64,
    end: u64,
};

const Self = @This();

const builtin = @import("builtin");

const Mapping = switch (builtin.os.tag) {
    .windows => struct {
        data: []const u8,
        handle: windows.HANDLE,

        fn init(allocator: std.mem.Allocator, path: []const u8) !Mapping {
            const path_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, path);
            defer allocator.free(path_wtf16);

            const file = CreateFileW(
                path_wtf16.ptr,
                windows.GENERIC_READ,
                windows.FILE_SHARE_READ,
                null,
                windows.OPEN_EXISTING,
                windows.FILE_ATTRIBUTE_NORMAL,
                null,
            );
            if (file == windows.INVALID_HANDLE_VALUE) {
                std.log.err("CreateFileW: {}", .{windows.GetLastError()});
                return error.CreateFileFailed;
            }
            defer windows.CloseHandle(file);

            const file_mapping = CreateFileMappingW(
                file,
                null,
                windows.PAGE_READONLY,
                0,
                0,
                null,
            );
            if (file_mapping == null) {
                std.log.err("CreateFileMappingW: {}", .{windows.GetLastError()});
                return error.CreateFileMappingFailed;
            }
            defer windows.CloseHandle(file_mapping.?);

            const file_base = MapViewOfFile(
                file_mapping.?,
                FILE_MAP_READ,
                0,
                0,
                0,
            );
            if (file_base == null) {
                std.log.err("MapViewOfFile: {}", .{windows.GetLastError()});
                return error.MapViewOfFileFailed;
            }

            const image_data = x: {
                var mbi: windows.MEMORY_BASIC_INFORMATION = undefined;
                _ = try windows.VirtualQuery(file_base, &mbi, @sizeOf(windows.MEMORY_BASIC_INFORMATION));
                const file_bytes_begin: [*]const u8 = @ptrCast(file_base);
                break :x file_bytes_begin[0..mbi.RegionSize];
            };

            return Mapping{
                .data = image_data,
                .handle = file_mapping,
            };
        }

        fn deinit(self: *Mapping) void {
            const ok = UnmapViewOfFile(self.data.ptr);
            if (ok == windows.FALSE) {
                std.log.err("UnmapViewOfFile: {}", .{windows.GetLastError()});
            }
            std.log.debug("UnmapViewOfFile: {}", .{ok});

            _ = windows.CloseHandle(self.handle);
        }
    },

    // .macos, .linux => struct {
    //     data: []const u8,

    //     fn init(allocator: std.mem.Allocator, path: []const u8) !Mapping {
    //         _ = allocator;

    //         const file = std.fs.cwd().openFile(path, .{}) catch return error.FileNotFound;
    //         defer file.close();

    //         const data = try std.posix.mmap(
    //             null,
    //             std.math.maxInt(usize),
    //             std.posix.PROT.READ,
    //             .{ .TYPE = .PRIVATE },
    //             file.handle,
    //             0,
    //         );

    //         return Mapping{ .data = data };
    //     }

    //     fn deinit(self: *Mapping) void {
    //         _ = std.posix.munmap(@alignCast(self.data));
    //     }
    // },

    else => struct {
        allocator: std.mem.Allocator,
        data: []const u8,

        fn init(allocator: std.mem.Allocator, path: []const u8) !Mapping {
            const file = std.fs.cwd().openFile(path, .{}) catch return error.FileNotFound;
            defer file.close();

            const data = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
            return Mapping{ .allocator = allocator, .data = data };
        }

        fn deinit(self: *Mapping) void {
            self.allocator.free(self.data);
        }
    },
};

pub fn init(allocator: std.mem.Allocator, path: []const u8) !Self {
    const mapping = try Mapping.init(allocator, path);
    const image_data = mapping.data;

    const dos_header: *const pe.IMAGE_DOS_HEADER = @ptrCast(@alignCast(image_data.ptr));
    if (dos_header.e_magic != pe.IMAGE_DOS_SIGNATURE) {
        return error.InvalidExecutable;
    }

    const nt_headers_begin: [*]const u8 = @ptrCast(&image_data[@intCast(dos_header.e_lfanew)]);
    const pe_magic = [_]u8{ 'P', 'E', 0, 0 };
    if (!std.mem.eql(u8, nt_headers_begin[0..pe_magic.len], pe_magic[0..pe_magic.len])) {
        return error.InvalidExecutable;
    }

    const file_header: *const pe.IMAGE_FILE_HEADER = @ptrCast(@alignCast(nt_headers_begin + pe_magic.len));
    if (file_header.Machine != pe.IMAGE_FILE_MACHINE_AMD64) {
        std.log.err("Unsupported machine type: {}", .{file_header.Machine});
        return error.UnsupportedMachineType;
    }
    if (file_header.SizeOfOptionalHeader < @sizeOf(pe.IMAGE_OPTIONAL_HEADER64)) {
        return error.InvalidExecutable;
    }

    const optional_header_begin: [*]const u8 = @ptrFromInt(@intFromPtr(file_header) + @sizeOf(pe.IMAGE_FILE_HEADER));
    const optional_header: *const pe.IMAGE_OPTIONAL_HEADER64 = @ptrCast(@alignCast(optional_header_begin));

    const section_headers = x: {
        const begin: [*]const u8 = @ptrFromInt(@intFromPtr(optional_header) + file_header.SizeOfOptionalHeader);
        const headers: [*]const pe.IMAGE_SECTION_HEADER = @ptrCast(@alignCast(begin));
        break :x headers[0..file_header.NumberOfSections];
    };

    const text_section: *const pe.IMAGE_SECTION_HEADER = x: {
        for (section_headers, 0..) |section_header, i| {
            if (std.mem.eql(u8, section_header.Name[0..5], ".text") and section_header.Name[5] == 0) {
                break :x &section_headers[i];
            }
        }
        std.log.err(".text section missing.", .{});
        return error.TextSectionNotFound;
    };

    const rdata_section: *const pe.IMAGE_SECTION_HEADER = x: {
        for (section_headers, 0..) |section_header, i| {
            if (std.mem.eql(u8, section_header.Name[0..6], ".rdata") and section_header.Name[6] == 0) {
                break :x &section_headers[i];
            }
        }
        std.log.err(".rdata section missing.", .{});
        return error.RdataSectionNotFound;
    };

    const export_directory: ?*const pe.IMAGE_EXPORT_DIRECTORY = x: {
        const export_dir_rva = optional_header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (export_dir_rva == 0) {
            break :x null;
        }
        const export_dir_file_rva = sectionRvaToFileRva(rdata_section, export_dir_rva);
        break :x @ptrCast(@alignCast(image_data.ptr + export_dir_file_rva));
    };

    const imports_data_directory: *const pe.IMAGE_DATA_DIRECTORY = &optional_header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT];
    var import_descriptors = file_rva_slice(
        pe.IMAGE_IMPORT_DESCRIPTOR,
        image_data,
        sectionRvaToFileRva(rdata_section, imports_data_directory.VirtualAddress),
        imports_data_directory.Size / @sizeOf(pe.IMAGE_IMPORT_DESCRIPTOR),
    );
    // Last entry is a null terminator.
    if (import_descriptors.len > 0) {
        import_descriptors.len -= 1;
    }

    var thunk_lo: u64 = std.math.maxInt(u64);
    var thunk_hi: u64 = 0;
    for (import_descriptors) |import_descriptor| {
        // if (import_descriptor.Name == 0) {
        //     continue;
        // }
        // const dll_name: [*:0]const u8 = @ptrCast(file_rva(u8, image_data, sectionRvaToFileRva(rdata_section, import_descriptor.Name)));
        // std.log.debug("dll_name: {s}", .{dll_name});
        // comptime sentinel = ;
        const thunks = file_rva(pe.IMAGE_THUNK_DATA64, image_data, sectionRvaToFileRva(rdata_section, import_descriptor.FirstThunk));
        thunk_lo = @min(thunk_lo, sectionRvaToFileRva(rdata_section, import_descriptor.FirstThunk));

        var i: usize = 0;
        while (true) : (i += 1) {
            const thunk = thunks[i];
            if (thunk.u.Ordinal == 0) {
                break;
            }

            // const thunk_rva = sectionRvaToFileRva(rdata_section, import_descriptor.FirstThunk) + i * @sizeOf(pe.IMAGE_THUNK_DATA64);
            // if (thunk.isOrdinal()) {
            //     const ordinal = thunk.asOrdinal();
            //     std.log.debug("0x{x:016}: ordinal: {d}", .{ thunk_rva, ordinal });
            // } else {
            //     const name_import = file_rva(pe.IMAGE_IMPORT_BY_NAME, image_data, sectionRvaToFileRva(rdata_section, thunk.u.AddressOfData));
            //     std.log.debug("0x{x:016}: name_import: {s}", .{ thunk_rva, name_import[0].name() });
            // }
        }

        {
            const thunk_rva = sectionRvaToFileRva(rdata_section, import_descriptor.FirstThunk) + i * @sizeOf(pe.IMAGE_THUNK_DATA64);
            thunk_hi = @max(thunk_hi, thunk_rva);
        }
    }

    const idata_range =
        if (import_descriptors.len > 0)
            RvaRange{
                .begin = thunk_lo,
                .end = thunk_hi,
            }
        else
            null;

    return Self{
        .mapping = mapping,
        .image_data = image_data,
        .dos_header = dos_header,
        .file_header = file_header,
        .optional_header = optional_header,
        .export_dir = export_directory,
        .text_section = text_section,
        .rdata_section = rdata_section,
        .idata_range = idata_range,
    };
}

pub fn deinit(self: *Self) void {
    self.mapping.deinit();
}

// Converts from an RVA inside a properly mapped .text section to a file offset.
pub fn textRvaToFileRva(self: *const Self, rva: usize) usize {
    return sectionRvaToFileRva(self.text_section, rva);
}

pub fn rdataRvaToFileRva(self: *const Self, rva: usize) usize {
    return sectionRvaToFileRva(self.rdata_section, rva);
}

fn sectionRvaToFileRva(section: *const pe.IMAGE_SECTION_HEADER, rva: usize) usize {
    // The address is relative to the base of the image, after the image has
    // been mapped according to the virtual addresses for each section.
    //
    // Therefore to find the location in the file, we subtract the virtual
    // address of the section to get the section offset, and add the offset
    // ofthe section within the file.
    return rva - section.VirtualAddress + section.PointerToRawData;
}

pub const ImportInfo = struct {
    import: union(enum) {
        name: [*:0]const u8,
        ordinal: u16,
    },
    dll_name: [*:0]const u8,
};

pub fn getImportInfo(self: *const Self, rva: usize) ?ImportInfo {
    if (self.idata_range == null) {
        return null;
    }

    const import_desc: *const pe.IMAGE_IMPORT_DESCRIPTOR = x: {
        const imports_data_directory: *const pe.IMAGE_DATA_DIRECTORY = &self.optional_header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT];
        var import_descriptors = file_rva_slice(
            pe.IMAGE_IMPORT_DESCRIPTOR,
            self.image_data,
            sectionRvaToFileRva(self.rdata_section, imports_data_directory.VirtualAddress),
            imports_data_directory.Size / @sizeOf(pe.IMAGE_IMPORT_DESCRIPTOR),
        );
        // Last entry is a null terminator.
        if (import_descriptors.len > 0) {
            import_descriptors.len -= 1;
        }

        if (import_descriptors.len == 0) {
            return null;
        }

        var best_desc: *const pe.IMAGE_IMPORT_DESCRIPTOR = undefined;
        var best_offset: usize = std.math.maxInt(usize);
        for (import_descriptors) |*import_descriptor| {
            const offset = rva - import_descriptor.FirstThunk;
            if (offset < best_offset) {
                best_desc = import_descriptor;
                best_offset = offset;
            }
        }
        break :x best_desc;
    };

    const dll_name: [*:0]const u8 = @ptrCast(file_rva(
        u8,
        self.image_data,
        sectionRvaToFileRva(
            self.rdata_section,
            import_desc.Name,
        ),
    ));

    const thunk = file_rva(pe.IMAGE_THUNK_DATA64, self.image_data, sectionRvaToFileRva(self.rdata_section, rva))[0];
    if (thunk.isOrdinal()) {
        return ImportInfo{
            .import = .{ .ordinal = thunk.asOrdinal() },
            .dll_name = dll_name,
        };
    }

    const name_import = file_rva(pe.IMAGE_IMPORT_BY_NAME, self.image_data, sectionRvaToFileRva(self.rdata_section, thunk.u.AddressOfData));
    return ImportInfo{
        .import = .{ .name = name_import[0].name() },
        .dll_name = dll_name,
    };
}

pub fn inIdataSection(self: *const Self, rva: usize) bool {
    if (self.idata_range == null) {
        return false;
    } else {
        return rva >= self.idata_range.?.begin and rva < self.idata_range.?.end;
    }
}

pub fn inTextSection(self: *const Self, rva: usize) bool {
    return rva >= self.text_section.VirtualAddress and rva < self.text_section.VirtualAddress + self.text_section.SizeOfRawData;
}

pub const ExportSymbol = struct {
    address: u64,
    ordinal: u16,
};

pub fn findExportSymbol(self: *const Self, symbol_name: []const u8) !?ExportSymbol {
    if (self.export_dir == null) {
        std.log.err("No export directory found in executable", .{});
        return error.NoExportDirectory;
    }

    const export_dir = self.export_dir.?;

    const function_addresses = file_rva_slice(u32, self.image_data, export_dir.AddressOfFunctions, export_dir.NumberOfFunctions);
    const function_names = file_rva_slice(u32, self.image_data, export_dir.AddressOfNames, export_dir.NumberOfNames);
    const function_ordinals = file_rva_slice(u16, self.image_data, export_dir.AddressOfNameOrdinals, export_dir.NumberOfNames);

    const CompareContext = struct {
        file_bytes: []const u8,
        symbol_name: []const u8,

        fn compare(ctx: @This(), name_rva: u32) std.math.Order {
            const name_ptr_bytes: [*:0]const u8 = @ptrCast(ctx.file_bytes.ptr + name_rva);
            const current_name_len = std.mem.len(name_ptr_bytes);
            const current_name = name_ptr_bytes[0..current_name_len];
            return std.mem.order(u8, ctx.symbol_name, current_name);
        }
    };

    const compare_context = CompareContext{
        .file_bytes = self.image_data,
        .symbol_name = symbol_name,
    };

    const symbol_index =
        std.sort.binarySearch(u32, function_names, compare_context, CompareContext.compare) orelse {
            return null;
        };

    const ordinal = function_ordinals[symbol_index];
    const symbol_address = function_addresses[ordinal];

    std.log.info("Found symbol {s} at address: 0x{x:08}, ordinal: {d}", .{ symbol_name, symbol_address, ordinal });

    return ExportSymbol{
        .address = symbol_address,
        .ordinal = ordinal,
    };
}
