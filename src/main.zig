const std = @import("std");
const flags = @import("flags");
const cs = @import("capstone.zig");
const dbghelp = @import("dbghelp.zig");
const Image = @import("Image.zig");

// Command line options
const Flags = struct {
    pub const description =
        \\Disassembles a specified symbol from a Portable Executable (PE) file (.exe, .dll).
        \\
        \\Example:
        \\  dizazm -s CreateFileW kernel32.dll
    ;

    pub const descriptions = .{
        .symbol = "The name of the symbol to disassemble",
        .address = "The address to disassemble (e.g., 0x1000)",
        .length = "Number of bytes to disassemble",
        .bytes = "Print raw instruction bytes",
    };

    pub const switches = .{
        .symbol = 's',
        .address = 'a',
        .length = 'l',
        .bytes = 'b',
    };

    symbol: ?[]const u8 = null,
    address: ?[]const u8 = null,
    length: ?[]const u8 = null,
    bytes: bool = false,
    positional: struct {
        image_path: []const u8,
    },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const colors = &flags.ColorScheme{
        .error_label = &.{ .bright_red, .bold },
        .command_name = &.{.bright_green},
        .header = &.{ .yellow, .bold },
        .usage = &.{.dim},
    };

    const flags_ = flags.parseOrExit(args, "dizazm", Flags, .{
        .colors = colors,
    });

    // Determine disassembly length
    var disassembly_length: usize = 80; // Default length
    if (flags_.length) |length_str| {
        disassembly_length = std.fmt.parseUnsigned(usize, length_str, 0) catch |err| {
            std.log.err("Invalid length '{s}': {s}", .{ length_str, @errorName(err) });
            return error.InvalidLengthFormat;
        };
    }

    // Check for mutual exclusivity and presence of either symbol or address
    if (flags_.symbol != null and flags_.address != null) {
        std.log.err("--symbol (-s) and --address (-a) are mutually exclusive.", .{});
        return error.InvalidArguments;
    }

    if (flags_.symbol == null and flags_.address == null) {
        std.log.err("Either --symbol (-s) or --address (-a) must be provided.", .{});
        return error.InvalidArguments;
    }

    if (flags_.positional.image_path.len == 0) {
        std.log.err("Executable path is required.", .{});
        return error.InvalidArguments;
    }

    const image_path = flags_.positional.image_path;

    var image = try Image.init(allocator, image_path);
    defer image.deinit();

    if (flags_.symbol) |symbol_name| {
        const stdout = std.io.getStdOut().writer();

        dbghelp.init() catch |err| {
            std.log.warn("dbghelp.dll is unavailable ({s}), using export table only", .{@errorName(err)});

            const export_symbol = image.findExportSymbol(symbol_name, disassembly_length) catch |export_err| {
                std.log.warn("Failed to find export symbol: {s}", .{@errorName(export_err)});
                std.process.exit(1);
            };

            std.log.warn("Symbol size is unknown, using {d}", .{disassembly_length});

            try stdout.print("{s}:\n", .{symbol_name});
            try printDisassembly(export_symbol.address, export_symbol.text, flags_.bytes);
        };
        defer dbghelp.deinit();

        const symbol_info = dbghelp.findSymbolInfo(image_path, symbol_name) catch |err| {
            std.log.warn("Failed to find symbol info: {s}", .{@errorName(err)});
            std.process.exit(1);
        };

        if (symbol_info.size != 0) {
            disassembly_length = symbol_info.size;
        } else {
            std.log.warn("Symbol size is unknown, using {d}", .{disassembly_length});
        }

        const text_begin = image.textRvaToFileRva(symbol_info.image_rva);
        const text_end = text_begin + disassembly_length;
        const text = image.image_data[text_begin..text_end];

        try stdout.print("{s}:\n", .{symbol_name});
        try printDisassembly(symbol_info.image_rva, text, flags_.bytes);

        return;
    }

    if (flags_.address) |address_str| {
        const address = std.fmt.parseUnsigned(usize, address_str, 0) catch |err| {
            std.log.err("Error parsing address '{s}': {s}", .{ address_str, @errorName(err) });
            return error.InvalidAddressFormat;
        };

        const text_begin = image.textRvaToFileRva(address);
        const text_end = text_begin + disassembly_length;
        const text = image.image_data[text_begin..text_end];
        try printDisassembly(address, text, flags_.bytes);
    }
}

fn printDisassembly(base_address: u64, text: []const u8, print_bytes: bool) !void {
    var handle: cs.Handle = undefined;
    var err: cs.Error = undefined;

    err = cs.cs_open(cs.Arch.x86, cs.Mode.mode_64, &handle);
    if (err != cs.Error.ok) {
        std.log.err("cs_open: {s}", .{cs.cs_strerror(err)});
        return error.CapstoneInitFailed;
    }
    defer _ = cs.cs_close(&handle);

    err = cs.cs_option(handle, cs.OptionType.syntax, @intFromEnum(cs.OptionValue.syntax_intel));
    if (err != cs.Error.ok) {
        std.log.err("cs_option: {s}", .{cs.cs_strerror(err)});
        return error.CapstoneOptionFailed;
    }

    err = cs.cs_option(handle, cs.OptionType.detail, @intFromEnum(cs.OptionValue.on));
    if (err != cs.Error.ok) {
        std.log.err("cs_option: {s}", .{cs.cs_strerror(err)});
        return error.CapstoneOptionFailed;
    }

    var instructions_begin: [*]cs.Instruction = undefined;
    const instructions_len = cs.cs_disasm(handle, text.ptr, text.len, base_address, 0, &instructions_begin);
    if (instructions_len == 0) {
        return error.DisassemblyFailed;
    }
    defer cs.cs_free(instructions_begin, instructions_len);
    const instructions = instructions_begin[0..instructions_len];

    const max_instruction_len = x: {
        var max_len: usize = 0;
        if (print_bytes) {
            for (instructions) |instruction| {
                if (instruction.size > max_len) {
                    max_len = instruction.size;
                }
            }
        }
        break :x max_len;
    };

    const stdout = std.io.getStdOut().writer();
    for (instructions) |instruction| {
        try stdout.print("0x{x:0>16}:  ", .{instruction.address});

        if (print_bytes) {
            const instruction_bytes = instruction.bytes[0..instruction.size];
            for (instruction_bytes) |b| {
                try stdout.print("{x:0>2} ", .{b});
            }
            for (0..max_instruction_len - instruction.size) |_| {
                try stdout.print("   ", .{});
            }
            try stdout.print(" ", .{});
        }

        try stdout.print("{s} {s}\n", .{
            std.mem.sliceTo(&instruction.mnemonic, 0),
            std.mem.sliceTo(&instruction.op_str, 0),
        });
    }
}
