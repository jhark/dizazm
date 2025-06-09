const builtin = @import("builtin");
const std = @import("std");
const flags = @import("flags");
const cs = @import("capstone.zig");
const dbghelp = if (builtin.os.tag == .windows) @import("dbghelp.zig") else @import("dbghelp_stub.zig");
const nt = @import("nt.zig");
const Image = @import("Image.zig");
const Enum = @import("Enum.zig").Enum;

const USE_COLORS = true;
var g_use_dbghelp = true;

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
    if (builtin.os.tag == .windows) {
        _ = std.os.windows.kernel32.SetConsoleOutputCP(65001); // UTF-8
    }

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

    dbghelp.init() catch |err| {
        std.log.warn("dbghelp.dll is unavailable ({s}), using export table only", .{@errorName(err)});
        g_use_dbghelp = false;
    };
    defer if (g_use_dbghelp) dbghelp.deinit();
    var sym_mod_base: u64 = 0;
    if (g_use_dbghelp) {
        sym_mod_base = try dbghelp.loadModule(image_path);
    }

    if (flags_.symbol) |symbol_name| {
        const stdout = std.io.getStdOut().writer();

        const symbol_info = findSymbol(&image, sym_mod_base, symbol_name) catch |err| {
            std.log.warn("Error finding symbol info: {s}", .{@errorName(err)});
            std.process.exit(1);
        } orelse {
            std.log.err("Symbol not found", .{});
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
        try printDisassembly(&image, sym_mod_base, symbol_info.image_rva, text, flags_.bytes);

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
        try printDisassembly(&image, sym_mod_base, address, text, flags_.bytes);
    }
}

fn findSymbol(image: *Image, sym_mod_base: u64, symbol_name: []const u8) !?dbghelp.SymbolInfo {
    if (g_use_dbghelp) {
        return try dbghelp.findSymbolInfo(sym_mod_base, symbol_name);
    }

    const export_symbol = image.findExportSymbol(symbol_name) catch |export_err| {
        std.log.warn("Failed to find export symbol: {s}", .{@errorName(export_err)});
        return export_err;
    } orelse return null;

    return .{
        .image_rva = export_symbol.address,
        .size = 0,
    };
}

fn printDisassembly(image: *Image, sym_mod_base: u64, base_address: u64, text: []const u8, print_bytes: bool) !void {
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

    const VT100 = struct {
        const RESET = "\x1b[0m";
        const BOLD = "\x1b[1m";
        const DIM = "\x1b[2m";
        const RED = "\x1b[31m";
        const GREEN = "\x1b[32m";
        const BLUE = "\x1b[34m";
        const YELLOW = "\x1b[33m";
        const MAGENTA = "\x1b[35m";
    };

    const ansi_supported = USE_COLORS and std.io.getStdOut().getOrEnableAnsiEscapeSupport();

    const cc_reset = if (ansi_supported) VT100.RESET else "";
    const cc_bold = if (ansi_supported) VT100.BOLD else "";
    const cc_dim = if (ansi_supported) VT100.DIM else "";
    const cc_ret = if (ansi_supported) VT100.RED else "";
    const cc_call = if (ansi_supported) VT100.GREEN else "";
    const cc_jmp = if (ansi_supported) VT100.BLUE else "";
    const cc_comment = if (ansi_supported) VT100.YELLOW else "";
    const cc_ex = if (ansi_supported) VT100.MAGENTA else "";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var jump_targets = std.AutoArrayHashMap(u32, void).init(allocator);
    defer jump_targets.deinit();
    try jump_targets.ensureTotalCapacity(instructions.len / 8);

    findJumpTargets(&jump_targets, instructions, base_address, text.len);

    const stdout = std.io.getStdOut().writer();

    for (instructions, 0..) |instruction, instruction_index| {
        if (jump_targets.get(@truncate(instruction.address - base_address))) |_| {
            try stdout.print("{s}{s}0x{x:0>16}:{s}  ", .{ cc_reset, cc_bold, instruction.address, cc_reset });
        } else {
            try stdout.print("{s}{s}0x{x:0>16}:{s}  ", .{ cc_reset, cc_dim, instruction.address, cc_reset });
        }

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

        var comment_buf: [4096]u8 = undefined;
        var comment: []const u8 = "";
        comment_buf[0] = 0;

        write_comment: {
            if (!g_use_dbghelp) {
                break :write_comment;
            }

            var lookup_target = false;

            const detail = instruction.detail.?;
            const groups = detail.groups[0..detail.groups_count];
            for (groups) |group| {
                switch (group) {
                    cs.X86_GRP_JUMP => {
                        try stdout.print("{s}", .{cc_jmp});
                        lookup_target = true;
                    },
                    cs.X86_GRP_CALL => {
                        try stdout.print("{s}", .{cc_call});
                        lookup_target = true;
                    },
                    cs.X86_GRP_RET => {
                        try stdout.print("{s}", .{cc_ret});
                    },
                    cs.X86_GRP_INT => {
                        try stdout.print("{s}", .{cc_ex});
                        if (instruction.id == cs.X86_INS_INT and instruction.size == 2 and instruction.bytes[1] == 0x29) {
                            comment = "__fastfail(rcx)";

                            if (instruction_index > 0) {
                                const prev_instruction = instructions[instruction_index - 1];
                                const detail2 = prev_instruction.detail.?;
                                if (prev_instruction.id == cs.X86_INS_MOV and detail2.arch_info.x86.op_count == 2) {
                                    const operand0 = detail2.arch_info.x86.operands[0];
                                    const operand1 = detail2.arch_info.x86.operands[1];
                                    if (operand0.type == cs.X86_OP_REG and operand0.u.reg == cs.X86_REG_ECX and operand1.type == cs.X86_OP_IMM) {
                                        const rcx: u64 = @bitCast(operand1.u.imm);
                                        const fast_fail_code = Enum(nt.FastFail).initVal(@truncate(rcx));
                                        comment = std.fmt.bufPrint(&comment_buf, "__fastfail({})", .{fast_fail_code}) catch "";
                                    }
                                }
                            }
                        }
                        if (instruction.id == cs.X86_INS_INT3) {
                            comment = "__debugbreak";
                        }

                        break :write_comment;
                    },
                    else => {},
                }
            }

            if (!lookup_target) {
                break :write_comment;
            }

            const info = detail.arch_info.x86;
            if (info.op_count != 1) {
                break :write_comment;
            }

            const operand = info.operands[0];

            const target: u64 = switch (operand.type) {
                cs.X86_OP_IMM => blk: {
                    break :blk @as(u64, @intCast(operand.u.imm));
                },
                cs.X86_OP_MEM => blk: {
                    const mem = operand.u.mem;
                    const disp = mem.disp;
                    const rip: i64 = @as(i64, @intCast(instruction.address)) + instruction.size;
                    break :blk @as(u64, @intCast(rip + disp));
                },
                else => {
                    break :write_comment;
                },
            };

            // Asking dbghelp about addresses outside the .text section gives
            // misleading results. E.g. <closest unrelated symbol> + <large offset>.
            if (!image.inTextSection(target)) {

                // Resolve import addresses to names directly instead of using debug info.
                if (image.inIdataSection(target)) {
                    const mb_import_info: ?Image.ImportInfo = image.getImportInfo(target);
                    if (mb_import_info) |import_info| {
                        switch (import_info.import) {
                            .name => |name| {
                                comment = std.fmt.bufPrint(&comment_buf, "{s}!{s}", .{ import_info.dll_name, name }) catch "";
                            },
                            .ordinal => |ordinal| {
                                comment = std.fmt.bufPrint(&comment_buf, "{s}!<ordinal:{d}>", .{ import_info.dll_name, ordinal }) catch "";
                            },
                        }
                    }
                }

                break :write_comment;
            }

            const symbol_info = dbghelp.findSymbolInfoFromAddress(sym_mod_base, target) catch {
                break :write_comment;
            } orelse break :write_comment;

            if (symbol_info.name_len == 0) {
                break :write_comment;
            }

            if (symbol_info.displacement == 0) {
                comment = std.fmt.bufPrint(&comment_buf, "{s}", .{symbol_info.name()}) catch "";
                break :write_comment;
            }

            var arrow: []const u8 = "";
            if (symbol_info.image_rva == base_address) {
                if (target > instruction.address)
                    arrow = " ↓";
                if (target < instruction.address)
                    arrow = " ↑";
            }
            comment = std.fmt.bufPrint(&comment_buf, "{s} + 0x{x}{s}", .{
                symbol_info.name(),
                symbol_info.displacement,
                arrow,
            }) catch "";
        }

        const mnemonic = std.mem.sliceTo(&instruction.mnemonic, 0);
        const op_str = std.mem.sliceTo(&instruction.op_str, 0);
        try stdout.print("{s: >16}{s}{s}{s}", .{
            mnemonic,
            cc_reset,
            if (op_str.len > 0) " " else "",
            op_str,
        });

        if (comment.len > 0) {
            try stdout.print(" {s}; {s}\n", .{ cc_comment, comment });
        } else {
            try stdout.print("\n", .{});
        }
    }
}

// Finds addresses of all internal jumps.
fn findJumpTargets(
    jump_targets: *std.AutoArrayHashMap(u32, void),
    instructions: []const cs.Instruction,
    base_address: u64,
    text_len: usize,
) void {
    for (instructions) |instruction| {
        const detail = instruction.detail.?;
        const groups = detail.groups[0..detail.groups_count];
        for (groups) |group| {
            switch (group) {
                cs.X86_GRP_JUMP => {
                    const info = detail.arch_info.x86;
                    if (info.op_count != 1) {
                        break;
                    }

                    const operand = info.operands[0];

                    switch (operand.type) {
                        cs.X86_OP_IMM => {
                            const target: u64 = @intCast(operand.u.imm);
                            const target_relative = target - base_address;
                            if (target_relative < text_len) {
                                jump_targets.put(@truncate(target_relative), void{}) catch unreachable;
                            }
                        },
                        else => {
                            break;
                        },
                    }
                },
                else => {},
            }
        }
    }
}
