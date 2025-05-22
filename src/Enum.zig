const std = @import("std");

/// Wraps an enum type so that printing via std.fmt omits the full namespace
/// prefix, and unknown values of open enums get printed in hex.
pub fn Enum(comptime EnumType: type) type {
    // Validate that T is actually an enum
    comptime {
        if (@typeInfo(EnumType) != .@"enum") {
            @compileError("Enum requires an enum type parameter");
        }
    }

    return struct {
        value: EnumType,

        const EnumInt = @typeInfo(EnumType).@"enum".tag_type;
        const Self = @This();

        pub fn init(value: EnumType) Self {
            return .{ .value = value };
        }

        pub fn initVal(value: EnumInt) Self {
            return .{ .value = @enumFromInt(value) };
        }

        pub fn format(
            self: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;

            const enum_info = @typeInfo(EnumType).@"enum";
            const is_open = enum_info.is_exhaustive == false;
            const int_val = @intFromEnum(self.value);

            inline for (enum_info.fields) |field| {
                if (@intFromEnum(@field(EnumType, field.name)) == int_val) {
                    return writer.writeAll(@tagName(@field(EnumType, field.name)));
                }
            }

            if (is_open) {
                return writer.print("0x{x}", .{int_val});
            }

            // We shouldn't be passed a a closed enum containing an invalid value.
            unreachable;
        }
    };
}
