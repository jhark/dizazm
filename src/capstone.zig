pub const Arch = enum(c_int) {
    arm = 0, // ARM architecture (including Thumb, Thumb-2)
    arm64, // ARM-64, also called AArch64
    mips, // Mips architecture
    x86, // X86 architecture (including x86 & x86-64)
    ppc, // PowerPC architecture
    sparc, // Sparc architecture
    sysz, // SystemZ architecture
    xcore, // XCore architecture
    m68k, // 68K architecture
    max,
    all = 0xFFFF, // All architectures - for cs_support()
};

pub const Mode = enum(c_uint) {
    // LITTLE_ENDIAN = 0, // little-endian mode (default mode)
    arm = 0, // 32-bit ARM
    mode_16 = 1 << 1, // 16-bit mode (X86)
    mode_32 = 1 << 2, // 32-bit mode (X86)
    mode_64 = 1 << 3, // 64-bit mode (X86, PPC)
    // THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    // MCLASS = 1 << 5, // ARM's Cortex-M series
    // V8 = 1 << 6, // ARMv8 A32 encodings for ARM
    // MICRO = 1 << 4, // MicroMips mode (MIPS)
    // MIPS3 = 1 << 5, // Mips III ISA
    // MIPS32R6 = 1 << 6, // Mips32r6 ISA
    // V9 = 1 << 4, // SparcV9 mode (Sparc)
    // QPX = 1 << 4, // Quad Processing eXtensions mode (PPC)
    // M68K_000 = 1 << 1, // M68K 68000 mode
    // M68K_010 = 1 << 2, // M68K 68010 mode
    // M68K_020 = 1 << 3, // M68K 68020 mode
    // M68K_030 = 1 << 4, // M68K 68030 mode
    // M68K_040 = 1 << 5, // M68K 68040 mode
    // M68K_060 = 1 << 6, // M68K 68060 mode
    // BIG_ENDIAN = 1 << 31, // big-endian mode
    // MIPS32 = 1 << 2, // Mips32 ISA (Mips)
    // MIPS64 = 1 << 3, // Mips64 ISA (Mips)
};

pub const OptionType = enum(c_int) {
    syntax = 1,
    detail = 2,
};

pub const OptionValue = enum(c_int) {
    syntax_intel = 1,
    on = 3,
};

pub const Instruction = extern struct {
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
    /// Find the instruction id in the '[ARCH]_insn' enum in the header file
    /// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    /// 'x86_insn' in x86.h for X86, etc...
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    /// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    id: c_uint,

    /// Address (EIP) of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    address: u64,

    /// Size of this instruction
    size: u16,

    /// Machine bytes of this instruction, with number of bytes indicated by @size above
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    bytes: [24]u8,

    /// Ascii text of instruction mnemonic
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    mnemonic: [32]u8,

    /// Ascii text of instruction operands
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    op_str: [160]u8,

    /// Pointer to cs_detail.
    /// NOTE: detail pointer is only valid when both requirements below are met:
    /// (1) CS_OP_DETAIL = CS_OPT_ON
    /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    ///
    /// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
    ///     is not NULL, its content is still irrelevant.
    detail: ?*const Detail,
};

const MAX_IMPL_W_REGS = 20;
const MAX_IMPL_R_REGS = 20;
const MAX_NUM_GROUPS = 8;

/// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
/// Initialized as memset(., 0, offsetof(cs_detail, ARCH)+sizeof(cs_ARCH))
/// by ARCH_getInstruction in arch/ARCH/ARCHDisassembler.c
/// if cs_detail changes, in particular if a field is added after the union,
/// then update arch/ARCH/ARCHDisassembler.c accordingly
const Detail = extern struct {
    /// List of implicit registers read by this instruction
    regs_read: [MAX_IMPL_R_REGS]u16,

    /// Number of implicit registers read by this instruction
    regs_read_count: u8,

    /// List of implicit registers modified by this instruction
    regs_write: [MAX_IMPL_W_REGS]u16,

    /// Number of implicit registers modified by this instruction
    regs_write_count: u8,

    /// list of group this instruction belong to
    groups: [MAX_NUM_GROUPS]u8,

    /// Number of groups this instruction belongs to
    groups_count: u8,

    /// Instruction has writeback operands.
    writeback: bool,

    arch_info: ArchInstructionInfo,

    /// Architecture-specific instruction info
    const ArchInstructionInfo = extern union {
        x86: ArchInstructionInfo_x86, // cs_x86;     ///< X86 architecture, including 16-bit, 32-bit & 64-bit mode
        arm64: struct {}, // cs_arm64; ///< ARM64 architecture (aka AArch64)
        arm: struct {}, // cs_arm;     ///< ARM architecture (including Thumb/Thumb2)
        m68k: struct {}, // cs_m68k;   ///< M68K architecture
        mips: struct {}, // cs_mips;   ///< MIPS architecture
        ppc: struct {}, // cs_ppc;      ///< PowerPC architecture
        sparc: struct {}, // cs_sparc; ///< Sparc architecture
        sysz: struct {}, // cs_sysz;   ///< SystemZ architecture
        xcore: struct {}, // cs_xcore; ///< XCore architecture
        tms320c64x: struct {}, // cs_tms320c64x;  ///< TMS320C64x architecture
        m680x: struct {}, // cs_m680x; ///< M680X architecture
        evm: struct {}, // cs_evm;      ///< Ethereum architecture
        mos65xx: struct {}, // cs_mos65xx;  ///< MOS65XX architecture (including MOS6502)
        wasm: struct {}, // cs_wasm;  ///< Web Assembly architecture
        bpf: struct {}, // cs_bpf;  ///< Berkeley Packet Filter architecture (including eBPF)
        riscv: struct {}, // cs_riscv; ///< RISCV architecture
        sh: struct {}, // cs_sh;        ///< SH architecture
        tricore: struct {}, // cs_tricore; ///< TriCore architecture
    };
};

pub const x86_reg = c_uint;
pub const X86_OP_INVALID: c_int = 0;
pub const X86_OP_REG: c_int = 1;
pub const X86_OP_IMM: c_int = 2;
pub const X86_OP_MEM: c_int = 3;

pub const X86_GRP_INVALID: c_int = 0;
pub const X86_GRP_JUMP: c_int = 1;
pub const X86_GRP_CALL: c_int = 2;
pub const X86_GRP_RET: c_int = 3;
pub const X86_GRP_INT: c_int = 4;
pub const X86_GRP_IRET: c_int = 5;
pub const X86_GRP_PRIVILEGE: c_int = 6;
pub const X86_GRP_BRANCH_RELATIVE: c_int = 7;

pub const X86_INS_INT: c_int = 238;
pub const X86_INS_INT1: c_int = 239;
pub const X86_INS_INT3: c_int = 240;
pub const X86_INS_MOV: c_int = 460;
pub const X86_INS_MOVD: c_int = 377;

pub const x86_xop_cc = c_uint;
pub const x86_sse_cc = c_uint;
pub const x86_avx_cc = c_uint;
pub const x86_avx_rm = c_uint;
pub const x86_op_type = c_uint;
pub const x86_avx_bcast = c_uint;

pub const ArchInstructionInfo_x86 = extern struct {
    prefix: [4]u8 = @import("std").mem.zeroes([4]u8),
    opcode: [4]u8 = @import("std").mem.zeroes([4]u8),
    rex: u8 = @import("std").mem.zeroes(u8),
    addr_size: u8 = @import("std").mem.zeroes(u8),
    modrm: u8 = @import("std").mem.zeroes(u8),
    sib: u8 = @import("std").mem.zeroes(u8),
    disp: i64 = @import("std").mem.zeroes(i64),
    sib_index: x86_reg = @import("std").mem.zeroes(x86_reg),
    sib_scale: i8 = @import("std").mem.zeroes(i8),
    sib_base: x86_reg = @import("std").mem.zeroes(x86_reg),
    xop_cc: x86_xop_cc = @import("std").mem.zeroes(x86_xop_cc),
    sse_cc: x86_sse_cc = @import("std").mem.zeroes(x86_sse_cc),
    avx_cc: x86_avx_cc = @import("std").mem.zeroes(x86_avx_cc),
    avx_sae: bool = @import("std").mem.zeroes(bool),
    avx_rm: x86_avx_rm = @import("std").mem.zeroes(x86_avx_rm),
    u: extern union {
        eflags: u64,
        fpu_flags: u64,
    },
    op_count: u8 = @import("std").mem.zeroes(u8),
    operands: [8]cs_x86_op = @import("std").mem.zeroes([8]cs_x86_op),
    encoding: cs_x86_encoding = @import("std").mem.zeroes(cs_x86_encoding),
};

pub const cs_x86_op = extern struct {
    type: x86_op_type = @import("std").mem.zeroes(x86_op_type),
    u: extern union {
        reg: x86_reg,
        imm: i64,
        mem: x86_op_mem,
    },
    size: u8 = @import("std").mem.zeroes(u8),
    access: u8 = @import("std").mem.zeroes(u8),
    avx_bcast: x86_avx_bcast = @import("std").mem.zeroes(x86_avx_bcast),
    avx_zero_opmask: bool = @import("std").mem.zeroes(bool),
};

pub const cs_x86_encoding = extern struct {
    modrm_offset: u8 = @import("std").mem.zeroes(u8),
    disp_offset: u8 = @import("std").mem.zeroes(u8),
    disp_size: u8 = @import("std").mem.zeroes(u8),
    imm_offset: u8 = @import("std").mem.zeroes(u8),
    imm_size: u8 = @import("std").mem.zeroes(u8),
};

const x86_op_mem = extern struct {
    segment: x86_reg = @import("std").mem.zeroes(x86_reg),
    base: x86_reg = @import("std").mem.zeroes(x86_reg),
    index: x86_reg = @import("std").mem.zeroes(x86_reg),
    scale: c_int = @import("std").mem.zeroes(c_int),
    disp: i64 = @import("std").mem.zeroes(i64),
};

pub const Handle = usize;
pub extern fn cs_open(arch: Arch, mode: Mode, handle: *Handle) Error;
pub extern fn cs_option(handle: Handle, type: OptionType, value: usize) Error;
pub extern fn cs_disasm(handle: Handle, code: [*]const u8, code_size: usize, address: u64, count: usize, insn: *[*]Instruction) usize;
pub extern fn cs_free(insn: [*]Instruction, count: usize) void;
pub extern fn cs_close(handle: *Handle) Error;
pub extern fn cs_strerror(code: Error) [*:0]const u8;

pub const Error = enum(c_int) {
    ok = 0, // No error: everything was fine
    mem, // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    arch, // Unsupported architecture: cs_open()
    handle, // Invalid handle: cs_op_count(), cs_op_index()
    csh, // Invalid csh argument: cs_close(), cs_errno(), cs_option()
    mode, // Invalid/unsupported mode: cs_open()
    option, // Invalid/unsupported option: cs_option()
    detail, // Information is unavailable because detail option is OFF
    memsetup, // Dynamic memory management uninitialized (see CS_OPT_MEM)
    version, // Unsupported version (bindings)
    diet, // Access irrelevant data in "diet" engine
    skipdata, // Access irrelevant data for "data" instruction in SKIPDATA mode
    x86_att, // X86 AT&T syntax is unsupported (opt-out at compile time)
    x86_intel, // X86 Intel syntax is unsupported (opt-out at compile time)
    x86_masm, // X86 Intel syntax is unsupported (opt-out at compile time)
};

pub const X86_REG_INVALID: c_int = 0;
pub const X86_REG_AH: c_int = 1;
pub const X86_REG_AL: c_int = 2;
pub const X86_REG_AX: c_int = 3;
pub const X86_REG_BH: c_int = 4;
pub const X86_REG_BL: c_int = 5;
pub const X86_REG_BP: c_int = 6;
pub const X86_REG_BPL: c_int = 7;
pub const X86_REG_BX: c_int = 8;
pub const X86_REG_CH: c_int = 9;
pub const X86_REG_CL: c_int = 10;
pub const X86_REG_CS: c_int = 11;
pub const X86_REG_CX: c_int = 12;
pub const X86_REG_DH: c_int = 13;
pub const X86_REG_DI: c_int = 14;
pub const X86_REG_DIL: c_int = 15;
pub const X86_REG_DL: c_int = 16;
pub const X86_REG_DS: c_int = 17;
pub const X86_REG_DX: c_int = 18;
pub const X86_REG_EAX: c_int = 19;
pub const X86_REG_EBP: c_int = 20;
pub const X86_REG_EBX: c_int = 21;
pub const X86_REG_ECX: c_int = 22;
pub const X86_REG_EDI: c_int = 23;
pub const X86_REG_EDX: c_int = 24;
pub const X86_REG_EFLAGS: c_int = 25;
pub const X86_REG_EIP: c_int = 26;
pub const X86_REG_EIZ: c_int = 27;
pub const X86_REG_ES: c_int = 28;
pub const X86_REG_ESI: c_int = 29;
pub const X86_REG_ESP: c_int = 30;
pub const X86_REG_FPSW: c_int = 31;
pub const X86_REG_FS: c_int = 32;
pub const X86_REG_GS: c_int = 33;
pub const X86_REG_IP: c_int = 34;
pub const X86_REG_RAX: c_int = 35;
pub const X86_REG_RBP: c_int = 36;
pub const X86_REG_RBX: c_int = 37;
pub const X86_REG_RCX: c_int = 38;
pub const X86_REG_RDI: c_int = 39;
pub const X86_REG_RDX: c_int = 40;
pub const X86_REG_RIP: c_int = 41;
pub const X86_REG_RIZ: c_int = 42;
pub const X86_REG_RSI: c_int = 43;
pub const X86_REG_RSP: c_int = 44;
pub const X86_REG_SI: c_int = 45;
pub const X86_REG_SIL: c_int = 46;
pub const X86_REG_SP: c_int = 47;
pub const X86_REG_SPL: c_int = 48;
pub const X86_REG_SS: c_int = 49;
pub const X86_REG_CR0: c_int = 50;
pub const X86_REG_CR1: c_int = 51;
pub const X86_REG_CR2: c_int = 52;
pub const X86_REG_CR3: c_int = 53;
pub const X86_REG_CR4: c_int = 54;
pub const X86_REG_CR5: c_int = 55;
pub const X86_REG_CR6: c_int = 56;
pub const X86_REG_CR7: c_int = 57;
pub const X86_REG_CR8: c_int = 58;
pub const X86_REG_CR9: c_int = 59;
pub const X86_REG_CR10: c_int = 60;
pub const X86_REG_CR11: c_int = 61;
pub const X86_REG_CR12: c_int = 62;
pub const X86_REG_CR13: c_int = 63;
pub const X86_REG_CR14: c_int = 64;
pub const X86_REG_CR15: c_int = 65;
pub const X86_REG_DR0: c_int = 66;
pub const X86_REG_DR1: c_int = 67;
pub const X86_REG_DR2: c_int = 68;
pub const X86_REG_DR3: c_int = 69;
pub const X86_REG_DR4: c_int = 70;
pub const X86_REG_DR5: c_int = 71;
pub const X86_REG_DR6: c_int = 72;
pub const X86_REG_DR7: c_int = 73;
pub const X86_REG_DR8: c_int = 74;
pub const X86_REG_DR9: c_int = 75;
pub const X86_REG_DR10: c_int = 76;
pub const X86_REG_DR11: c_int = 77;
pub const X86_REG_DR12: c_int = 78;
pub const X86_REG_DR13: c_int = 79;
pub const X86_REG_DR14: c_int = 80;
pub const X86_REG_DR15: c_int = 81;
pub const X86_REG_FP0: c_int = 82;
pub const X86_REG_FP1: c_int = 83;
pub const X86_REG_FP2: c_int = 84;
pub const X86_REG_FP3: c_int = 85;
pub const X86_REG_FP4: c_int = 86;
pub const X86_REG_FP5: c_int = 87;
pub const X86_REG_FP6: c_int = 88;
pub const X86_REG_FP7: c_int = 89;
pub const X86_REG_K0: c_int = 90;
pub const X86_REG_K1: c_int = 91;
pub const X86_REG_K2: c_int = 92;
pub const X86_REG_K3: c_int = 93;
pub const X86_REG_K4: c_int = 94;
pub const X86_REG_K5: c_int = 95;
pub const X86_REG_K6: c_int = 96;
pub const X86_REG_K7: c_int = 97;
pub const X86_REG_MM0: c_int = 98;
pub const X86_REG_MM1: c_int = 99;
pub const X86_REG_MM2: c_int = 100;
pub const X86_REG_MM3: c_int = 101;
pub const X86_REG_MM4: c_int = 102;
pub const X86_REG_MM5: c_int = 103;
pub const X86_REG_MM6: c_int = 104;
pub const X86_REG_MM7: c_int = 105;
pub const X86_REG_R8: c_int = 106;
pub const X86_REG_R9: c_int = 107;
pub const X86_REG_R10: c_int = 108;
pub const X86_REG_R11: c_int = 109;
pub const X86_REG_R12: c_int = 110;
pub const X86_REG_R13: c_int = 111;
pub const X86_REG_R14: c_int = 112;
pub const X86_REG_R15: c_int = 113;
pub const X86_REG_ST0: c_int = 114;
pub const X86_REG_ST1: c_int = 115;
pub const X86_REG_ST2: c_int = 116;
pub const X86_REG_ST3: c_int = 117;
pub const X86_REG_ST4: c_int = 118;
pub const X86_REG_ST5: c_int = 119;
pub const X86_REG_ST6: c_int = 120;
pub const X86_REG_ST7: c_int = 121;
pub const X86_REG_XMM0: c_int = 122;
pub const X86_REG_XMM1: c_int = 123;
pub const X86_REG_XMM2: c_int = 124;
pub const X86_REG_XMM3: c_int = 125;
pub const X86_REG_XMM4: c_int = 126;
pub const X86_REG_XMM5: c_int = 127;
pub const X86_REG_XMM6: c_int = 128;
pub const X86_REG_XMM7: c_int = 129;
pub const X86_REG_XMM8: c_int = 130;
pub const X86_REG_XMM9: c_int = 131;
pub const X86_REG_XMM10: c_int = 132;
pub const X86_REG_XMM11: c_int = 133;
pub const X86_REG_XMM12: c_int = 134;
pub const X86_REG_XMM13: c_int = 135;
pub const X86_REG_XMM14: c_int = 136;
pub const X86_REG_XMM15: c_int = 137;
pub const X86_REG_XMM16: c_int = 138;
pub const X86_REG_XMM17: c_int = 139;
pub const X86_REG_XMM18: c_int = 140;
pub const X86_REG_XMM19: c_int = 141;
pub const X86_REG_XMM20: c_int = 142;
pub const X86_REG_XMM21: c_int = 143;
pub const X86_REG_XMM22: c_int = 144;
pub const X86_REG_XMM23: c_int = 145;
pub const X86_REG_XMM24: c_int = 146;
pub const X86_REG_XMM25: c_int = 147;
pub const X86_REG_XMM26: c_int = 148;
pub const X86_REG_XMM27: c_int = 149;
pub const X86_REG_XMM28: c_int = 150;
pub const X86_REG_XMM29: c_int = 151;
pub const X86_REG_XMM30: c_int = 152;
pub const X86_REG_XMM31: c_int = 153;
pub const X86_REG_YMM0: c_int = 154;
pub const X86_REG_YMM1: c_int = 155;
pub const X86_REG_YMM2: c_int = 156;
pub const X86_REG_YMM3: c_int = 157;
pub const X86_REG_YMM4: c_int = 158;
pub const X86_REG_YMM5: c_int = 159;
pub const X86_REG_YMM6: c_int = 160;
pub const X86_REG_YMM7: c_int = 161;
pub const X86_REG_YMM8: c_int = 162;
pub const X86_REG_YMM9: c_int = 163;
pub const X86_REG_YMM10: c_int = 164;
pub const X86_REG_YMM11: c_int = 165;
pub const X86_REG_YMM12: c_int = 166;
pub const X86_REG_YMM13: c_int = 167;
pub const X86_REG_YMM14: c_int = 168;
pub const X86_REG_YMM15: c_int = 169;
pub const X86_REG_YMM16: c_int = 170;
pub const X86_REG_YMM17: c_int = 171;
pub const X86_REG_YMM18: c_int = 172;
pub const X86_REG_YMM19: c_int = 173;
pub const X86_REG_YMM20: c_int = 174;
pub const X86_REG_YMM21: c_int = 175;
pub const X86_REG_YMM22: c_int = 176;
pub const X86_REG_YMM23: c_int = 177;
pub const X86_REG_YMM24: c_int = 178;
pub const X86_REG_YMM25: c_int = 179;
pub const X86_REG_YMM26: c_int = 180;
pub const X86_REG_YMM27: c_int = 181;
pub const X86_REG_YMM28: c_int = 182;
pub const X86_REG_YMM29: c_int = 183;
pub const X86_REG_YMM30: c_int = 184;
pub const X86_REG_YMM31: c_int = 185;
pub const X86_REG_ZMM0: c_int = 186;
pub const X86_REG_ZMM1: c_int = 187;
pub const X86_REG_ZMM2: c_int = 188;
pub const X86_REG_ZMM3: c_int = 189;
pub const X86_REG_ZMM4: c_int = 190;
pub const X86_REG_ZMM5: c_int = 191;
pub const X86_REG_ZMM6: c_int = 192;
pub const X86_REG_ZMM7: c_int = 193;
pub const X86_REG_ZMM8: c_int = 194;
pub const X86_REG_ZMM9: c_int = 195;
pub const X86_REG_ZMM10: c_int = 196;
pub const X86_REG_ZMM11: c_int = 197;
pub const X86_REG_ZMM12: c_int = 198;
pub const X86_REG_ZMM13: c_int = 199;
pub const X86_REG_ZMM14: c_int = 200;
pub const X86_REG_ZMM15: c_int = 201;
pub const X86_REG_ZMM16: c_int = 202;
pub const X86_REG_ZMM17: c_int = 203;
pub const X86_REG_ZMM18: c_int = 204;
pub const X86_REG_ZMM19: c_int = 205;
pub const X86_REG_ZMM20: c_int = 206;
pub const X86_REG_ZMM21: c_int = 207;
pub const X86_REG_ZMM22: c_int = 208;
pub const X86_REG_ZMM23: c_int = 209;
pub const X86_REG_ZMM24: c_int = 210;
pub const X86_REG_ZMM25: c_int = 211;
pub const X86_REG_ZMM26: c_int = 212;
pub const X86_REG_ZMM27: c_int = 213;
pub const X86_REG_ZMM28: c_int = 214;
pub const X86_REG_ZMM29: c_int = 215;
pub const X86_REG_ZMM30: c_int = 216;
pub const X86_REG_ZMM31: c_int = 217;
pub const X86_REG_R8B: c_int = 218;
pub const X86_REG_R9B: c_int = 219;
pub const X86_REG_R10B: c_int = 220;
pub const X86_REG_R11B: c_int = 221;
pub const X86_REG_R12B: c_int = 222;
pub const X86_REG_R13B: c_int = 223;
pub const X86_REG_R14B: c_int = 224;
pub const X86_REG_R15B: c_int = 225;
pub const X86_REG_R8D: c_int = 226;
pub const X86_REG_R9D: c_int = 227;
pub const X86_REG_R10D: c_int = 228;
pub const X86_REG_R11D: c_int = 229;
pub const X86_REG_R12D: c_int = 230;
pub const X86_REG_R13D: c_int = 231;
pub const X86_REG_R14D: c_int = 232;
pub const X86_REG_R15D: c_int = 233;
pub const X86_REG_R8W: c_int = 234;
pub const X86_REG_R9W: c_int = 235;
pub const X86_REG_R10W: c_int = 236;
pub const X86_REG_R11W: c_int = 237;
pub const X86_REG_R12W: c_int = 238;
pub const X86_REG_R13W: c_int = 239;
pub const X86_REG_R14W: c_int = 240;
pub const X86_REG_R15W: c_int = 241;
pub const X86_REG_BND0: c_int = 242;
pub const X86_REG_BND1: c_int = 243;
pub const X86_REG_BND2: c_int = 244;
pub const X86_REG_BND3: c_int = 245;
