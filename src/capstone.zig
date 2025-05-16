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
    detail: ?*const anyopaque,
};

// #define MAX_IMPL_W_REGS 20
// #define MAX_IMPL_R_REGS 20
// #define MAX_NUM_GROUPS 8

// /// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
// /// Initialized as memset(., 0, offsetof(cs_detail, ARCH)+sizeof(cs_ARCH))
// /// by ARCH_getInstruction in arch/ARCH/ARCHDisassembler.c
// /// if cs_detail changes, in particular if a field is added after the union,
// /// then update arch/ARCH/ARCHDisassembler.c accordingly
// typedef struct cs_detail {
//   uint16_t regs_read
//     [MAX_IMPL_R_REGS]; ///< list of implicit registers read by this insn
//   uint8_t regs_read_count; ///< number of implicit registers read by this insn

//   uint16_t regs_write
//     [MAX_IMPL_W_REGS]; ///< list of implicit registers modified by this insn
//   uint8_t regs_write_count; ///< number of implicit registers modified by this insn

//   uint8_t groups[MAX_NUM_GROUPS]; ///< list of group this instruction belong to
//   uint8_t groups_count; ///< number of groups this insn belongs to

//   bool writeback;        ///< Instruction has writeback operands.

//   /// Architecture-specific instruction info
//   union {
//     cs_x86 x86;     ///< X86 architecture, including 16-bit, 32-bit & 64-bit mode
//     cs_arm64 arm64; ///< ARM64 architecture (aka AArch64)
//     cs_arm arm;     ///< ARM architecture (including Thumb/Thumb2)
//     cs_m68k m68k;   ///< M68K architecture
//     cs_mips mips;   ///< MIPS architecture
//     cs_ppc ppc;      ///< PowerPC architecture
//     cs_sparc sparc; ///< Sparc architecture
//     cs_sysz sysz;   ///< SystemZ architecture
//     cs_xcore xcore; ///< XCore architecture
//     cs_tms320c64x tms320c64x;  ///< TMS320C64x architecture
//     cs_m680x m680x; ///< M680X architecture
//     cs_evm evm;      ///< Ethereum architecture
//     cs_mos65xx mos65xx;  ///< MOS65XX architecture (including MOS6502)
//     cs_wasm wasm;  ///< Web Assembly architecture
//     cs_bpf bpf;  ///< Berkeley Packet Filter architecture (including eBPF)
//     cs_riscv riscv; ///< RISCV architecture
//     cs_sh sh;        ///< SH architecture
//     cs_tricore tricore; ///< TriCore architecture
//   };
// } cs_detail;

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
