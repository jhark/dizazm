// Windows Portable Executable File Format.
//
// References:
//
//   * winnt.h
//   * https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: IMAGE_FILE_MACHINE,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    PhysicalAddress: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

pub const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    u: extern union {
        Characteristics: u32, // 0 for terminating null import descriptor
        OriginalFirstThunk: u32, // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    },

    // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)
    TimeDateStamp: u32,

    // -1 if no forwarders
    ForwarderChain: u32,

    Name: u32, // RVA to name of dll.

    // RVA to IAT (if bound this IAT has actual addresses)
    FirstThunk: u32, // Array of IMAGE_THUNK_DATA64
};

pub const IMAGE_THUNK_DATA64 = extern struct {
    u: extern union {
        // PBYTE
        ForwarderString: u64,

        // Active after binding. Address of function.
        Function: u64,

        // Active before binding if the ordinal flag is set.
        Ordinal: u64,

        // Active before binding if the ordinal flag is not set.
        // RVA to IMAGE_IMPORT_BY_NAME.
        AddressOfData: u64,
    },

    pub inline fn isOrdinal(self: IMAGE_THUNK_DATA64) bool {
        return (self.u.Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
    }

    pub inline fn asOrdinal(self: IMAGE_THUNK_DATA64) u16 {
        if (!self.isOrdinal()) {
            @panic("Not an ordinal");
        }
        return @truncate(self.u.Ordinal);
    }
};

pub const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;
pub const IMAGE_ORDINAL_FLAG32 = 0x80000000;

pub const IMAGE_IMPORT_BY_NAME = extern struct {
    Hint: u16, // Possible ordinal.
    Name: [1]u8, // Null-terminated name.

    pub inline fn name(self: *const IMAGE_IMPORT_BY_NAME) [*:0]const u8 {
        return @ptrCast(&self.Name);
    }
};

pub const IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ

pub const IMAGE_FILE_RELOCS_STRIPPED = 0x0001; // Relocation info stripped from file.
pub const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002; // File is executable  (i.e. no unresolved external references).
pub const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004; // Line nunbers stripped from file.
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008; // Local symbols stripped from file.
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010; // Aggressively trim working set
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020; // App can handle >2gb addresses
pub const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080; // Bytes of machine word are reversed.
pub const IMAGE_FILE_32BIT_MACHINE = 0x0100; // 32 bit word machine.
pub const IMAGE_FILE_DEBUG_STRIPPED = 0x0200; // Debugging info stripped from file in .DBG file
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400; // If Image is on removable media, copy and run from the swap file.
pub const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800; // If Image is on Net, copy and run from the swap file.
pub const IMAGE_FILE_SYSTEM = 0x1000; // System File.
pub const IMAGE_FILE_DLL = 0x2000; // File is a DLL.
pub const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000; // File should only be run on a UP machine
pub const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000; // Bytes of machine word are reversed.

pub const IMAGE_FILE_MACHINE_UNKNOWN = 0;
pub const IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001; // Useful for indicating we want to interact with the host and not a WoW guest.
pub const IMAGE_FILE_MACHINE_I386 = 0x014c; // Intel 386.
pub const IMAGE_FILE_MACHINE_R3000 = 0x0162; // MIPS little-endian, 0x160 big-endian
pub const IMAGE_FILE_MACHINE_R4000 = 0x0166; // MIPS little-endian
pub const IMAGE_FILE_MACHINE_R10000 = 0x0168; // MIPS little-endian
pub const IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169; // MIPS little-endian WCE v2
pub const IMAGE_FILE_MACHINE_ALPHA = 0x0184; // Alpha_AXP
pub const IMAGE_FILE_MACHINE_SH3 = 0x01a2; // SH3 little-endian
pub const IMAGE_FILE_MACHINE_SH3DSP = 0x01a3;
pub const IMAGE_FILE_MACHINE_SH3E = 0x01a4; // SH3E little-endian
pub const IMAGE_FILE_MACHINE_SH4 = 0x01a6; // SH4 little-endian
pub const IMAGE_FILE_MACHINE_SH5 = 0x01a8; // SH5
pub const IMAGE_FILE_MACHINE_ARM = 0x01c0; // ARM Little-Endian
pub const IMAGE_FILE_MACHINE_THUMB = 0x01c2; // ARM Thumb/Thumb-2 Little-Endian
pub const IMAGE_FILE_MACHINE_ARMNT = 0x01c4; // ARM Thumb-2 Little-Endian
pub const IMAGE_FILE_MACHINE_AM33 = 0x01d3;
pub const IMAGE_FILE_MACHINE_POWERPC = 0x01F0; // IBM PowerPC Little-Endian
pub const IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1;
pub const IMAGE_FILE_MACHINE_IA64 = 0x0200; // Intel 64
pub const IMAGE_FILE_MACHINE_MIPS16 = 0x0266; // MIPS
pub const IMAGE_FILE_MACHINE_ALPHA64 = 0x0284; // ALPHA64
pub const IMAGE_FILE_MACHINE_MIPSFPU = 0x0366; // MIPS
pub const IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466; // MIPS
pub const IMAGE_FILE_MACHINE_AXP64 = IMAGE_FILE_MACHINE_ALPHA64;
pub const IMAGE_FILE_MACHINE_TRICORE = 0x0520; // Infineon
pub const IMAGE_FILE_MACHINE_CEF = 0x0CEF;
pub const IMAGE_FILE_MACHINE_EBC = 0x0EBC; // EFI Byte Code
pub const IMAGE_FILE_MACHINE_AMD64 = 0x8664; // AMD64 (K8)
pub const IMAGE_FILE_MACHINE_M32R = 0x9041; // M32R little-endian
pub const IMAGE_FILE_MACHINE_ARM64 = 0xAA64; // ARM64 Little-Endian
pub const IMAGE_FILE_MACHINE_CEE = 0xC0EE;

pub const IMAGE_FILE_MACHINE = enum(u16) {
    unknown = IMAGE_FILE_MACHINE_UNKNOWN,
    target_host = IMAGE_FILE_MACHINE_TARGET_HOST,
    i386 = IMAGE_FILE_MACHINE_I386,
    r3000 = IMAGE_FILE_MACHINE_R3000,
    r4000 = IMAGE_FILE_MACHINE_R4000,
    r10000 = IMAGE_FILE_MACHINE_R10000,
    wcemipsv2 = IMAGE_FILE_MACHINE_WCEMIPSV2,
    alpha = IMAGE_FILE_MACHINE_ALPHA,
    sh3 = IMAGE_FILE_MACHINE_SH3,
    sh3dsp = IMAGE_FILE_MACHINE_SH3DSP,
    sh3e = IMAGE_FILE_MACHINE_SH3E,
    sh4 = IMAGE_FILE_MACHINE_SH4,
    sh5 = IMAGE_FILE_MACHINE_SH5,
    arm = IMAGE_FILE_MACHINE_ARM,
    thumb = IMAGE_FILE_MACHINE_THUMB,
    armnt = IMAGE_FILE_MACHINE_ARMNT,
    am33 = IMAGE_FILE_MACHINE_AM33,
    powerpc = IMAGE_FILE_MACHINE_POWERPC,
    powerpcfp = IMAGE_FILE_MACHINE_POWERPCFP,
    ia64 = IMAGE_FILE_MACHINE_IA64,
    mips16 = IMAGE_FILE_MACHINE_MIPS16,
    alpha64 = IMAGE_FILE_MACHINE_ALPHA64,
    mipsfpu = IMAGE_FILE_MACHINE_MIPSFPU,
    mipsfpu16 = IMAGE_FILE_MACHINE_MIPSFPU16,
    // IMAGE_FILE_MACHINE_AXP64 = IMAGE_FILE_MACHINE_AXP64, // === IMAGE_FILE_MACHINE_ALPHA64
    tricore = IMAGE_FILE_MACHINE_TRICORE,
    cef = IMAGE_FILE_MACHINE_CEF,
    ebc = IMAGE_FILE_MACHINE_EBC,
    amd64 = IMAGE_FILE_MACHINE_AMD64,
    m32r = IMAGE_FILE_MACHINE_M32R,
    arm64 = IMAGE_FILE_MACHINE_ARM64,
    cee = IMAGE_FILE_MACHINE_CEE,
    _,
};
