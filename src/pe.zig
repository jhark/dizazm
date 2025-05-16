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
    Machine: u16,
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
