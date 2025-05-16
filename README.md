# dizazm

A command-line tool for Windows that disassembles symbols in PE files.

Uses [Capstone](https://www.capstone-engine.org/) and [dbghelp.dll](https://learn.microsoft.com/en-us/windows/win32/debug/debug-help-library).

## Requirements

- Windows.
- Zig compiler (version 0.14.0)

## Building

```sh
zig build
```

## Usage

```
Usage: dizazm [-s | --symbol <symbol>] [-a | --address <address>]
              [-l | --length <length>] [-b | --bytes] [-h | --help] <IMAGE_PATH>

Disassembles a specified symbol from a Portable Executable (PE) file (.exe, .dll).

Example:
  dizazm -s CreateFileW kernel32.dll

Options:

  -s, --symbol  The name of the symbol to disassemble
  -a, --address The address to disassemble (e.g., 0x1000)
  -l, --length  Number of bytes to disassemble
  -b, --bytes   Print raw instruction bytes
  -h, --help    Show this help and exit

Arguments:

  <IMAGE_PATH>

```

Note: For dbghelp support you will need to place dbghelp.dll (and optionally symsrv.dll) in the same directory as dizazm.exe. You can get these from the [Windows Debugging Tools](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools). The DLL is loaded on demand, so dizazm will work without it, but only be able to find symbols in the export table.

If symsrv.dll is made available then you may also specify a symbol path via `_NT_SYMBOL_PATH` see [Using SymSrv](https://learn.microsoft.com/en-us/windows/win32/debug/using-symsrv).

E.g. `_NT_SYMBOL_PATH="srv*https://msdl.microsoft.com/download/symbols"`.

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details. 