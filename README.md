# TRIPROT Protector ≽^•⩊•^≼

TRIPROT transforms Windows x64 executables through a systematic protection pipeline:

1. **Shellcode Conversion** - Transforms input PE into position-independent shellcode using Donut
   - *Xpress Compression + Symmetric Encryption applied during this step*
3. **Polymorphic Encoding Layer** - Applies SGN encoding to obfuscate the payload polymorphically
4. **Custom Shellcode Loader** - Generates a C++ stub with a randomized executable section name
   - *This section is marked RX (to avoid requesting executable memory permissions during runtime)*
5. **Compilation** - Compiles the protected executable with LTCG

## Features?

- Uses EnumMetaFile callback for shellcode execution. I've found reference to this is literature but never a PoC
- Data validation of payload (will not execute if payload has been modified)
- Customizable args for use across different environments
- x64 Onlu

## Usage

```bash
python triprot.py -i "input.exe" -o "protected.exe"
```
Please launch form a x64 msvc developer cmd so it may have access to cl.

### Command Line Options

```
-i, --input       Input x64 executable (.exe) to protect
-o, --output      Output path for the protected executable
--donut           Custom Donut path (default: ./Utils/E2S.X)
--sgn             Custom SGN path (default: ./Utils/SGN.X)
--compiler        Custom compiler path (default: cl.exe)
--keep-temp       Keep temporary files for analysis
```

## Requirements

- **MUST be run from a Visual Studio Developer Command Prompt**
- Python 3.6+
- x64 executables only (32-bit not supported)
