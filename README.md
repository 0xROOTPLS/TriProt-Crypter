# TRIPROT Protector ≽^•⩊•^≼

TRIPROT transforms Windows x64 executables through a systematic protection pipeline:

1. **Shellcode Conversion** - Transforms input PE into position-independent shellcode using Donut
   - *Xpress Compression + Symmetric Encryption applied during this step*
3. **Polymorphic Encoding Layer** - Applies SGN encoding to obfuscate the payload polymorphically
4. **Custom Shellcode Loader** - Generates a C++ stub with a randomized executable section name
   - *This section is marked X (to avoid requesting executable memory permissions during runtime)*
5. **Compilation** - Compiles the protected executable with LTCG

## Features?

- Not much, it just takes an input and then protects your files from AV.
- The three different py scripts operate the same, but offer different execution methods.

## Usage

```bash
python triprot.py -i "input.exe" -o "protected.exe"
```

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
