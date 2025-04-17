# TRIPROT Protector

TRIPROT transforms Windows x64 executables through a systematic protection pipeline:

1. **Shellcode Conversion** - Transforms input PE into position-independent shellcode using Donut
2. **Encryption Layer** - Applies SGN encoding to obfuscate the payload polymorphically
3. **Custom Loader** - Generates a C++ stub with a randomized executable section name
4. **Compilation** - Compiles the protected executable with LTCG

## Features

- Creates a randomly-named RWX section to store the encoded payload
- Executes the payload indirectly through DbgHelp API callbacks
- Completely eliminates the original PE structure and import table

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
