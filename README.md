# TriProt PE Protector / Crypter

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Language](https://img.shields.io/badge/language-Python-yellow)

## Overview

TriProt is a specialized utility designed to protect Windows PE executables. It functions through a three-stage pipeline:

1. **Donut (E2S.X)**: Converts your PE executable into position-independent shellcode
   - Utilizes symmetric encryption and express compression
3. **SGN (SGN.X)**: Applies advanced encoding to the shellcode
5. **C++ Stub**: Compiles a custom loader for the protected payload

## Important Note

This project is open source, you *may* have to modify the stub within TriProt.py to achieve better detection results.
Use x64 executables as input. 32 bit does not work.

## Features

-  **Complete Protection Pipeline**: Handles all conversion steps in a single command
-  **Streamlined Process**: Automatic temporary file management
-  **DbgHelp Execution**: Uses SymEnumProcesses callback technique for shellcode execution


## Requirements

- Windows Operating System
- Visual Studio (with C++ compiler) or Visual C++ Build Tools
- Python 3.6+


## Usage

Run the python script from a Visual Studio Developer Command Prompt to ensure the C++ environment variables are properly set.

```
python TriProt.py -i "Input.exe" -o "Ouput.exe"
```

Output:
```
[*] Starting PE Protector...
[*] Developer environment check passed.
[*] Using temp directory: C:\Users\user\AppData\Local\Temp\tmp123abc
[*] Running Donut (E2S.X)...
[+] Donut processing complete.
[*] Running SGN...
[+] SGN processing complete.
[*] Reading SGN encoded shellcode...
[*] Read 24680 bytes.
[*] Step 4: Generating C++ stub...
[*] Step 5: Writing stub to file...
[*] Stub written to C:\Users\user\AppData\Local\Temp\tmp123abc\stub.cpp
[*] Step 6: Compiling C++ stub...
[+] Compilation complete.
[+] ----------------------------------------
[+] Protected executable created successfully!
[+] Output: C:\path\to\Protected_MyApplication.exe
[+] Total time: 3.45 seconds
[+] ----------------------------------------
[*] Cleaning up temporary files...
[*] Removed 3 file(s).
[*] Removed temporary directory.
```

## Disclaimer

This tool is provided for educational and legitimate software protection purposes only. Users are responsible for ensuring they comply with all applicable laws and regulations when using this software.
