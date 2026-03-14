"""
Upload, convert, and analyze VCD files.
Fixed for PyInstaller: uses runpy instead of subprocess.
"""
import os
import sys
import json
import shutil
import runpy
import io
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime

from file_manager import get_or_create_user, save_vcd_file
from vcd_converter import convert_vcd_to_json_csv
from clock_estimation import estimate_first_chunk_cycles


# ============================================================
# BASE OUTPUT (single source of truth)
# ============================================================
# -- FIX: Use WAVEEYE_WORKSPACE env var if available (set by main.py),
#    otherwise fall back to ~/WaveEye/outputs --

_workspace = os.environ.get('WAVEEYE_WORKSPACE',
                            os.path.join(os.path.expanduser("~"), "WaveEye"))
BASE_OUTPUT_DIR = os.path.join(_workspace, "outputs")
os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)

UPLOAD_SOURCE_DIR = BASE_OUTPUT_DIR
RUN_LOG_FILE = os.path.join(BASE_OUTPUT_DIR, "run_history.json")


# ============================================================
# SCRIPT DIRECTORY (PyInstaller-safe)
# ============================================================

def _get_script_dir():
    """Get directory containing this script (for finding sibling scripts)."""
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        # Fallback: check env var
        bundle_dir = os.environ.get('WAVEEYE_BUNDLE_DIR')
        if bundle_dir:
            return os.path.join(bundle_dir, "Preprocessing", "vcd")
        return os.getcwd()

SCRIPT_DIR = _get_script_dir()


# ============================================================
# HELPERS
# ============================================================

def get_latest_vcd():
    vcd_files = [
        os.path.join(UPLOAD_SOURCE_DIR, f)
        for f in os.listdir(UPLOAD_SOURCE_DIR)
        if f.lower().endswith(".vcd")
    ]
    if not vcd_files:
        raise FileNotFoundError("No .vcd files found.")
    return max(vcd_files, key=os.path.getmtime)


def save_rtl_and_uvm_testbench_files(user_id, source_dir=UPLOAD_SOURCE_DIR, dest_base_dir=None):
    username = f"{user_id}A"
    dest_dir = os.path.join(dest_base_dir, username)
    os.makedirs(dest_dir, exist_ok=True)

    rtl_files = []
    tb_files = []
    tb_keywords = [
        "tb", "testbench", "driver", "monitor", "agent",
        "env", "sequence", "scoreboard", "test", "uvm"
    ]

    for filename in os.listdir(source_dir):
        if filename.lower().endswith((".v", ".sv")):
            if any(kw in filename.lower() for kw in tb_keywords):
                tb_files.append(filename)
            else:
                rtl_files.append(filename)

    saved_files = []

    for filename in rtl_files + tb_files:
        src = os.path.join(source_dir, filename)
        dst = os.path.join(dest_base_dir, f"{user_id}A", filename)
        try:
            shutil.copy2(src, dst)
            saved_files.append(dst)
            print("Saved file:", dst)
        except Exception as e:
            print("Failed to save", filename, "Error:", e)

    return rtl_files, tb_files, saved_files


def log_run(entry):
    try:
        if os.path.exists(RUN_LOG_FILE):
            with open(RUN_LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        else:
            logs = []

        logs.append(entry)

        with open(RUN_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

    except Exception as e:
        print("Failed to update run history:", e)


# ============================================================
# RUNPY-BASED SCRIPT EXECUTION (replaces subprocess)
# ============================================================

class _RunResult:
    """Minimal result object matching subprocess.CompletedProcess interface."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _run_script_via_runpy(script_path, args, capture_output=True):
    """
    Run a Python script in-process using runpy.
    
    OLD (broken in frozen mode):
        subprocess.run(["python", script_path, ...])
    
    NEW (works everywhere):
        runpy.run_path(script_path, run_name="__main__")
    """
    if not os.path.exists(script_path):
        print(f"[ERROR] Script not found: {script_path}")
        return _RunResult(1, "", f"Script not found: {script_path}")

    old_argv = sys.argv[:]
    old_path = sys.path[:]

    # Add script's directory to sys.path for its local imports
    script_dir = os.path.dirname(os.path.abspath(script_path))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    stdout_buf = io.StringIO() if capture_output else None
    stderr_buf = io.StringIO() if capture_output else None

    try:
        sys.argv = [script_path] + args

        if capture_output:
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                runpy.run_path(script_path, run_name="__main__")
            stdout_text = stdout_buf.getvalue()
            stderr_text = stderr_buf.getvalue()
            # Also print to console so user sees it
            if stdout_text.strip():
                print(stdout_text)
            if stderr_text.strip():
                print("STDERR:", stderr_text)
            return _RunResult(0, stdout_text, stderr_text)
        else:
            runpy.run_path(script_path, run_name="__main__")
            return _RunResult(0)

    except SystemExit as e:
        stdout_text = stdout_buf.getvalue() if stdout_buf else ""
        stderr_text = stderr_buf.getvalue() if stderr_buf else ""
        if stdout_text.strip():
            print(stdout_text)
        code = e.code if e.code is not None else 0
        return _RunResult(code, stdout_text, stderr_text)

    except Exception as e:
        stdout_text = stdout_buf.getvalue() if stdout_buf else ""
        stderr_text = stderr_buf.getvalue() if stderr_buf else ""
        if stdout_text.strip():
            print(stdout_text)
        print(f"[ERROR] {os.path.basename(script_path)} failed: {e}")
        return _RunResult(1, stdout_text, str(e))

    finally:
        sys.argv = old_argv
        sys.path = old_path


# ============================================================
# MAIN ENTRY
# ============================================================

def upload_and_run():
    # Determine source VCD
    if len(sys.argv) > 1:
        input_filename = sys.argv[1]
        # -- FIX: Handle both absolute and relative paths --
        if os.path.isabs(input_filename):
            source_path = input_filename
        else:
            source_path = os.path.join(UPLOAD_SOURCE_DIR, input_filename)

        if not os.path.exists(source_path):
            print("File not found:", source_path)
            sys.exit(1)
        print("Using specified file:", input_filename)
    else:
        source_path = get_latest_vcd()
        input_filename = os.path.basename(source_path)
        print("Using latest VCD:", input_filename)

    user_id = get_or_create_user()
    print("Assigned User ID:", user_id)

    # Copy VCD
    dest_path, _ = save_vcd_file(user_id, os.path.basename(input_filename), source_path)
    print("Saved", input_filename, "to", dest_path)

    # Copy RTL and testbench
    print("\nUploading RTL and testbench files...")
    rtl_files, tb_files, saved_files = save_rtl_and_uvm_testbench_files(
        user_id,
        source_dir=UPLOAD_SOURCE_DIR,
        dest_base_dir=os.path.dirname(dest_path),
    )

    print("Saved RTL files:", rtl_files)
    print("Saved Testbench files:", tb_files)

    # -- FIX: Use SCRIPT_DIR to find run_script.py (bundle path, not cwd) --
    print("\nRunning run_script.py...")
    script_path = os.path.join(SCRIPT_DIR, "run_script.py")

    run_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "source_file": os.path.basename(input_filename),
        "saved_path": dest_path,
        "rtl_files": rtl_files,
        "testbench_files": tb_files,
        "status": "Started"
    }

    try:
        # -- FIX: use runpy instead of subprocess.run(["python", ...]) --
        # OLD (broken): subprocess.run(["python", script_path, dest_path], ...)
        # NEW (works in frozen mode):
        result = _run_script_via_runpy(script_path, [dest_path], capture_output=True)

        # Clock detection (parse captured output -- same logic as before)
        main_clock = None
        for line in result.stdout.splitlines():
            if "Main Clock Chosen:" in line or "Detected main clock:" in line:
                main_clock = line.split(":")[-1].strip()

        if main_clock:
            print("Detected main clock:", main_clock)
            clock_info = estimate_first_chunk_cycles(dest_path, main_clock)
            clock_period_ps = (
                clock_info.get("avg_period")
                if isinstance(clock_info, dict)
                else None
            )
        else:
            clock_period_ps = None
            print("No main clock detected. Using default resolution.")

        print("Converting VCD to JSON/CSV...")
        convert_vcd_to_json_csv(
            dest_path,
            f"{user_id}A",
            main_clock_period_units=clock_period_ps
        )

        run_entry["status"] = "Success"

    except Exception as e:
        print("Error during processing:", e)
        import traceback
        traceback.print_exc()
        run_entry["status"] = "Error: " + str(e)

    log_run(run_entry)
    print("Run logged.")
    print("Processing completed.")


if __name__ == "__main__":
    upload_and_run()