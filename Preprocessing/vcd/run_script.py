"""
Run waveform analysis sub-scripts.
Fixed for PyInstaller: uses runpy instead of subprocess.
"""
import sys
import os
import io
import runpy
from contextlib import redirect_stdout, redirect_stderr
from clock_estimation import estimate_first_chunk_cycles


# ============================================================
# RUNPY-BASED SCRIPT EXECUTION (replaces subprocess)
# ============================================================

class _RunResult:
    """Minimal result object matching subprocess.CompletedProcess interface."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_script(script_path, vcd_file):
    """
    Run a sub-script and return its output.
    
    OLD (broken in frozen mode):
        subprocess.run([sys.executable, script_path, vcd_file], ...)
    
    NEW (works everywhere):
        runpy.run_path() with stdout capture
    """
    print(f"\nRunning {os.path.basename(script_path)}\n" + "-" * 60)

    if not os.path.exists(script_path):
        print(f"Missing script: {script_path}")
        return _RunResult(1, "", f"Missing: {script_path}")

    old_argv = sys.argv[:]
    old_path = sys.path[:]

    # Add script's directory to sys.path for its local imports
    script_dir = os.path.dirname(os.path.abspath(script_path))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    try:
        sys.argv = [script_path, vcd_file]

        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            runpy.run_path(script_path, run_name="__main__")

        stdout_text = stdout_buf.getvalue()
        stderr_text = stderr_buf.getvalue()

        if stdout_text.strip():
            print(stdout_text)
        if stderr_text.strip():
            print("ERROR/WARNINGS:\n", stderr_text)

        return _RunResult(0, stdout_text, stderr_text)

    except SystemExit as e:
        stdout_text = stdout_buf.getvalue()
        stderr_text = stderr_buf.getvalue()
        if stdout_text.strip():
            print(stdout_text)
        code = e.code if e.code is not None else 0
        return _RunResult(code, stdout_text, stderr_text)

    except Exception as e:
        stdout_text = stdout_buf.getvalue()
        stderr_text = stderr_buf.getvalue()
        if stdout_text.strip():
            print(stdout_text)
        print(f"[ERROR] {os.path.basename(script_path)} failed: {e}")
        import traceback
        traceback.print_exc()
        return _RunResult(1, stdout_text, str(e))

    finally:
        sys.argv = old_argv
        sys.path = old_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_script.py <vcd_file>")
        sys.exit(1)

    vcd_file = sys.argv[1]

    if not os.path.exists(vcd_file):
        print(f"ERROR: VCD file does not exist: {vcd_file}")
        sys.exit(1)

    # -- FIX: Use __file__ to find sibling scripts (not cwd) --
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        # Fallback for runpy execution
        bundle_dir = os.environ.get('WAVEEYE_BUNDLE_DIR')
        if bundle_dir:
            script_dir = os.path.join(bundle_dir, "Preprocessing", "vcd")
        else:
            script_dir = os.getcwd()

    # Tools inside vcd directory
    tools = [
        os.path.join(script_dir, "inspect_vcd_structure.py"),
        os.path.join(script_dir, "list_vcd_signals.py"),
        os.path.join(script_dir, "detect_clocks.py")
    ]

    print(f"Analyzing waveform: {vcd_file}\n")

    main_clock = None

    for tool in tools:
        if not os.path.exists(tool):
            print(f"Missing script: {tool}")
            continue

        result = run_script(tool, vcd_file)

        # Extract clock name
        if tool.endswith("detect_clocks.py"):
            for line in result.stdout.splitlines():
                if "Main Clock Chosen:" in line:
                    main_clock = line.split(":")[1].strip()
                    print(f"\nDetected main clock: {main_clock}")
                    break

    # Clock estimation
    if main_clock:
        print("\nRunning clock estimation\n" + "-" * 60)
        estimate_first_chunk_cycles(vcd_file, main_clock)
    else:
        print("\nNo main clock found. Skipping clock estimation.")

    print("\nWaveform analysis completed.\n")


if __name__ == "__main__":
    main()