#!/usr/bin/env python3
"""
WaveEye Master Pipeline
=======================
Orchestrates complete workflow:
1. Preprocessing (VCD -> CSV)
2. IR Backtracking & Analysis

CRITICAL: Uses runpy.run_path() - NO subprocess calls.
"""

import sys
import os
import shutil
import runpy
import time
from pathlib import Path


# ============================================================
# PATH RESOLUTION (PyInstaller-safe)
# ============================================================

def get_base_path() -> Path:
    """
    Get base directory containing bundled resources.
    - Packaged: /tmp/_MEIxxxxxx (PyInstaller extraction dir)
    - Dev: Directory containing main.py
    """
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent.resolve()


def get_runtime_workspace() -> Path:
    """
    Get persistent workspace (survives PyInstaller temp cleanup).
    Use ~/WaveEye for all outputs and runtime data.
    """
    workspace = Path.home() / "WaveEye"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


# ============================================================
# UI
# ============================================================

def print_banner():
    banner = """
+===========================================================================+
|                                                                           |
|                   WAVEEYE AXI4-LITE PROTOCOL ANALYZER                    |
|                              Version 1.0.0                                |
|                                                                           |
|         Automated Protocol Violation Detection & Root Cause Analysis     |
|                                                                           |
+===========================================================================+

Professional RTL debugging tool with 70-80 % automated RCA:
  [OK] 13+ AXI4-Lite protocol rules
  [OK] IR-level RTL backtracking
  [OK] Inter-FSM dependency analysis
  [OK] Execution order bug detection
  [OK] Interactive signal analysis (v/vp/vs commands)
"""
    print(banner)


# ============================================================
# USER INPUT HANDLING
# ============================================================

def get_user_input_dir():
    """Ask user for folder containing rtl/ and wave/ subdirectories."""
    path = input("\nEnter path to input folder (contains rtl/ and wave/): ").strip()
    p = Path(path)

    if not p.exists():
        print("[ERROR] Input path does not exist")
        return None

    if not (p / "rtl").exists() or not (p / "wave").exists():
        print("[ERROR] Folder must contain 'rtl/' and 'wave/' subfolders")
        return None

    return p


def prepare_user_input(input_root: Path, preprocessing_dir: Path) -> bool:
    """
    Copy user RTL and VCD files into Preprocessing/user_input.
    Supports both structured (rtl/wave/) and flat layouts.
    """
    user_input_dir = preprocessing_dir / "user_input"
    user_input_dir.mkdir(parents=True, exist_ok=True)

    # Clear old inputs
    for f in user_input_dir.glob("*"):
        if f.is_file():
            f.unlink()

    copied = False

    # Case 1: rtl/ and wave/ subfolders exist
    rtl_dir = input_root / "rtl"
    wave_dir = input_root / "wave"

    if rtl_dir.exists():
        for ext in ("*.sv", "*.v"):
            for f in rtl_dir.glob(ext):
                shutil.copy(f, user_input_dir)
                copied = True

    if wave_dir.exists():
        for f in wave_dir.glob("*.vcd"):
            shutil.copy(f, user_input_dir)
            copied = True

    # Case 2: flat folder (files directly inside input_root)
    if not copied:
        for ext in ("*.sv", "*.v", "*.vcd"):
            for f in input_root.glob(ext):
                shutil.copy(f, user_input_dir)
                copied = True

    if not copied:
        print("[ERROR] No RTL or VCD files found in input folder")
        return False

    return True


# ============================================================
# USER SESSION
# ============================================================

def get_user_id(workspace: Path) -> str:
    """Get most recent user ID from outputs directory."""
    if '--user' in sys.argv:
        idx = sys.argv.index('--user')
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]

    outputs_dir = workspace / "outputs"
    if outputs_dir.exists():
        users = sorted(
            [d for d in outputs_dir.glob("user*") if d.is_dir()],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        if users:
            return users[0].name

    return None


# ============================================================
# ASSET MATERIALIZATION (PyInstaller -> Runtime Workspace)
# ============================================================

def materialize_preprocessing_assets(workspace):
    """Copy Preprocessing assets to runtime workspace."""
    base_path = get_base_path()
    preprocessing_src = base_path / "Preprocessing"
    preprocessing_dst = workspace / "Preprocessing"
    preprocessing_dst.mkdir(parents=True, exist_ok=True)
    
    for folder in ("vcd", "rtl", "mapping"):
        src = preprocessing_src / folder
        dst = preprocessing_dst / folder
        
        if src.exists() and src != dst:  # Added: don't copy to self
            if dst.exists():
                shutil.rmtree(dst)  # Remove old copy
            shutil.copytree(src, dst)

# ============================================================
# STAGE EXECUTION (NO subprocess, NO recursion)
# ============================================================

def run_stage(stage_name: str, script_name: str = "cli.py", 
              args: list = None, cwd: Path = None) -> bool:
    """
    Execute a pipeline stage using runpy (in-process).
    
    Args:
        stage_name: Subfolder name (e.g., 'Preprocessing')
        script_name: Script filename (default: 'cli.py')
        args: Command-line arguments to pass
        cwd: Working directory to execute in
    
    Returns:
        True if stage succeeded, False otherwise
    """
    base_path = get_base_path()
    script_path = base_path / stage_name / script_name

    if not script_path.exists():
        print(f"[ERROR] Stage script not found: {script_path}")
        return False

    # Save current state
    old_argv = sys.argv[:]
    old_cwd = os.getcwd()
    old_syspath = sys.path[:]

    try:
        if cwd:
            os.chdir(str(cwd))

        # Ensure stage-local imports win (important when running multiple runpy stages).
        stage_dir = str(script_path.parent.resolve())
        sys.path = [p for p in sys.path if str(Path(p).resolve()) != stage_dir]
        sys.path.insert(0, stage_dir)

        sys.argv = [str(script_path)] + (args or [])
        runpy.run_path(str(script_path), run_name="__main__")
        return True

    # -- FIX: catch SystemExit so a child script's sys.exit()
    #    doesn't kill the master pipeline --
    except SystemExit as e:
        code = e.code if e.code is not None else 0
        if code == 0:
            return True
        else:
            print(f"[ERROR] Stage {stage_name} exited with code {code}")
            return False

    except Exception as e:
        print(f"[ERROR] {stage_name} failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Restore state
        sys.argv = old_argv
        sys.path = old_syspath
        os.chdir(old_cwd)


# ============================================================
# IR BACKTRACKING HELPERS
# ============================================================

def collect_rtl_and_waveform(workspace: Path, user_id: str):
    """Collect RTL files and waveform CSV for IR backtracking."""
    user_input_dir = workspace / "Preprocessing" / "user_input"
    preprocessing_out = workspace / "outputs" / user_id / "preprocessing"

    rtl_files = (
        list(user_input_dir.glob("*.sv")) +
        list(user_input_dir.glob("*.v"))
    )

    # Try all_mapped_values.csv first (multi-RTL case)
    waveform_csv = preprocessing_out / "all_mapped_values.csv"
    
    # If not found, look for single *_mapped.csv file
    if not waveform_csv.exists():
        mapped_files = list(preprocessing_out.glob("*_mapped.csv"))
        if mapped_files:
            waveform_csv = mapped_files[0]
            print(f"[INFO] Using waveform CSV: {waveform_csv.name}")
    
    return rtl_files, waveform_csv


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline(interactive_mode: bool = False) -> int:
    """
    Execute the complete WaveEye pipeline.
    
    Returns:
        0 on success, 1 on failure
    """
    start_time = time.time()

    # Get runtime workspace (persistent, PyInstaller-safe)
    workspace = get_runtime_workspace()

    base_path = get_base_path()
    os.environ['WAVEEYE_BUNDLE_DIR'] = str(base_path)
    os.environ['WAVEEYE_WORKSPACE'] = str(workspace)

    materialize_preprocessing_assets(workspace)

    preprocessing_dir = workspace / "Preprocessing"
    preprocessing_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------
    # Collect user input
    # ------------------------------------------------------------
    input_root = get_user_input_dir()
    if input_root is None:
        return 1

    if not prepare_user_input(input_root, preprocessing_dir):
        return 1

    # ------------------------------------------------------------
    # STAGE 1: PREPROCESSING
    # ------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  STAGE 1: PREPROCESSING")
    print("=" * 70)

    user_id = get_user_id(workspace)
    stage_args = ['--user', user_id] if user_id else []

    if not run_stage(
        stage_name="Preprocessing",
        script_name="cli.py",
        args=stage_args,
        cwd=preprocessing_dir
    ):
        print("[ERROR] Preprocessing failed")
        return 1

    # Update user_id after preprocessing completes
    user_id = get_user_id(workspace)
    if not user_id:
        print("[ERROR] Could not determine user_id after preprocessing")
        return 1

    # ------------------------------------------------------------
    # STAGE 2: IR BACKTRACKING
    # ------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  STAGE 2: IR BACKTRACKING")
    print("=" * 70)

    if interactive_mode:
        _, waveform_csv = collect_rtl_and_waveform(workspace, user_id)
        ir_args = ['--interactive', str(waveform_csv)]
    else:
        rtl_files, waveform_csv = collect_rtl_and_waveform(workspace, user_id)
        ir_args = [str(f) for f in rtl_files] + [str(waveform_csv)]

    if not run_stage(
        stage_name="IR_backtracking",
        script_name="cli.py",
        args=ir_args,
        cwd=workspace
    ):
        print("[ERROR] IR Backtracking failed")
        return 1

    elapsed = time.time() - start_time
    print(f"\n[SUCCESS] Pipeline complete in {elapsed:.2f}s")
    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    print_banner()

    print("\nOptions:")
    print("  1. Automated Mode")
    print("  2. Interactive Mode")
    print("  3. Exit")

    choice = input("\nEnter choice (1-3): ").strip()

    def maybe_pause_before_exit():
        # Pause only when launched by double-click (no CLI args)
        if len(sys.argv) == 1:
            input("\nAnalysis complete. Press Enter to exit...")

    if choice == "1":
        rc = run_pipeline(interactive_mode=False)
        maybe_pause_before_exit()
        sys.exit(rc)

    elif choice == "2":
        rc = run_pipeline(interactive_mode=True)
        maybe_pause_before_exit()
        sys.exit(rc)

    elif choice == "3":
        print("\nExiting...")
        maybe_pause_before_exit()
        sys.exit(0)

    else:
        print("[ERROR] Invalid choice")
        maybe_pause_before_exit()
        sys.exit(1)
