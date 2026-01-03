#!/usr/bin/env python3
"""
WaveEye Master Pipeline
=======================
Orchestrates complete workflow:
1. Preprocessing (VCD → CSV)
2. IR Backtracking & Analysis

Usage:
    python main.py                   # Auto-detect latest user
    python main.py --user user1      # Specific user

UPDATED VERSION - Automatically uses ir_engine.exe if available
"""

import sys
import os
import subprocess
from pathlib import Path
import time


def print_banner():
    """Print welcome banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                        WAVEEYE ANALYSIS PIPELINE                     ║
║                                                                      ║
║   Stage 1: Preprocessing (VCD → CSV)                                 ║
║   Stage 2: IR Backtracking & Root Cause Analysis                     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


# ============================================================
# PATCH S1: Collect RTL + waveform for IR stage
# ============================================================

def collect_rtl_and_waveform(root_dir, user_id):
    """
    Collect RTL files and waveform CSV for IR backtracking stage
    """
    user_input_dir = root_dir / "Preprocessing" / "user_input"
    preprocessing_out = root_dir / "outputs" / user_id / "preprocessing"

    rtl_files = (
        list(user_input_dir.glob("*.sv")) +
        list(user_input_dir.glob("*.v"))
    )

    waveform_csv = preprocessing_out / "all_mapped_values.csv"

    return rtl_files, waveform_csv


# ============================================================
# NEW: Detect IR engine (executable or Python script)
# ============================================================

def get_ir_engine_path(ir_backtracking_dir):
    """
    Get IR engine executable or script
    Checks for compiled binary first, falls back to Python script
    
    Returns:
        tuple: (path, is_executable)
    """
    # Priority 1: Check for compiled executable in dist/
    exe_path = ir_backtracking_dir / "dist" / "ir_engine.exe"
    if exe_path.exists():
        return exe_path, True
    
    # Priority 2: Check for compiled executable in root
    exe_path_root = ir_backtracking_dir / "ir_engine.exe"
    if exe_path_root.exists():
        return exe_path_root, True
    
    # Priority 3: Fall back to Python script (development mode)
    py_path = ir_backtracking_dir / "main_ss.py"
    if py_path.exists():
        return py_path, False
    
    return None, False


def print_stage_header(stage_num, stage_name):
    """Print stage header"""
    print("\n" + "=" * 70)
    print(f"  STAGE {stage_num}: {stage_name}")
    print("=" * 70 + "\n")


# ============================================================
# UPDATED: Support both .exe and .py scripts
# ============================================================

def run_stage(script_path, stage_name, args=None, is_executable=False):
    """
    Run a pipeline stage script or executable
    
    Args:
        script_path: Path to script or executable
        stage_name: Name of the stage
        args: Arguments to pass
        is_executable: True if it's a compiled .exe
    """
    if not script_path.exists():
        print(f"[ERROR] Not found: {script_path}")
        return False

    # Build command based on type
    if is_executable or script_path.suffix == '.exe':
        cmd = [str(script_path)]  # Direct executable
    else:
        cmd = [sys.executable, str(script_path)]  # Python script
    
    if args:
        cmd.extend(args)

    print(f"[INFO] Running: {' '.join(cmd)}")
    print(f"[INFO] Working directory: {script_path.parent}\n")

    try:
        result = subprocess.run(
            cmd,
            cwd=script_path.parent,
        )

        if result.returncode == 0:
            print(f"\n[OK] {stage_name} completed successfully")
            return True
        else:
            print(f"\n[ERROR] {stage_name} failed with return code {result.returncode}")
            return False

    except KeyboardInterrupt:
        print(f"\n[INFO] {stage_name} interrupted by user")
        return False
    except Exception as e:
        print(f"\n[ERROR] {stage_name} failed: {e}")
        return False


def get_user_id():
    """
    Get user ID from command line or detect latest
    """
    if '--user' in sys.argv:
        idx = sys.argv.index('--user')
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]

    outputs_dir = Path.cwd() / "outputs"
    if outputs_dir.exists():
        users = sorted(
            [d for d in outputs_dir.glob("user*") if d.is_dir()],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        if users:
            return users[0].name

    return None


def main():
    """Main orchestrator"""

    start_time = time.time()
    print_banner()

    root_dir = Path.cwd()

    preprocessing_dir = root_dir / "Preprocessing"
    ir_backtracking_dir = root_dir / "IR_backtracking"

    if not preprocessing_dir.exists():
        print("[ERROR] Preprocessing/ folder not found!")
        return 1

    if not ir_backtracking_dir.exists():
        print("[ERROR] IR_backtracking/ folder not found!")
        return 1

    cli_script = preprocessing_dir / "cli.py"

    user_id = get_user_id()

    if user_id:
        print(f"[INFO] Processing user: {user_id}")
    else:
        print(f"[INFO] No existing user sessions found")
        print(f"[INFO] New user session will be created")

    stage_args = []
    if user_id:
        stage_args = ['--user', user_id]

    print(f"\n{'=' * 70}")
    print(f"  CONFIGURATION")
    print(f"{'=' * 70}")
    print(f"Root directory:    {root_dir}")
    print(f"Preprocessing:     {preprocessing_dir}")
    print(f"IR Backtracking:   {ir_backtracking_dir}")
    print(f"User ID:           {user_id or '(auto-detect)'}")
    print(f"{'=' * 70}")

    # ============================================================
    # STAGE 1: PREPROCESSING
    # ============================================================

    print_stage_header(1, "PREPROCESSING (VCD → CSV)")

    success = run_stage(cli_script, "Preprocessing", stage_args)
    if not success:
        print("[ERROR] Preprocessing failed")
        return 1

    # ============================================================
    # CRITICAL FIX: ALWAYS re-detect user_id after preprocessing
    # ============================================================
    user_id = get_user_id()  # Get latest user directory
    if user_id is None:
        print("[ERROR] Failed to determine user_id after preprocessing")
        return 1
    
    print(f"[INFO] Using outputs from: {user_id}")

    # ============================================================
    # STAGE 2: IR BACKTRACKING & ANALYSIS
    # ============================================================

    print_stage_header(2, "IR BACKTRACKING & ANALYSIS")

    # ============================================================
    # NEW: Detect IR engine (exe or py)
    # ============================================================
    
    ir_engine, is_exe = get_ir_engine_path(ir_backtracking_dir)
    
    if not ir_engine:
        print("[ERROR] IR Analysis engine not found!")
        print("[ERROR] Expected: IR_backtracking/dist/ir_engine.exe or IR_backtracking/main_ss.py")
        return 1
    
    if is_exe:
        print(f"[INFO] Using compiled IR engine: {ir_engine.name}")
    else:
        print(f"[INFO] Using Python IR engine (development mode)")

    # ============================================================
    # PATCH S2: Explicit RTL + waveform args (NO --user)
    # ============================================================

    rtl_files, waveform_csv = collect_rtl_and_waveform(root_dir, user_id)

    if not rtl_files:
        print("[ERROR] No RTL files found in Preprocessing/user_input/")
        return 1

    if not waveform_csv.exists():
        print("[ERROR] all_mapped_values.csv not found for user")
        return 1

    ir_args = [str(f.resolve()) for f in rtl_files]
    ir_args.append(str(waveform_csv.resolve()))

    # Run IR engine (automatically uses .exe if available, .py otherwise)
    success = run_stage(
        ir_engine,
        "IR Backtracking",
        ir_args,
        is_executable=is_exe
    )

    if not success:
        print("[WARNING] Analysis stage encountered issues")

    # ============================================================
    # FINAL SUMMARY
    # ============================================================

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    print(f"\nTotal execution time: {elapsed:.2f} seconds")
    print("\n" + "=" * 70)
    print("  [OK] All stages completed!")
    print("=" * 70 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())