#!/usr/bin/env python3
"""
WaveEye Preprocessing CLI
==========================
Fixed for PyInstaller: uses runpy instead of subprocess,
resolves script paths from __file__ (bundle), data paths from cwd (workspace).
"""
import os
import sys
import glob
import re
import runpy

# ============================================================
# PATH RESOLUTION (PyInstaller-safe)
# ============================================================
# SCRIPT_DIR = where the bundled tool scripts live (_MEIPASS/Preprocessing/)
# WORK_DIR   = where runtime data lives (~/WaveEye/Preprocessing/)
#
# OLD (broken): BASE_DIR = os.getcwd()  -> used for BOTH scripts and data
# FIX: split into two separate roots
# ============================================================

def _get_script_dir():
    """
    Get directory containing THIS script and its sub-tools (vcd/, rtl/, mapping/).
    - Frozen exe: _MEIPASS/Preprocessing/
    - Dev mode:   directory containing this cli.py
    - Fallback:   WAVEEYE_BUNDLE_DIR env var (set by main.py)
    """
    # 1. Try __file__ (set by runpy.run_path or normal execution)
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        pass

    # 2. Try env var set by main.py
    bundle_dir = os.environ.get('WAVEEYE_BUNDLE_DIR')
    if bundle_dir:
        candidate = os.path.join(bundle_dir, "Preprocessing")
        if os.path.isdir(candidate):
            return candidate

    # 3. Try _MEIPASS directly
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        candidate = os.path.join(sys._MEIPASS, "Preprocessing")
        if os.path.isdir(candidate):
            return candidate

    # 4. Last resort: cwd (original behavior)
    return os.getcwd()


SCRIPT_DIR = _get_script_dir()   # bundled tools: vcd/, rtl/, mapping/
WORK_DIR = os.getcwd()            # runtime data:  user_input/, uploaded_vcds/

print(f"[DEBUG] SCRIPT_DIR = {SCRIPT_DIR}")
print(f"[DEBUG] WORK_DIR   = {WORK_DIR}")

# -- Data paths (relative to workspace) --
USER_INPUT = os.path.join(WORK_DIR, "user_input")

# -- Tool paths (relative to bundle) --
VCD_DIR = os.path.join(SCRIPT_DIR, "vcd")
RTL_DIR = os.path.join(SCRIPT_DIR, "rtl")
MAP_DIR = os.path.join(SCRIPT_DIR, "mapping")

OUTPUT_DIR = None   # will be set per user folder

os.makedirs(USER_INPUT, exist_ok=True)


# ============================================================
# SCRIPT EXECUTION (PyInstaller-safe: runpy, NOT subprocess)
# ============================================================

class _RunResult:
    """Minimal result object matching subprocess.CompletedProcess interface."""
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run_step(script_path, args):
    """
    Run a sub-script using runpy (in-process).
    
    This replaces the old subprocess.run() call which BREAKS in PyInstaller
    frozen mode because sys.executable points to the .exe, not a Python
    interpreter.
    
    How it works:
    - Adds script's directory to sys.path so its local imports resolve
    - Simulates sys.argv as if the script were invoked from command line
    - Catches SystemExit so child scripts don't kill the parent pipeline
    """
    if not os.path.exists(script_path):
        print(f"[ERROR] Missing script: {script_path}")
        return None

    print(f"\n[RUN] {os.path.basename(script_path)} {' '.join(args)}")
    print("-" * 60)

    old_argv = sys.argv[:]
    old_path = sys.path[:]

    # Add script's directory to sys.path so its sibling imports work
    # e.g., upload_run_convert_rtl_tb.py imports file_manager from same dir
    script_dir = os.path.dirname(os.path.abspath(script_path))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    try:
        sys.argv = [script_path] + args
        runpy.run_path(script_path, run_name="__main__")
        return _RunResult(0)

    except SystemExit as e:
        # Child scripts may call sys.exit() -- don't propagate
        code = e.code if e.code is not None else 0
        if code != 0:
            print(f"[WARNING] {os.path.basename(script_path)} exited with code {code}")
        return _RunResult(code)

    except Exception as e:
        print(f"[ERROR] {os.path.basename(script_path)} failed: {e}")
        import traceback
        traceback.print_exc()
        return _RunResult(1)

    finally:
        sys.argv = old_argv
        sys.path = old_path


# ============================================================
# RTL ANALYSIS (UNTOUCHED)
# ============================================================

def find_top_module(rtl_files):
    """
    Find the top-level module (DUT) that instantiates other modules.
    """
    candidates = []

    for rtl_file in rtl_files:
        with open(rtl_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        module_match = re.search(r'module\s+(\w+)', content)
        if not module_match:
            continue

        module_name = module_match.group(1)
        instantiations = len(re.findall(r'\w+\s+\w+\s*\(', content))

        score = instantiations
        name_lower = module_name.lower()

        if 'top' in name_lower:
            score += 1000
        elif 'dut' in name_lower:
            score += 900
        elif 'soc' in name_lower:
            score += 800
        elif 'tb' in name_lower or 'testbench' in name_lower:
            score += 100

        candidates.append((score, rtl_file, module_name))

    if not candidates:
        return rtl_files[0] if rtl_files else None

    candidates.sort(reverse=True)

    top_file = candidates[0][1]
    top_module = candidates[0][2]

    print(f"Detected top module: {top_module} (in {os.path.basename(top_file)})")

    return top_file


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():
    global OUTPUT_DIR

    print("\n============================")
    print("  WaveEye Preprocessing CLI")
    print("============================")

    vcd_files = glob.glob(os.path.join(USER_INPUT, "*.vcd"))
    rtl_files = glob.glob(os.path.join(USER_INPUT, "*.v")) + \
                glob.glob(os.path.join(USER_INPUT, "*.sv"))

    if not vcd_files:
        print("No VCD file found in user_input/.")
        return

    if not rtl_files:
        print("No RTL (.v or .sv) files found in user_input/.")
        return

    vcd_file = vcd_files[0]

    print(f"\nUsing VCD: {vcd_file}")
    print("RTL files found:")
    for f in rtl_files:
        print("  -", f)
    print()

    # STEP 1: Convert VCD
    # -- FIX: script path uses SCRIPT_DIR (bundle), not WORK_DIR --
    print("\n==========================")
    print("STEP 1: Upload + Convert")
    print("==========================")

    upload_py = os.path.join(VCD_DIR, "upload_run_convert_rtl_tb.py")
    run_step(upload_py, [vcd_file])

    # DETERMINE USER DIRECTORY
    # -- uploaded_vcds is created in WORK_DIR (cwd) by file_manager.py --
    uploaded_dir = os.path.join(WORK_DIR, "uploaded_vcds")
    user_dirs = sorted(
        [d for d in glob.glob(os.path.join(uploaded_dir, "user*")) if os.path.isdir(d)],
        key=os.path.getmtime,
        reverse=True
    )

    if not user_dirs:
        print("No userXX folder found in uploaded_vcds/. Cannot continue.")
        return

    user_dir = user_dirs[0]

    user_id = os.path.basename(user_dir)
    print(f"[INFO] Processing for: {user_id}")

    # -- FIX: OUTPUT_DIR uses workspace root, not SCRIPT_DIR --
    # Get workspace root (parent of Preprocessing work dir)
    root_dir = os.path.dirname(WORK_DIR)
    OUTPUT_DIR = os.path.join(root_dir, "outputs", user_id, "preprocessing")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"\nAll output files will be stored in: {OUTPUT_DIR}\n")

    # STEP 2: Classify Signals
    # -- FIX: script path uses SCRIPT_DIR (bundle) --
    print("\n==========================")
    print("STEP 2: Classify Signals (Per RTL File)")
    print("==========================")

    classify_signals_py = os.path.join(RTL_DIR, "classify_signals.py")
    metadata_files = []

    for rtl_file in rtl_files:
        base = os.path.splitext(os.path.basename(rtl_file))[0]
        out_prefix = os.path.join(OUTPUT_DIR, base)

        print(f"\n-> Classifying: {rtl_file}")
        run_step(classify_signals_py, [rtl_file, out_prefix])

        json_out = f"{out_prefix}_signals.json"
        csv_out = f"{out_prefix}_signals.csv"

        if os.path.exists(json_out):
            metadata_files.append((base, json_out))
        elif os.path.exists(csv_out):
            metadata_files.append((base, csv_out))

    # STEP 3: System Connectivity (TOP/DUT MODULE ONLY!)
    # -- FIX: script path uses SCRIPT_DIR (bundle) --
    print("\n===============================")
    print("STEP 3: System Connectivity (TOP/DUT Module)")
    print("===============================")

    classify_system_py = os.path.join(RTL_DIR, "classify_system.py")

    top_module_file = find_top_module(rtl_files)

    if not top_module_file:
        print("ERROR: Could not determine top module")
        system_json = None
    else:
        top_base = os.path.splitext(os.path.basename(top_module_file))[0]
        top_prefix = os.path.join(OUTPUT_DIR, top_base)

        print(f"\n-> Extracting connectivity from TOP module: {os.path.basename(top_module_file)}")
        print(f"  (This module contains ALL inter-module connections)")

        run_step(classify_system_py, [top_module_file, top_prefix])

        system_json = f"{top_prefix}_system.json"

        if not os.path.exists(system_json):
            print(f"Warning: System connectivity JSON not created at {system_json}")
            system_json = None
        else:
            print(f"[OK] System connectivity created: {system_json}")
            print(f"  This file contains ALL inter-module connections")

    # STEP 4: Enhanced Mapping Values
    # -- FIX: script path uses SCRIPT_DIR (bundle) --
    print("\n===============================")
    print("STEP 4: Map Waveform Values (Enhanced)")
    print("===============================")

    map_values_enhanced_py = os.path.join(MAP_DIR, "mapping.py")
    map_values_py = os.path.join(MAP_DIR, "mapping_values.py")

    if os.path.exists(map_values_enhanced_py):
        map_script = map_values_enhanced_py
        use_enhanced = True
        print("-> Using mapping.py (with cross-module filling)")
    elif os.path.exists(map_values_py):
        map_script = map_values_py
        use_enhanced = False
        print("-> Using mapping_values.py (standard mapping)")
    else:
        print("ERROR: No mapping script found")
        map_script = None

    if map_script:
        chunk_dir = os.path.join(user_dir, "chunks")
        chunk_files = glob.glob(os.path.join(chunk_dir, "*_chunk_1.csv"))

        if not chunk_files:
            print("No waveform chunk found. Skipping Step 4.")
        else:
            waveform_csv = chunk_files[0]
            print(f"-> Using waveform: {waveform_csv}")

            if system_json:
                print(f"-> Using TOP module connectivity: {os.path.basename(system_json)}\n")
            else:
                print("-> No connectivity available (cross-module values won't be filled)\n")

            for rtl_base, meta_file in metadata_files:
                print(f"-> Mapping values for: {rtl_base}")

                output_file = os.path.join(OUTPUT_DIR, f"{rtl_base}_mapped.csv")

                if use_enhanced and system_json:
                    args = [
                        meta_file,
                        waveform_csv,
                        output_file,
                        "--connectivity", system_json
                    ]
                    print(f"  Using TOP connectivity: {os.path.basename(system_json)}")
                else:
                    output_file = os.path.join(OUTPUT_DIR, f"{rtl_base}_mapped_values.csv")
                    args = [meta_file, waveform_csv, output_file]

                result = run_step(map_script, args)

                if os.path.exists(output_file):
                    print(f"[OK] Created: {output_file}\n")
                else:
                    print(f"[FAIL] Failed to create: {output_file}\n")

    # STEP 5: MERGE MAPPED FILES
    # -- FIX: script path uses SCRIPT_DIR (bundle) --
    print("\n===============================")
    print("STEP 5: Merge Mapping Outputs")
    print("===============================")

    merge_maps_py = os.path.join(MAP_DIR, "merge_map_signals.py")

    if os.path.exists(merge_maps_py):
        mapped_files = sorted(glob.glob(os.path.join(OUTPUT_DIR, "*_mapped.csv")))
        if not mapped_files:
            mapped_files = sorted(glob.glob(os.path.join(OUTPUT_DIR, "*_mapped_values.csv")))

        if len(mapped_files) < 2:
            print("Not enough mapped files to merge (need at least 2).")
            if len(mapped_files) == 1:
                print(f"Single mapped file: {mapped_files[0]}")
        else:
            print("Merging these mapped CSV files:")
            for f in mapped_files:
                print("  -", f)

            run_step(merge_maps_py, [OUTPUT_DIR])

            merged_file = os.path.join(OUTPUT_DIR, 'all_mapped_values.csv')
            if os.path.exists(merged_file):
                print(f"[OK] Merged CSV created: {merged_file}")
            else:
                print(f"[FAIL] Failed to create merged CSV")
    else:
        print("merge_map_signals.py missing - skipping merge.")

    print("\n======================================")
    print("       ALL PROCESSING FINISHED")
    print("======================================")
    print(f"User ID: {user_id}")
    print(f"Output folder: {OUTPUT_DIR}")
    print("\nGenerated files:")
    for f in sorted(glob.glob(os.path.join(OUTPUT_DIR, "*.csv"))):
        print(f"  - {os.path.basename(f)}")
    for f in sorted(glob.glob(os.path.join(OUTPUT_DIR, "*.json"))):
        print(f"  - {os.path.basename(f)}")
    print()


if __name__ == "__main__":
    main()