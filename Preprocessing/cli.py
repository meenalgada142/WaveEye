#!/usr/bin/env python3 
import os
import sys
import subprocess
import glob
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_INPUT = os.path.join(BASE_DIR, "user_input")

OUTPUT_DIR = None   # will be set per user folder

VCD_DIR = os.path.join(BASE_DIR, "vcd")
RTL_DIR = os.path.join(BASE_DIR, "rtl")
MAP_DIR = os.path.join(BASE_DIR, "mapping")

os.makedirs(USER_INPUT, exist_ok=True)


def run_step(script_path, args):
    if not os.path.exists(script_path):
        print(f"Missing script: {script_path}")
        return None

    cmd = [sys.executable, script_path] + args
    print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout.strip():
        print(result.stdout)

    if result.stderr.strip():
        print("STDERR:\n", result.stderr)

    return result


def find_top_module(rtl_files):
    """
    Find the top-level module (DUT) that instantiates other modules
    
    Heuristics:
    1. Module with name containing 'top', 'dut', 'tb', or 'soc'
    2. Module that instantiates the most other modules
    3. First module in the list (fallback)
    """
    candidates = []
    
    for rtl_file in rtl_files:
        with open(rtl_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find module name
        module_match = re.search(r'module\s+(\w+)', content)
        if not module_match:
            continue
        
        module_name = module_match.group(1)
        
        # Count module instantiations
        instantiations = len(re.findall(r'\w+\s+\w+\s*\(', content))
        
        # Score based on name and instantiations
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
    
    # Sort by score (highest first)
    candidates.sort(reverse=True)
    
    top_file = candidates[0][1]
    top_module = candidates[0][2]
    
    print(f"Detected top module: {top_module} (in {os.path.basename(top_file)})")
    
    return top_file


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
    print("\n==========================")
    print("STEP 1: Upload + Convert")
    print("==========================")

    upload_py = os.path.join(VCD_DIR, "upload_run_convert_rtl_tb.py")
    run_step(upload_py, [vcd_file])

    # DETERMINE USER DIRECTORY
    uploaded_dir = os.path.join(BASE_DIR, "uploaded_vcds")
    user_dirs = sorted(
        [d for d in glob.glob(os.path.join(uploaded_dir, "user*")) if os.path.isdir(d)],
        key=os.path.getmtime,
        reverse=True
    )

    if not user_dirs:
        print("No userXX folder found in uploaded_vcds/. Cannot continue.")
        return

    user_dir = user_dirs[0]
    
    # FIX: Extract user_id from user_dir path
    # user_dir looks like: /path/to/uploaded_vcds/user1
    user_id = os.path.basename(user_dir)  # Gets "user1"
    print(f"[INFO] Processing for: {user_id}")

    # NEW: Set OUTPUT_DIR to outputs/userX/preprocessing/
    # Get root directory (parent of Preprocessing/)
    root_dir = os.path.dirname(BASE_DIR)
    OUTPUT_DIR = os.path.join(root_dir, "outputs", user_id, "preprocessing")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"\nAll output files will be stored in: {OUTPUT_DIR}\n")

    # STEP 2: Classify Signals
    print("\n==========================")
    print("STEP 2: Classify Signals (Per RTL File)")
    print("==========================")

    classify_signals_py = os.path.join(RTL_DIR, "classify_signals.py")
    metadata_files = []  # Store (rtl_base, metadata_path) tuples

    for rtl_file in rtl_files:
        base = os.path.splitext(os.path.basename(rtl_file))[0]
        out_prefix = os.path.join(OUTPUT_DIR, base)

        print(f"\n→ Classifying: {rtl_file}")
        run_step(classify_signals_py, [rtl_file, out_prefix])

        json_out = f"{out_prefix}_signals.json"
        csv_out = f"{out_prefix}_signals.csv"

        if os.path.exists(json_out):
            metadata_files.append((base, json_out))
        elif os.path.exists(csv_out):
            metadata_files.append((base, csv_out))

    # STEP 3: System Connectivity (TOP/DUT MODULE ONLY!)
    print("\n===============================")
    print("STEP 3: System Connectivity (TOP/DUT Module)")
    print("===============================")

    classify_system_py = os.path.join(RTL_DIR, "classify_system.py")
    
    # Find the top-level module (DUT)
    top_module_file = find_top_module(rtl_files)
    
    if not top_module_file:
        print("ERROR: Could not determine top module")
        system_json = None
    else:
        # Extract base name for top module
        top_base = os.path.splitext(os.path.basename(top_module_file))[0]
        top_prefix = os.path.join(OUTPUT_DIR, top_base)
        
        print(f"\n→ Extracting connectivity from TOP module: {os.path.basename(top_module_file)}")
        print(f"  (This module contains ALL inter-module connections)")
        
        # Run classify_system.py on TOP module only
        run_step(classify_system_py, [top_module_file, top_prefix])
        
        # The system JSON will be named after the top module
        system_json = f"{top_prefix}_system.json"
        
        if not os.path.exists(system_json):
            print(f"Warning: System connectivity JSON not created at {system_json}")
            system_json = None
        else:
            print(f"✓ System connectivity created: {system_json}")
            print(f"  This file contains ALL inter-module connections")

    # STEP 4: Enhanced Mapping Values (with cross-module support)
    print("\n===============================")
    print("STEP 4: Map Waveform Values (Enhanced)")
    print("===============================")

    # Try enhanced version first, fallback to regular
    map_values_enhanced_py = os.path.join(MAP_DIR, "mapping.py")
    map_values_py = os.path.join(MAP_DIR, "mapping_values.py")
    
    if os.path.exists(map_values_enhanced_py):
        map_script = map_values_enhanced_py
        use_enhanced = True
        print("→ Using mapping.py (with cross-module filling)")
    elif os.path.exists(map_values_py):
        map_script = map_values_py
        use_enhanced = False
        print("→ Using mapping_values.py (standard mapping)")
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
            print(f"→ Using waveform: {waveform_csv}")
            
            if system_json:
                print(f"→ Using TOP module connectivity: {os.path.basename(system_json)}\n")
            else:
                print("→ No connectivity available (cross-module values won't be filled)\n")

            for rtl_base, meta_file in metadata_files:
                print(f"→ Mapping values for: {rtl_base}")
                
                # Define output file path (full path in OUTPUT_DIR)
                output_file = os.path.join(OUTPUT_DIR, f"{rtl_base}_mapped.csv")
                
                if use_enhanced and system_json:
                    # Enhanced mapping with TOP module connectivity
                    args = [
                        meta_file,
                        waveform_csv,
                        output_file,  # Full output path
                        "--connectivity", system_json
                    ]
                    print(f"  Using TOP connectivity: {os.path.basename(system_json)}")
                else:
                    # Standard mapping
                    output_file = os.path.join(OUTPUT_DIR, f"{rtl_base}_mapped_values.csv")
                    args = [meta_file, waveform_csv, output_file]
                
                result = run_step(map_script, args)
                
                if os.path.exists(output_file):
                    print(f"✓ Created: {output_file}\n")
                else:
                    print(f"✗ Failed to create: {output_file}\n")

    # STEP 5: MERGE MAPPED FILES
    print("\n===============================")
    print("STEP 5: Merge Mapping Outputs")
    print("===============================")

    merge_maps_py = os.path.join(MAP_DIR, "merge_map_signals.py")

    if os.path.exists(merge_maps_py):
        # Look for both naming conventions
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
                print(f"✓ Merged CSV created: {merged_file}")
            else:
                print(f"✗ Failed to create merged CSV")

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