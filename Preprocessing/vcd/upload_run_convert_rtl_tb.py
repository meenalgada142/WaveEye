import os
import sys
import json
import shutil
import subprocess
from datetime import datetime

from file_manager import get_or_create_user, save_vcd_file
from vcd_converter import convert_vcd_to_json_csv
from clock_estimation import estimate_first_chunk_cycles

UPLOAD_SOURCE_DIR = r"C:\Users\gadap\OneDrive\Desktop\WaveEye\CLI_Test_Runs"
RUN_LOG_FILE = os.path.join(UPLOAD_SOURCE_DIR, "run_history.json")


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
    tb_keywords = ["tb", "testbench", "driver", "monitor", "agent", "env", "sequence",
                   "scoreboard", "test", "uvm"]

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


def upload_and_run():
    # Determine source VCD
    if len(sys.argv) > 1:
        input_filename = sys.argv[1]
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

    # Copy VCD to uploaded_vcds
    dest_path, _ = save_vcd_file(user_id, input_filename, source_path)
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

    # Run run_script.py
    print("\nRunning run_script.py...")

    script_path = os.path.join(os.path.dirname(__file__), "run_script.py")

    run_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "source_file": input_filename,
        "saved_path": dest_path,
        "rtl_files": rtl_files,
        "testbench_files": tb_files,
        "status": "Started"
    }

    try:
        result = subprocess.run(
            ["python", script_path, dest_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:\n", result.stderr)

        # Check output for main clock
        main_clock = None
        for line in result.stdout.splitlines():
            if "Main Clock Chosen:" in line or "Detected main clock:" in line:
                main_clock = line.split(":")[-1].strip()
        if main_clock:
            print("Detected main clock:", main_clock)
            clock_info = estimate_first_chunk_cycles(dest_path, main_clock)
            clock_period_ps = clock_info.get("avg_period") if isinstance(clock_info, dict) else None
        else:
            clock_period_ps = None
            print("No main clock detected. Using default resolution.")

        print("Converting VCD to JSON/CSV...")
        convert_vcd_to_json_csv(dest_path, f"{user_id}A", main_clock_period_units=clock_period_ps)


        run_entry["status"] = "Success"

    except subprocess.TimeoutExpired:
        print("Analysis timed out.")
        run_entry["status"] = "Timeout"

    except Exception as e:
        print("Error during processing:", e)
        run_entry["status"] = "Error: " + str(e)

    log_run(run_entry)
    print("Run logged.")
    print("Processing completed.")


if __name__ == "__main__":
    upload_and_run()
