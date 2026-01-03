import subprocess
import sys
import os
from clock_estimation import estimate_first_chunk_cycles


def run_script(script_path, vcd_file):
    """Run a sub-script and return its output."""
    print(f"\nRunning {os.path.basename(script_path)}\n" + "-" * 60)

    result = subprocess.run(
        [sys.executable, script_path, vcd_file],
        text=True,
        capture_output=True
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("ERROR/WARNINGS:\n", result.stderr)

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_script.py <vcd_file>")
        sys.exit(1)

    vcd_file = sys.argv[1]

    if not os.path.exists(vcd_file):
        print(f"ERROR: VCD file does not exist: {vcd_file}")
        sys.exit(1)

    # Directory where this script lives
    script_dir = os.path.dirname(os.path.abspath(__file__))

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
