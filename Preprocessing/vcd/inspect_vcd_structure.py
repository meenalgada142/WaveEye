import sys
import os
import subprocess
import shutil
from vcdvcd import VCDVCD

# -------------------------------------------------------------------
# Convert .fst → .vcd using fst2vcd
# -------------------------------------------------------------------
def convert_fst_to_vcd(fst_path: str) -> str:
    vcd_path = fst_path.replace(".fst", ".vcd")
    print(f"🔄 Converting {fst_path} → {vcd_path} ...")

    if not shutil.which("fst2vcd"):
        print("'fst2vcd' not found on PATH.")
        sys.exit(1)

    try:
        subprocess.run(["fst2vcd", "-f", fst_path, "-o", vcd_path], check=True)
        print(f" Conversion successful: {vcd_path}")
        return vcd_path
    except subprocess.CalledProcessError:
        print("❌ fst2vcd conversion failed.")
        sys.exit(1)


# -------------------------------------------------------------------
# Load VCD with silent fallback encodings
# -------------------------------------------------------------------
def load_vcd_with_fallback(vcd_path: str):
    encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]

    for enc in encodings:
        try:
            with open(vcd_path, "r", encoding=enc, errors="ignore") as f:
                text = f.read()

            temp_vcd = "_temp_vcd.vcd"
            with open(temp_vcd, "w", encoding="utf-8") as f:
                f.write(text)

            vcd = VCDVCD(temp_vcd, store_tvs=True, store_scopes=True)
            os.remove(temp_vcd)

            print(f"Loaded successfully using encoding: {enc}")
            return vcd

        except Exception:
            continue

    print(" Failed to read file with any supported encoding. Exiting.")
    sys.exit(1)


# -------------------------------------------------------------------
# Inspect the VCD structure
# -------------------------------------------------------------------
def inspect_vcd_structure(file_path: str):
    if file_path.endswith(".fst"):
        print("Detected FST file — converting to VCD...")
        file_path = convert_fst_to_vcd(file_path)

    print(f"\n Loading {file_path} ...")
    vcd = load_vcd_with_fallback(file_path)

    print("\n=== File Summary ===")
    print(f"Total signals parsed: {len(vcd.data)}")

    if hasattr(vcd, "timescale") and vcd.timescale:
        ts = vcd.timescale
        print(f"Timescale: {ts.get('magnitude', '?')}{ts.get('unit', '?')}")

    signals = list(vcd.data.keys())
    print(f"Signal codes: {signals[:10]}{' ...' if len(signals) > 10 else ''}")

    #  Safe scope extraction (avoid heavy lookups)
    scopes = []
    for k, sig in list(vcd.data.items())[:10]:
        if isinstance(sig, dict) and "nets" in sig:
            for n in sig["nets"]:
                if "hier" in n and "name" in n:
                    scopes.append(f"{n['hier']}.{n['name']}")

    if scopes:
        print("Example scope paths:")
        for s in scopes:
            print(f"  • {s}")

    print("\n Inspection completed successfully.")
    sys.exit(0)


# -------------------------------------------------------------------
# Entry point
# -------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(" Usage: python inspect_vcd_structure.py <vcd_or_fst_file>")
        sys.exit(1)

    inspect_vcd_structure(sys.argv[1])
