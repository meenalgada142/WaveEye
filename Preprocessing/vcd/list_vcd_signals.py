from vcdvcd import VCDVCD
import os, sys

# -------------------------------------------------------------------
# Load VCD with fallback encodings (keep all characters)
# -------------------------------------------------------------------
def load_vcd_with_fallback(vcd_path: str):
    encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]

    for enc in encodings:
        try:
            print(f" Trying encoding: {enc}")
            
            # Read file with chosen encoding; ignore undecodable bytes
            with open(vcd_path, "r", encoding=enc, errors="ignore") as f:
                text = f.read()

            # Save to a UTF-8 cleaned temporary file
            temp_vcd = "_temp_vcd.vcd"
            with open(temp_vcd, "w", encoding="utf-8", errors="ignore") as f:
                f.write(text)

            # Parse using vcdvcd
            vcd = VCDVCD(temp_vcd, store_tvs=False, store_scopes=True)
            os.remove(temp_vcd)

            print(f" Loaded successfully using encoding: {enc}\n")
            return vcd

        except Exception as e:
            print(f" Failed with encoding {enc}: {e}")
            continue

    print(" Failed to read file with any supported encoding.")
    sys.exit(1)


# -------------------------------------------------------------------
# List all signals (keep non-ASCII too)
# -------------------------------------------------------------------
def list_vcd_signals(filepath: str):
    vcd = load_vcd_with_fallback(filepath)

    # Handle dict/list structures
    if isinstance(vcd.signals, dict):
        signals = list(vcd.signals.keys())
    elif isinstance(vcd.signals, list):
        signals = vcd.signals
    else:
        print(" Unknown VCD structure — no signals found.")
        return []

    print(" Signals found in the VCD:")
    for sig in signals:
        print(f" • {sig}")

    print(f"\nTotal signals: {len(signals)}")
    return signals


# -------------------------------------------------------------------
# CLI entry
# -------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python list_vcd_signals.py <path_to_vcd>")
        sys.exit(1)

    list_vcd_signals(sys.argv[1])
