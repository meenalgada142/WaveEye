from vcdvcd import VCDVCD
import numpy as np
import os
import sys
import re   #  for name filtering

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

            print(f" Loaded successfully using encoding: {enc}")
            return vcd

        except Exception:
            continue

    print(" Failed to read file with any supported encoding. Exiting.")
    sys.exit(1)


# -------------------------------------------------------------------
# Detect clock-like signals
# -------------------------------------------------------------------
def detect_clocks(vcd_path, min_toggles=None, max_duty_variation=0.2):
    print(f" Loading {vcd_path} ...")

    # === Adaptive toggle threshold based on file size ===
    file_size_mb = os.path.getsize(vcd_path) / (1024 * 1024)
    if min_toggles is None:
        if file_size_mb > 100:
            min_toggles = 200
        elif file_size_mb > 10:
            min_toggles = 100
        else:
            min_toggles = 50

    print(f" File size: {file_size_mb:.2f} MB , Using min_toggles = {min_toggles}")

    # === Load with fallback encoders ===
    vcd = load_vcd_with_fallback(vcd_path)
    print(" VCD parsed successfully\n")

    clocks = []

    for signal_name, signal_obj in vcd.data.items():
        #  Filter only signals with 'clk' in name or reference
        ref_name = (signal_obj.references[0] if hasattr(signal_obj, "references") and signal_obj.references else signal_name)
        if not re.search(r'clk', ref_name, re.IGNORECASE) and not re.search(r'clk', signal_name, re.IGNORECASE):
            continue

        # Access the signal's time-value pairs
        tv = getattr(signal_obj, "tv", [])
        if not tv or len(tv) < 4:
            continue

        # Keep only binary transitions
        tv_filtered = [(t, v) for t, v in tv if v in ("0", "1")]
        if len(tv_filtered) < min_toggles:
            continue

        times, values = zip(*tv_filtered)
        times = np.array(times, dtype=float)
        values = np.array(values)

        # Skip invalid or too short signals
        if len(values) < 2:
            continue

        # --- Detect rising and falling edges safely ---
        rising_mask = (values[:-1] == "0") & (values[1:] == "1")
        falling_mask = (values[:-1] == "1") & (values[1:] == "0")

        rising_edges = times[1:][rising_mask]
        falling_edges = times[1:][falling_mask]

        if len(rising_edges) < 3 and len(falling_edges) < 3:
            continue

        # --- Compute edge statistics ---
        def edge_stats(edges):
            if len(edges) < 3:
                return None, None, None
            periods = np.diff(edges)
            avg_period = np.mean(periods)
            period_std = np.std(periods)
            return avg_period, period_std, len(edges)

        r_avg, r_std, r_cnt = edge_stats(rising_edges)
        f_avg, f_std, f_cnt = edge_stats(falling_edges)

        if r_avg and f_avg:
            avg_period = min(r_avg, f_avg)
        elif r_avg:
            avg_period = r_avg
        elif f_avg:
            avg_period = f_avg
        else:
            continue

        # --- Duty cycle estimation ---
        high_times = []
        for i in range(1, len(tv_filtered)):
            if values[i - 1] == "1":
                high_times.append(tv_filtered[i][0] - tv_filtered[i - 1][0])

        if not high_times:
            continue

        avg_high = np.mean(high_times)
        duty_cycle = avg_high / avg_period if avg_period > 0 else 0
        duty_var = np.std(high_times) / (avg_high + 1e-9)

        # --- Resolve full signal name ---
        full_name = (
            getattr(signal_obj, "references", [signal_name])[0]
            if hasattr(signal_obj, "references") and signal_obj.references
            else signal_name
        )

        # --- Clock validation ---
        if duty_var < max_duty_variation:
            clocks.append({
                "id": signal_name,
                "name": full_name,
                "period": round(avg_period, 3),
                "duty_cycle": round(duty_cycle, 2),
                "toggles": len(tv_filtered)
            })

    # --- Choose main clock ---
    clocks.sort(key=lambda x: x["toggles"], reverse=True)
    main_clock = clocks[0] if clocks else None

    # --- Print results ---
    print("\nDetected Clock Signals:")
    if clocks:
        for c in clocks:
            print(f" {c['name']:40s} | Period: {c['period']:>8} | Duty: {c['duty_cycle']*100:5.1f}% | Toggles: {c['toggles']}")
        print(f"\n Main Clock Chosen: {main_clock['name']}")
    else:
        print(" No clock-like signals detected.")

    return {"clocks": clocks, "main_clock": main_clock}


# -------------------------------------------------------------------
# CLI Entry
# -------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect_clocks.py <path_to_vcd>")
        sys.exit(1)

    detect_clocks(sys.argv[1])
