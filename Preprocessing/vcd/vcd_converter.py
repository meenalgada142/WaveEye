import os
import json
import csv
from vcdvcd import VCDVCD

def get_auto_resolution(clock_period_units=None):
    """
    Decide sampling resolution in *VCD time units* (whatever the VCD uses).
    clock_period_units is the clock period expressed in those same units.
    """
    try:
        if clock_period_units and isinstance(clock_period_units, (int, float)) and clock_period_units > 0:
            # Sample at ~ 10 points per clock, but never finer than 1 unit.
            if clock_period_units > 10:
                return max(1, clock_period_units / 10)
            else:
                return 1
        return 1
    except Exception:
        return 1


def parse_timescale(timescale_str):
    """
    Parse VCD timescale string and return (scale_value, unit_str).

    Example inputs:
        "1 ns"  -> (1.0, "ns")
        "10 ps" -> (10.0, "ps")
        "100 fs"-> (100.0, "fs")

    We use:
        real_time_in_unit = time_index * scale_value
    """
    try:
        parts = str(timescale_str).strip().split()
        if len(parts) != 2:
            return 1.0, "ps"  # fallback

        value_str, unit = parts
        value = float(value_str)

        # Only allow typical VCD units; fallback otherwise
        valid_units = {"s", "ms", "us", "ns", "ps", "fs", "as"}
        if unit not in valid_units:
            unit = "ps"
            value = 1.0

        return value, unit
    except Exception:
        return 1.0, "ps"


def convert_vcd_to_json_csv(vcd_path, username, main_clock_period_units=None):
    """
    Convert VCD into JSON + CSV with auto timescale.

    - Reads VCD timescale (e.g., "1 ns", "10 ps").
    - Samples waveform in the VCD's native time units.
    - Writes time column as "time_<unit>" (e.g., time_ns, time_ps).
    """
    try:
        # Load VCD first so we can inspect timescale
        print(f"Parsing VCD file: {vcd_path}")
        vcd = VCDVCD(vcd_path, store_tvs=True)

        # Detect VCD timescale
        scale_value, unit = parse_timescale(getattr(vcd, "timescale", "1 ps"))
        print(f"Detected VCD timescale: {getattr(vcd, 'timescale', '1 ps')} -> unit = {unit}, scale_value = {scale_value}")

        # Time resolution: in *VCD time indices*, not physical units yet
        resolution_units = get_auto_resolution(main_clock_period_units)
        print(f"Using auto time resolution: {resolution_units:.3f} VCD time units")

        # Chunk folder (same as before)
        user_dir = os.path.join(os.path.dirname(vcd_path), "chunks")
        os.makedirs(user_dir, exist_ok=True)

        # Build signal lists
        signals = list(vcd.data.items())
        signal_names = [
            sig.references[0] if sig.references else f"sig_{code}"
            for code, sig in signals
        ]
        signal_values = {name: [] for name in signal_names}

        # Compute time bounds in raw VCD time indices
        min_time, max_time = None, None
        for _, sig in signals:
            if not sig.tv:
                continue
            t0 = sig.tv[0][0]
            t1 = sig.tv[-1][0]
            if min_time is None or t0 < min_time:
                min_time = t0
            if max_time is None or t1 > max_time:
                max_time = t1

        if min_time is None or max_time is None:
            print("Warning: VCD contains no time-value transitions.")
            return

        # Build raw time index array (VCD time units)
        timestamps_idx = list(
            range(
                int(min_time),
                int(max_time) + 1,
                max(1, int(resolution_units))
            )
        )

        # Convert all tv lists to allow pop(0)
        tvs = {name: sig.tv.copy() for (_, sig), name in zip(signals, signal_names)}
        current_vals = {name: 'x' for name in signal_names}

        # Fill sampled waveform at each timestamp index
        for t in timestamps_idx:
            for name in signal_names:
                tv_list = tvs[name]
                while tv_list and tv_list[0][0] <= t:
                    current_vals[name] = tv_list.pop(0)[1]
                signal_values[name].append(current_vals[name])

        # Convert VCD index times into real times in the VCD unit
        # real_time = index * scale_value
        timestamps_real = [t * scale_value for t in timestamps_idx]
                # if VCD used ps units but sampling is coarse (>=1000 ps), present times in ns
        if unit == "ps" and isinstance(resolution_units, (int,float)) and resolution_units >= 1000:
            timestamps_real = [t/1000.0 for t in timestamps_real]
            unit = "ns"

        # ---------------- JSON Output ----------------
        json_path = os.path.join(user_dir, f"{username}_chunk_1.json")
        with open(json_path, "w") as jf:
            json.dump(
                {
                    f"time_{unit}": timestamps_real,
                    "signals": signal_values
                },
                jf,
                indent=2
            )

        # ---------------- CSV Output ----------------
        csv_path = os.path.join(user_dir, f"{username}_chunk_1.csv")
        time_col_name = f"time_{unit}"

        with open(csv_path, "w", newline="") as cf:
            writer = csv.writer(cf)
            # Header row: time_<unit>, then all signal names
            writer.writerow([time_col_name] + signal_names)

            for i, t_val in enumerate(timestamps_real):
                row = [t_val] + [signal_values[name][i] for name in signal_names]
                writer.writerow(row)

        print("Saved JSON:", json_path)
        print("Saved CSV :", csv_path)
        print("Created JSON and CSV waveform files.")

    except Exception as e:
        print("Chunk conversion failed:", e)
