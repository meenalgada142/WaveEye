#!/usr/bin/env python3
"""
PATCHED VERSION - Now accepts waveform CSV path as command-line argument

Usage:
    python rising_falling_edges.py [waveform_csv_path]
"""

import os
import sys
import csv
import json
import glob
import pandas as pd


def main(waveform_path):
    # ============================================================
    # PATCH: Accept waveform CSV from argument ONLY
    # ============================================================
    DEBUG = False

    if not waveform_path:
        raise ValueError("waveform_path must be provided")

    if not os.path.exists(waveform_path):
        raise FileNotFoundError(f"Waveform CSV not found: {waveform_path}")

    # Anchor base_path to waveform directory
    base_path = os.path.dirname(os.path.abspath(waveform_path))

    print(f"[INFO] Reading waveform from: {waveform_path}")

    with open(waveform_path, "r") as f:
        reader = csv.reader(f)
        classification_row = next(reader)
        signal_name_row = next(reader)
        waveform_rows = list(reader)

    # ============================================================
    # Step 2: Detect TIME column
    # ============================================================
    time_col = None
    for col in signal_name_row:
        if col.lower().startswith("time_"):
            time_col = col
            break

    if not time_col:
        raise ValueError("No time_* column found")

    print(f"[INFO] Using time column: {time_col}")

    # ============================================================
    # Step 3: Identify clock signal
    # ============================================================
    clock_index = next(
        (i for i, val in enumerate(classification_row)
         if val.strip().lower() == "clock"),
        None
    )

    if clock_index is None:
        raise ValueError("No signal classified as clock found")

    clock_signal_name = signal_name_row[clock_index].strip()

    # ============================================================
    # Step 4: Build waveform DataFrame
    # ============================================================
    df = pd.DataFrame(waveform_rows, columns=signal_name_row)

    df[time_col] = (
        pd.to_numeric(df[time_col], errors="coerce")
        .fillna(0)
        .astype(int)
    )

    # ============================================================
    # Helper: match column by suffix
    # ============================================================
    def find_column(df, sig_name):
        return next((col for col in df.columns if col.endswith(sig_name)), None)

    # ============================================================
    # Step 5: Detect clock edges and build cycle index
    # ============================================================
    clock_col = find_column(df, clock_signal_name)
    if not clock_col:
        raise ValueError(f"Clock signal {clock_signal_name} not found")

    rising_edges = []
    falling_edges = []
    clk_cycles = {}

    prev_val = None
    cycle_index = -1

    for _, row in df.iterrows():
        raw_clk = str(row[clock_col]).lower()
        if raw_clk not in ("0", "1"):
            continue

        clk = int(raw_clk)
        time = row[time_col]

        if prev_val is not None:
            if prev_val == 0 and clk == 1:
                cycle_index += 1
                rising_edges.append(time)
                clk_cycles[time] = cycle_index
            elif prev_val == 1 and clk == 0:
                falling_edges.append(time)
                clk_cycles[time] = cycle_index

        prev_val = clk

    print(f"Clock signal detected: {clock_signal_name} column {clock_col}")

    if DEBUG:
        print("Rising edges:", rising_edges)
        print("Falling edges:", falling_edges)

    # ============================================================
    # PRECOMPUTE SORTED CLOCK CYCLES
    # ============================================================
    sorted_clk_cycles = sorted(clk_cycles.items())

    # ============================================================
    # Step 6: Detect edges for all other signals
    # ============================================================
    edge_records = []

    def detect_edges(signal_name, col_name):
        prev_val = None
        for _, row in df.iterrows():
            raw = str(row[col_name]).lower()
            if raw not in ("0", "1"):
                prev_val = None
                continue

            sig_val = int(raw)
            time = row[time_col]

            clk_cycle = None
            for t, c in sorted_clk_cycles:
                if t > time:
                    break
                clk_cycle = c

            if prev_val is not None:
                if prev_val == 0 and sig_val == 1:
                    edge_records.append({
                        "signal": signal_name,
                        "edge_type": "rising",
                        "time": time,
                        "clk_cycle": clk_cycle
                    })
                elif prev_val == 1 and sig_val == 0:
                    edge_records.append({
                        "signal": signal_name,
                        "edge_type": "falling",
                        "time": time,
                        "clk_cycle": clk_cycle
                    })

            prev_val = sig_val

    for i, class_type in enumerate(classification_row):
        sig_name = signal_name_row[i].strip()
        if class_type.strip().lower() == "clock":
            continue

        col = find_column(df, sig_name)
        if col:
            detect_edges(sig_name, col)

    # ============================================================
    # Step 6.5: Detect NO_EDGE signals
    # ============================================================
    print("Checking for signals with no rising or falling edges")

    no_edge_signals = []

    for i, class_type in enumerate(classification_row):
        sig_name = signal_name_row[i].strip()
        if class_type.strip().lower() == "clock":
            continue

        col = find_column(df, sig_name)
        if not col:
            continue

        raw_vals = (
            df[col]
            .astype(str)
            .str.lower()
            .replace("", pd.NA)
            .dropna()
        )

        bin_vals = [v for v in raw_vals if v in ("0", "1")]

        transitions = sum(
            bin_vals[j] != bin_vals[j - 1]
            for j in range(1, len(bin_vals))
        )

        if transitions == 0:
            no_edge_signals.append(sig_name)

    for sig in no_edge_signals:
        edge_records.append({
            "signal": sig,
            "edge_type": "NO_EDGE",
            "time": None,
            "clk_cycle": None
        })

    # ============================================================
    # Step 7–10: Build tables and save outputs (UNCHANGED)
    # ============================================================
    edges_df = pd.DataFrame(
        edge_records,
        columns=["signal", "edge_type", "time", "clk_cycle"]
    )

    signals = sorted(edges_df["signal"].unique())
    metric_order = ["edge_type", "time", "clk_cycle"]

    blocks = []
    max_len = 0

    for sig in signals:
        block = edges_df.loc[
            edges_df["signal"] == sig,
            metric_order
        ].reset_index(drop=True)

        max_len = max(max_len, len(block))
        classification = classification_row[signal_name_row.index(sig)].strip()

        block.columns = pd.MultiIndex.from_tuples(
            [(classification, sig, metric) for metric in metric_order]
        )
        blocks.append(block)

    for i, block in enumerate(blocks):
        if len(block) < max_len:
            blocks[i] = block.reindex(range(max_len))

    reshaped = pd.concat(blocks, axis=1)
    reshaped.index.name = "transition_index"

    rtl_name = os.path.splitext(os.path.basename(waveform_path))[0]

    if rtl_name == "all_mapped_values":
        ir_files = glob.glob(os.path.join(base_path, "*_ir.json"))
        if ir_files:
            rtl_name = os.path.basename(ir_files[0]).replace("_ir.json", "")
        else:
            rtl_name = "wrapper"

    csv_path = os.path.join(base_path, f"{rtl_name}_edges.csv")
    reshaped.to_csv(csv_path, index=False)

    json_path = os.path.join(base_path, f"{rtl_name}_edges.json")
    with open(json_path, "w") as f:
        json.dump([], f, indent=2)

    print(f"[INFO] Saved edge tables to {base_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[ERROR] Usage: rising_falling_edges.py <waveform.csv>")
        sys.exit(1)
    main(sys.argv[1])
