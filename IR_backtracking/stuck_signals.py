#!/usr/bin/env python3
"""
PATCHED VERSION - Now accepts optional waveform CSV path as command-line argument
(though this script primarily looks for *_edges.csv files)
"""

import os
import sys
import glob
import pandas as pd
import json
from dataclasses import dataclass
from typing import List, Dict, Optional


def main(waveform_path=None):
    # ============================================================
    # FIX: Use waveform_path parameter to find base_path
    # ============================================================
    if waveform_path and os.path.exists(waveform_path):
        base_path = os.path.dirname(os.path.abspath(waveform_path))
        print(f"[INFO] Using waveform directory: {base_path}")
    elif len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        base_path = os.path.dirname(os.path.abspath(sys.argv[1]))
    else:
        base_path = os.getcwd()

    # --- Config thresholds ---
    @dataclass
    class StuckConfig:
        suspicious_min: int = 10
        suspicious_max: int = 20
        likely_min: int = 50
        confirmed_min: int = 100
        post_reset_window: int = 20
        clock_pause_tolerance_cycles: int = 5
        counter_freeze_threshold: int = 20

    @dataclass
    class Segment:
        start: int
        end: int
        length: int

    @dataclass
    class StuckResult:
        signal: str
        categories: List[str]
        longest_flatline: int
        longest_segment: Optional[Segment]
        first_toggle_cycle: Optional[int]
        last_toggle_cycle: Optional[int]
        notes: List[str]
        confidence: str

    def pick_primary_category(cats):
        priority = [
            "globally_stuck",
            "confirmed_stuck",
            "oneshot_stuck",
            "post_reset_likely_stuck",
            "likely_stuck",
            "suspicious_flatline"
        ]
        for p in priority:
            if p in cats:
                return p
        return None

    def expand_category(cat):
        return {
            "globally_stuck": "No edges detected throughout the simulation",
            "confirmed_stuck": "Flatline duration exceeds confirmed threshold (>= 100 cycles)",
            "likely_stuck": "Flatline duration exceeds likely threshold (>= 50 cycles)",
            "suspicious_flatline": "Flatline duration falls within suspicious range (10-20 cycles)",
            "oneshot_stuck": "Signal toggled once, then remained flat for the rest of the simulation",
            "post_reset_likely_stuck": "Signal did not toggle within 20 cycles after reset deassertion"
        }.get(cat, None)

    def assign_confidence(categories: List[str]) -> str:
        if "globally_stuck" in categories:
            return "high"
        if "confirmed_stuck" in categories:
            return "high"
        if "oneshot_stuck" in categories:
            return "medium"
        if "post_reset_likely_stuck" in categories:
            return "medium"
        if "likely_stuck" in categories:
            return "medium"
        if "suspicious_flatline" in categories:
            return "low"
        return "low"




    edges_files = glob.glob(os.path.join(base_path, '*_edges.csv'))

    if not edges_files:
        print("[ERROR] No *_edges.csv file found in current directory")
        print(f"[ERROR] Searched in: {base_path}")
        print("[ERROR] Make sure rising_falling_edges.py has been run first")
        sys.exit(1)

    csv_path = edges_files[0]
    edges_filename = os.path.basename(csv_path)
    print(f"[INFO] Using edges file: {edges_filename}")

    rtl_name = edges_filename.replace('_edges.csv', '')
    print(f"[INFO] Detected RTL module name: {rtl_name}")

    df = pd.read_csv(csv_path, header=[0, 1, 2])

    edge_data = {}
    signal_types = {}

    for (class_type, sig, metric) in df.columns:
        if metric != 'clk_cycle':
            continue
        cycles = df[(class_type, sig, 'clk_cycle')].dropna().astype(int).tolist()
        edge_data.setdefault(sig, []).extend(cycles)
        signal_types[sig] = {"type": class_type.lower()}

    reset_deassert_cycles = {}

    for sig, meta in signal_types.items():
        if meta["type"].startswith("reset_active_"):
            polarity = meta["type"].split("_")[-1]
            edge_types = df[(meta["type"], sig, 'edge_type')].dropna().tolist()
            cycles = df[(meta["type"], sig, 'clk_cycle')].dropna().astype(int).tolist()

            for i in range(1, len(edge_types)):
                prev_edge, curr_edge = edge_types[i-1], edge_types[i]
                prev_cycle, curr_cycle = cycles[i-1], cycles[i]

                if polarity == "low":
                    if prev_edge == "falling" and curr_edge == "rising":
                        reset_deassert_cycles[sig] = curr_cycle
                        break
                elif polarity == "high":
                    if prev_edge == "rising" and curr_edge == "falling":
                        reset_deassert_cycles[sig] = curr_cycle
                        break

    def build_flatline_segments(total_cycles: int, edge_cycles: List[int]) -> List[Segment]:
        if not edge_cycles:
            return [Segment(0, total_cycles - 1, total_cycles)]
        cycles = sorted(edge_cycles)
        segments = []
        if cycles[0] > 0:
            segments.append(Segment(0, cycles[0] - 1, cycles[0]))
        for i in range(len(cycles) - 1):
            start = cycles[i] + 1
            end = cycles[i + 1] - 1
            if end >= start:
                segments.append(Segment(start, end, end - start + 1))
        if cycles[-1] < total_cycles - 1:
            segments.append(Segment(cycles[-1] + 1, total_cycles - 1,
                                    total_cycles - cycles[-1] - 1))
        return segments

    def classify_stuck(signal, edge_cycles, total_cycles, cfg, reset_deassert_cycle,
                       signal_type=None, expected_period=None):
        segments = build_flatline_segments(total_cycles, edge_cycles)
        longest = max((s.length for s in segments), default=0)
        longest_seg = max(segments, key=lambda s: s.length) if segments else None
        first_toggle = edge_cycles[0] if edge_cycles else None
        last_toggle = edge_cycles[-1] if edge_cycles else None
        notes, cats = [], []

        if not edge_cycles:
            cats.append("globally_stuck")
            notes.append("no edges detected")
            if reset_deassert_cycle is not None:
                cats.append("post_reset_likely_stuck")
            return StuckResult(signal, cats, longest, longest_seg,
                               None, None, notes, "high")

        if len(edge_cycles) == 1 and longest_seg and longest_seg.start >= edge_cycles[0]:
            cats.append("oneshot_stuck")

        if longest >= cfg.confirmed_min:
            cats.append("confirmed_stuck")
        elif longest >= cfg.likely_min:
            cats.append("likely_stuck")
        elif cfg.suspicious_min <= longest <= cfg.suspicious_max:
            cats.append("suspicious_flatline")

        if reset_deassert_cycle is not None:
            if first_toggle is None or first_toggle - reset_deassert_cycle > cfg.post_reset_window:
                cats.append("post_reset_likely_stuck")

        return StuckResult(signal, cats, longest, longest_seg,
                           first_toggle, last_toggle, notes,
                           assign_confidence(cats))

    cfg = StuckConfig()
    all_edge_cycles = [c for v in edge_data.values() for c in v]
    total_cycles = max(all_edge_cycles) + 1 if all_edge_cycles else len(df)
    reset_cycle = max(reset_deassert_cycles.values()) if reset_deassert_cycles else None

    results = []

    for sig, edges in edge_data.items():
        res = classify_stuck(sig, edges, total_cycles, cfg,
                             reset_cycle, signal_types[sig].get("type"))
        primary = pick_primary_category(res.categories)
        results.append({
            "signal": res.signal,
            "categories": res.categories,
            "stuck_reason": expand_category(primary),
            "confidence": res.confidence,
            "first_toggle_cycle": res.first_toggle_cycle,
            "last_toggle_cycle": res.last_toggle_cycle,
            "longest_flatline": res.longest_flatline,
            "flatline_start": res.longest_segment.start if res.longest_segment else None,
            "flatline_end": res.longest_segment.end if res.longest_segment else None,
            "notes": res.notes
        })

    high_conf = [r["signal"] for r in results if r["confidence"] == "high"]
    med_conf = [r["signal"] for r in results if r["confidence"] == "medium"]

    out_csv = os.path.join(base_path, f"{rtl_name}_stuck_signals.csv")
    pd.DataFrame(results).to_csv(out_csv, index=False)

    out_json = os.path.join(base_path, f"{rtl_name}_stuck_signals.json")
    with open(out_json, "w") as f:
        json.dump({
            "HighConfidenceSignals": high_conf,
            "MediumConfidenceSignals": med_conf,
            "Results": results
        }, f, indent=2)

    print(f"[OK] Analyzed {len(results)} signals "
          f"({len(high_conf)} high, {len(med_conf)} medium confidence)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
