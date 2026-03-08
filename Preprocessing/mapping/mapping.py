#!/usr/bin/env python3
"""
Waveform signal mapping -- streaming, pandas-free.

Transforms a raw waveform CSV into a normalized AXI signal CSV by:
  1. Reading <module>_signals.json for the desired signal set.
  2. Optionally reading a connectivity JSON to resolve cross-module aliases.
  3. Streaming the waveform CSV row-by-row (O(1) memory, multi-GB capable).
  4. Writing output with csv.writer using the canonical downstream column order.

CLI (unchanged from previous version):
  python mapping.py signals.json waveform.csv output.csv --connectivity system.json
"""
import csv
import json
import argparse
import re
import sys
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ─── signal name normalization ─────────────────────────────────────────────────

def normalize(name: str) -> str:
    """
    Normalize signal name for matching.
      soc_tb.dut.uart_busy       -> uart_busy
      soc_tb.dut.u_uart.tx_busy  -> u_uart.tx_busy
      reg0[31:0]                 -> reg0
    """
    name = re.sub(r'^[^.]*\.dut\.', '', name)
    name = re.sub(r'^[^.]*\.tb\.', '', name)
    name = re.sub(r'^top\.', '', name)
    name = re.sub(r'\[.*?\]', '', name)
    return name.lower()


# ─── metadata loading ──────────────────────────────────────────────────────────

def load_metadata(path: str) -> Tuple[Dict[str, str], List[str]]:
    """Load signal->class mapping from .json or .csv metadata file."""
    if path.lower().endswith('.json'):
        return _load_metadata_json(path)
    elif path.lower().endswith('.csv'):
        return _load_metadata_csv(path)
    raise ValueError(f"Unsupported metadata format: {path!r}. Expected .json or .csv")


def _load_metadata_json(path: str) -> Tuple[Dict[str, str], List[str]]:
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    mapping: Dict[str, str] = data.get('signals', {})
    clocks = [s for s, c in mapping.items() if c.lower() == 'clock']
    return mapping, clocks


def _load_metadata_csv(path: str) -> Tuple[Dict[str, str], List[str]]:
    with open(path, newline='', encoding='utf-8') as f:
        next(f)  # skip descriptor/header line
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []
        signal_col = next((h for h in headers if 'signal' in h.lower()), None)
        class_col  = next((h for h in headers if 'class'  in h.lower()), None)
        if not signal_col or not class_col:
            raise ValueError("Metadata CSV must have 'signal' and 'class' columns")
        mapping: Dict[str, str] = {}
        clocks: List[str] = []
        for row in reader:
            sig = row[signal_col].strip()
            cls = row[class_col].strip()
            mapping[sig] = cls
            if cls.lower() == 'clock':
                clocks.append(sig)
    return mapping, clocks


# ─── connectivity loading ──────────────────────────────────────────────────────

def load_connectivity(path: Optional[str]):
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def build_connection_map(connectivity) -> Dict[str, List[str]]:
    """Build bidirectional signal->connected_signals lookup from connectivity JSON."""
    if not connectivity:
        return {}
    conn_map: Dict[str, List[str]] = {}
    for conn in connectivity.get('connections_direct', []):
        parent_mod = conn['parent_module']
        parent_sig = conn['parent_signal']
        instance   = conn['instance']
        child_port = conn['child_port']

        parent_names = [
            parent_sig,
            f"{parent_mod}.{parent_sig}",
            parent_sig.split('[')[0],
        ]
        child_names = [
            child_port,
            f"{instance}.{child_port}",
            child_port.split('[')[0],
        ]
        for p in parent_names:
            for c in child_names:
                conn_map.setdefault(p, []).append(c)
                conn_map.setdefault(c, []).append(p)

    # deduplicate, preserving first-seen order
    for key in conn_map:
        seen: Dict[str, None] = {}
        conn_map[key] = [seen.setdefault(x, x) for x in conn_map[key] if x not in seen]
    return conn_map


# ─── header-level signal matching (runs once, not per row) ────────────────────

def _build_meta_norm(metadata_map: Dict[str, str]) -> Dict[str, str]:
    """Build {normalized_form -> meta_signal_name} lookup."""
    meta_norm: Dict[str, str] = {}
    for meta_sig in metadata_map:
        meta_norm[normalize(meta_sig)] = meta_sig
        meta_norm[meta_sig.split('.')[-1].lower()] = meta_sig
    return meta_norm


def match_headers_to_metadata(
    wf_headers: List[str],
    metadata_map: Dict[str, str],
) -> Dict[str, str]:
    """
    Build {waveform_column -> meta_signal} from the waveform header only.
    Applies the same four progressive matching strategies as the original code.
    """
    meta_norm = _build_meta_norm(metadata_map)
    mapping: Dict[str, str] = {}

    for wf_sig in wf_headers:
        # Strategy 1: full normalized match
        cleaned = normalize(wf_sig)
        if cleaned in meta_norm:
            mapping[wf_sig] = meta_norm[cleaned]
            continue

        # Strategy 2: last-component match
        wf_base = re.sub(r'\[.*?\]', '', wf_sig.split('.')[-1]).lower()
        if wf_base in meta_norm:
            mapping[wf_sig] = meta_norm[wf_base]
            continue

        # Strategy 3: two-level instance.signal match (e.g. u_uart.tx_busy)
        if '.' in cleaned:
            parts = cleaned.split('.')
            two_level = '.'.join(parts[-2:])
            if two_level in meta_norm:
                mapping[wf_sig] = meta_norm[two_level]
                continue

    return mapping


def _find_connected_col(
    meta_sig: str,
    wf_headers: List[str],
    conn_map: Dict[str, List[str]],
) -> Optional[str]:
    """
    Resolve the waveform column connected to meta_sig via conn_map.
    Mirrors the four strategies from the original find_connected_signal().
    Called once per signal before streaming starts.
    """
    if not conn_map or meta_sig not in conn_map:
        return None
    for connected_sig in conn_map[meta_sig]:
        # Strategy 1: exact
        if connected_sig in wf_headers:
            return connected_sig
        # Strategy 2: normalized
        norm_target = normalize(connected_sig)
        for h in wf_headers:
            if normalize(h) == norm_target:
                return h
        # Strategy 3: last-component
        target_base = connected_sig.split('.')[-1].lower()
        for h in wf_headers:
            h_base = re.sub(r'\[.*?\]', '', h.split('.')[-1]).lower()
            if h_base == target_base:
                return h
        # Strategy 4: suffix match
        for h in wf_headers:
            if h.endswith('.' + connected_sig) or h.endswith('_' + connected_sig):
                return h
    return None


# ─── value helper ─────────────────────────────────────────────────────────────

def is_empty_value(val: str) -> bool:
    """
    True only for truly missing values.
    'x' and 'z' are valid HDL states and must NOT be treated as empty.
    """
    v = val.strip()
    return not v or v in {'-', '?'}


# ─── column plan (precomputed once before streaming) ──────────────────────────

def build_column_plan(
    metadata_map: Dict[str, str],
    clock_signals: List[str],
    wf_headers: List[str],
    conn_map: Dict[str, List[str]],
) -> Tuple[str, Optional[str], List[str], List[str], Dict[str, Tuple[Optional[str], Optional[str]]]]:
    """
    Precompute everything needed for the O(1)-per-row streaming pass.

    Returns:
        time_col     -- waveform column for the time axis
        clock_col    -- meta_signal name for the clock (or None)
        ordered_cols -- output column order
        class_row    -- first CSV row (signal class labels)
        col_plan     -- meta_sig -> (primary_wf_col, fallback_wf_col)
    """
    time_col = next((c for c in wf_headers if c.startswith('time_')), None)
    if time_col is None:
        raise ValueError(
            "Waveform CSV has no 'time_*' column "
            "(expected time_ps / time_ns / time_us)"
        )

    # waveform_col -> meta_sig  (from header only, once)
    signal_map = match_headers_to_metadata(wf_headers, metadata_map)

    # reverse: meta_sig -> waveform_col
    meta_to_wf: Dict[str, str] = {v: k for k, v in signal_map.items()}

    # clock column
    clock_col: Optional[str] = None
    for meta_sig in clock_signals:
        if meta_sig in meta_to_wf:
            clock_col = meta_sig
            break

    # ordered output columns: time | clock? | all meta signals
    ordered_cols: List[str] = [time_col]
    if clock_col:
        ordered_cols.append(clock_col)
    for s in metadata_map:
        if s not in ordered_cols:
            ordered_cols.append(s)

    # class row (row 0 of output CSV)
    class_row: List[str] = []
    for col in ordered_cols:
        if col == time_col:
            class_row.append('')
        elif col == clock_col:
            class_row.append('clock')
        else:
            class_row.append(metadata_map.get(col, 'other'))

    # per-signal plan: (primary_wf_col, fallback_wf_col)
    col_plan: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    for meta_sig in metadata_map:
        primary  = meta_to_wf.get(meta_sig)
        fallback = _find_connected_col(meta_sig, wf_headers, conn_map) if conn_map else None
        col_plan[meta_sig] = (primary, fallback)

    return time_col, clock_col, ordered_cols, class_row, col_plan


# ─── fast-fail validation + mapping summary ───────────────────────────────────

def validate_and_summarise(
    metadata_map: Dict[str, str],
    col_plan: Dict[str, Tuple[Optional[str], Optional[str]]],
    wf_headers: List[str],
) -> None:
    """
    Print a mapping summary and exit(1) if no signals could be resolved.
    Must be called BEFORE the streaming pass.
    """
    n_requested = len(metadata_map)
    missing  = [s for s, (p, _) in col_plan.items() if p is None]
    n_resolved = n_requested - len(missing)
    n_missing  = len(missing)

    print("Mapping Summary:")
    print(f"  Signals requested : {n_requested}")
    print(f"  Signals resolved  : {n_resolved}")
    print(f"  Missing           : {n_missing}")
    if missing:
        limit = 10
        for m in missing[:limit]:
            print(f"    - {m}")
        if n_missing > limit:
            print(f"    ... and {n_missing - limit} more")

    if n_resolved == 0:
        print("ERROR: No AXI signals could be mapped to waveform columns.", file=sys.stderr)
        print(f"  Waveform columns (first 10): {wf_headers[:10]}", file=sys.stderr)
        sys.exit(1)


# ─── streaming transform ──────────────────────────────────────────────────────

def stream_transform(
    waveform_path: str,
    output_path: str,
    time_col: str,
    ordered_cols: List[str],
    class_row: List[str],
    col_plan: Dict[str, Tuple[Optional[str], Optional[str]]],
    progress_interval: int = 100_000,
) -> int:
    """
    Stream waveform CSV -> output CSV without loading into memory.
    Returns total row count processed.
    """
    # Build ordered action list: [(meta_sig, primary_wf_col, fallback_wf_col)]
    # Time column is handled separately (always the first output field).
    plan_ordered: List[Tuple[str, Optional[str], Optional[str]]] = [
        (col, col_plan[col][0], col_plan[col][1])
        for col in ordered_cols
        if col != time_col
    ]

    with (
        open(waveform_path, newline='', encoding='utf-8') as fin,
        open(output_path,   'w', newline='', encoding='utf-8') as fout,
    ):
        reader = csv.DictReader(fin)
        writer = csv.writer(fout)

        writer.writerow(class_row)     # row 0: class labels
        writer.writerow(ordered_cols)  # row 1: column names

        row_count = 0
        for raw in reader:
            out_row = [raw.get(time_col, '')]
            for _meta_sig, primary, fallback in plan_ordered:
                value = raw.get(primary, '') if primary else ''
                if is_empty_value(value) and fallback:
                    fb_val = raw.get(fallback, '')
                    if not is_empty_value(fb_val):
                        value = fb_val
                out_row.append(value)
            writer.writerow(out_row)
            row_count += 1

            if progress_interval > 0 and row_count % progress_interval == 0:
                print(f"[mapping] processed {row_count:,} rows...")

    return row_count


# ─── entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Map waveform values to RTL signals (streaming, pandas-free)'
    )
    parser.add_argument('metadata_file', help='Path to signals.json or signals.csv')
    parser.add_argument('waveform_csv',  help='Waveform CSV generated by VCD converter')
    parser.add_argument('output_csv', nargs='?',
                        help='Output CSV path (auto-generated if omitted)')
    parser.add_argument('--connectivity', '-c',
                        help='Optional: system connectivity JSON from classify_system.py',
                        default=None)
    parser.add_argument('--rtl-name',
                        help='RTL module name for output file (e.g. uart_tx)')
    parser.add_argument('--progress-interval', type=int, default=100_000,
                        help='Print progress every N rows (0 = silent, default 100000)')
    args = parser.parse_args()

    try:
        t0 = time.perf_counter()

        # Auto-generate output path if not provided
        if not args.output_csv:
            if args.rtl_name:
                args.output_csv = f"{args.rtl_name}_mapped.csv"
            else:
                base = os.path.splitext(os.path.basename(args.waveform_csv))[0]
                args.output_csv = f"{base}_mapped.csv"

        # ── Phase 1: load metadata and connectivity (small files, O(signals)) ──
        metadata_map, clock_signals = load_metadata(args.metadata_file)
        connectivity = load_connectivity(args.connectivity)
        conn_map = build_connection_map(connectivity) if connectivity else {}

        # ── Phase 2: read waveform HEADER ONLY -- zero rows loaded into memory ──
        with open(args.waveform_csv, newline='', encoding='utf-8') as f:
            wf_reader = csv.DictReader(f)
            # Reading fieldnames consumes only the header line.
            wf_headers = list(wf_reader.fieldnames or [])

        if not wf_headers:
            print('ERROR: Waveform CSV has no header row.', file=sys.stderr)
            sys.exit(1)

        time_col, _clock_col, ordered_cols, class_row, col_plan = build_column_plan(
            metadata_map, clock_signals, wf_headers, conn_map
        )

        # ── Phase 3: fast-fail validation + mapping summary ────────────────────
        validate_and_summarise(metadata_map, col_plan, wf_headers)

        # ── Phase 4: streaming transform (O(1) memory) ─────────────────────────
        total_rows = stream_transform(
            waveform_path=args.waveform_csv,
            output_path=args.output_csv,
            time_col=time_col,
            ordered_cols=ordered_cols,
            class_row=class_row,
            col_plan=col_plan,
            progress_interval=args.progress_interval,
        )

        elapsed = time.perf_counter() - t0
        print(f"OK: {args.output_csv}")
        print(f"Completed mapping in {elapsed:.2f}s  ({total_rows:,} rows)")

    except SystemExit:
        raise
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
