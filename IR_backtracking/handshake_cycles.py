#!/usr/bin/env python3
"""
handshake_cycles.py — AXI4-Lite handshake cycle finder

Reads a preprocessed waveform CSV (all_signals_mapped.csv or similar) and
prints every AW / W / B handshake cycle, showing:
  - Burst start + end cycle for each channel
  - Whether each write transaction completed (BVALID fired) or was aborted
  - The cycle where BVALID fired (or the abort cycle if FSM jumped to idle)

Usage:
  python handshake_cycles.py <waveform.csv> [--fsm-signal w_state]

The output can be used to confirm which cycle numbers are used as backtrack
anchors in WaveEye's RCA engine (specifically for RULE_13 / RULE_6).
"""
from __future__ import annotations

import argparse
import csv
import sys
from typing import Dict, List, Optional, Tuple


# ── Signal name candidates ────────────────────────────────────────────────────
# Each entry is a list of candidate column names (case-insensitive).
_CANDIDATES: Dict[str, List[str]] = {
    "AWVALID": ["awvalid", "s_awvalid", "m_awvalid", "s_axi_awvalid"],
    "AWREADY": ["awready", "s_awready", "m_awready", "s_axi_awready"],
    "WVALID":  ["wvalid",  "s_wvalid",  "m_wvalid",  "s_axi_wvalid"],
    "WREADY":  ["wready",  "s_wready",  "m_wready",  "s_axi_wready"],
    "BVALID":  ["bvalid",  "s_bvalid",  "m_bvalid",  "s_axi_bvalid"],
    "BREADY":  ["bready",  "s_bready",  "m_bready",  "s_axi_bready"],
}


def _resolve(header: List[str], canonical: str) -> Optional[str]:
    """Return the actual column name matching the canonical AXI signal."""
    candidates = _CANDIDATES.get(canonical.upper(), [canonical.lower()])
    lc_header = {c.lower(): c for c in header}
    for cand in candidates:
        if cand.lower() in lc_header:
            return lc_header[cand.lower()]
    # Prefix-strip fallback: strip common AXI prefixes and compare
    for col in header:
        bare = col.lower()
        for pfx in ("s_axi_", "m_axi_", "s_axil_", "m_axil_", "axi_", "axil_",
                    "s_", "m_"):
            if bare.startswith(pfx):
                bare = bare[len(pfx):]
                break
        if bare == canonical.lower():
            return col
    return None


def _int_val(raw: str) -> Optional[int]:
    """Parse a CSV cell that might be blank, 'x', 'z', hex, etc."""
    s = raw.strip().lower()
    if not s or s in ("x", "z", "?", "u"):
        return None
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if s.startswith("0b"):
            return int(s, 2)
        return int(float(s))
    except ValueError:
        return None


def _read_csv(path: str) -> Tuple[List[str], List[Dict[str, str]]]:
    """
    Return (header, rows) from a CSV file.

    Handles the two-row header format used by WaveEye's preprocessed waveforms:
      Row 1: generic channel category names (axil_aw_channel, control_output…)
      Row 2: actual signal names (awvalid, awready, bvalid, w_state…)
      Row 3+: data

    Detection: if the second row looks like signal names (contains known AXI
    signal keywords), use it as the real header and skip row 1.
    """
    _AXI_KEYWORDS = {"awvalid", "awready", "wvalid", "wready", "bvalid", "bready",
                     "arvalid", "arready", "rvalid", "rready"}

    def _has_axi_keywords(row: List[str]) -> bool:
        """Return True if any cell contains an AXI keyword (handles prefixes)."""
        for cell in row:
            bare = cell.strip().lower()
            # Strip common AXI port prefixes
            for pfx in ("s_axi_", "m_axi_", "s_axil_", "m_axil_", "s_", "m_"):
                if bare.startswith(pfx):
                    bare = bare[len(pfx):]
                    break
            if bare in _AXI_KEYWORDS:
                return True
        return False

    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = list(csv.reader(fh))

    if len(raw) < 2:
        # Not enough rows
        header = [c.strip() for c in raw[0]] if raw else []
        return header, []

    # Check whether row 2 (index 1) looks like real signal names
    row1 = [c.strip() for c in raw[0]]
    row2 = [c.strip() for c in raw[1]]
    has_axi_in_row2 = _has_axi_keywords(row2)

    if has_axi_in_row2 and not _has_axi_keywords(row1):
        # Two-row header: use row2 as the actual column names
        real_header = [c.strip() for c in raw[1]]
        data_rows = raw[2:]
    else:
        real_header = [c.strip() for c in raw[0]]
        data_rows = raw[1:]

    # Build list of dicts
    rows: List[Dict[str, str]] = []
    for raw_row in data_rows:
        # Pad or truncate to header length
        padded = list(raw_row) + [""] * max(0, len(real_header) - len(raw_row))
        rows.append(dict(zip(real_header, padded)))

    return real_header, rows


def _find_bursts(
    rows: List[Dict[str, str]],
    cycle_col: str,
    sig_a: str,
    sig_b: str,
) -> List[Tuple[int, int]]:
    """
    Return list of (start_cycle, end_cycle) for each burst where both
    sig_a and sig_b are 1.  Consecutive cycles are merged into one burst.
    """
    bursts: List[Tuple[int, int]] = []
    in_burst = False
    burst_start = 0
    prev_cyc = -1
    for row in rows:
        cyc_raw = row.get(cycle_col, "")
        cyc = _int_val(cyc_raw)
        if cyc is None:
            continue
        a = _int_val(row.get(sig_a, ""))
        b = _int_val(row.get(sig_b, ""))
        active = (a == 1 and b == 1)
        if active and not in_burst:
            burst_start = cyc
            in_burst = True
        elif in_burst and (not active or cyc != prev_cyc + 1):
            bursts.append((burst_start, prev_cyc))
            in_burst = False
            if active:
                burst_start = cyc
                in_burst = True
        prev_cyc = cyc
    if in_burst:
        bursts.append((burst_start, prev_cyc))
    return bursts


def analyze(
    waveform_csv: str,
    fsm_signal: Optional[str] = None,
) -> None:
    header, rows = _read_csv(waveform_csv)

    # Auto-detect cycle column (first column is usually 'cycle' or 'time')
    cycle_col = header[0] if header else "cycle"

    # Resolve signal columns
    awvalid = _resolve(header, "AWVALID")
    awready = _resolve(header, "AWREADY")
    wvalid  = _resolve(header, "WVALID")
    wready  = _resolve(header, "WREADY")
    bvalid  = _resolve(header, "BVALID")
    bready  = _resolve(header, "BREADY")

    if not awvalid or not awready:
        print("ERROR: AWVALID / AWREADY not found in CSV header.")
        print(f"  Header: {header[:20]}")
        sys.exit(1)

    print(f"\nWaveform : {waveform_csv}")
    print(f"Cycle col: {cycle_col}")
    print(f"AWVALID  : {awvalid}")
    print(f"AWREADY  : {awready}")
    print(f"WVALID   : {wvalid or '(not found)'}")
    print(f"WREADY   : {wready or '(not found)'}")
    print(f"BVALID   : {bvalid or '(not found)'}")
    print(f"BREADY   : {bready or '(not found)'}")
    if fsm_signal:
        fsm_col = _resolve(header, fsm_signal) or fsm_signal
        print(f"FSM sig  : {fsm_col}")
    else:
        fsm_col = None
        # Auto-detect a state signal
        for col in header:
            if "state" in col.lower():
                fsm_col = col
                print(f"FSM sig  : {fsm_col} (auto-detected)")
                break

    print()

    # ── AW handshake bursts ──────────────────────────────────────────────────
    aw_bursts = _find_bursts(rows, cycle_col, awvalid, awready)
    print(f"AW handshake bursts ({len(aw_bursts)} total):")
    print(f"  {'#':<4} {'Start':>8} {'End':>8}  Completion")
    print(f"  {'-'*4} {'-'*8} {'-'*8}  {'-'*40}")

    # Build a lookup: cycle → row index for fast access
    cycle_to_row: Dict[int, int] = {}
    for i, row in enumerate(rows):
        cyc = _int_val(row.get(cycle_col, ""))
        if cyc is not None:
            cycle_to_row[cyc] = i

    max_cycle = max(cycle_to_row.keys()) if cycle_to_row else 0

    def _sig_at(sig: Optional[str], cyc: int) -> Optional[int]:
        if not sig:
            return None
        ridx = cycle_to_row.get(cyc)
        if ridx is None:
            return None
        return _int_val(rows[ridx].get(sig, ""))

    incomplete_bursts: List[int] = []  # start cycles of incomplete bursts

    for i, (bs, be) in enumerate(aw_bursts):
        # Next burst start (or end of waveform)
        next_start = aw_bursts[i + 1][0] if i + 1 < len(aw_bursts) else max_cycle + 1
        # Scan for BVALID between burst end and next burst start
        bvalid_cyc: Optional[int] = None
        if bvalid:
            for cyc in range(be + 1, next_start):
                if _sig_at(bvalid, cyc) == 1:
                    bvalid_cyc = cyc
                    break
        # Also scan for FSM abort (active→idle) in same window
        abort_cyc: Optional[int] = None
        if fsm_col:
            prev_v: Optional[int] = None
            for cyc in range(bs, next_start):
                v = _sig_at(fsm_col, cyc)
                if v is None:
                    continue
                if prev_v is not None and prev_v != 0 and v == 0:
                    abort_cyc = cyc
                    break
                prev_v = v

        if bvalid_cyc is not None:
            completion = f"COMPLETE  - BVALID at cycle {bvalid_cyc}"
        elif abort_cyc is not None:
            completion = f"ABORTED   - FSM->IDLE at cycle {abort_cyc}"
            incomplete_bursts.append(bs)
        else:
            completion = "INCOMPLETE - no BVALID observed"
            incomplete_bursts.append(bs)

        marker = " <-- FIRST INCOMPLETE" if incomplete_bursts and incomplete_bursts[0] == bs and bvalid_cyc is None else ""
        print(f"  {i+1:<4} {bs:>8} {be:>8}  {completion}{marker}")

    # ── W handshake bursts ───────────────────────────────────────────────────
    if wvalid and wready:
        w_bursts = _find_bursts(rows, cycle_col, wvalid, wready)
        print(f"\nW  handshake bursts ({len(w_bursts)} total):")
        print(f"  {'#':<4} {'Start':>8} {'End':>8}")
        print(f"  {'-'*4} {'-'*8} {'-'*8}")
        for i, (bs, be) in enumerate(w_bursts):
            print(f"  {i+1:<4} {bs:>8} {be:>8}")

    # ── B handshake bursts ───────────────────────────────────────────────────
    if bvalid and bready:
        b_bursts = _find_bursts(rows, cycle_col, bvalid, bready)
        print(f"\nB  handshake bursts ({len(b_bursts)} total):")
        print(f"  {'#':<4} {'Start':>8} {'End':>8}")
        print(f"  {'-'*4} {'-'*8} {'-'*8}")
        for i, (bs, be) in enumerate(b_bursts):
            print(f"  {i+1:<4} {bs:>8} {be:>8}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    if incomplete_bursts:
        print(f"First incomplete AW handshake cycle : {incomplete_bursts[0]}")
        print(f"  -> WaveEye RCA will anchor RULE_13 backtrack from cycle {incomplete_bursts[0]}")
    else:
        print("All AW handshakes completed (BVALID observed for each).")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find AXI4-Lite handshake cycles in a preprocessed waveform CSV."
    )
    parser.add_argument("waveform_csv", help="Path to preprocessed waveform CSV")
    parser.add_argument(
        "--fsm-signal", default=None,
        help="Name of the FSM state signal to track for abort detection (e.g. w_state)"
    )
    args = parser.parse_args()
    analyze(args.waveform_csv, fsm_signal=args.fsm_signal)


if __name__ == "__main__":
    main()
