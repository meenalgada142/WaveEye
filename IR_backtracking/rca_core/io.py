from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils import (
    detect_clock,
    eval_expr,
    expand_row_with_aliases,
    get_signal_value,
    load_waveform_csv,
    parse_literal_token,
)


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        try:
            return int(float(s))
        except ValueError:
            return None


def load_waveform_file(path: str) -> Tuple[List[Dict[str, str]], List[str], List[str], Optional[str]]:
    wave, header, classifications = load_waveform_csv(path)
    clock_sig = detect_clock(path)
    return wave, header, classifications, clock_sig


def load_driver_table(path: str) -> Dict[str, List[Dict[str, Any]]]:
    table: Dict[str, List[Dict[str, Any]]] = {}
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sig = (row.get("signal") or "").strip()
            if not sig:
                continue
            table.setdefault(sig, []).append(
                {
                    "signal": sig,
                    "driver_idx": _to_int(row.get("driver_idx")),
                    "cond": (row.get("condition") or "").strip(),
                    "rhs": (row.get("rhs") or "").strip(),
                    "sensitivity": (row.get("sensitivity") or "").strip(),
                    "assign_type": (row.get("assign_type") or "").strip(),
                    "always_block_id": _to_int(row.get("always_block_id")),
                    "file": (row.get("file") or "").strip() or None,
                }
            )
    return table


def load_violations_file(path: Optional[str]) -> List[Dict[str, Any]]:
    if not path:
        return []
    if path.lower().endswith(".json"):
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        if isinstance(payload, list):
            data = payload
        elif isinstance(payload, dict):
            data = payload.get("violations", [])
        else:
            data = []
        if not isinstance(data, list):
            return []
        return [dict(x) for x in data if isinstance(x, dict)]

    out: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            out.append(dict(row))
    return out


@dataclass
class CycleResolution:
    cycle: int
    row_idx: int


class WaveformView:
    def __init__(
        self,
        rows: List[Dict[str, str]],
        header: Optional[List[str]] = None,
        classifications: Optional[List[str]] = None,
        clock_signal: Optional[str] = None,
    ) -> None:
        self.rows = rows or []
        self.header = header or []
        self.classifications = classifications or []
        self.clock_signal = (clock_signal or "").strip() or None
        self.time_column = self._detect_time_column()
        self.time_to_row = self._build_time_index()
        self.cycle_to_row, self.row_to_cycle, self.cycle_period = self._build_cycle_index()
        self._expanded_row_cache: Dict[int, Dict[str, Any]] = {}

    def _detect_time_column(self) -> Optional[str]:
        if not self.rows:
            return None
        probe = self.rows[0]
        for candidate in ("time_ps", "time_ns", "time", "timestamp"):
            if candidate in probe:
                return candidate
        return None

    def _build_time_index(self) -> Dict[int, int]:
        if not self.time_column:
            return {}
        out: Dict[int, int] = {}
        for idx, row in enumerate(self.rows):
            key = _to_int(row.get(self.time_column))
            if key is not None:
                out[key] = idx
        return out

    def _build_cycle_index(self) -> Tuple[Dict[int, int], Dict[int, int], Optional[int]]:
        if not self.rows:
            return {}, {}, None

        # Fallback index on raw row numbers.
        identity = {i: i for i in range(len(self.rows))}
        if not self.clock_signal or self.clock_signal not in self.rows[0]:
            return identity, dict(identity), None

        cycle_to_row: Dict[int, int] = {}
        row_to_cycle: Dict[int, int] = {}
        posedge_times: List[int] = []

        prev_clk: Optional[int] = None
        cycle_num = -1
        for row_idx, row in enumerate(self.rows):
            clk_val = parse_literal_token(row.get(self.clock_signal))
            if clk_val is None:
                continue
            clk_int = int(clk_val)
            if prev_clk == 0 and clk_int == 1:
                cycle_num += 1
                cycle_to_row[cycle_num] = row_idx
                if self.time_column:
                    t = _to_int(row.get(self.time_column))
                    if t is not None:
                        posedge_times.append(t)
            if cycle_num >= 0:
                row_to_cycle[row_idx] = cycle_num
            prev_clk = clk_int

        if not cycle_to_row:
            return identity, dict(identity), None

        period = None
        if len(posedge_times) >= 2:
            diffs = [b - a for a, b in zip(posedge_times[:-1], posedge_times[1:]) if b > a]
            if diffs:
                diffs_sorted = sorted(diffs)
                period = diffs_sorted[len(diffs_sorted) // 2]

        return cycle_to_row, row_to_cycle, period

    @property
    def max_cycle(self) -> int:
        if not self.cycle_to_row:
            return 0
        return max(self.cycle_to_row.keys())

    @property
    def signals(self) -> Iterable[str]:
        if self.header:
            return self.header
        if not self.rows:
            return []
        return self.rows[0].keys()

    def resolve_cycle(self, cycle_hint: int) -> CycleResolution:
        if not self.rows:
            return CycleResolution(cycle=0, row_idx=0)

        hint = int(cycle_hint)

        if hint in self.cycle_to_row:
            return CycleResolution(cycle=hint, row_idx=self.cycle_to_row[hint])

        # Timestamp-space input support (e.g. violation timestamp key).
        if hint in self.time_to_row:
            row_idx = self.time_to_row[hint]
            cycle = self.row_to_cycle.get(row_idx, row_idx)
            return CycleResolution(cycle=cycle, row_idx=row_idx)

        # Approximate timestamp->cycle conversion from measured clock period.
        if self.cycle_period and self.cycle_to_row:
            est_cycle = int(round(hint / self.cycle_period))
            if est_cycle in self.cycle_to_row:
                return CycleResolution(cycle=est_cycle, row_idx=self.cycle_to_row[est_cycle])
            max_cycle = self.max_cycle
            if est_cycle > max_cycle:
                return CycleResolution(cycle=max_cycle, row_idx=self.cycle_to_row[max_cycle])

        if self.cycle_to_row:
            max_cycle = self.max_cycle
            clamped = min(max(hint, 0), max_cycle)
            return CycleResolution(cycle=clamped, row_idx=self.cycle_to_row[clamped])

        row_idx = min(max(hint, 0), len(self.rows) - 1)
        return CycleResolution(cycle=row_idx, row_idx=row_idx)

    def row_at_cycle(self, cycle_hint: int) -> Tuple[int, Dict[str, str]]:
        resolved = self.resolve_cycle(cycle_hint)
        return resolved.cycle, self.rows[resolved.row_idx]

    def signal_value(self, signal: str, cycle_hint: int) -> Optional[int]:
        _, row = self.row_at_cycle(cycle_hint)
        raw = get_signal_value(signal, row)
        if raw is None:
            return None
        parsed = parse_literal_token(raw)
        if parsed is not None:
            return int(parsed)
        return _to_int(raw)

    def condition_true(self, expr: str, cycle_hint: int) -> Optional[bool]:
        if not expr:
            return None
        resolved = self.resolve_cycle(cycle_hint)
        row = self.rows[resolved.row_idx]
        row_idx = resolved.row_idx
        row_ext = self._expanded_row_cache.get(row_idx)
        if row_ext is None:
            row_ext = expand_row_with_aliases(row)
            self._expanded_row_cache[row_idx] = row_ext
        try:
            value = eval_expr(expr, row_ext)
        except TypeError:
            try:
                value = eval_expr(expr, row_ext, fsm_regs=None, fsm_enc=None)
            except Exception:
                return None
        except Exception:
            return None

        if value in (True, 1):
            return True
        if value in (False, 0):
            return False
        return None

    def iter_cycles(self, start_cycle: int = 0, end_cycle: Optional[int] = None) -> Iterable[Tuple[int, Dict[str, str]]]:
        if not self.cycle_to_row:
            return
        stop = self.max_cycle if end_cycle is None else min(end_cycle, self.max_cycle)
        for cycle in range(max(start_cycle, 0), stop + 1):
            row_idx = self.cycle_to_row.get(cycle)
            if row_idx is None:
                continue
            yield cycle, self.rows[row_idx]

