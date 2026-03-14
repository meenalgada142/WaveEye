from __future__ import annotations

from typing import Any, Dict, List, Optional

from utils import eval_rhs_expression, eval_rhs_numeric, expand_row_with_aliases, parse_literal_token

from .io import WaveformView


def _eval_rhs(rhs: str, row: Dict[str, Any]) -> Optional[int]:
    if not rhs:
        return None
    value = None
    try:
        value = eval_rhs_expression(rhs, row)
    except Exception:
        value = None
    if value is None:
        try:
            value = eval_rhs_numeric(rhs, row)
        except Exception:
            value = None
    if isinstance(value, str):
        parsed = parse_literal_token(value)
        if parsed is not None:
            value = parsed
        else:
            try:
                value = int(value)
            except Exception:
                return None
    if value is None:
        parsed_rhs = parse_literal_token(rhs)
        if parsed_rhs is not None:
            value = parsed_rhs
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _active_drivers_for_signal(
    waveform: WaveformView,
    logic_table: Dict[str, List[Dict[str, Any]]],
    signal: str,
    cycle: int,
) -> List[Dict[str, Any]]:
    active: List[Dict[str, Any]] = []
    for idx, drv in enumerate(logic_table.get(signal, [])):
        cond = (drv.get("cond") or drv.get("condition") or "").strip()
        sensitivity = str(drv.get("sensitivity") or "").lower()
        eval_cycle = cycle
        # For edge-triggered drivers, predicates are sampled before register update.
        if ("posedge" in sensitivity or "negedge" in sensitivity) and cycle > 0:
            eval_cycle = cycle - 1

        _, eval_row = waveform.row_at_cycle(eval_cycle)
        row_ext = expand_row_with_aliases(eval_row)
        cond_true = True if not cond else waveform.condition_true(cond, eval_cycle)
        if cond_true is not True:
            continue
        rhs = (drv.get("rhs") or "").strip()
        rhs_val = _eval_rhs(rhs, row_ext)
        active.append(
            {
                "driver_idx": drv.get("driver_idx", idx),
                "condition": cond,
                "rhs": rhs,
                "rhs_value": rhs_val,
                "condition_true": True,
                "eval_cycle": eval_cycle,
                "sensitivity": drv.get("sensitivity"),
            }
        )
    return active


def detect_intra_cycle_cancellation(
    waveform: WaveformView,
    logic_table: Dict[str, List[Dict[str, Any]]],
    signal: str,
    t_eval: int,
    expected_value: int,
    lookahead_cycles: int = 0,
    gate_signals: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Detect whether an expected transition was cancelled by conflicting writes in
    the same timestep (or immediate lookahead cycle for registered overwrite).
    """
    gate_signals = list(gate_signals or [])
    expected_value = int(expected_value)

    for probe_cycle in range(int(t_eval), int(t_eval) + max(0, int(lookahead_cycles)) + 1):
        active = _active_drivers_for_signal(waveform, logic_table, signal, probe_cycle)
        if len(active) < 2:
            continue

        assigned_values: List[int] = [
            int(d["rhs_value"]) for d in active if d.get("condition_true") and d.get("rhs_value") is not None
        ]
        if len(set(assigned_values)) <= 1:
            continue
        if expected_value not in assigned_values:
            continue

        final_val = waveform.signal_value(signal, probe_cycle)
        if final_val is None or int(final_val) == expected_value:
            continue

        expected_conds = [d["condition"] for d in active if d.get("rhs_value") == expected_value]
        overwrite_conds = [d["condition"] for d in active if d.get("rhs_value") == final_val]

        ready_high: List[str] = []
        for g in gate_signals:
            gv = waveform.signal_value(g, probe_cycle)
            if gv == 1:
                ready_high.append(g)

        return {
            "detected": True,
            "anchor_cycle": int(t_eval),
            "analysis_cycle": probe_cycle,
            "expected_value": expected_value,
            "final_value": int(final_val),
            "conflict_values": sorted(set(assigned_values)),
            "expected_driver_conditions": expected_conds,
            "final_overwrite_conditions": overwrite_conds,
            "active_drivers": active,
            "ready_signals_high_next_cycle": ready_high if probe_cycle > int(t_eval) else [],
        }

    return {
        "detected": False,
        "anchor_cycle": int(t_eval),
        "analysis_cycle": int(t_eval),
    }


def find_first_cancellation(
    waveform: WaveformView,
    logic_table: Dict[str, List[Dict[str, Any]]],
    signal: str,
    expected_value: int = 1,
    start_cycle: int = 0,
    end_cycle: Optional[int] = None,
    lookahead_cycles: int = 0,
) -> Dict[str, Any]:
    end = waveform.max_cycle if end_cycle is None else min(int(end_cycle), waveform.max_cycle)
    for cycle in range(max(0, int(start_cycle)), end + 1):
        result = detect_intra_cycle_cancellation(
            waveform=waveform,
            logic_table=logic_table,
            signal=signal,
            t_eval=cycle,
            expected_value=expected_value,
            lookahead_cycles=lookahead_cycles,
        )
        if result.get("detected"):
            return result
    return {"detected": False}
