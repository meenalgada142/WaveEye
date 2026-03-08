#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Temporal predicate reachability analysis (bounded, deterministic).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from utils import split_conditions, eval_expr, expand_row_with_aliases
except Exception:
    split_conditions = None
    eval_expr = None
    expand_row_with_aliases = None


def _to_bool(v: Any) -> Optional[bool]:
    if v is True or v == 1:
        return True
    if v is False or v == 0:
        return False
    return None


def _strip_outer_parens(expr: str) -> str:
    s = (expr or "").strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth == 0 and i != len(s) - 1:
                balanced = False
                break
        if not balanced:
            break
        s = s[1:-1].strip()
    return s


def _split_top_level_terms(cond: str) -> List[str]:
    """
    Use existing split helper first; fallback to shallow top-level splitting for & and |.
    """
    c = (cond or "").strip()
    if not c:
        return []
    if split_conditions is not None:
        terms = split_conditions(c)
        if len(terms) > 1:
            return terms

    s = _strip_outer_parens(c)
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            depth -= 1
            buf.append(ch)
            i += 1
            continue
        if depth == 0:
            two = s[i:i + 2]
            if two in ("&&", "||"):
                t = "".join(buf).strip()
                if t:
                    out.append(t)
                buf = []
                i += 2
                continue
            if ch in ("&", "|"):
                t = "".join(buf).strip()
                if t:
                    out.append(t)
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    t = "".join(buf).strip()
    if t:
        out.append(t)
    return out if out else [c]


def _eval_term(expr: str, row: Dict[str, Any]) -> Optional[bool]:
    if eval_expr is None:
        return None
    r = expand_row_with_aliases(row) if expand_row_with_aliases else row
    try:
        return _to_bool(eval_expr(expr, r))
    except TypeError:
        try:
            return _to_bool(eval_expr(expr, r, fsm_regs=None, fsm_enc=None))
        except Exception:
            return None
    except Exception:
        return None


def analyze_temporal_reachability(
    condition_str: str,
    waveform_rows: List[Dict[str, Any]],
    cycle_window: int,
) -> Dict[str, Any]:
    """
    Analyze each top-level term over a bounded cycle window.
    waveform_rows are ordered oldest->newest and may include '__cycle__'.
    """
    terms = _split_top_level_terms(condition_str)
    if cycle_window <= 0:
        cycle_window = 20
    rows = waveform_rows[-cycle_window:] if waveform_rows else []

    term_reports: List[Dict[str, Any]] = []
    blocking_terms: List[str] = []

    for term in terms:
        ever_true = False
        first_true_cycle = None

        for idx, row in enumerate(rows):
            v = _eval_term(term, row)
            if v is True:
                ever_true = True
                cyc = row.get("__cycle__")
                first_true_cycle = cyc if isinstance(cyc, int) else idx
                break

        if not ever_true:
            blocking_terms.append(term)

        term_reports.append(
            {
                "expression": term,
                "ever_true": ever_true,
                "first_true_cycle": first_true_cycle,
            }
        )

    classification = "UNREACHABLE_ENABLE_CONDITION" if blocking_terms else "TEMPORAL_DELAY"

    return {
        "condition": condition_str,
        "terms": term_reports,
        "blocking_terms": blocking_terms,
        "classification": classification,
    }

