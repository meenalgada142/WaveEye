#!/usr/bin/env python3
"""
rca_core/predicate_backtrack.py
================================
Predicate-level backtracking engine — logic ported from rca_7.

Evaluates every RTL driver for a signal at a violation cycle against
actual waveform values, detects driver overwrites and blocked asserting
drivers, then builds a recursive causal chain exactly like rca_7's
STEP 3 (predicate-level backtracking) output.

Resolution modes (mirrors rca_7):
  MODE-A (UNEXPECTED_ASSERTION):   signal is 1, correct driver is ACTIVE.
                                   Backtrack TRUE terms → why did this fire?
  MODE-A (BLOCKED_ASSERTER):       signal is 0, asserting driver is INACTIVE.
                                   Winning driver (→0) is ACTIVE → overwrite.
  MODE-B (UNSATISFIED_ENABLE):     asserting driver INACTIVE, false term blocks.
                                   Backtrack the blocking false term.
  DERIVED:                         normal active driver with derived signal(s).
  LEAF:                            no RTL driver (primary input / constant).

Public API
----------
  evaluate_all_drivers(signal, logic, view, cycle) -> List[DriverEval]
  detect_overwrite(sig_val, driver_evals)           -> Dict | None
  build_causal_chain_trace(signal, logic, view, cycle, max_depth) -> ChainNode
  format_driver_table(signal, cycle, driver_evals, view)          -> str
  format_causal_chain(chain_node, view)                           -> str
  format_full_trace(signal, cycle, logic, view, rule_id)          -> str
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

try:
    from utils import split_conditions
except ImportError:
    def split_conditions(expr: str) -> List[str]:
        if not expr:
            return []
        return [t.strip() for t in expr.replace("&&", "\n").split("\n") if t.strip()]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IDENT = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')
_KW = frozenset({
    "and", "or", "not", "if", "else", "true", "false",
    "posedge", "negedge", "reg", "wire", "input", "output",
    "inout", "assign", "begin", "end",
})
_RESET_KW  = frozenset({"reset", "rst", "areset", "arestn", "aresetn", "nreset", "arstn"})
_FSM_KW    = frozenset({"state", "_state", "state_"})
_ASSERT_RHS = frozenset({"1", "1'b1", "1'h1"})
_DEFAULT_DEPTH = 6


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _rtl_line_from_loc(loc: Any) -> Optional[int]:
    """Extract a trailing RTL line number from 'file:line' style locations."""
    text = str(loc or "").strip()
    if not text:
        return None
    match = re.search(r":(\d+)(?::\d+)?$", text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None

def _tag_driver(drv: Dict) -> str:
    """Classify a driver as RESET / FSM / DEFAULT / LOGIC (mirrors rca_7)."""
    cond = (drv.get("condition") or drv.get("cond") or "").lower().strip()
    if not cond or cond in ("1", "true", "1'b1"):
        return "DEFAULT"
    if any(kw in cond for kw in _RESET_KW):
        return "RESET"
    if any(kw in cond for kw in _FSM_KW):
        return "FSM"
    return "LOGIC"


def _is_asserting(rhs: str) -> bool:
    return rhs.strip() in _ASSERT_RHS


def _resolve_logic_key(signal: str, logic: Dict) -> Optional[str]:
    """Find the actual logic-table key for `signal`, tolerating case/prefix."""
    if signal in logic:
        return signal
    sig_lower = signal.lower()
    for k in logic:
        kl = k.lower()
        if kl == sig_lower or kl.endswith(sig_lower) or sig_lower.endswith(kl):
            return k
    return None


def _sig_val_annotation(tokens: List[str], view: Any, cycle: int) -> str:
    """Return ' [sig1=v1, sig2=v2]' for non-keyword tokens found in waveform."""
    parts = []
    seen: Set[str] = set()
    for tok in tokens:
        if tok.lower() in _KW or tok in seen:
            continue
        seen.add(tok)
        try:
            v = view.signal_value(tok, cycle)
            if v is None:
                v = view.signal_value(tok.lower(), cycle)
            if v is not None:
                parts.append(f"{tok}={v}")
        except Exception:
            pass
    return ("  [" + ", ".join(parts) + "]") if parts else ""


def _term_annotation(term: str, view: Any, cycle: int) -> str:
    return _sig_val_annotation(_IDENT.findall(term), view, cycle)


# ---------------------------------------------------------------------------
# Driver evaluation
# ---------------------------------------------------------------------------

def evaluate_all_drivers(
    signal: str,
    logic: Dict[str, List[Dict]],
    view: Any,
    cycle: int,
) -> List[Dict]:
    """
    Evaluate every RTL driver for `signal` at `cycle` against waveform.

    Returns list of DriverEval dicts:
        driver_idx        int
        condition         str
        rhs               str
        assign_type       str
        always_block_id   int | None
        tag               str            (RESET / FSM / LOGIC / DEFAULT)
        is_asserting      bool           (rhs == 1)
        condition_active  bool | None
        true_terms        list[str]
        false_terms       list[str]
        first_false_term  str | None     (first blocking term for inactive drivers)
        term_values       dict[str, bool | None]
        rhs_sig_values    dict[str, Any] (waveform values of signals in RHS)
    """
    key = _resolve_logic_key(signal, logic)
    if key is None:
        return []

    results: List[Dict] = []
    for d_idx, drv in enumerate(logic[key]):
        cond  = (drv.get("condition") or drv.get("cond") or "").strip()
        rhs   = (drv.get("rhs") or "").strip()
        atype = (drv.get("assign_type") or drv.get("block_type") or "").strip()
        blk   = drv.get("always_block_id")
        src   = (drv.get("file") or drv.get("source_location") or "").strip()
        rtl_line = _rtl_line_from_loc(src)

        # Whole-condition evaluation
        try:
            cond_active: Optional[bool] = (
                view.condition_true(cond, cycle) if cond else True
            )
        except Exception:
            cond_active = None

        # Per-term evaluation (rca-7 style: split && terms, evaluate each)
        terms = split_conditions(cond) if cond else []
        true_terms:  List[str] = []
        false_terms: List[str] = []
        term_values: Dict[str, Any] = {}
        first_false: Optional[str] = None

        for term in terms:
            try:
                result = view.condition_true(term, cycle)
                term_values[term] = result
                if result is True:
                    true_terms.append(term)
                elif result is False:
                    false_terms.append(term)
                    if first_false is None:
                        first_false = term
            except Exception:
                term_values[term] = None

        # Waveform values of signals referenced in RHS (for display)
        rhs_sig_values: Dict[str, Any] = {}
        for tok in _IDENT.findall(rhs):
            if tok.lower() not in _KW:
                try:
                    v = view.signal_value(tok, cycle)
                    rhs_sig_values[tok] = v
                except Exception:
                    rhs_sig_values[tok] = None

        results.append({
            "driver_idx":       d_idx,
            "condition":        cond,
            "rhs":              rhs,
            "assign_type":      atype,
            "always_block_id":  blk,
            "file":             src,
            "source_location":  src,
            "rtl_line":         rtl_line,
            "tag":              _tag_driver(drv),
            "is_asserting":     _is_asserting(rhs),
            "condition_active": cond_active,
            "true_terms":       true_terms,
            "false_terms":      false_terms,
            "first_false_term": first_false,
            "term_values":      term_values,
            "rhs_sig_values":   rhs_sig_values,
        })

    return results


# ---------------------------------------------------------------------------
# Overwrite detection  (mirrors rca_7 MODE-A detection)
# ---------------------------------------------------------------------------

def detect_overwrite(
    sig_val: Optional[int],
    driver_evals: List[Dict],
) -> Optional[Dict]:
    """
    Detect MODE-A overwrite scenarios (mirrors rca_7).

    Returns an overwrite dict when:
      BLOCKED_ASSERTER:       asserting driver (→1) is INACTIVE, a non-asserting
                              driver is ACTIVE — overwrite prevents the assertion.
      UNEXPECTED_ASSERTION:   signal is 1, active driver (→1) fired without a
                              protocol requirement being met.
    Returns None if no overwrite detected.
    """
    active_drvs     = [d for d in driver_evals if d["condition_active"] is True]
    inactive_assert = [d for d in driver_evals
                       if d["is_asserting"] and d["condition_active"] is False]
    active_assert   = [d for d in active_drvs if d["is_asserting"]]
    active_deassert = [d for d in active_drvs if not d["is_asserting"]]

    # MODE-A: asserting driver blocked by a winning deassert driver
    if inactive_assert and active_deassert:
        return {
            "mode":              "MODE-A_BLOCKED_ASSERTER",
            "asserting_driver":  inactive_assert[0],
            "winning_driver":    active_deassert[-1],   # last-wins NBA
            "verdict":           "ASSERTING_DRIVER_BLOCKED_BY_OVERWRITE",
        }

    # MODE-A inverse: signal observed=1, active assert driver fired
    # (used for RULE_10 — RVALID should NOT have fired)
    if active_assert and sig_val == 1:
        return {
            "mode":           "MODE-A_UNEXPECTED_ASSERTION",
            "winning_driver": active_assert[-1],
            "verdict":        "UNEXPECTED_DRIVER_ACTIVATION",
        }

    return None


# ---------------------------------------------------------------------------
# Recursive causal chain builder  (mirrors rca_7 backtrack_true_path)
# ---------------------------------------------------------------------------

def build_causal_chain_trace(
    signal: str,
    logic: Dict,
    view: Any,
    cycle: int,
    max_depth: int = _DEFAULT_DEPTH,
    _visited: Optional[Set[str]] = None,
    _depth: int = 0,
) -> Dict:
    """
    Build a recursive ChainNode for `signal` at `cycle`.

    Mirrors rca_7's backtrack_true_path + _backtrack_condition_chain.

    ChainNode fields:
        signal            str
        depth             int
        value             Any
        mode              "MODE-A" | "MODE-B" | "DERIVED" | "LEAF" | "CYCLIC" | "NO_DRIVER"
        driver_evals      list[DriverEval]
        active_driver     DriverEval | None
        asserting_driver  DriverEval | None  (INACTIVE asserting driver)
        blocking_term     str | None
        overwrite_info    dict | None
        children          list[ {term, source, child: ChainNode} ]
    """
    if _visited is None:
        _visited = set()

    sig_lower = signal.lower()
    node: Dict = {
        "signal":           signal,
        "depth":            _depth,
        "value":            None,
        "mode":             "LEAF",
        "driver_evals":     [],
        "active_driver":    None,
        "asserting_driver": None,
        "blocking_term":    None,
        "overwrite_info":   None,
        "children":         [],
    }

    try:
        node["value"] = view.signal_value(signal, cycle)
    except Exception:
        pass

    if sig_lower in _visited or _depth >= max_depth:
        node["mode"] = "CYCLIC" if sig_lower in _visited else "MAX_DEPTH"
        return node

    _visited.add(sig_lower)

    driver_evals = evaluate_all_drivers(signal, logic, view, cycle)
    node["driver_evals"] = driver_evals

    if not driver_evals:
        node["mode"] = "LEAF"
        return node

    active_drvs     = [d for d in driver_evals if d["condition_active"] is True]
    inactive_assert = [d for d in driver_evals
                       if d["is_asserting"] and d["condition_active"] is False]

    overwrite = detect_overwrite(node["value"], driver_evals)
    node["overwrite_info"] = overwrite

    if overwrite and overwrite["mode"] == "MODE-A_UNEXPECTED_ASSERTION":
        # Signal is 1, active asserting driver fired — should NOT have.
        # Backtrack the TRUE terms of the active driver to find why.
        node["mode"]          = "MODE-A"
        node["active_driver"] = overwrite["winning_driver"]
        for term in overwrite["winning_driver"].get("true_terms") or []:
            _add_child_from_term(
                term, "active_condition_term",
                signal, logic, view, cycle, max_depth, set(_visited), _depth,
                node["children"],
            )

    elif overwrite and overwrite["mode"] == "MODE-A_BLOCKED_ASSERTER":
        # Asserting driver is blocked; winning (deassert) driver is ACTIVE.
        # Backtrack the TRUE terms of the winning driver → why did it fire?
        node["mode"]             = "MODE-A"
        node["asserting_driver"] = overwrite["asserting_driver"]
        node["active_driver"]    = overwrite["winning_driver"]
        for term in overwrite["winning_driver"].get("true_terms") or []:
            _add_child_from_term(
                term, "winning_condition_term",
                signal, logic, view, cycle, max_depth, set(_visited), _depth,
                node["children"],
            )

    elif inactive_assert and active_drvs:
        # MODE-B: asserting driver INACTIVE (condition not met); another driver
        # is active. Backtrack the first FALSE (blocking) term.
        node["mode"]             = "MODE-B"
        node["asserting_driver"] = inactive_assert[0]
        node["active_driver"]    = active_drvs[-1]
        first_false              = inactive_assert[0].get("first_false_term")
        node["blocking_term"]    = first_false
        if first_false:
            _add_child_from_term(
                first_false, "blocking_false_term",
                signal, logic, view, cycle, max_depth, set(_visited), _depth,
                node["children"],
            )

    elif active_drvs:
        # Normal active driver — recurse into derived signals in TRUE terms.
        node["mode"]          = "DERIVED"
        node["active_driver"] = active_drvs[-1]
        for term in active_drvs[-1].get("true_terms") or []:
            _add_child_from_term(
                term, "condition_term",
                signal, logic, view, cycle, max_depth, set(_visited), _depth,
                node["children"],
            )

    else:
        node["mode"] = "NO_DRIVER_ACTIVE"

    return node


def _add_child_from_term(
    term: str,
    source: str,
    parent_signal: str,
    logic: Dict,
    view: Any,
    cycle: int,
    max_depth: int,
    visited: Set[str],
    parent_depth: int,
    children_list: List[Dict],
) -> None:
    """Helper: for each derived signal in `term`, recurse and append child."""
    for tok in _IDENT.findall(term):
        tok_lower = tok.lower()
        if tok_lower in _KW or tok_lower in visited:
            continue
        if tok_lower == parent_signal.lower():
            continue
        if _resolve_logic_key(tok, logic) is None:
            continue
        child = build_causal_chain_trace(
            tok, logic, view, cycle, max_depth, set(visited), parent_depth + 1
        )
        children_list.append({"term": term, "source": source, "child": child})
        break  # one child per term avoids explosion


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_driver_table(
    signal: str,
    cycle: int,
    driver_evals: List[Dict],
    view: Any,
    indent: str = "  ",
) -> str:
    """
    Format the ✓/✗ per-driver evaluation table (rca-7 WAVEFORM EVAL style).

        ✓ D0 [LOGIC] (assert): if (cond) -> 1  *** ACTIVE @ waveform ***
               TRUE: cond_term  [sig=val]
        ✗ D1 [FSM] (deassert): if (cond2) -> 0  [inactive]
               BLOCKED by: false_term  [sig=val]
    """
    active_count = sum(1 for d in driver_evals if d["condition_active"] is True)
    lines = [
        f"{indent}Waveform eval: {active_count}/{len(driver_evals)} driver(s) active",
    ]
    for de in driver_evals:
        mark    = "✓" if de["condition_active"] else "✗"
        role    = "assert" if de["is_asserting"] else "deassert"
        cond_s  = f"if ({de['condition']})" if de["condition"] else "if (true)"
        tag_s   = f"[{de['tag']}]"
        act_s   = "  *** ACTIVE @ waveform ***" if de["condition_active"] else "  [inactive]"
        blk_s   = f"  block={de['always_block_id']}" if de["always_block_id"] is not None else ""
        lines.append(
            f"{indent}  {mark} D{de['driver_idx']} {tag_s} ({role}):"
            f" {cond_s} -> {de['rhs']}{blk_s}{act_s}"
        )
        if de["condition_active"] is True:
            for tt in de["true_terms"]:
                ann = _term_annotation(tt, view, cycle)
                lines.append(f"{indent}         TRUE: {tt}{ann}")
        elif de["first_false_term"]:
            ann = _term_annotation(de["first_false_term"], view, cycle)
            lines.append(f"{indent}         BLOCKED by: {de['first_false_term']}{ann}")

    return "\n".join(lines)


def format_causal_chain(
    node: Dict,
    view: Any,
    cycle: int,
    indent: str = "  ",
    _depth: int = 0,
) -> str:
    """
    Recursively format the ChainNode tree (rca-7 '-- Causal chain --' style).

        SIGNAL = val @ cycle N  (mode=MODE-A)
          Active driver: if (cond) -> rhs
          Asserting driver (INACTIVE): if (cond2) -> 1
          ↳ BLOCKED by: blocking_term  [sig=val]
          ↓ via [winning_condition_term]: true_term
            child_signal = val @ cycle N  (mode=LEAF)
    """
    lines: List[str] = []
    pad  = "  " * _depth
    sig  = node["signal"]
    val  = node["value"]
    mode = node["mode"]
    val_s = f" = {val}" if val is not None else ""

    lines.append(f"{indent}{pad}{sig}{val_s}  (mode={mode})")

    active   = node.get("active_driver")
    asserter = node.get("asserting_driver")
    blocking = node.get("blocking_term")

    if active:
        cond_s = f"if ({active['condition']})" if active["condition"] else "if (true)"
        lines.append(f"{indent}{pad}  Active driver D{active['driver_idx']}: {cond_s} -> {active['rhs']}")
        for tt in active.get("true_terms") or []:
            ann = _term_annotation(tt, view, cycle)
            lines.append(f"{indent}{pad}    TRUE: {tt}{ann}")

    if asserter and mode in ("MODE-B", "MODE-A"):
        cond_s = f"if ({asserter['condition']})" if asserter["condition"] else "if (true)"
        lines.append(
            f"{indent}{pad}  Asserting driver D{asserter['driver_idx']} (INACTIVE):"
            f" {cond_s} -> {asserter['rhs']}"
        )
        if blocking:
            ann = _term_annotation(blocking, view, cycle)
            lines.append(f"{indent}{pad}  ↳ BLOCKED by: {blocking}{ann}")

    for ch in node.get("children") or []:
        src   = ch.get("source", "")
        term  = ch.get("term", "")
        child = ch.get("child")
        if child:
            lines.append(f"{indent}{pad}  ↓ via [{src}]: {term}")
            lines.append(
                format_causal_chain(child, view, cycle, indent, _depth + 1)
            )

    return "\n".join(lines)


def format_full_trace(
    signal: str,
    cycle: int,
    logic: Dict,
    view: Any,
    rule_id: str = "?",
    max_depth: int = _DEFAULT_DEPTH,
) -> str:
    """
    Build a complete FULL_TRACE block for `signal` at `cycle`.

    Mirrors rca_7's _format_trace_result() output:

        -- Trace: SIGNAL @ cycle N [RULE_X] --
        Waveform: SIGNAL = V @ cycle N
        Analysis mode: MODE-A | MODE-B
        Waveform eval: K/N driver(s) active
          ✓ D0 [LOGIC] (assert): ...
          ✗ D1 [FSM] (deassert): ...

        -- Causal chain --
          SIGNAL = V  (mode=MODE-A)
            Active driver D3: ...
              ...

        CONDITION BREAKDOWN:
          term1  =  TRUE   [sig=val]
          term2  =  FALSE  <- blocks execution

        RESULT: ...
        RCA: ...
    """
    sep = "-" * 72
    lines: List[str] = [sep]

    sig_val: Optional[int] = None
    try:
        sig_val = view.signal_value(signal, cycle)
    except Exception:
        pass

    lines.append(f"-- Trace: {signal} @ cycle {cycle}  [{rule_id}] --")
    if sig_val is not None:
        lines.append(f"Waveform: {signal} = {sig_val} @ cycle {cycle}")
    lines.append("")

    driver_evals = evaluate_all_drivers(signal, logic, view, cycle)
    if not driver_evals:
        lines.append(f"  No RTL drivers found for '{signal}' in logic table.")
        lines.append(sep)
        return "\n".join(lines)

    overwrite = detect_overwrite(sig_val, driver_evals)
    active_count = sum(1 for d in driver_evals if d["condition_active"] is True)

    if overwrite:
        mode_label = overwrite["mode"]
    elif any(d["is_asserting"] and not d["condition_active"] for d in driver_evals):
        mode_label = "MODE-B_UNSATISFIED_ENABLE"
    else:
        mode_label = "MODE-A_UNEXPECTED_ASSERTION" if active_count else "NO_ACTIVE_DRIVER"

    lines.append(f"Analysis mode: {mode_label}")
    lines.append("")
    lines.append(format_driver_table(signal, cycle, driver_evals, view, indent="  "))
    lines.append("")

    # Causal chain
    chain_node = build_causal_chain_trace(signal, logic, view, cycle, max_depth)
    lines.append("-- Causal chain --")
    lines.append(format_causal_chain(chain_node, view, cycle, indent="  "))
    lines.append("")

    # Condition breakdown table
    all_asserting = [d for d in driver_evals if d["is_asserting"]]
    if all_asserting:
        lines.append("CONDITION BREAKDOWN:")
        for term, result in all_asserting[0]["term_values"].items():
            status  = "TRUE " if result is True else ("FALSE" if result is False else "?    ")
            arrow   = "  <- blocks execution" if result is False else ""
            ann     = _term_annotation(term, view, cycle)
            lines.append(f"  {term:<40s}  =  {status}{ann}{arrow}")
        lines.append("")

    # RESULT + RCA summary
    active_drvs = [d for d in driver_evals if d["condition_active"] is True]
    if overwrite and overwrite["mode"] == "MODE-A_BLOCKED_ASSERTER":
        win = overwrite["winning_driver"]
        asserter = overwrite["asserting_driver"]
        lines.append(
            f"RESULT: Asserting driver D{asserter['driver_idx']} (-> {asserter['rhs']}) "
            f"is BLOCKED. Winning driver D{win['driver_idx']} "
            f"(if {win['condition']} -> {win['rhs']}) prevails."
        )
        lines.append(
            f"RCA: The condition '{win.get('first_false_term') or win['condition']}' "
            f"is unexpectedly TRUE, activating a driver that overrides the correct path."
        )
    elif overwrite and overwrite["mode"] == "MODE-A_UNEXPECTED_ASSERTION":
        win = overwrite["winning_driver"]
        lines.append(
            f"RESULT: {signal} = {sig_val} driven by D{win['driver_idx']} "
            f"(if {win['condition']} -> {win['rhs']})  *** ACTIVE @ waveform ***"
        )
        ann = _term_annotation(win["condition"], view, cycle)
        lines.append(
            f"RCA: {signal} asserted because '{win['condition']}'{ann} is TRUE "
            f"without a preceding protocol requirement (AR handshake) being met."
        )
    elif active_drvs:
        win = active_drvs[-1]
        lines.append(
            f"RESULT: {signal} = {sig_val} — active driver D{win['driver_idx']}: "
            f"if ({win['condition']}) -> {win['rhs']}"
        )
    else:
        lines.append(f"RESULT: No active driver found for {signal} at cycle {cycle}.")

    lines.append(sep)
    return "\n".join(lines)
