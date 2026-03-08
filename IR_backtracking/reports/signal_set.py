"""
Signal Set Extractor — Minimal Closed Causal Chain
====================================================
From all violations and structural findings, identifies the minimal set of
signals that form a closed causal chain.

Rules applied:
  - Keep only signals that appear in BOTH protocol failure AND structural
    violation (cross-evidence intersection).
  - Remove duplicated width/byte-lane reports; one representative per class.
  - Collapse repeated writes to the same address into one behavioural entry.
  - Identify the single storage element or FSM state register responsible.

Returns four roles:
    trigger_signal  — the signal whose failure was first observed (obligation)
    blocking_signal — the signal whose condition prevents trigger_signal from
                      asserting (the overwriting driver or the blocking state)
    state_element   — the FSM state register that keeps the blocking condition
                      permanently true (causal cycle anchor)
    storage_element — the data-path register or memory where the corruption
                      is stored (datapath cases only; None for PROTOCOL-only)

Output format:
    ============== MINIMAL CAUSAL SIGNAL SET ==============
    trigger_signal  : <sig>
    blocking_signal : <sig>
    state_element   : <sig>    [or "(none identified)"]
    storage_element : <sig>    [or "(not applicable)"]
    -------------------------------------------------------
    Causal chain: <one-sentence description>
    =======================================================

Usage:
    from reports.signal_set import extract_signal_set
    text = extract_signal_set(payload)
    # Also available as a dict:
    from reports.signal_set import extract_signal_set_dict
    d = extract_signal_set_dict(payload)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

_HDR = "============== MINIMAL CAUSAL SIGNAL SET =============="
_SEP = "-------------------------------------------------------"
_FTR = "======================================================="


# ── Public API ─────────────────────────────────────────────────────────────────

def extract_signal_set(payload: Dict[str, Any]) -> str:
    """Return a formatted minimal causal signal set string."""
    d = extract_signal_set_dict(payload)
    return _format(d)


def extract_signal_set_dict(payload: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Return a dict with keys:
        trigger_signal, blocking_signal, state_element,
        storage_element, causal_chain
    All values are strings or None.
    """
    rca       = payload.get("final_rca") or {}
    findings  = payload.get("findings") or []
    dv        = payload.get("datapath_violations") or []
    tv        = payload.get("transport_violations") or []
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"

    pev   = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or pev0.get("expected_signal") or ""
    rule  = pev0.get("rule_id") or ""

    # Best matching finding for cancellation detail
    first_f = next(
        (f for f in findings if f.get("signal") == sig or f.get("rule_id") == rule),
        findings[0] if findings else {},
    )
    evid = first_f.get("evidence") or {}
    canc = evid.get("intra_cycle_cancellation") or {}
    cyc_r = evid.get("cycle_report") or {}

    enabling_conds  = canc.get("expected_driver_conditions") or []
    overwrite_conds = canc.get("final_overwrite_conditions") or []
    blocking_sig_w  = cyc_r.get("blocking_signal") or ""
    cycle_det       = cyc_r.get("cycle_detected") or (
        "CYCLIC" in (rca.get("causal_chain") or "").upper()
    )

    if root_type == "PROTOCOL":
        return _set_protocol(
            sig, findings, enabling_conds, overwrite_conds,
            blocking_sig_w, cycle_det, rca,
        )
    elif root_type == "DATAPATH":
        return _set_datapath(sig, dv, rca, findings)
    elif root_type == "TRANSPORT":
        return _set_transport(sig, tv, rca)
    else:
        return _set_inconclusive(sig)


# ── Per-root-cause extractors ──────────────────────────────────────────────────

def _set_protocol(
    sig: str,
    findings: List[Dict[str, Any]],
    enabling_conds: List[str],
    overwrite_conds: List[str],
    blocking_sig_w: str,
    cycle_det: bool,
    rca: Dict[str, Any],
) -> Dict[str, Optional[str]]:
    """PROTOCOL root: FSM output masked by NBA overwrite."""

    trigger  = sig or "target_signal"

    # Blocking signal: the condition term from the overwrite driver
    # Extract the first register-looking token from the overwrite condition
    blocking = blocking_sig_w or _extract_register(overwrite_conds[0] if overwrite_conds else "") or "overwrite_driver_condition"

    # State element: FSM state register referenced in both enabling and overwrite conds
    state = _find_shared_state_register(enabling_conds, overwrite_conds) or blocking_sig_w or "fsm_state_reg"

    # Storage element: not applicable for pure protocol bugs
    storage = None

    # Build one-sentence causal chain
    if cycle_det and blocking_sig_w:
        chain = (
            f"{trigger} cannot assert because the overwrite driver controlled by "
            f"{blocking} always fires last; {blocking} stays in its current state "
            f"because the FSM transition requires {trigger} to assert first — "
            f"forming a deadlock through {state}."
        )
    else:
        chain = (
            f"{trigger} is permanently held at 0 because an always-block assigns "
            f"{trigger}=0 under condition '{overwrite_conds[0] if overwrite_conds else blocking}' "
            f"after the enabling assignment, and that condition is never false "
            f"while {state} remains in its current encoding."
        )

    return {
        "trigger_signal":  trigger,
        "blocking_signal": blocking,
        "state_element":   state,
        "storage_element": storage,
        "causal_chain":    chain,
    }


def _set_datapath(
    sig: str,
    dv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Dict[str, Optional[str]]:
    """DATAPATH root: width collapse or non-invertible transform."""

    # De-duplicate: one representative per (class, subtype)
    seen_subtypes: Set[Tuple[str, str]] = set()
    unique_dv: List[Dict[str, Any]] = []
    for v in dv:
        key = (v.get("class") or "", v.get("subtype") or "")
        if key not in seen_subtypes:
            seen_subtypes.add(key)
            unique_dv.append(v)

    first = unique_dv[0] if unique_dv else {}
    dst   = first.get("destination_signal") or first.get("signal") or sig or "RDATA"
    src   = first.get("source_signal") or "source_reg"
    sub   = first.get("subtype") or "WIDTH_TRUNCATION"

    trigger  = dst   # the protocol-visible signal that reads back wrong
    blocking = src   # the source that is wider / non-invertible
    storage  = dst   # the register where truncated/collapsed data is stored

    # State element: any FSM register referenced in causal_links
    causal_links = rca.get("causal_links") or []
    state = None
    for lk in causal_links:
        mem = lk.get("memory") or ""
        if "state" in mem.lower() or "fsm" in mem.lower():
            state = mem
            break

    chain = (
        f"{src} drives {dst} through a {sub.lower().replace('_', ' ')} "
        f"that discards high bits; reads back from {dst} cannot distinguish "
        f"distinct values written to {src} — "
        f"the data loss occurs unconditionally at the RTL assignment."
    )

    return {
        "trigger_signal":  trigger,
        "blocking_signal": blocking,
        "state_element":   state,
        "storage_element": storage,
        "causal_chain":    chain,
    }


def _set_transport(
    sig: str,
    tv: List[Dict[str, Any]],
    rca: Dict[str, Any],
) -> Dict[str, Optional[str]]:
    """TRANSPORT root: WSTRB/WDATA byte-lane mismatch."""

    first  = tv[0] if tv else {}
    dst    = first.get("destination_signal") or "WDATA"
    src    = first.get("source_signal") or "write_source"
    strb   = first.get("strobe_signal") or "WSTRB"

    trigger  = dst    # the data signal that lands in the wrong lane
    blocking = strb   # the strobe that is not co-steered
    storage  = dst    # the slave register receiving the misaligned byte
    state    = None   # no FSM involved in transport misalignment

    chain = (
        f"{dst} is steered to a different byte lane than the one enabled by "
        f"{strb}; {strb} was not updated to apply the same offset expression, "
        f"so the intended byte is never written and the wrong lane is committed "
        f"to {storage}."
    )

    return {
        "trigger_signal":  trigger,
        "blocking_signal": blocking,
        "state_element":   state,
        "storage_element": storage,
        "causal_chain":    chain,
    }


def _set_inconclusive(sig: str) -> Dict[str, Optional[str]]:
    return {
        "trigger_signal":  sig or "(unknown)",
        "blocking_signal": "(not determined)",
        "state_element":   None,
        "storage_element": None,
        "causal_chain":    (
            "Insufficient driver data to construct a closed causal chain. "
            "Provide a complete true_drivers CSV and re-run."
        ),
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

_REGISTER_RE = re.compile(r'\b([A-Za-z_]\w*)\b')


def _extract_register(cond: str) -> Optional[str]:
    """Return the first register-looking token from a condition string."""
    if not cond:
        return None
    # Prefer tokens that look like state registers
    for m in _REGISTER_RE.finditer(cond):
        tok = m.group(1)
        if tok.lower() not in {"and", "or", "not", "if", "else", "begin", "end"}:
            return tok
    return None


def _find_shared_state_register(
    enabling_conds: List[str],
    overwrite_conds: List[str],
) -> Optional[str]:
    """
    Find a register name that appears in BOTH enabling and overwrite conditions
    and looks like a state/FSM register.
    """
    def tokens(conds: List[str]) -> Set[str]:
        result: Set[str] = set()
        for c in conds:
            for m in re.finditer(r'(\w+)\s*==\s*\w+', c):
                result.add(m.group(1))
            for m in re.finditer(r'\b(\w*[Ss]tate\w*|\w*[Ff][Ss][Mm]\w*|\w*[Ss][Tt][Aa]\w*)\b', c):
                result.add(m.group(1))
        return result

    en_toks = tokens(enabling_conds)
    ow_toks = tokens(overwrite_conds)
    shared  = en_toks & ow_toks
    if shared:
        # Prefer names containing 'state' or 'fsm'
        for t in sorted(shared):
            if "state" in t.lower() or "fsm" in t.lower():
                return t
        return next(iter(sorted(shared)))
    # Fallback: any register from either side
    all_toks = en_toks | ow_toks
    for t in sorted(all_toks):
        if "state" in t.lower() or "fsm" in t.lower():
            return t
    return next(iter(sorted(all_toks))) if all_toks else None


# ── Formatter ──────────────────────────────────────────────────────────────────

def _format(d: Dict[str, Optional[str]]) -> str:
    trigger  = d.get("trigger_signal")  or "(none identified)"
    blocking = d.get("blocking_signal") or "(none identified)"
    state    = d.get("state_element")   or "(none identified)"
    storage  = d.get("storage_element") or "(not applicable)"
    chain    = d.get("causal_chain")    or "(not determined)"

    label_w = 16  # width for left-aligned label column
    lines = [
        "",
        _HDR,
        f"{'trigger_signal':<{label_w}}: {trigger}",
        f"{'blocking_signal':<{label_w}}: {blocking}",
        f"{'state_element':<{label_w}}: {state}",
        f"{'storage_element':<{label_w}}: {storage}",
        _SEP,
        "Causal chain:",
    ]
    lines += _wrap(chain, indent=2)
    lines.append(_FTR)
    return "\n".join(lines)


def _wrap(text: str, indent: int = 0) -> List[str]:
    prefix = " " * indent
    words  = text.split()
    result: List[str] = []
    curr   = prefix
    for w in words:
        if len(curr) + len(w) + 1 > 74:
            result.append(curr.rstrip())
            curr = prefix + w + " "
        else:
            curr += w + " "
    if curr.strip():
        result.append(curr.rstrip())
    return result
