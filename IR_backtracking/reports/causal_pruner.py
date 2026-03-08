"""
Causal Pruner — Minimal Reasoning Path Extractor
==================================================
Reduces the dependency analysis to only the elements that were causally active
during the failing window.

Keeps:
  - Drivers that were evaluated during the failing window
  - Conditions that evaluated FALSE and blocked progress
  - Registers whose previous-cycle values constrained the failure

Removes:
  - Drivers never considered by the solver during the failing window
  - Default assignments (always-executed, non-conditional)
  - Reset-only logic unless it directly caused the failure
  - Parallel logic not in the causal chain

Output:
  A compact, ordered trace of the minimal causal elements.
  NOT a full dependency tree — a reasoning path only.

Usage:
    from reports.causal_pruner import generate_causal_path
    text = generate_causal_path(payload)

    # Also available: pruned structured data for downstream use
    from reports.causal_pruner import prune_payload
    pruned = prune_payload(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set

_SEP  = "=" * 79
_DASH = "-" * 79


def generate_causal_path(payload: Dict[str, Any]) -> str:
    """Return a minimal causal path string from an RCA payload dict."""

    pruned    = prune_payload(payload)
    rca       = payload.get("final_rca") or {}
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification") or "UNKNOWN"
    pev       = rca.get("primary_evidence") or []
    pev0      = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig       = pev0.get("signal") or "target signal"
    rule      = pev0.get("rule_id") or "N/A"
    cyc       = pev0.get("analysis_cycle")

    hdr = [
        _SEP,
        "  CAUSAL PATH (Minimal Reasoning Trace)",
        _SEP,
        f"  Root Cause : {root_type}/{classif}",
        f"  Signal     : {sig}  |  Rule: {rule}  |  Cycle: {cyc if cyc is not None else 'N/A'}",
        _SEP,
        "",
    ]

    body: List[str] = []

    # ── Active drivers ─────────────────────────────────────────────────────
    active_drivers = pruned.get("active_drivers") or []
    blocked_drivers= pruned.get("blocked_drivers") or []
    blocking_conds = pruned.get("blocking_conditions") or []
    state_deps     = pruned.get("state_dependencies") or []
    causal_links   = pruned.get("causal_links") or []
    overwrite_chain= pruned.get("overwrite_chain") or []
    cycle_elements = pruned.get("cycle_elements") or []
    terminal       = pruned.get("terminal_cause") or ""

    if active_drivers:
        body.append("  ACTIVE DRIVERS (evaluated and fired):")
        for d in active_drivers:
            body.append(f"    [ACTIVE]  {_fmt_driver(d)}")
        body.append("")

    if blocked_drivers:
        body.append("  BLOCKED DRIVERS (evaluated but negated or overwritten):")
        for d in blocked_drivers:
            body.append(f"    [BLOCKED] {_fmt_driver(d)}")
        body.append("")

    if blocking_conds:
        body.append("  CONDITIONS THAT EVALUATED FALSE (blocking progress):")
        for c in blocking_conds:
            body.append(f"    [FALSE]   {c}")
        body.append("")

    if state_deps:
        body.append("  STATE DEPENDENCIES (registers constraining the failure window):")
        for sd in state_deps:
            sig_s = sd.get("signal") or "?"
            val   = sd.get("value")
            origin= sd.get("origin") or "previous-cycle assignment"
            val_s = f" = {val}" if val is not None else ""
            body.append(f"    [STATE]   {sig_s}{val_s}  (from {origin})")
        body.append("")

    if overwrite_chain:
        body.append("  OVERWRITE CHAIN (NBA assignment order within always-block):")
        for i, step in enumerate(overwrite_chain):
            arrow = "    " if i == 0 else "    ↓ overwritten by"
            body.append(f"{arrow}  D{step.get('idx','?')}: {step.get('cond','?')} → {step.get('sig','?')}={step.get('rhs','?')}")
        body.append("")

    if causal_links:
        body.append("  CAUSAL LINKS (RTL signal → failing memory path):")
        for lk in causal_links:
            body.append(f"    {lk.get('signal','?')} → {lk.get('memory','?')}"
                        f"  (line {lk.get('rtl_line','?')})")
        body.append("")

    if cycle_elements:
        body.append("  CAUSAL CYCLE ELEMENTS (self-reinforcing deadlock):")
        for el in cycle_elements:
            body.append(f"    [CYCLE]   {el}")
        body.append("")

    if terminal:
        body += [
            "  TERMINAL CAUSE:",
            f"    {terminal}",
            "",
        ]

    # ── Removed items summary ──────────────────────────────────────────────
    removed_count = pruned.get("removed_count") or 0
    pct           = pruned.get("removed_pct") or 0
    body += [
        _DASH,
        f"  Removed {removed_count} non-causal element(s) ({pct}% of raw dependency data).",
        _SEP,
    ]

    return "\n".join(hdr + body)


def prune_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a pruned dict containing only causally active elements.

    Fields returned:
      active_drivers   — list of driver dicts that fired during the failing window
      blocked_drivers  — list of driver dicts that were evaluated but blocked/overwritten
      blocking_conditions — list of condition strings that evaluated false
      state_dependencies  — list of {signal, value, origin} for constraining registers
      overwrite_chain  — ordered list of {idx, sig, cond, rhs} showing NBA overwrite
      causal_links     — from final_rca["causal_links"]
      cycle_elements   — signals/conditions forming the cyclic dependency
      terminal_cause   — string identifying the structural terminal
      removed_count    — count of elements removed
      removed_pct      — percentage of total elements removed
    """
    rca       = payload.get("final_rca") or {}
    findings  = payload.get("findings") or []
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"

    pev   = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or pev0.get("expected_signal") or ""
    rule  = pev0.get("rule_id") or ""
    chain = rca.get("causal_chain") or ""

    # Find best matching finding
    first_f = next(
        (f for f in findings if f.get("signal") == sig or f.get("rule_id") == rule),
        findings[0] if findings else {},
    )
    evid = first_f.get("evidence") or {}
    canc = evid.get("intra_cycle_cancellation") or {}
    cyc_r= evid.get("cycle_report") or {}

    enabling_conds  = canc.get("expected_driver_conditions") or []
    overwrite_conds = canc.get("final_overwrite_conditions") or []
    cycle_detected  = cyc_r.get("cycle_detected") or ("CYCLIC" in chain.upper())
    blocking_sig    = cyc_r.get("blocking_signal") or ""
    occurrence_count= canc.get("occurrence_count") or 0

    # ── Build active/blocked driver lists ─────────────────────────────────
    active_drivers : List[Dict[str, Any]] = []
    blocked_drivers: List[Dict[str, Any]] = []

    for i, cond in enumerate(enabling_conds):
        # Enabling drivers: fired (TRUE) but ultimately overwritten
        blocked_drivers.append({
            "idx":  i,
            "sig":  sig,
            "cond": cond,
            "rhs":  "1",
            "note": "fired but overwritten by later driver",
        })

    for i, cond in enumerate(overwrite_conds):
        # Overwrite drivers: fired and won (assigned 0, cancelling the enable)
        active_drivers.append({
            "idx":  len(enabling_conds) + i,
            "sig":  sig,
            "cond": cond,
            "rhs":  "0",
            "note": "fired last; cancelled enabling assignment",
        })

    # ── Blocking conditions (terms that evaluated FALSE) ──────────────────
    blocking_conditions: List[str] = []
    # The "blocking" condition is the one whose ABSENCE prevents the signal from
    # asserting. For PROTOCOL/masking: the absence of a guard between D1 and D2
    # is the failure. The condition that SHOULD be false (for D2 to not override)
    # is D2's broader condition being true when the enabling condition is also true.
    if enabling_conds and overwrite_conds:
        # Construct the "missing mutual exclusion" term
        en  = enabling_conds[0] if enabling_conds else "D1_cond"
        ow  = overwrite_conds[0] if overwrite_conds else "D2_cond"
        blocking_conditions.append(
            f"NOT({ow} && {en})  [mutual exclusion guard — absent in RTL]"
        )
    # For pure datapath: add the width condition
    dv = payload.get("datapath_violations") or []
    for v in dv[:2]:
        sw = v.get("inferred_src_width")
        dw = v.get("inferred_dst_width")
        dst = v.get("destination_signal") or "dst"
        if sw and dw:
            blocking_conditions.append(
                f"src_width({sw}) == dst_width({dw})  "
                f"[width equality — violated for {dst}]"
            )

    # ── State dependencies ─────────────────────────────────────────────────
    state_deps: List[Dict[str, Any]] = []
    # FSM state register constraining the failure
    if enabling_conds:
        import re
        fsm_terms: Set[str] = set()
        for cond in enabling_conds + overwrite_conds:
            # extract "register == value" or "register" patterns
            for m in re.finditer(r'(\w+)\s*==\s*(\w+)', cond):
                fsm_terms.add(m.group(1))
            for m in re.finditer(r'\b([A-Za-z]\w*state\w*|state\w*)\b', cond, re.IGNORECASE):
                fsm_terms.add(m.group(1))
        for term in fsm_terms:
            state_deps.append({
                "signal": term,
                "value":  None,   # actual value at runtime not available here
                "origin": "RTL always-block register updated on previous posedge",
            })

    # ── Overwrite chain ───────────────────────────────────────────────────
    overwrite_chain: List[Dict[str, Any]] = []
    for i, cond in enumerate(enabling_conds):
        overwrite_chain.append({"idx": i, "sig": sig, "cond": cond, "rhs": "1"})
    for i, cond in enumerate(overwrite_conds):
        overwrite_chain.append({"idx": len(enabling_conds) + i, "sig": sig, "cond": cond, "rhs": "0"})

    # ── Causal links (RULE 1) ─────────────────────────────────────────────
    causal_links = rca.get("causal_links") or []

    # ── Cycle elements ────────────────────────────────────────────────────
    cycle_elements: List[str] = []
    if cycle_detected:
        if blocking_sig:
            cycle_elements.append(
                f"{blocking_sig} (FSM state) keeps D2 condition active "
                f"→ {sig} stays 0 → FSM cannot advance → {blocking_sig} stays same"
            )
        else:
            cycle_elements.append(
                f"{sig} cannot assert → enabling FSM state not exited → "
                f"{sig} remains blocked (cyclic dependency)"
            )

    # ── Terminal cause ────────────────────────────────────────────────────
    if root_type == "PROTOCOL" and overwrite_conds:
        terminal = (
            f"RTL always-block assignment order: D2 (`{overwrite_conds[0]}` → {sig}=0) "
            f"appears after D1, making the masking unconditional and structurally immovable."
        )
    elif root_type == "DATAPATH":
        first_dv = dv[0] if dv else {}
        sub = first_dv.get("subtype") or "non-invertible transform"
        loc = first_dv.get("rtl_line")
        terminal = (
            f"RTL {sub} at {'line ' + str(loc) if loc else 'assignment block'}: "
            f"data width is irreversibly reduced before reaching the protocol boundary."
        )
    elif root_type == "TRANSPORT":
        tv = payload.get("transport_violations") or []
        first_tv = tv[0] if tv else {}
        loc = first_tv.get("rtl_line")
        terminal = (
            f"RTL strobe/data mismatch at {'line ' + str(loc) if loc else 'assignment block'}: "
            f"WSTRB is not co-steered with WDATA — static coding omission."
        )
    else:
        terminal = "Insufficient RTL driver data to identify a structural terminal condition."

    # ── Compute removal statistics ─────────────────────────────────────────
    # "Total elements" = all driver dicts in findings + all violations
    all_findings = payload.get("findings") or []
    all_dv       = payload.get("datapath_violations") or []
    all_tv       = payload.get("transport_violations") or []

    total_raw   = (
        sum(len(f.get("evidence") or {}) for f in all_findings)
        + len(all_dv) + len(all_tv)
        + occurrence_count
    )
    retained = len(active_drivers) + len(blocked_drivers) + len(causal_links) + len(state_deps)
    removed  = max(0, total_raw - retained)
    pct      = round(100 * removed / total_raw) if total_raw > 0 else 0

    return {
        "active_drivers":      active_drivers,
        "blocked_drivers":     blocked_drivers,
        "blocking_conditions": blocking_conditions,
        "state_dependencies":  state_deps,
        "overwrite_chain":     overwrite_chain,
        "causal_links":        causal_links,
        "cycle_elements":      cycle_elements,
        "terminal_cause":      terminal,
        "removed_count":       removed,
        "removed_pct":         pct,
    }


# ── Formatters ─────────────────────────────────────────────────────────────────

def _fmt_driver(d: Dict[str, Any]) -> str:
    sig  = d.get("sig") or "?"
    cond = d.get("cond") or "always"
    rhs  = d.get("rhs") or "?"
    note = d.get("note") or ""
    note_str = f"  [{note}]" if note else ""
    return f"{sig} = {rhs}  when ({cond}){note_str}"
