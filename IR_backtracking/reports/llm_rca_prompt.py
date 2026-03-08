"""
WaveEye — Pure Python Structural RCA Analysis Engine
=====================================================
Derives a structured RCA report (RULE_ID, VIOLATION_TYPE, CAUSAL_CLASS,
VERDICT, MISSING_DEPS, DRIVER_PREDICATE, ACTIVE_TERMS, FIX_GUIDANCE,
CONFIDENCE, NOTES) entirely from the WaveEye payload dict.

No LLM calls.  No API keys.  All fields computed algorithmically.

Output: a formatted .rca_analysis.txt report saved alongside other reports.

Usage:
    from reports.llm_rca_prompt import generate_rca_analysis
    text = generate_rca_analysis(payload)
"""

from __future__ import annotations

from typing import Any, Dict, List

# ── Rule metadata ──────────────────────────────────────────────────────────────

_RULE_CANON = {
    "RULE_1":  ("AXI4L_ADDR_STABILITY",           "§A3.1.2",  "stability"),
    "RULE_2":  ("AXI4L_ARVALID_PERSISTENCE",       "§A3.1.2",  "persistence"),
    "RULE_3":  ("AXI4L_AWVALID_PERSISTENCE",       "§A3.1.2",  "persistence"),
    "RULE_4":  ("AXI4L_WVALID_PERSISTENCE",        "§A3.1.2",  "persistence"),
    "RULE_5":  ("AXI4L_RVALID_PERSISTENCE",        "§A3.1.2",  "persistence"),
    "RULE_6":  ("AXI4L_BVALID_PERSISTENCE",        "§A3.1.2",  "persistence"),
    "RULE_7":  ("AXI4L_WDATA_STABILITY",           "§A3.2.1",  "stability"),
    "RULE_8":  ("AXI4L_RDATA_STABILITY",           "§A3.3.1",  "stability"),
    "RULE_9":  ("AXI4L_BRESP_STABILITY",           "§A3.2.2",  "stability"),
    "RULE_10": ("AXI4L_RVALID_UNPROMPTED",         "§A3.3.1",  "unprompted"),
    "RULE_11": ("AXI4L_BVALID_UNPROMPTED",         "§A3.2.2",  "unprompted"),
    "RULE_12": ("AXI4L_READ_RESPONSE_MISSING",     "§A3.3.1",  "no-response"),
    "RULE_13": ("AXI4L_WRITE_RESPONSE_MISSING",    "§A3.2.1",  "no-response"),
    "RULE_14": ("AXI4L_ARPROT_STABILITY",          "§A3.2.1",  "stability"),
    "RULE_15": ("AXI4L_AWPROT_STABILITY",          "§A3.2.1",  "stability"),
}

# Default MODE per violation class (used as fallback if payload lacks mode_analysis)
_MODE_FOR_CLASS = {
    "stability":   "MODE-C",
    "persistence": "MODE-B",
    "unprompted":  "MODE-A",
    "no-response": "MODE-D",
}

# AXI4-Lite required dependency signals per channel
_CHANNEL_DEPS = {
    "AR": ["ARVALID", "ARREADY"],
    "AW": ["AWVALID", "AWREADY"],
    "W":  ["WVALID",  "WREADY"],
    "R":  ["RVALID",  "RREADY"],
    "B":  ["BVALID",  "BREADY"],
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _rule_meta(rule_id: str):
    """Return (canon_name, spec_ref, violation_class) for a rule ID."""
    return _RULE_CANON.get(str(rule_id).upper(), (rule_id, "§unknown", "no-response"))


def _extract_rule_id(payload: Dict) -> str:
    rca      = payload.get("final_rca") or {}
    findings = payload.get("findings") or []
    pev      = rca.get("primary_evidence") or []
    pev0     = pev[0] if pev and isinstance(pev[0], dict) else {}
    r = pev0.get("rule_id")
    if r:
        return str(r).upper()
    for f in findings:
        r = f.get("rule_id")
        if r:
            return str(r).upper()
    return ""


def _rtl_location(payload: Dict) -> str:
    dv = payload.get("datapath_violations") or []
    tv = payload.get("transport_violations") or []
    for v in list(dv) + list(tv):
        loc = v.get("source_location") or v.get("source") or v.get("rtl_line")
        if loc:
            return str(loc)
        blk = v.get("always_block_id")
        if blk is not None:
            return f"always_block {blk}"
    findings = payload.get("findings") or []
    for f in findings:
        ev = f.get("evidence") or {}
        loc = ev.get("source_location") or ev.get("rtl_location")
        if loc:
            return str(loc)
    return "(see appendix)"


def _format_terms(pred_a: Dict) -> str:
    """Format ACTIVE_TERMS block from predicate_analysis data."""
    lines: List[str] = []
    ma      = pred_a.get("mode_analysis") or {}
    t_ev    = pred_a.get("t_eval")
    pri_sig = pred_a.get("signal") or "?"
    pri_val = pred_a.get("primary_waveform_value")

    lines.append(
        f"  {pri_sig} = {pri_val if pri_val is not None else '?'}"
        f"  @ t_eval={t_ev}  [source: rtl_driven]"
    )

    term_bt = ma.get("term_backtrack") or {}
    for sig, entry in term_bt.items():
        val = entry.get("value")
        if entry.get("is_leaf"):
            src = "master_input"
        elif entry.get("registered"):
            src = "fsm_state"
        else:
            src = "rtl_driven"
        lines.append(
            f"  {sig} = {val if val is not None else '?'}"
            f"  @ t_eval={t_ev}  [source: {src}]"
        )

    sec_wave = pred_a.get("secondary_waveform") or {}
    sec_bt   = ma.get("secondary_backtrack") or {}
    for sig in sorted(sec_wave.keys()):
        if sig in term_bt:
            continue
        val = sec_wave.get(sig)
        entry = sec_bt.get(sig, {})
        if entry.get("is_leaf", True):
            src = "master_input"
        elif entry.get("registered"):
            src = "fsm_state"
        else:
            src = "rtl_driven"
        lines.append(
            f"  {sig} = {val if val is not None else '?'}"
            f"  @ t_eval={t_ev}  [source: {src}]"
        )

    return "\n".join(lines) if lines else "  (no term values available)"


def _format_structural(payload: Dict) -> str:
    """Format structural defect entries."""
    dv = payload.get("datapath_violations") or []
    tv = payload.get("transport_violations") or []
    lines: List[str] = []
    for v in list(dv) + list(tv):
        cls   = v.get("class") or v.get("violation_class") or ""
        sub   = v.get("subtype") or ""
        dst   = v.get("destination_signal") or v.get("memory") or "-"
        src   = v.get("source_signal") or "-"
        loc   = v.get("source_location") or v.get("rtl_line") or "-"
        sw    = v.get("inferred_src_width")
        dw    = v.get("inferred_dst_width")
        width = f" ({sw}→{dw} bits)" if sw and dw else ""
        lines.append(f"  {cls}/{sub}: {src} → {dst}{width}  at {loc}")
    return "\n".join(lines) if lines else "  NONE"


# ── Pure Python classifiers ────────────────────────────────────────────────────

def _compute_violation_type(payload: Dict, viol_class: str) -> str:
    """
    Return MODE-A/B/C/D.
    Priority: predicate_analysis.mode_analysis.mode from rca_8 → rule class fallback.
    """
    rca    = payload.get("final_rca") or {}
    pred_a = rca.get("predicate_analysis") or {}
    ma     = pred_a.get("mode_analysis") or {}
    mode   = ma.get("mode")
    if mode in ("MODE-A", "MODE-B", "MODE-C", "MODE-D"):
        return mode
    return _MODE_FOR_CLASS.get(viol_class, "MODE-D")


def _compute_causal_class(payload: Dict) -> str:
    """
    STRUCTURALLY_CAUSED if:
      - root_cause_type contains DATAPATH or TRANSPORT, OR
      - binding pass reports ≥1 causal violation, OR
      - datapath/transport violations are non-empty
    Otherwise PREDICATE_ONLY.
    """
    rca       = payload.get("final_rca") or {}
    root_type = rca.get("root_cause_type") or ""
    if "DATAPATH" in root_type or "TRANSPORT" in root_type:
        return "STRUCTURALLY_CAUSED"
    br = payload.get("binding_result") or {}
    bs = br.get("summary") or {}
    if bs.get("causal", 0) > 0:
        return "STRUCTURALLY_CAUSED"
    dv = payload.get("datapath_violations") or []
    tv = payload.get("transport_violations") or []
    if dv or tv:
        return "STRUCTURALLY_CAUSED"
    return "PREDICATE_ONLY"


def _compute_verdict(payload: Dict, missing: List[str]) -> str:
    """
    GUARANTEED  — PREDICATE_PROOF authority AND missing required deps confirmed
    INTERMITTENT — scheduling cancellation detected (driver wins non-deterministically)
    CONDITIONAL  — missing deps present but not full proof, or no missing deps found
    """
    rca       = payload.get("final_rca") or {}
    authority = rca.get("authority") or ""

    # Check scheduling cancellation → non-deterministic outcome
    pev  = rca.get("primary_evidence") or []
    pev0 = pev[0] if pev and isinstance(pev[0], dict) else {}
    ev0  = pev0.get("evidence") or {}
    ic   = ev0.get("intra_cycle_cancellation") or {}
    if isinstance(ic, dict) and ic.get("detected"):
        return "INTERMITTENT"

    if authority == "PREDICATE_PROOF" and missing:
        return "GUARANTEED"
    if missing:
        return "CONDITIONAL"
    # No missing deps but violation observed → conditional on runtime state
    return "CONDITIONAL"


def _compute_confidence(payload: Dict) -> str:
    """
    HIGH   — score ≥ 6
    MEDIUM — score ≥ 3
    LOW    — score < 3

    Scoring:
      +3  PREDICATE_PROOF authority
      +2  binding pass found ≥1 causal violation
      +2  ≥5 transactions analyzed  (+1 for ≥2)
      +1  structural violations present
    """
    rca       = payload.get("final_rca") or {}
    authority = rca.get("authority") or ""
    br        = payload.get("binding_result") or {}
    bs        = br.get("summary") or {}
    txns      = len(payload.get("transactions") or [])
    dv        = payload.get("datapath_violations") or []
    tv        = payload.get("transport_violations") or []

    score = 0
    if authority == "PREDICATE_PROOF":
        score += 3
    if bs.get("causal", 0) > 0:
        score += 2
    if txns >= 5:
        score += 2
    elif txns >= 2:
        score += 1
    if dv or tv:
        score += 1

    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def _compute_fix_guidance(payload: Dict, pa_sig: str, missing: List[str],
                          causal_class: str) -> str:
    """
    Derive specific RTL fix from structural violations and/or missing dependencies.
    No file I/O — uses payload fields only.
    Includes MODE-C ready_gate_absent check for precise stability fix guidance.
    """
    rca    = payload.get("final_rca") or {}
    pred_a = rca.get("predicate_analysis") or {}
    ma     = pred_a.get("mode_analysis") or {}
    dv     = payload.get("datapath_violations") or []
    tv     = payload.get("transport_violations") or []
    lines: List[str] = []

    # ── MODE-C: stability mutation fix guidance ────────────────────────────────
    if ma.get("mode") == "MODE-C":
        stab_sig          = ma.get("stability_signal", pa_sig)
        ready_sig         = ma.get("ready_signal", "READY")
        ready_gate_absent = ma.get("ready_gate_absent", False)
        if ready_gate_absent:
            lines.append(
                f"  [STRUCTURAL] {stab_sig} has no {ready_sig} gate in RTL driver:\n"
                f"    Option A: gate the update on (!{ready_sig}):\n"
                f"      if (!{ready_sig}) {stab_sig} <= next_value;\n"
                f"    Option B: register {stab_sig} at transaction-accept time:\n"
                f"      always_ff @(posedge clk) if ({ready_sig}) {stab_sig}_q <= {stab_sig};"
            )
        else:
            lines.append(
                f"  [PREDICATE] {ready_sig} is referenced in {stab_sig} driver but\n"
                f"    the active predicate at mutation cycle did not block the update.\n"
                f"    Verify all driver branches correctly gate on {ready_sig}."
            )

    if causal_class == "STRUCTURALLY_CAUSED":
        for v in list(dv) + list(tv):
            cls  = v.get("class") or v.get("violation_class") or ""
            sub  = v.get("subtype") or ""
            dst  = v.get("destination_signal") or v.get("memory") or "-"
            src  = v.get("source_signal") or "-"
            loc  = v.get("source_location") or v.get("rtl_line") or "-"
            sw   = v.get("inferred_src_width")
            dw   = v.get("inferred_dst_width")

            if "WIDTH" in cls or "TRUNCATION" in sub:
                width_note = f" ({sw}→{dw} bits)" if sw and dw else ""
                lines.append(
                    f"  Widen destination: {dst} <= {src};"
                    f"  [at {loc}{width_note} — source is wider than destination]"
                )
            elif "BIJECTION" in cls or "BIJECTION" in sub or "ALIASING" in cls:
                lines.append(
                    f"  Fix non-bijective mapping: {dst} <= {src};"
                    f"  [at {loc} — one-to-one mapping required]"
                )
            elif "TRANSPORT" in cls or "SHIFT" in sub or "REPLICATE" in sub:
                lines.append(
                    f"  Correct transport transform on {dst} at {loc}"
                    f"  — verify byte-lane alignment between {src} and {dst}."
                )
            elif "INVERTIBILITY" in cls:
                lines.append(
                    f"  Make transform reversible: {dst} <= {src};"
                    f"  [at {loc} — current operation loses information]"
                )
            else:
                lines.append(f"  Review assignment {dst} <= {src}  at {loc}  [{cls}/{sub}]")

    if missing:
        gate_list = ", ".join(missing)
        lines.append(
            f"  Gate {pa_sig} on: {gate_list}"
            f"  — add these signals as required conditions in the driver predicate."
        )

    if not lines:
        lines.append("  No specific RTL fix identified — review predicate logic manually.")

    return "\n".join(lines)


def _compute_notes(payload: Dict) -> str:
    """Collect anomalies: scheduling cancellation, registered FF timing shifts."""
    notes: List[str] = []
    rca  = payload.get("final_rca") or {}
    pev  = rca.get("primary_evidence") or []
    pev0 = pev[0] if pev and isinstance(pev[0], dict) else {}
    ev0  = pev0.get("evidence") or {}
    ic   = ev0.get("intra_cycle_cancellation") or {}
    if isinstance(ic, dict) and ic.get("detected"):
        cycle = ic.get("anchor_cycle") or ic.get("analysis_cycle") or "?"
        notes.append(f"Intra-cycle scheduling cancellation at cycle {cycle}")

    pred_a = rca.get("predicate_analysis") or {}
    ma     = pred_a.get("mode_analysis") or {}
    if ma.get("registered"):
        notes.append(
            "Primary signal is a registered FF — "
            "t_eval shifted one cycle back to last transition"
        )

    root_type = rca.get("root_cause_type") or ""
    if "INCONCLUSIVE" in root_type:
        notes.append("Root cause inconclusive — insufficient waveform evidence")

    return "; ".join(notes) if notes else "None"


# ── Main entry ─────────────────────────────────────────────────────────────────

def generate_rca_analysis(payload: Dict[str, Any]) -> str:
    """
    Pure Python structural RCA report.

    Computes VIOLATION_TYPE, CAUSAL_CLASS, VERDICT, CONFIDENCE, FIX_GUIDANCE
    algorithmically from the WaveEye payload — no LLM, no API calls.

    Returns a formatted string.  Saved to .rca_analysis.txt alongside other reports.
    """
    rca      = payload.get("final_rca") or {}
    rule_id  = _extract_rule_id(payload)
    pev      = rca.get("primary_evidence") or []
    pev0     = pev[0] if pev and isinstance(pev[0], dict) else {}

    canon_name, spec_ref, viol_class = _rule_meta(rule_id)
    t_violation = pev0.get("analysis_cycle") or "?"
    rtl_file    = _rtl_location(payload)

    txns     = payload.get("transactions") or []
    txn0     = txns[0] if txns else {}
    t_accept = txn0.get("accept_cycle", "?")

    pred_a   = rca.get("predicate_analysis") or {}
    pa_sig   = pred_a.get("signal") or (pev0.get("expected_signal") or "?")
    pred_str = pred_a.get("driver_predicate") or "(not available)"
    missing  = pred_a.get("missing_signals") or []
    found    = pred_a.get("found_signals") or []
    t_eval   = pred_a.get("t_eval") or t_violation

    # ── Algorithmic classification ─────────────────────────────────────────────
    violation_type = _compute_violation_type(payload, viol_class)
    causal_class   = _compute_causal_class(payload)
    verdict        = _compute_verdict(payload, missing)
    confidence     = _compute_confidence(payload)
    fix_guidance   = _compute_fix_guidance(payload, pa_sig, missing, causal_class)
    notes          = _compute_notes(payload)

    missing_str = ", ".join(missing) if missing else "NONE"
    found_str   = ", ".join(found)   if found   else "NONE"

    sep = "─" * 72
    return (
        f"{sep}\n"
        f"WaveEye — Structural RCA Analysis\n"
        f"{sep}\n"
        f"RULE_ID         : {rule_id} — {canon_name}\n"
        f"SPEC_REFERENCE  : AXI4-Lite Spec {spec_ref}\n"
        f"RTL_LOCATION    : {rtl_file}\n"
        f"t_violation     : {t_violation}   t_accept : {t_accept}   t_eval : {t_eval}\n"
        f"\n"
        f"VIOLATION_TYPE  : {violation_type}\n"
        f"CAUSAL_CLASS    : {causal_class}\n"
        f"VERDICT         : {verdict}\n"
        f"CONFIDENCE      : {confidence}\n"
        f"\n"
        f"MISSING_DEPS    : {missing_str}\n"
        f"FOUND_IN_PRED   : {found_str}\n"
        f"\n"
        f"DRIVER_PREDICATE  (signal: {pa_sig} @ t_eval={t_eval}):\n"
        f"  if ({pred_str})\n"
        f"\n"
        f"ACTIVE_TERMS:\n"
        f"{_format_terms(pred_a)}\n"
        f"\n"
        f"STRUCTURAL_DEFECTS:\n"
        f"{_format_structural(payload)}\n"
        f"\n"
        f"FIX_GUIDANCE:\n"
        f"{fix_guidance}\n"
        f"\n"
        f"NOTES           : {notes}\n"
        f"{sep}"
    )


# Backward-compatible alias (keeps rca_8.py import working without change)
generate_llm_rca_prompt = generate_rca_analysis

# SYSTEM_PROMPT is no longer used — kept as empty string to avoid ImportError
# from any external code that imported it directly.
SYSTEM_PROMPT = ""
