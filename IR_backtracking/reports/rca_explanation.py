"""
RCA Explanation — Engineer-Facing Waveform Walkback
=====================================================
Final-stage explanation: walks backward through the computed backtracking
results and answers seven questions in plain language.

No classifications, invariants, proof language, or violation counts.
Reads like an engineer manually tracing the waveform.

Output format:
    ================ RCA EXPLANATION ================
    Observed Failure:    ...
    Expected Behavior:   ...
    What Actually Happened: ...
    Why It Happened:     ...
    What Caused That Condition: ...
    Terminal Cause in RTL: ...
    =================================================

Usage:
    from reports.rca_explanation import generate_rca_explanation
    text = generate_rca_explanation(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

_HDR = "================ RCA EXPLANATION ================"
_FTR = "================================================="


def generate_rca_explanation(payload: Dict[str, Any]) -> str:
    """Return a plain-language RCA explanation string."""

    rca       = payload.get("final_rca") or {}
    findings  = payload.get("findings") or []
    dv        = payload.get("datapath_violations") or []
    tv        = payload.get("transport_violations") or []

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or pev0.get("expected_signal") or "target signal"
    rule  = pev0.get("rule_id") or "N/A"
    cyc   = pev0.get("analysis_cycle")

    # Best matching finding for evidence detail
    first_f = next(
        (f for f in findings if f.get("signal") == sig or f.get("rule_id") == rule),
        findings[0] if findings else {},
    )
    evid = first_f.get("evidence") or {}
    canc = evid.get("intra_cycle_cancellation") or {}
    cyc_r= evid.get("cycle_report") or {}

    enabling  = canc.get("expected_driver_conditions") or []
    overwrite = canc.get("final_overwrite_conditions") or []
    trigger   = evid.get("trigger_condition") or ""
    cycle_det = cyc_r.get("cycle_detected") or ("CYCLIC" in (rca.get("causal_chain") or "").upper())
    block_sig = cyc_r.get("blocking_signal") or ""
    chain     = rca.get("causal_chain") or ""

    if root_type == "PROTOCOL":
        answers = _explain_protocol(
            sig, rule, cyc, trigger, enabling, overwrite,
            cycle_det, block_sig, chain, rca,
        )
    elif root_type == "DATAPATH":
        answers = _explain_datapath(sig, rca, dv, cyc)
    elif root_type == "TRANSPORT":
        answers = _explain_transport(sig, rca, tv, cyc)
    else:
        answers = _explain_inconclusive(sig, cyc)

    return _format(answers)


# ── Per-root-cause answer builders ────────────────────────────────────────────

def _explain_protocol(
    sig: str,
    rule: str,
    cyc: Any,
    trigger: str,
    enabling: List[str],
    overwrite: List[str],
    cycle_det: bool,
    block_sig: str,
    chain: str,
    rca: Dict[str, Any],
) -> Dict[str, str]:
    cyc_s  = f" at cycle {cyc}" if cyc is not None else ""
    trig   = trigger or "the master asserted its request signal"
    en_c   = enabling[0]  if enabling  else f"the condition that should drive {sig} high"
    ow_c   = overwrite[0] if overwrite else f"a broader condition that resets {sig} to 0"

    # Observed failure
    observed = (
        f"The waveform showed {sig} staying at 0{cyc_s} even though the master had "
        f"completed the handshake required to trigger a response."
    )

    # Expected behavior
    expected = (
        f"After {trig}, the slave was required to assert {sig} to acknowledge "
        f"the request and allow the transaction to proceed."
    )

    # What actually happened
    happened = (
        f"{sig} never went high. Every time the enabling condition "
        f"`{en_c}` was true, a second assignment in the same always-block "
        f"immediately wrote {sig} back to 0 before the clock edge committed the value."
    )

    # Why it happened
    why = (
        f"The always-block has two assignments to {sig}. "
        f"The first writes {sig}=1 when `{en_c}` is true. "
        f"The second writes {sig}=0 when `{ow_c}` is true. "
        f"Because the second condition includes every situation where the first is true "
        f"— it is a broader condition — the second assignment always fires after the first "
        f"and always wins. The 0 is what gets registered on the clock edge."
    )

    # What caused that condition
    if cycle_det and block_sig:
        caused = (
            f"The condition `{ow_c}` stays permanently true because it depends on "
            f"`{block_sig}`, an FSM state register. "
            f"That register is stuck in the state that keeps the broad condition active "
            f"because the FSM transition that would change it requires {sig} to assert "
            f"first — which never happens. The two signals are waiting for each other."
        )
    else:
        caused = (
            f"The condition `{ow_c}` is continuously true because the FSM state "
            f"register it depends on has not moved out of its current state. "
            f"That state persists because the transaction that was supposed to advance "
            f"the FSM cannot complete while {sig} is held at 0."
        )

    # Terminal cause
    terminal = (
        f"In the RTL always-block for {sig}, the default assignment "
        f"(`{ow_c}` → {sig}=0) is written after the specific enabling assignment "
        f"(`{en_c}` → {sig}=1). "
        f"In SystemVerilog, the last non-blocking assignment to a register in a given "
        f"time step wins. So the default always overwrites the enable. "
        f"Swapping the order — or restructuring as an if-else chain so only one branch "
        f"executes — is the fix."
    )

    return {
        "Observed Failure":          observed,
        "Expected Behavior":         expected,
        "What Actually Happened":    happened,
        "Why It Happened":           why,
        "What Caused That Condition":caused,
        "Terminal Cause in RTL":     terminal,
    }


def _explain_datapath(
    sig: str,
    rca: Dict[str, Any],
    dv: List[Dict[str, Any]],
    cyc: Any,
) -> Dict[str, str]:
    first  = dv[0] if dv else {}
    dst    = first.get("destination_signal") or first.get("signal") or sig
    src    = first.get("source_signal") or "the source register"
    sub    = first.get("subtype") or "non-invertible transform"
    rtl    = first.get("rtl_line")
    src_w  = first.get("inferred_src_width")
    dst_w  = first.get("inferred_dst_width")
    loc    = f"line {rtl}" if rtl else "the assignment block"
    cyc_s  = f" at cycle {cyc}" if cyc is not None else ""
    lost   = (src_w - dst_w) if (src_w and dst_w) else None
    lost_s = f" — {lost} bit{'s' if lost and lost > 1 else ''} are silently dropped" if lost else ""

    observed = (
        f"A read-back of {dst}{cyc_s} returned a value that did not match "
        f"what had been written — the upper bits were zero even when the source data was not."
    )

    expected = (
        f"The slave was expected to return the exact value written to the relevant "
        f"address; a read after a write to the same location should be consistent."
    )

    happened = (
        f"{dst} is driven from {src}, but the RTL expression at {loc} is narrower "
        f"than the source{lost_s}. "
        f"The {sub} in that expression means two different source values can produce "
        f"the same value on {dst}; once the data passes through, the original cannot "
        f"be recovered from what the master reads back."
    )

    why = (
        f"The RTL at {loc} assigns {dst} using a slice or reduction of {src} "
        f"rather than the full word. "
        f"{'The destination is only ' + str(dst_w) + ' bits wide, so bits [' + str(src_w-1) + ':' + str(dst_w) + '] of the source are truncated.' if src_w and dst_w else 'The output is narrower than the source, so some input bits are always discarded.'} "
        f"This happens unconditionally — there is no path through the always-block "
        f"that preserves the full source width."
    )

    caused = (
        f"The source register {src} can hold values that differ only in the bits "
        f"that the assignment drops. "
        f"A write that puts a non-zero value in those upper bits will appear to succeed "
        f"(the write channel handshake completes normally), but when the master reads "
        f"back, those bits come back as zero because they were never stored."
    )

    terminal = (
        f"At {loc}, the assignment to {dst} is written as a fixed slice or reduction "
        f"of {src} — it is not a conditional expression and it is not guarded. "
        f"Every clock edge that updates {dst} applies the same narrowing. "
        f"The fix is to widen {dst} to match {src}, or to explicitly prove "
        f"the dropped bits are always zero before suppressing the warning."
    )

    return {
        "Observed Failure":          observed,
        "Expected Behavior":         expected,
        "What Actually Happened":    happened,
        "Why It Happened":           why,
        "What Caused That Condition":caused,
        "Terminal Cause in RTL":     terminal,
    }


def _explain_transport(
    sig: str,
    rca: Dict[str, Any],
    tv: List[Dict[str, Any]],
    cyc: Any,
) -> Dict[str, str]:
    first  = tv[0] if tv else {}
    dst    = first.get("destination_signal") or "WDATA"
    src    = first.get("source_signal") or "the write source"
    strb   = first.get("strobe_signal") or "WSTRB"
    rtl    = first.get("rtl_line")
    loc    = f"line {rtl}" if rtl else "the write assignment block"
    cyc_s  = f" at cycle {cyc}" if cyc is not None else ""

    observed = (
        f"A write transaction{cyc_s} stored the wrong byte in slave memory — "
        f"the byte that the master intended for one lane ended up in a different lane."
    )

    expected = (
        f"Each bit in {strb} should correspond to the byte in the matching lane "
        f"of {dst}. When {strb}[i]=1, the slave should write {dst}[8i+7:8i] to "
        f"its storage — and that byte should be the one the master intended for lane i."
    )

    happened = (
        f"{dst} was steered — shifted or rearranged — so that the intended byte "
        f"moved to a different lane. But {strb} was not steered by the same amount. "
        f"So the strobe enabled the original lane (now carrying the wrong byte) "
        f"while the intended byte sat in an un-enabled lane and was discarded."
    )

    why = (
        f"At {loc}, the RTL applies a transformation to {dst} (shifting it, "
        f"replicating it, or rearranging its lanes) but the expression that drives "
        f"{strb} was not updated to apply the same transformation. "
        f"The two signals are driven by independent expressions that disagree "
        f"about which lane is active."
    )

    caused = (
        f"The byte-offset or steering-select signal that controls the {dst} "
        f"rearrangement is a registered value set earlier in the write sequence. "
        f"It correctly steers {dst} but was never connected to a matching steering "
        f"expression for {strb} — so {strb} reflects the pre-steering lane assignment "
        f"for every write transaction, regardless of offset."
    )

    terminal = (
        f"At {loc}, the assignment to {strb} is missing the same shift or permutation "
        f"that is applied to {dst}. "
        f"This is a coding omission — there is no conditional path that corrects for it. "
        f"Adding the same steering expression to {strb} that is already applied to "
        f"{dst} is the fix; no other logic needs to change."
    )

    return {
        "Observed Failure":          observed,
        "Expected Behavior":         expected,
        "What Actually Happened":    happened,
        "Why It Happened":           why,
        "What Caused That Condition":caused,
        "Terminal Cause in RTL":     terminal,
    }


def _explain_inconclusive(sig: str, cyc: Any) -> Dict[str, str]:
    cyc_s = f" at cycle {cyc}" if cyc is not None else ""
    return {
        "Observed Failure":
            f"The waveform showed {sig} in an unexpected state{cyc_s}, "
            f"but the analysis could not trace the cause to a specific RTL location.",
        "Expected Behavior":
            f"{sig} should have changed state to satisfy the protocol obligation.",
        "What Actually Happened":
            f"{sig} did not change as required, but no RTL driver was found "
            f"that could be confirmed as the cause.",
        "Why It Happened":
            "The RTL driver table does not cover all assignments to this signal, "
            "or the signal is driven by a primary input (master-side) with no "
            "slave-side driver to analyse.",
        "What Caused That Condition":
            "Cannot be determined without a complete driver table for this signal.",
        "Terminal Cause in RTL":
            "Provide the true_drivers CSV with all always-block assignments to "
            f"{sig} and re-run the analysis.",
    }


# ── Formatter ──────────────────────────────────────────────────────────────────

def _format(answers: Dict[str, str]) -> str:
    """Render the seven-field answer dict into the specified output format."""
    _order = [
        "Observed Failure",
        "Expected Behavior",
        "What Actually Happened",
        "Why It Happened",
        "What Caused That Condition",
        "Terminal Cause in RTL",
    ]

    lines = ["", _HDR, ""]
    for key in _order:
        text = answers.get(key, "(not determined)")
        lines.append(f"{key}:")
        lines += _wrap(text, indent=2)
        lines.append("")
    lines.append(_FTR)
    return "\n".join(lines)


def _wrap(text: str, indent: int = 0) -> List[str]:
    prefix = " " * indent
    words  = text.split()
    result = []
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
