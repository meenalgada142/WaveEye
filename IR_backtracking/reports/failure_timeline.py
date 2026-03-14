"""
Failure Timeline Generator
===========================
Constructs a minimal, human-readable causality timeline from the RCA payload.

Rules:
  - Select only cycles that contribute to the observed bug.
  - No unrelated waveform activity.
  - Limit to 6-10 steps.
  - Highlight: first write, second conflicting write, address-reuse point,
    observable corruption window.

Output format per step:

    Step N  [Cycle CCC]  TRANSACTION_TYPE
    Signals : KEY=VAL, KEY=VAL
    Effect  : one-line consequence

Usage:
    from reports.failure_timeline import generate_failure_timeline
    text = generate_failure_timeline(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

_SEP  = "=" * 79
_DASH = "-" * 79
_MAX_STEPS = 10
_MIN_STEPS = 6


def generate_failure_timeline(payload: Dict[str, Any]) -> str:
    """Return a 6-10 step causality timeline from an RCA payload dict."""

    rca       = payload.get("final_rca") or {}
    txns      = payload.get("transactions") or []
    findings  = payload.get("findings") or []
    tv        = payload.get("transport_violations") or []
    dv        = payload.get("datapath_violations") or []
    binding   = payload.get("binding_result") or {}

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification") or "UNKNOWN"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or pev0.get("expected_signal") or "target signal"
    cyc   = pev0.get("analysis_cycle")

    hdr = [
        _SEP,
        "  FAILURE CAUSALITY TIMELINE",
        _SEP,
        f"  Root Cause     : {root_type}/{classif}",
        f"  Primary Signal : {sig}",
        f"  Violation Cycle: {cyc if cyc is not None else 'N/A'}",
        _SEP,
        "",
        "  Step  Cycle  Transaction                    Key Signals               Effect",
        "  " + _DASH,
    ]

    steps: List[Tuple[Optional[int], str, str, str, str]] = []
    # Tuple: (cycle, step_label, tx_type, signal_summary, effect)

    if root_type == "TRANSPORT":
        steps = _timeline_transport(tv, txns, rca)
    elif root_type == "DATAPATH":
        steps = _timeline_datapath(dv, txns, rca, binding, classif)
    elif root_type == "PROTOCOL":
        steps = _timeline_protocol(findings, txns, rca, sig, cyc)
    else:
        steps = _timeline_inconclusive(rca, cyc)

    # Trim to [MIN, MAX] steps
    steps = steps[:_MAX_STEPS]
    while len(steps) < _MIN_STEPS:
        steps.append((None, f"Step {len(steps)+1}", "—", "—", "(no further causal events)"))

    body: List[str] = []
    for i, (cycle, label, tx, sigs, effect) in enumerate(steps, 1):
        cyc_str = str(cycle) if cycle is not None else " ? "
        body.append(f"  [{i:>2}]  {cyc_str:>5}  {tx:<30}  {sigs:<24}  {effect}")

    footer = [
        "",
        "  " + _DASH,
        "  KEY: [W]=first write  [CW]=conflicting write  [AR]=address reuse",
        "       [CW!]=corruption window  [VIO]=violation observed",
        _SEP,
    ]

    return "\n".join(hdr + body + footer)


# ── Per-root-cause timeline builders ──────────────────────────────────────────

def _timeline_transport(
    tv: List[Dict[str, Any]],
    txns: List[Dict[str, Any]],
    rca: Dict[str, Any],
) -> List[Tuple]:
    first_viol = tv[0] if tv else {}
    rtl_line   = first_viol.get("rtl_line")
    dst        = first_viol.get("destination_signal") or "WDATA"
    strb       = first_viol.get("strobe_signal") or "WSTRB"
    src        = first_viol.get("source_signal") or "source_data"

    # Collect write transactions
    writes = [t for t in txns if str(t.get("type", "")).upper() in ("WRITE", "W")]
    reads  = [t for t in txns if str(t.get("type", "")).upper() in ("READ", "R")]

    steps: List[Tuple] = []

    # Step: RTL is elaborated with mismatched steering
    steps.append((
        None,
        "RTL elaboration",
        "STATIC — design flaw present",
        f"{dst} ← f({src}), {strb} unchanged",
        f"Byte-lane steering mismatch at {'line '+str(rtl_line) if rtl_line else 'assignment block'}.",
    ))

    # Step: first write transaction
    w0 = writes[0] if writes else {}
    w0_cyc  = w0.get("accept_cycle") or w0.get("cycle") or "?"
    w0_addr = w0.get("address") or w0.get("awaddr") or "?"
    steps.append((
        w0_cyc,
        "WRITE — address accepted",
        "[W] AWVALID && AWREADY",
        f"AWADDR={w0_addr}",
        "Transaction begins; RTL begins driving WDATA with rearranged data.",
    ))

    # Step: data phase
    steps.append((
        w0_cyc,
        "WRITE — data phase",
        "[W] WVALID && WREADY",
        f"{strb}≠expected, {dst} missteered",
        "WSTRB asserts lane i; WDATA[i] carries wrong byte due to mismatch.",
    ))

    # Step: slave commits wrong byte
    steps.append((
        w0_cyc,
        "WRITE — slave commit",
        "[W] memory write",
        "storage[i] ← WDATA[i]",
        "Wrong data committed to slave storage; BRESP=OKAY masks the error.",
    ))

    # Step: second write (if any)
    if len(writes) > 1:
        w1 = writes[1]
        w1_cyc  = w1.get("accept_cycle") or w1.get("cycle") or "?"
        w1_addr = w1.get("address") or w1.get("awaddr") or "?"
        same_addr = str(w1_addr) == str(w0_addr)
        tag = "[AR]" if same_addr else "[CW]"
        steps.append((
            w1_cyc,
            "WRITE — second transaction",
            f"{tag} AWVALID && AWREADY",
            f"AWADDR={w1_addr}",
            "Address " + ("reused — second write aliases first." if same_addr
                          else "distinct but same mismatch applies."),
        ))

    # Step: observable corruption on read
    r0 = reads[0] if reads else {}
    r0_cyc  = r0.get("accept_cycle") or r0.get("cycle") or rca.get("analysis_cycle") or "?"
    steps.append((
        r0_cyc,
        "READ — RDATA corruption",
        "[CW!] RVALID && RREADY",
        f"RDATA = wrong_byte",
        "Master reads back an aliased value; data integrity is lost.",
    ))

    # Step: violation observed
    cyc_vio = rca.get("analysis_cycle") or r0_cyc
    steps.append((
        cyc_vio,
        "VIOLATION OBSERVED",
        "[VIO] protocol check",
        f"{strb} / {dst} mismatch",
        "WSTRB-WDATA alignment invariant confirmed broken.",
    ))

    return steps


def _timeline_datapath(
    dv: List[Dict[str, Any]],
    txns: List[Dict[str, Any]],
    rca: Dict[str, Any],
    binding: Dict[str, Any],
    classif: str,
) -> List[Tuple]:
    first  = dv[0] if dv else {}
    dst    = first.get("destination_signal") or first.get("signal") or "RDATA"
    src    = first.get("source_signal") or "source"
    sub    = first.get("subtype") or classif
    rtl    = first.get("rtl_line")
    src_w  = first.get("inferred_src_width")
    dst_w  = first.get("inferred_dst_width")

    writes = [t for t in txns if str(t.get("type", "")).upper() in ("WRITE", "W")]
    reads  = [t for t in txns if str(t.get("type", "")).upper() in ("READ", "R")]

    causal_bindings = binding.get("causal_bindings") or []
    bound_cyc = causal_bindings[0].get("cycle") if causal_bindings else None

    steps: List[Tuple] = []

    # Step 0: static defect in RTL
    width_note = f"{src_w}→{dst_w} bits" if src_w and dst_w else "width reduced"
    steps.append((
        None,
        "RTL elaboration",
        "STATIC — non-invertible transform",
        f"{dst} ← f({src})",
        f"{sub} at {'line '+str(rtl) if rtl else 'block'}: {width_note}.",
    ))

    # Step: master writes data
    w0 = writes[0] if writes else {}
    w0_cyc  = w0.get("accept_cycle") or w0.get("cycle") or "?"
    w0_addr = w0.get("address") or w0.get("awaddr") or "?"
    steps.append((
        w0_cyc,
        "WRITE — data accepted",
        "[W] WVALID && WREADY",
        f"AWADDR={w0_addr}",
        "Source data written to slave; original value intact in slave storage.",
    ))

    # Step: RTL apply transform
    steps.append((
        w0_cyc,
        "DATAPATH — transform applied",
        "[W] combinational path",
        f"{src} → f() → {dst}",
        f"{sub}: bits are {'truncated' if 'TRUNCAT' in sub else 'collapsed/fabricated'} here.",
    ))

    # Step: second write with different data (aliasing)
    if len(writes) > 1:
        w1 = writes[1]
        w1_cyc  = w1.get("accept_cycle") or w1.get("cycle") or "?"
        w1_addr = w1.get("address") or w1.get("awaddr") or "?"
        same_addr = str(w1_addr) == str(w0_addr)
        tag = "[AR]" if same_addr else "[CW]"
        steps.append((
            w1_cyc,
            "WRITE — second transaction",
            f"{tag} WVALID && WREADY",
            f"AWADDR={w1_addr}",
            "Different logical value written; same transform maps it to same output — aliasing confirmed." if same_addr
            else "Second distinct value also truncated by the same path.",
        ))

    # Step: master reads back
    r0 = reads[0] if reads else {}
    r0_cyc = r0.get("accept_cycle") or r0.get("cycle") or bound_cyc or "?"
    steps.append((
        r0_cyc,
        "READ — RDATA driven",
        "[CW!] RVALID && RREADY",
        f"RDATA = collapsed_value",
        "Master receives output of non-invertible transform; original value unrecoverable.",
    ))

    # Step: causal binding (if transaction binding pass ran)
    if causal_bindings:
        cb = causal_bindings[0]
        cb_cyc = cb.get("cycle") or r0_cyc
        cb_sig = cb.get("assignment_signal") or dst
        steps.append((
            cb_cyc,
            "CAUSAL BINDING — confirmed",
            "[CW!] transaction matched",
            f"{cb_sig} ← defective expr",
            "Transaction-level binding confirms the structural defect was exercised in this transaction.",
        ))

    # Step: violation observed
    cyc_vio = rca.get("analysis_cycle") or r0_cyc
    steps.append((
        cyc_vio,
        "VIOLATION OBSERVED",
        "[VIO] datapath check",
        f"{sub} on {dst}",
        "Non-bijective transform invariant confirmed broken; defect is deterministic.",
    ))

    return steps


def _timeline_protocol(
    findings: List[Dict[str, Any]],
    txns: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
    viol_cyc: Any,
) -> List[Tuple]:
    chain = rca.get("causal_chain") or ""
    pev   = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    rule  = pev0.get("rule_id") or "protocol rule"

    evid  = pev0.get("evidence") or {}
    canc  = evid.get("intra_cycle_cancellation") or {}
    overwrites = canc.get("final_overwrite_conditions") or []
    enabling   = evid.get("trigger_condition") or "enabling condition"

    reads  = [t for t in txns if str(t.get("type", "")).upper() in ("READ", "R")]
    writes = [t for t in txns if str(t.get("type", "")).upper() in ("WRITE", "W")]

    steps: List[Tuple] = []

    # Step: RTL has structural overwrite
    ow_str = overwrites[0] if overwrites else "superset condition"
    steps.append((
        None,
        "RTL elaboration",
        "STATIC — driver masking present",
        f"{sig}: D1=1 overwritten by D2=0",
        f"Always-block has a later driver whose condition ({ow_str}) subsumes the enabling path.",
    ))

    # Step: master asserts enabling condition
    t0 = reads[0] if reads else (writes[0] if writes else {})
    t0_cyc = t0.get("accept_cycle") or t0.get("cycle") or "?"
    steps.append((
        t0_cyc,
        "MASTER — enabling condition",
        "[W] enabling signal asserted",
        f"{enabling}=1",
        f"Enabling condition for {sig} is now true; RTL D1 writes {sig}=1.",
    ))

    # Step: masking driver fires
    steps.append((
        t0_cyc,
        "RTL — masking overwrite",
        "[CW] same always-block cycle",
        f"D2 condition true → {sig}=0",
        f"D2 (superset condition) fires at same delta; {sig} is overwritten to 0 before clock edge.",
    ))

    # Step: clock edge commits wrong value
    steps.append((
        t0_cyc,
        "CLOCK EDGE — wrong value committed",
        "posedge ACLK",
        f"{sig} registers 0",
        f"{sig} captures 0 instead of 1; FSM or handshake does not advance.",
    ))

    # Step: handshake stalls
    stall_cyc = viol_cyc
    steps.append((
        stall_cyc,
        "HANDSHAKE — stall begins",
        "[CW!] VALID without READY",
        f"VALID=1, {sig}=0",
        "Master holds VALID high waiting for READY; slave cannot assert READY due to structural mask.",
    ))

    # Step: cyclic dependency (if mentioned in chain)
    if "CYCLIC" in chain.upper() or "cyclic" in chain.lower():
        steps.append((
            stall_cyc,
            "CYCLIC DEPENDENCY — detected",
            "FSM lock",
            "state stuck",
            "FSM state required for READY de-masking is itself gated by a stalled signal — deadlock.",
        ))

    # Step: violation observed
    steps.append((
        viol_cyc,
        "VIOLATION OBSERVED",
        f"[VIO] {rule}",
        f"{sig} stuck at 0",
        f"{rule} handshake obligation not met; transaction cannot complete.",
    ))

    return steps


def _timeline_inconclusive(rca: Dict[str, Any], cyc: Any) -> List[Tuple]:
    return [
        (None, "Analysis start",      "—", "waveform loaded",       "No structural violation detected."),
        (cyc,  "Violation cycle",      "—", "signal stuck",          "Temporal failure observed but root cause not isolated."),
        (None, "RTL drivers",         "—", "logic table incomplete", "Insufficient driver coverage to trace causation."),
        (None, "Recommendation",      "—", "extend coverage",        "Provide RTL drivers CSV and FSM encoding file."),
        (None, "—",                   "—", "—",                      "(no further causal events isolable)"),
        (None, "—",                   "—", "—",                      "(no further causal events isolable)"),
    ]
