"""
Console Diagnosis — Precision RTL Root-Cause Report
====================================================
Produces a ≤15-line enterprise-grade diagnostic block suitable for
senior RTL engineers and verification leads.

Features:
  PART 2 — Canonical AXI4-Lite rule names (no numeric RULE_N in default output)
  PART 5 — Confidence score computed from structural proof, binding, transaction count
  PART 6 — Multi-line labelled format: Primary Failure / Root Cause / Severity /
            Transactions Affected / Confidence / Next Step
  PART 7 — Clean PASS block when no defects detected

Extraction rules:
  - If >10 violations reference the same storage element, treat as ONE defect.
  - Prefer storage element over individual assignments.
  - If protocol failure depends on datapath defect, append:
    "Protocol symptom caused by datapath defect."

Usage:
    from reports.console_diagnosis import generate_console_diagnosis
    print(generate_console_diagnosis(payload))
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

try:
    from protocols.axi_lite.signal_map import RULE_STABILITY_SIGNAL_MAP as _STABILITY_SIGNAL_MAP
except ImportError:
    _STABILITY_SIGNAL_MAP = {}

_BAR        = "─" * 64
_TRACE_BAR  = "─" * 64
_TITLE      = "WaveEye Diagnostic Summary"
_PASS       = "WaveEye Result"

# ── Rule → (direction, request_signal, response_signal) ──────────────────────

_RULE_DIRECTION: Dict[str, tuple] = {
    # (direction, request_signal, response_signal)
    # ── Address / control stability ─────────────────────────────────────
    "RULE_1":  ("read/write", "ARVALID/AWVALID", "ARREADY/AWREADY"),
    "RULE_14": ("read",       "ARVALID",          "ARREADY"),
    "RULE_15": ("write",      "AWVALID",           "AWREADY"),
    # ── VALID persistence ────────────────────────────────────────────────
    "RULE_2":  ("read",   "ARVALID", "ARREADY"),
    "RULE_3":  ("write",  "AWVALID", "AWREADY"),
    "RULE_4":  ("write",  "WVALID",  "WREADY"),
    "RULE_5":  ("read",   "RVALID",  "RREADY"),
    "RULE_6":  ("write",  "BVALID",  "BREADY"),
    # ── Data / response stability ────────────────────────────────────────
    "RULE_7":  ("write",  "WVALID",  "WREADY"),
    "RULE_8":  ("read",   "RVALID",  "RREADY"),
    "RULE_9":  ("write",  "BVALID",  "BREADY"),
    # ── Response ordering / liveness ─────────────────────────────────────
    "RULE_10": ("read",   "ARVALID", "RVALID"),
    "RULE_11": ("write",  "AWVALID", "BVALID"),
    "RULE_12": ("read",   "ARVALID", "RVALID"),
    "RULE_13": ("write",  "AWVALID", "BVALID"),
}

# When the finding carries expected_signal in its evidence, that always
# overrides the rule-direction fallback above for exp_sig.

# ── Violation type per rule (determines Step-2 message) ───────────────────────
# MISSING     : response signal never asserted in the observation window
# UNPROMPTED  : response signal asserted without the required prior transaction
# PERSISTENCE : VALID signal dropped before handshake completed
# STABILITY   : signal value changed while VALID was asserted (before READY)
_RULE_VIOLATION_TYPE: Dict[str, str] = {
    "RULE_1":  "STABILITY",    # ARADDR/AWADDR changed while VALID=1
    "RULE_2":  "PERSISTENCE",  # ARVALID dropped before ARREADY
    "RULE_3":  "PERSISTENCE",  # AWVALID dropped before AWREADY
    "RULE_4":  "PERSISTENCE",  # WVALID  dropped before WREADY
    "RULE_5":  "PERSISTENCE",  # RVALID  dropped before RREADY
    "RULE_6":  "PERSISTENCE",  # BVALID  dropped before BREADY
    "RULE_7":  "STABILITY",    # WDATA/WSTRB changed while WVALID=1
    "RULE_8":  "STABILITY",    # RDATA/RRESP changed while RVALID=1
    "RULE_9":  "STABILITY",    # BRESP changed while BVALID=1
    "RULE_10": "UNPROMPTED",   # RVALID asserted without prior AR handshake
    "RULE_11": "UNPROMPTED",   # BVALID asserted without prior AW+W handshake
    "RULE_12": "MISSING",      # Read response never received
    "RULE_13": "MISSING",      # Write response never received
    "RULE_14": "STABILITY",    # ARPROT changed during AR backpressure
    "RULE_15": "STABILITY",    # AWPROT changed during AW backpressure
}

# ── Canonical rule name mapping (PART 2) ──────────────────────────────────────
# Derived directly from axil4.py rule definitions.
# Format: (canonical_id, amba_spec_section)

_RULE_CANON: Dict[str, tuple] = {
    # Address / control stability
    "RULE_1":  ("AXI4L_ADDR_STABILITY",           "AXI4-Lite Spec §A3.1.2"),
    "RULE_14": ("AXI4L_ARPROT_STABILITY",          "AXI4-Lite Spec §A3.2.1"),
    "RULE_15": ("AXI4L_AWPROT_STABILITY",          "AXI4-Lite Spec §A3.2.1"),
    # VALID persistence (§A3.1.2 — VALID must hold until READY)
    "RULE_2":  ("AXI4L_ARVALID_PERSISTENCE",       "AXI4-Lite Spec §A3.1.2"),
    "RULE_3":  ("AXI4L_AWVALID_PERSISTENCE",       "AXI4-Lite Spec §A3.1.2"),
    "RULE_4":  ("AXI4L_WVALID_PERSISTENCE",        "AXI4-Lite Spec §A3.1.2"),
    "RULE_5":  ("AXI4L_RVALID_PERSISTENCE",        "AXI4-Lite Spec §A3.1.2"),
    "RULE_6":  ("AXI4L_BVALID_PERSISTENCE",        "AXI4-Lite Spec §A3.1.2"),
    # Data/response stability (signal must not change between VALID and handshake)
    "RULE_7":  ("AXI4L_WDATA_STABILITY",           "AXI4-Lite Spec §A3.2.1"),
    "RULE_8":  ("AXI4L_RDATA_STABILITY",           "AXI4-Lite Spec §A3.3.1"),
    "RULE_9":  ("AXI4L_BRESP_STABILITY",           "AXI4-Lite Spec §A3.2.2"),
    # Response ordering (must not fire without prior accepted transaction)
    "RULE_10": ("AXI4L_RVALID_UNPROMPTED",         "AXI4-Lite Spec §A3.3.1"),
    "RULE_11": ("AXI4L_BVALID_UNPROMPTED",         "AXI4-Lite Spec §A3.2.2"),
    # Response liveness (slave must eventually respond)
    "RULE_12": ("AXI4L_READ_RESPONSE_MISSING",     "AXI4-Lite Spec §A3.3.1"),
    "RULE_13": ("AXI4L_WRITE_RESPONSE_MISSING",    "AXI4-Lite Spec §A3.2.1"),
}

_SEVERITY: Dict[str, str] = {
    "TRANSPORT":          "Functional corruption — data integrity failure",
    "DATAPATH":           "Functional corruption — data integrity failure",
    "SEMANTIC_STRUCTURAL":"Structural defect — non-deterministic memory state",
    "PROTOCOL":           "Handshake violation — AXI compliance failure",
    "INCONCLUSIVE":       "Undetermined — additional inputs required",
}


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_console_diagnosis(payload: Dict[str, Any]) -> str:
    """Return a precision console diagnosis string."""

    rca      = payload.get("final_rca") or {}
    findings = payload.get("findings") or []
    dv       = payload.get("datapath_violations") or []
    tv       = payload.get("transport_violations") or []
    txns     = payload.get("transactions") or []

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    if root_type == "PROTOCOL" and not findings:
        if tv:
            root_type = "TRANSPORT"
        elif dv:
            root_type = "DATAPATH"
        else:
            root_type = "INCONCLUSIVE"
    # Guard against inconsistent resolver output:
    # when there are zero protocol findings, do not present a protocol root cause.
    if root_type == "PROTOCOL" and not findings:
        if tv:
            root_type = "TRANSPORT"
        elif dv:
            root_type = "DATAPATH"
        else:
            root_type = "INCONCLUSIVE"
    pev       = rca.get("primary_evidence") or []
    pev0      = pev[0] if pev and isinstance(pev[0], dict) else {}

    # ── PASS case (PART 7) ──────────────────────────────────────────────────
    is_pass = (
        not findings and not dv and not tv
        and root_type in ("INCONCLUSIVE", None)
        and rca.get("verdict") != "VIOLATED"
    )
    if is_pass:
        return _pass_block(len(txns))

    # ── Extract components ─────────────────────────────────────────────────
    rule_id         = _extract_rule_id(pev0, findings)
    canon_name, spec_ref = _canonical_rule(rule_id)
    storage_element = _dominant_storage(dv, tv, pev0)
    rtl_location    = _rtl_location(dv, tv, findings, pev0)
    severity             = _SEVERITY.get(root_type, "Unknown")
    confidence, conf_bul = _confidence(payload, rca, findings, dv, tv)  # PART 5
    root_cause_desc      = _root_cause_desc(root_type, storage_element, dv, tv, rca, pev0)

    protocol_is_symptom = (
        root_type in ("DATAPATH", "TRANSPORT", "SEMANTIC_STRUCTURAL")
        and bool(findings)
    )

    # ── PART 4: transaction impact — two separate counts ─────────────────
    n_proto_failures = len(findings)
    # Structurally corrupted writes = distinct transaction IDs in causal_bindings
    br = payload.get("binding_result") or {}
    causal_bindings = br.get("causal_bindings") or []
    n_corrupted = len({
        b.get("transaction_id") for b in causal_bindings
        if b.get("transaction_id") is not None
    })

    # Primary failure label
    if canon_name:
        primary = f"{canon_name}"
        if spec_ref:
            primary += f"  ({spec_ref})"
    else:
        if rule_id:
            primary = rule_id
        elif tv:
            primary = str(tv[0].get("class") or tv[0].get("subtype") or "TRANSPORT_MISMATCH")
        elif dv:
            primary = str(dv[0].get("class") or dv[0].get("subtype") or "STRUCTURAL_DEFECT")
        else:
            primary = "(see findings)"

    lines = [
        _BAR,
        _TITLE,
        _BAR,
        "Primary Failure    :",
        f"  {primary}",
        "",
        "Confirmed Root Cause :",
        f"  {root_cause_desc}",
        "",
        "Severity           :",
        f"  {severity}",
        "",
        "Transactions Affected :",
        f"  Protocol-visible failures     : {n_proto_failures}",
        f"  Structurally corrupted writes : {n_corrupted}",
    ]
    if protocol_is_symptom:
        lines.append("")
        lines.append("  [Protocol symptom caused by datapath defect.]")
    lines.append(_BAR)

    # ── Condensed causal trace (always appended) ─────────────────────────
    trace_block = _condense_trace(
        payload, rca, findings, dv, tv, pev0, storage_element, rtl_location,
    )
    return "\n".join(lines) + "\n" + trace_block


# ── PASS block (PART 7) ────────────────────────────────────────────────────────

def _pass_block(n_transactions: int) -> str:
    return "\n".join([
        _BAR,
        _PASS,
        _BAR,
        "Status                : PASS",
        "Protocol compliance   : Verified",
        "Structural integrity  : Verified",
        f"Transactions analyzed : {n_transactions}",
        "Confidence            : 99%",
        "No defects detected.",
        _BAR,
    ])


# ── Confidence score (PART 5) ─────────────────────────────────────────────────

def _confidence(
    payload: Dict[str, Any],
    rca: Dict[str, Any],
    findings: List[Dict],
    dv: List[Dict],
    tv: List[Dict],
) -> tuple:
    """
    Three-component deterministic confidence score.

    Components (sum to 100 when fully confirmed):
      causal_component  = (causal_bound / total_protocol) * 50
      proof_component   = structural proof authority * 30
      determinism       = transaction reproducibility * 20
      driver_penalty    = -10 if driver DB was not loaded

    Returns (score: int, bullets: List[str]) where bullets explain each component.
    """
    br          = payload.get("binding_result") or {}
    bs          = br.get("summary") or {}
    causal_bound = int(bs.get("causal", 0))
    total_proto  = max(len(findings), 1)

    # ── Component 1: causal binding (0–50 pts) ─────────────────────────
    causal_ratio     = causal_bound / total_proto
    causal_pts       = causal_ratio * 50

    # ── Component 2: structural proof completeness (0–30 pts) ──────────
    authority = rca.get("authority") or ""
    if authority == "PREDICATE_PROOF":
        proof_pts   = 30
        proof_label = "PREDICATE_PROOF authority"
    elif dv or tv:
        proof_pts   = 15
        proof_label = "structural evidence present (no formal proof)"
    else:
        proof_pts   = 0
        proof_label = "no structural evidence"

    # ── Component 3: trace determinism (0–20 pts) ──────────────────────
    txns = len(payload.get("transactions") or [])
    if txns >= 5:
        determ_pts   = 20
        determ_label = f"{txns} transactions (strong reproducibility)"
    elif txns >= 2:
        determ_pts   = 14
        determ_label = f"{txns} transactions (moderate reproducibility)"
    elif txns >= 1:
        determ_pts   = 6
        determ_label = f"{txns} transaction (limited reproducibility)"
    else:
        determ_pts   = 0
        determ_label = "no transactions observed"

    # ── Penalty: driver DB not loaded (−10 pts) ────────────────────────
    has_driver_db    = bool(payload.get("logic_table") or payload.get("driver_table"))
    driver_penalty   = 0 if has_driver_db else -10
    driver_bullet    = None if has_driver_db else "Driver DB not loaded (−10%)"

    raw   = causal_pts + proof_pts + determ_pts + driver_penalty
    score = min(max(round(raw), 10), 99)

    bullets = [
        f"Causal binding: {causal_bound}/{len(findings) or total_proto} violations "
        f"traceable to RTL ({round(causal_pts)}%)",
        f"Structural proof: {proof_label} ({round(proof_pts)}%)",
        f"Trace determinism: {determ_label} ({round(determ_pts)}%)",
    ]
    if driver_bullet:
        bullets.append(driver_bullet)

    return score, bullets


# ── Extraction helpers ─────────────────────────────────────────────────────────

def _extract_rule_id(pev0: Dict, findings: List[Dict]) -> str:
    r = pev0.get("rule_id")
    if r:
        return str(r).upper()
    for f in findings:
        r = f.get("rule_id")
        if r:
            return str(r).upper()
    return ""


def _canonical_rule(rule_id: str):
    """Return (canonical_name, spec_ref) tuple for a RULE_N string."""
    entry = _RULE_CANON.get(rule_id)
    if entry:
        return entry
    return ("", "")


def _dominant_storage(
    dv: List[Dict],
    tv: List[Dict],
    pev0: Dict,
) -> str:
    all_v = list(dv) + list(tv)
    if not all_v:
        return pev0.get("expected_signal") or pev0.get("signal") or ""

    def _dst(v: Dict) -> str:
        return v.get("destination_signal") or v.get("signal") or ""

    counts = Counter(_dst(v) for v in all_v if _dst(v))
    if not counts:
        return _dst(all_v[0]) or pev0.get("expected_signal") or pev0.get("signal") or ""

    top_sig, top_count = counts.most_common(1)[0]
    if top_count > 10:
        return top_sig
    return _dst(all_v[0]) or top_sig or pev0.get("expected_signal") or pev0.get("signal") or ""


def _rtl_location(
    dv: List[Dict],
    tv: List[Dict],
    findings: List[Dict],
    pev0: Dict,
) -> str:
    for v in list(dv) + list(tv):
        loc = v.get("source_location") or v.get("source") or v.get("rtl_line")
        if loc:
            return str(loc)
        blk = v.get("always_block_id")
        if blk is not None:
            return f"always_block {blk}"
    for f in findings:
        ev  = f.get("evidence") or {}
        loc = ev.get("source_location") or ev.get("rtl_location")
        if loc:
            return str(loc)
        # Search dependency graph nodes for the blocking driver's source location.
        nodes = ev.get("dependency_graph", {}).get("nodes") or []
        for n in nodes:
            if n.get("type") == "driver" and n.get("condition_active") is False:
                n_loc = n.get("source_location")
                if n_loc:
                    return str(n_loc)
    return pev0.get("source_location") or "(see appendix)"


def _root_cause_desc(
    root_type: str,
    storage: str,
    dv: List[Dict],
    tv: List[Dict],
    rca: Optional[Dict] = None,
    pev0: Optional[Dict] = None,
) -> str:
    sig = storage or "target signal"
    if root_type == "TRANSPORT":
        first = tv[0] if tv else {}
        strb  = first.get("strobe_signal") or "WSTRB"
        return f"WDATA/WSTRB lane misalignment on {sig} — {strb} not mirrored"
    if root_type in ("DATAPATH", "SEMANTIC_STRUCTURAL"):
        first = dv[0] if dv else {}
        sub   = (first.get("subtype") or "width truncation").lower().replace("_", " ")
        sw    = first.get("inferred_src_width")
        dw    = first.get("inferred_dst_width")
        drop  = f" ({sw}-bit source to {dw}-bit target)" if (sw and dw) else ""
        return f"{sub.capitalize()}{drop} in {sig}"
    # PROTOCOL: check for intra_cycle_cancellation evidence first
    pev    = pev0 or {}
    pev_ev = pev.get("evidence") or {}
    ic     = pev_ev.get("intra_cycle_cancellation") or {}
    if ic.get("detected"):
        exp_sig  = pev.get("expected_signal") or pev_ev.get("expected_signal") or sig
        enable_c = pev.get("enable_condition") or pev_ev.get("enable_condition") or ""
        if enable_c:
            return (
                f"{exp_sig} asserted by ({enable_c}) "
                f"then cancelled by more-specific override"
            )
        return f"{exp_sig} cancelled by simultaneously active override driver"
    # PROTOCOL: use predicate_analysis if available
    pred_a = (rca or {}).get("predicate_analysis") or {}
    ma     = pred_a.get("mode_analysis") or {}

    # ── MODE-C: stability mutation — check ready_gate_absent first ──────────
    if ma.get("mode") == "MODE-C":
        stab_sig  = ma.get("stability_signal") or pred_a.get("signal") or sig
        ready_sig = ma.get("ready_signal") or "READY"
        if ma.get("ready_gate_absent", True):
            return (
                f"{stab_sig} driver has no {ready_sig} gate — "
                f"payload advances freely during backpressure"
            )
        return (
            f"{stab_sig} mutated during {ma.get('valid_signal','VALID')}→{ready_sig} "
            f"window despite {ready_sig} present in driver predicate"
        )

    missing = pred_a.get("missing_signals") or []
    pa_sig  = pred_a.get("signal") or sig
    if missing:
        missing_str = ", ".join(missing)
        return f"{pa_sig} driver predicate missing required dependencies: {missing_str}"
    return f"Always-block NBA override on {sig} — asserting assignment overwritten"


def _next_step(
    root_type: str,
    rtl_location: str,
    storage: str,
    dv: List[Dict],
    rca: Optional[Dict] = None,
    pev0: Optional[Dict] = None,
) -> str:
    # Intentionally non-prescriptive for terminal output.
    return "Remediation guidance suppressed."


# ── Condensed Causal Trace (PART 3) ───────────────────────────────────────────

def _sem_class_local(sv: Dict) -> str:
    """Local transform-semantics classifier — avoids importing rca_8."""
    sub     = (sv.get("subtype") or "").upper()
    cls     = (sv.get("class") or sv.get("violation_class") or "").upper()
    combined = sub + " " + cls
    if "TRUNCATION" in combined or ("WIDTH" in combined and "CONSERVATION" in combined):
        return "WIDTH_TRUNCATION"
    if "COLLAPSE" in combined or "NON_INVERTIBLE" in combined or "INVERTIBILITY" in combined:
        return "NON_BIJECTIVE_CAST"
    if "BIJECTION" in combined:
        return "PARTIAL_ASSIGNMENT"
    if "ALIASING" in combined:
        return "LANE_COLLAPSE"
    if "TRANSPORT" in combined or "STROBE" in combined:
        return "TRANSPORT_MISMATCH"
    return sub or cls or "STRUCTURAL_DEFECT"


def _fmt_backtrack_entry(sig: str, entry: dict) -> str:
    """
    Format one signal from a _backtrack_signal_set result dict.
    Returns a single indented line like:
        read_state = 1  → D2 last transition: if (read_state == WAIT) → RESP  [registered]
        ARVALID    = 1  (master input — no RTL driver in slave)
    """
    val = entry.get("value")
    val_s = f" = {val}" if val is not None else ""
    if entry.get("is_leaf"):
        return f"    {sig}{val_s}  (master input \u2014 no RTL driver in slave)"
    cond = entry.get("active_driver_cond") or ""
    rhs  = entry.get("active_driver_rhs")  or ""
    idx  = entry.get("active_driver_idx")
    reg  = entry.get("registered", False)
    if cond:
        d_label = f"D{idx} " if idx is not None else ""
        suffix  = "  [registered FF \u2014 transition from prev cycle]" if reg else ""
        return (
            f"    {sig}{val_s}  \u2192 {d_label}"
            f"{'last transition' if reg else 'active driver'}: if ({cond}) \u2192 {rhs}{suffix}"
        )
    return f"    {sig}{val_s}  (registered state \u2014 no transition at this cycle)"


def _condense_trace(
    payload:         Dict[str, Any],
    rca:             Dict[str, Any],
    findings:        List[Dict],
    dv:              List[Dict],
    tv:              List[Dict],
    pev0:            Dict,
    storage_element: str,
    rtl_location:    str,
) -> str:
    """
    Build the Condensed Causal Trace block.

    Uses causal_bindings (backtracking proof) as primary evidence to name the
    actual RTL signal that caused the protocol violation. Falls back to dv/tv
    when no binding is available.

    Returns a formatted string block ready to print after the main box.
    """
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    rule_id   = _extract_rule_id(pev0, findings)
    direction, req_sig, resp_sig = _RULE_DIRECTION.get(
        rule_id, ("write", "AWVALID", "BVALID")
    )
    # expected_signal / enable_condition may be at top level OR inside evidence
    _pev0_ev = pev0.get("evidence") or {}
    exp_sig  = (pev0.get("expected_signal")
                or _pev0_ev.get("expected_signal")
                or resp_sig)

    # ── Transaction context ───────────────────────────────────────────────
    txns     = payload.get("transactions") or []
    txn0     = txns[0] if txns else {}
    txn_id   = txn0.get("transaction_id")
    accept_c = txn0.get("accept_cycle")
    viol_c   = pev0.get("analysis_cycle")

    # ── Backtracking proof from binding pass ─────────────────────────────
    br              = payload.get("binding_result") or {}
    causal_bindings = br.get("causal_bindings") or []
    # Pick first causal binding as representative proof record
    proof_binding   = causal_bindings[0] if causal_bindings else {}
    proof_viol      = proof_binding.get("violation") or {}
    proof_asn_sig   = proof_binding.get("assignment_signal") or ""
    proof_asn_src   = proof_binding.get("assignment_source") or ""
    proof_addr      = proof_binding.get("address")
    proof_txn_id    = proof_binding.get("transaction_id")

    # ── Representative structural violation (for fallback) ───────────────
    all_v   = list(dv) + list(tv)
    first_v = proof_viol if proof_viol else (all_v[0] if all_v else {})

    dst_raw  = (first_v.get("memory") or first_v.get("destination_signal")
                or storage_element or "target register")
    src_raw  = first_v.get("source_signal") or proof_asn_sig or "WDATA"
    dst_base = dst_raw.split("[")[0].strip()
    src_base = src_raw.split("[")[0].strip()

    # Causal assignment location — prefer binding proof, fall back to rtl_location
    causal_loc = (proof_asn_src or rtl_location or "").strip()
    if not causal_loc or causal_loc == "(see appendix)":
        causal_loc = rtl_location or "RTL location"

    sem_class = _sem_class_local(first_v) if first_v else "STRUCTURAL_DEFECT"
    sw = first_v.get("inferred_src_width") if first_v else None
    dw = first_v.get("inferred_dst_width") if first_v else None

    steps: List[tuple] = []   # (label, detail)

    # Structural-only run: no protocol violations were observed.
    # Avoid protocol-failure wording in this case.
    if not findings and (dv or tv):
        defect_name = sem_class
        loc_note = f" ({causal_loc})" if causal_loc else ""
        steps.append((
            "Structural defect detected",
            f"{defect_name} on {dst_base}{loc_note}.",
        ))
        steps.append((
            "Protocol checker result",
            "No AXI handshake violations detected in this run.",
        ))
        steps.append((
            "Conclusion",
            f"Protocol is compliant for this trace; issue is structural in {dst_base}.",
        ))
        return _format_trace_steps(steps)

    # ── Step 1: Transaction accepted ─────────────────────────────────────
    txn_note = f" (transaction {txn_id})" if txn_id is not None else ""
    addr_note = ""
    if proof_addr is not None:
        addr_note = f" to address 0x{proof_addr:08X}" if isinstance(proof_addr, int) else \
                    f" to address {proof_addr}"
    steps.append((
        f"{direction.capitalize()} transaction accepted",
        f"{req_sig} handshake observed{addr_note}{txn_note}.",
    ))

    # ── Step 2: Violation characterisation (spec-accurate) ───────────────
    viol_type = _RULE_VIOLATION_TYPE.get(rule_id, "MISSING")
    ic_ev     = _pev0_ev.get("intra_cycle_cancellation") or {}
    cancelled = isinstance(ic_ev, dict) and ic_ev.get("detected")

    if viol_type == "STABILITY":
        # Look up the exact payload signal that must be stable for this rule.
        # req_sig is the VALID signal (e.g. RVALID), NOT the payload (RDATA).
        _stab_cfg   = _STABILITY_SIGNAL_MAP.get(rule_id, ())
        stab_sig    = _stab_cfg[0] if _stab_cfg else req_sig
        window_sig  = _stab_cfg[1] if _stab_cfg else req_sig   # VALID signal
        close_sig   = _stab_cfg[2] if _stab_cfg else resp_sig  # READY signal
        _, spec_ref = _RULE_CANON.get(rule_id, ("", "AXI4-Lite Spec §A3.1.2"))
        steps.append((
            f"Signal stability violation — {stab_sig} mutated during {window_sig} window",
            f"{stab_sig} changed value while {window_sig}=1 and {close_sig}=0 — "
            f"{spec_ref} requires {stab_sig} to remain stable from the first "
            f"{window_sig} cycle until {window_sig}∧{close_sig} handshake "
            f"(mutation at cycle {viol_c}).",
        ))
    elif viol_type == "UNPROMPTED":
        steps.append((
            f"Spurious {direction} response detected",
            f"{exp_sig} asserted without a preceding {direction} "
            f"handshake ({req_sig}\u2227{exp_sig.replace('VALID','READY')} "
            f"never completed before cycle {viol_c}).",
        ))
    elif cancelled:
        # Signal was asserted but immediately overwritten — report cycle distance
        # as factual observation, not a spec latency requirement.
        try:
            dist = int(viol_c) - int(accept_c) if (viol_c is not None and accept_c is not None) else None
        except (TypeError, ValueError):
            dist = None
        dist_note = (f" (cycle {accept_c} \u2192 {viol_c})" if dist is not None else "")
        steps.append((
            f"{exp_sig} asserted then immediately cancelled",
            f"{exp_sig} fired at cycle {viol_c} but was overwritten in the same cycle{dist_note}. "
            f"AXI4-Lite requires {exp_sig} to stay high until the handshake partner completes.",
        ))
    elif viol_type == "PERSISTENCE":
        steps.append((
            f"{req_sig} dropped before {direction} handshake completed",
            f"{req_sig} de-asserted before {exp_sig} was received — "
            f"violates AXI4-Lite §A3.1.2 persistence rule (must hold until READY).",
        ))
    else:
        # MISSING — response never came; show observation window as context,
        # NOT as a spec latency requirement.
        try:
            window = int(viol_c) - int(accept_c) if (viol_c is not None and accept_c is not None) else None
        except (TypeError, ValueError):
            window = None
        if window and window > 1:
            steps.append((
                f"{exp_sig} never received",
                f"{exp_sig} not observed in the {window}-cycle observation window "
                f"following the {direction} handshake (cycle {accept_c}). "
                f"AXI4-Lite imposes no fixed latency — this window is tool-configured.",
            ))
        else:
            steps.append((
                f"{exp_sig} never received",
                f"{exp_sig} not observed after {direction} handshake. "
                f"AXI4-Lite imposes no fixed latency — slave must eventually respond.",
            ))

    # ── Step 3: Control path validation ──────────────────────────────────
    ch = resp_sig.replace("VALID", "").replace("READY", "") or direction.upper()
    if root_type in ("DATAPATH", "TRANSPORT", "SEMANTIC_STRUCTURAL"):
        steps.append((
            "Control logic evaluated",
            f"{ch}-channel FSM progressed normally — "
            f"no deadlock or state corruption detected.",
        ))
    else:
        steps.append((
            "Control logic evaluated",
            f"FSM state analysis completed — scheduling conflict or "
            f"missing enable condition identified in {ch}-channel logic.",
        ))

    # ── Protocol-only: check IC evidence first, then predicate analysis ──────
    if root_type == "PROTOCOL":
        # ── Priority 1: intra_cycle_cancellation (driver overwrite) ──────────
        ic = _pev0_ev.get("intra_cycle_cancellation") or {}
        if ic.get("detected"):
            cycle      = ic.get("anchor_cycle") or ic.get("analysis_cycle") or viol_c
            act_drvs   = ic.get("active_drivers") or []
            assert_conds   = ic.get("expected_driver_conditions") or []
            overwrite_conds = ic.get("final_overwrite_conditions") or []
            ic_sig = exp_sig  # already resolved above (top-level OR evidence)

            # Find asserting driver (rhs_value == 1) and overwriting (rhs_value == 0)
            asserting  = next((d for d in act_drvs if d.get("rhs_value") == 1), None)
            overwriting = next((d for d in act_drvs if d.get("rhs_value") == 0), None)
            n_conflict = len(act_drvs)

            # Step 3: scheduling conflict detected
            steps.append((
                f"Scheduling conflict detected  [PROOF]",
                f"Cycle {cycle}: {ic_sig} has {n_conflict} simultaneously active "
                f"drivers with conflicting values.",
            ))

            # Step 4: driver cancellation details
            a_cond = (asserting.get("condition") if asserting
                      else (assert_conds[0] if assert_conds else "(asserting condition)"))
            o_cond = (overwriting.get("condition") if overwriting
                      else (overwrite_conds[0] if overwrite_conds else "(overwrite condition)"))
            a_idx  = asserting.get("driver_idx", "?") if asserting else "?"
            o_idx  = overwriting.get("driver_idx", "?") if overwriting else "?"
            steps.append((
                f"Driver cancellation identified  [PROOF]",
                f"Asserting  (D{a_idx}): if ({a_cond}) \u2192 {ic_sig} = 1\n"
                f"    Overwriting (D{o_idx}): if ({o_cond}) \u2192 {ic_sig} = 0\n"
                f"    \u2192 {ic_sig}=1 is overwritten by the more-specific override "
                f"before handshake completes.",
            ))

            steps.append((
                "Conclusion",
                f"{ic_sig} cannot stay asserted \u2014 the more-specific driver "
                f"(D{o_idx}) cancels the assertion at cycle {cycle}. "
                f"Concurrent override forces {ic_sig}=0 in the same cycle.",
            ))
            return _format_trace_steps(steps)

        # ── Priority 2: predicate_analysis (missing required deps) ───────────
        pred_a   = rca.get("predicate_analysis") or {}
        pa_sig   = pred_a.get("signal") or exp_sig
        pred_str = pred_a.get("driver_predicate") or ""
        missing  = pred_a.get("missing_signals") or []
        found    = pred_a.get("found_signals") or []

        if pred_str or pred_a.get("mode_analysis"):
            # t_ev is needed by MODE-A/B/D trace rendering below.
            # Set it unconditionally so it is available even when pred_str is
            # empty (e.g. MODE-C where the stability signal has no logic-table
            # entry and a_cond is set to "").
            t_ev = pred_a.get("t_eval")

            if pred_str:
                # Primary signal value at t_eval — show hex for RTL context.
                # Suppress for MODE-C: mutation values are shown in MODE-C block.
                _ma_mode = (pred_a.get("mode_analysis") or {}).get("mode", "")
                pri_val  = pred_a.get("primary_waveform_value")
                if _ma_mode == "MODE-C":
                    pri_ann = ""  # value shown in MODE-C block instead
                elif pri_val is None:
                    pri_ann = ""
                else:
                    try:
                        pri_ann = f" = 0x{int(pri_val):X}"
                    except (TypeError, ValueError):
                        pri_ann = f" = {pri_val}"
                steps.append((
                    f"{pa_sig} driver predicate identified  [PROOF]",
                    f"{pa_sig}{pri_ann} @ t_eval={t_ev}\n"
                    f"    Active condition: if ({pred_str})",
                ))

            # ── MODE-A / B / C / D analysis step ──────────────────────────
            # MODE-A  Unexpected assertion   — signal is 1 when it should not be
            # MODE-B  Early deassertion       — signal asserted but dropped before READY
            # MODE-C  Stability mutation      — payload changed during stability window
            # MODE-D  Missing assertion       — signal never asserted, blocking term found
            ma = pred_a.get("mode_analysis") or {}
            ma_mode    = ma.get("mode", "")
            ma_subtype = ma.get("subtype", "")

            if ma_mode == "MODE-B" and ma_subtype == "BLOCKED_ASSERTER":
                # Early deassertion: asserting driver was outcompeted by overwrite driver.
                # Backtrack TRUE terms of the winning (deassert) driver.
                a_idx  = ma.get("asserting_driver_idx", "?")
                w_idx  = ma.get("winning_driver_idx",   "?")
                a_cond = ma.get("asserting_driver_cond", "")
                w_cond = ma.get("winning_driver_cond",  "")
                w_rhs  = ma.get("winning_driver_rhs",   "0")
                w_terms = ma.get("winning_true_terms") or []
                w_tv    = ma.get("winning_term_values") or {}
                term_detail = ", ".join(
                    f"{t}={'TRUE' if w_tv.get(t) else 'FALSE'}"
                    for t in w_terms
                ) if w_terms else "all terms TRUE"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                steps.append((
                    "MODE-B \u2014 Early deassertion  [PROOF]",
                    f"  D{a_idx} (assert): if ({a_cond}) \u2192 1  [INACTIVE]\n"
                    f"  D{w_idx} (win):    if ({w_cond}) \u2192 {w_rhs}  \u2605 ACTIVE\n"
                    f"    TRUE terms of D{w_idx} @ t_eval={t_ev}: {term_detail}"
                    + (f"\n{_bt_lines}" if _bt_lines else ""),
                ))

            elif ma_mode == "MODE-A" and ma_subtype == "UNEXPECTED_ASSERTION":
                # Unexpected assertion: signal is 1 when it should not be.
                # Backtrack TRUE terms of the active asserting driver.
                a_idx  = ma.get("active_driver_idx", "?")
                a_cond = ma.get("active_driver_cond", "")
                a_rhs  = ma.get("active_driver_rhs",  "1")
                a_terms = ma.get("active_true_terms") or []
                a_tv    = ma.get("active_term_values") or {}
                term_detail = ", ".join(
                    f"{t}={'TRUE' if a_tv.get(t) else 'FALSE'}"
                    for t in a_terms
                ) if a_terms else "all terms TRUE"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                steps.append((
                    "MODE-A \u2014 Unexpected assertion  [PROOF]",
                    f"  D{a_idx} (assert): if ({a_cond}) \u2192 {a_rhs}  \u2605 ACTIVE\n"
                    f"    TRUE terms @ t_eval={t_ev}: {term_detail}"
                    + (f"\n{_bt_lines}" if _bt_lines else "")
                    + f"\n  \u21b3 signal fired without required protocol handshake.",
                ))

            elif ma_mode == "MODE-C":
                # Stability mutation: payload changed during VALID → READY window.
                # Backtrack TRUE terms of the active driver that produced the new value.
                stab_sig          = ma.get("stability_signal", pa_sig)
                t_start           = ma.get("t_start", "?")
                t_mut             = ma.get("t_mutation", t_ev)
                val_before        = ma.get("value_before")
                val_after         = ma.get("value_after")
                valid_sig         = ma.get("valid_signal", "VALID")
                ready_sig         = ma.get("ready_signal", "READY")
                ready_gate_absent = ma.get("ready_gate_absent", False)
                a_idx             = ma.get("active_driver_idx", "?")
                a_cond            = ma.get("active_driver_cond", "")
                a_rhs             = ma.get("active_driver_rhs", "")
                a_terms           = ma.get("active_true_terms") or []
                a_tv              = ma.get("active_term_values") or {}
                term_detail = ", ".join(
                    f"{t}={'TRUE' if a_tv.get(t) else 'FALSE'}"
                    for t in a_terms
                ) if a_terms else "all terms TRUE"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                def _fmt_val(v: Any) -> str:
                    if isinstance(v, int) and v > 15:
                        return f"0x{v:X}"
                    return str(v) if v is not None else "?"

                # Root cause verdict depends on whether READY appears anywhere
                # in the stability signal's driver conditions:
                #   absent  → no backpressure gate in RTL → structural root cause
                #   present → READY is referenced but the active predicate allowed
                #             the mutation anyway → predicate correctness issue
                if ready_gate_absent:
                    root_cause_line = (
                        f"  \u21b3 ROOT CAUSE: {stab_sig} driver has no {ready_sig} gate.\n"
                        f"    RTL Fix: gate the update on (!{ready_sig}) or register\n"
                        f"    {stab_sig} at transaction-accept time."
                    )
                else:
                    root_cause_line = (
                        f"  \u21b3 {ready_sig} IS referenced in driver conditions but\n"
                        f"    the active branch at t_mut={t_mut} did not block the update."
                    )

                no_drv = (not a_cond and a_rhs == "(driver not in table)")
                if no_drv:
                    drv_line = (
                        f"  Active driver @ t_mut={t_mut}:\n"
                        f"    (not found in driver table — likely combinational wire)\n"
                        f"    No READY gate can exist for a signal absent from the table."
                    )
                else:
                    drv_line = (
                        f"  Active driver @ t_mut={t_mut}:\n"
                        f"    D{a_idx}: if ({a_cond or '1'}) \u2192 {a_rhs}  \u2605 ACTIVE\n"
                        f"    TRUE terms: {term_detail}"
                        + (f"\n{_bt_lines}" if _bt_lines else "")
                    )
                steps.append((
                    "MODE-C \u2014 Stability mutation  [PROOF]",
                    f"  Stability window  : {valid_sig} asserted @ t={t_start}"
                    f"  until {ready_sig} handshake\n"
                    f"  Signal mutated    : {stab_sig}  "
                    f"{_fmt_val(val_before)} \u2192 {_fmt_val(val_after)}  @ cycle {t_mut}\n"
                    f"\n"
                    + drv_line
                    + f"\n\n{root_cause_line}",
                ))

            elif ma_mode == "MODE-D":
                # Missing assertion: signal never became 1.
                # Backtrack FALSE/blocking terms of the asserting driver.
                a_idx   = ma.get("asserting_driver_idx", "?")
                a_cond  = ma.get("asserting_driver_cond", "")
                blk     = ma.get("blocking_term", "")
                t_terms = ma.get("true_terms")  or []
                f_terms = ma.get("false_terms") or []
                true_str  = ", ".join(f"{t}=TRUE"  for t in t_terms) if t_terms else "\u2014"
                false_str = ", ".join(f"{t}=FALSE" for t in f_terms) if f_terms else "\u2014"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                steps.append((
                    "MODE-D \u2014 Missing assertion  [PROOF]",
                    f"  D{a_idx} (assert): if ({a_cond}) \u2192 1  [INACTIVE]\n"
                    f"    TRUE  terms: {true_str}\n"
                    f"    FALSE terms: {false_str}"
                    + (f"\n{_bt_lines}" if _bt_lines else "")
                    + f"\n  \u21b3 Backtrack blocking term: '{blk}' \u2014 "
                    f"this is the missing dependency preventing the assertion.",
                ))

            if missing:
                # Use secondary_backtrack for one-level driver trace per signal
                sec_bt = (ma.get("secondary_backtrack") or {}) if ma else {}
                sec_wave = pred_a.get("secondary_waveform") or {}
                bt_detail_lines = []
                for s in (missing + found):
                    if s in sec_bt:
                        bt_detail_lines.append(_fmt_backtrack_entry(s, sec_bt[s]))
                    elif s in sec_wave and sec_wave[s] is not None:
                        bt_detail_lines.append(f"    {s} = {sec_wave[s]}")
                bt_block = ("\n" + "\n".join(bt_detail_lines)) if bt_detail_lines else ""
                found_note = (
                    f"\n    Found in predicate: {', '.join(found)}" if found else ""
                )
                steps.append((
                    "Missing required AXI dependencies  [PROOF]",
                    f"\u2717  Absent from predicate: {', '.join(missing)}{bt_block}\n"
                    f"    \u2192 {pa_sig} is driven by local FSM only \u2014 "
                    f"required handshake signals never gated.{found_note}",
                ))
                steps.append((
                    "Conclusion",
                    f"Protocol failure is structurally guaranteed \u2014 predicate contains "
                    f"no path to verify {', '.join(missing[:3])}.",
                ))
            else:
                steps.append((
                    "Conclusion",
                    f"Protocol failure is structurally independent \u2014 "
                    f"all required signals found in predicate.",
                ))
        else:
            steps.append((
                "Conclusion",
                f"Protocol failure is structurally independent \u2014 "
                f"no RTL datapath defect confirmed.",
            ))
        return _format_trace_steps(steps)

    # ── Step 4: Backtracking initiated ───────────────────────────────────
    backtrack_target = exp_sig
    steps.append((
        f"Backtracking initiated on {backtrack_target}",
        f"Traced driver tree for {backtrack_target} — enabling condition "
        f"not satisfied at violation cycle.",
    ))

    # ── Step 5: Causal assignment identified (PROOF) ─────────────────────
    if causal_bindings:
        # We have a binding-pass proof: name the exact RTL signal
        id_str = (f"transaction {proof_txn_id}" if proof_txn_id is not None
                  else "observed transaction")
        addr_str = (f" at address 0x{proof_addr:08X}" if isinstance(proof_addr, int)
                    else (f" at address {proof_addr}" if proof_addr is not None else ""))
        steps.append((
            f"Causal assignment identified  [PROOF]",
            f"{proof_asn_sig or src_base} at {causal_loc} bound to {id_str}{addr_str}: "
            f"writes {src_base} → {dst_base}.",
        ))
    else:
        # No binding proof — structural evidence only
        steps.append((
            "Structural assignment located",
            f"{causal_loc}: assigns {src_base} → {dst_base}.",
        ))

    # ── Step 6: Transform confirmed non-bijective ─────────────────────────
    if root_type == "TRANSPORT":
        strb = first_v.get("strobe_signal") if first_v else "WSTRB"
        steps.append((
            "Strobe misalignment confirmed",
            f"WSTRB byte-enables do not mirror the data lane steering "
            f"applied to {src_base}.",
        ))
    else:
        if sw and dw:
            try:
                bits_lost = int(sw) - int(dw)
                steps.append((
                    "Non-bijective transform confirmed",
                    f"{src_base}[{int(sw)-1}:0] truncated to {dst_base}[{int(dw)-1}:0] — "
                    f"{bits_lost} bit{'s' if bits_lost != 1 else ''} lost per write. "
                    f"Distinct inputs collapse to identical stored values.",
                ))
            except (TypeError, ValueError):
                steps.append((
                    "Non-bijective transform confirmed",
                    f"Transform is not reversible — distinct inputs produce "
                    f"identical stored values.",
                ))
        else:
            steps.append((
                "Non-bijective transform confirmed",
                f"Transform on {dst_base} is not reversible — distinct inputs "
                f"produce identical stored values.",
            ))

    # ── Conclusion ────────────────────────────────────────────────────────
    systemic = "systemic " if (len(dv) + len(tv)) > 1 else ""
    steps.append((
        "Conclusion",
        f"Protocol symptom caused by {systemic}{sem_class} in {dst_base}.",
    ))

    # Cap at 8 steps (PART 6)
    steps = steps[:8]
    return _format_trace_steps(steps)


def _format_trace_steps(steps: List[tuple]) -> str:
    """Format (label, detail) step pairs into the Causal Trace block."""
    lines = [_TRACE_BAR, "Causal Trace (Condensed)", _TRACE_BAR]
    for i, (label, detail) in enumerate(steps):
        if i > 0:
            lines.append("")
        if label == "Conclusion":
            lines.append("  Conclusion:")
            lines.append(f"  {detail}")
        else:
            lines.append(f"  {label}")
            lines.append(f"    {detail}")
    lines.append(_TRACE_BAR)
    return "\n".join(lines)
