"""
Executive Verification Summary Generator
=========================================
Audience : senior silicon architects evaluating tool credibility.
Tone     : precise, factual, zero marketing language.
Output   : 12 lines maximum, no debug wording, no internal engine terminology.

Usage:
    from reports.executive_summary import generate_executive_summary
    text = generate_executive_summary(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List

_SEP = "=" * 79


def generate_executive_summary(payload: Dict[str, Any]) -> str:
    """Return a <=12-line executive report string from an RCA payload dict."""

    rca       = payload.get("final_rca") or {}
    txns      = payload.get("transactions") or []
    findings  = payload.get("findings") or []
    dv        = payload.get("datapath_violations") or []
    tv        = payload.get("transport_violations") or []
    proto     = (payload.get("protocol") or "axi_lite").upper()
    max_cycle = int(payload.get("waveform_max_cycle") or 0)

    root_type  = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif    = rca.get("classification") or "UNKNOWN"
    confidence = rca.get("confidence") or "LOW"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []

    # Primary failing signal from evidence list
    pev0      = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig       = pev0.get("signal") or pev0.get("expected_signal") or ""
    rule      = pev0.get("rule_id") or ""
    cyc       = pev0.get("analysis_cycle")

    # ── Finding severity counts ────────────────────────────────────────────
    # Critical: transport violations + structural datapath violations proven HIGH
    n_crit = len(tv) + (
        len(dv) if root_type == "DATAPATH" and confidence == "HIGH" else 0
    )
    # Major: protocol handshake failures + datapath proven MEDIUM
    _major_classes = {
        "TEMPORAL_VIOLATION",
        "SCHEDULING_CANCELLATION",
        "DESIGN_STRUCTURAL_BLOCKAGE",
    }
    n_major = sum(
        1 for f in findings
        if (f.get("classification") or "") in _major_classes
    ) + (len(dv) if root_type == "DATAPATH" and confidence == "MEDIUM" else 0)
    n_minor = max(0, len(findings) - n_major)

    # ── One-sentence root cause ────────────────────────────────────────────
    root_cause = _root_cause_sentence(root_type, classif, sig, rule, cyc, rca)

    # ── Functional impact ──────────────────────────────────────────────────
    impact = _functional_impact(root_type, classif, sig)

    # ── Determinism risk ──────────────────────────────────────────────────
    det_risk = _determinism_risk(root_type, confidence)

    # ── Confidence display label ───────────────────────────────────────────
    conf_label = {"HIGH": "DETERMINISTIC", "MEDIUM": "PROBABLE", "LOW": "INCONCLUSIVE"}.get(
        confidence, confidence
    )

    # ── Responsibility attribution ─────────────────────────────────────────
    if root_type in ("TRANSPORT", "DATAPATH"):
        responsibility = "RTL"
    elif root_type == "PROTOCOL":
        responsibility = "RTL"       # handshake obligation failures are RTL defects
    else:
        responsibility = "Undetermined"

    # ── Cycle qualifier ───────────────────────────────────────────────────
    cycle_note = f" (first observed: cycle {cyc})" if cyc is not None else ""

    lines: List[str] = [
        _SEP,
        "  EXECUTIVE VERIFICATION SUMMARY",
        _SEP,
        f"  Design        : {proto} — {max_cycle:,} cycles analyzed,"
        f" {len(txns)} transaction(s) detected.",
        f"  Findings      : Critical {n_crit}  |  Major {n_major}  |  Minor {n_minor}",
        f"  Root Cause    : {root_cause}",
        f"  Impact        : {impact}",
        f"  Determinism   : {det_risk}",
        f"  Confidence    : {conf_label} ({confidence}){cycle_note}",
        f"  Attributed to : {responsibility}",
        _SEP,
    ]

    return "\n".join(lines)


# ── Private helpers ────────────────────────────────────────────────────────────

def _root_cause_sentence(
    root_type: str,
    classif: str,
    sig: str,
    rule: str,
    cyc: Any,
    rca: Dict[str, Any],
) -> str:
    _s = sig or "data path"
    _r = rule or classif

    if root_type == "TRANSPORT":
        rtl_line = rca.get("rtl_line")
        loc = f" (RTL line {rtl_line})" if rtl_line else ""
        return (
            f"Byte-lane steering defect{loc} in RTL drives WDATA without "
            f"corresponding WSTRB steering, corrupting write data on every "
            f"affected transaction."
        )

    if root_type == "DATAPATH":
        if classif == "SEMANTIC_STRUCTURAL":
            mem = rca.get("storage_element") or _s
            return (
                f"Structural write-masking defect aliases multiple addresses "
                f"to a single storage element ({mem}), causing non-deterministic "
                f"data corruption on overlapping writes."
            )
        if classif == "STRUCTURAL_CAUSAL":
            return (
                f"RTL assignment to {_s} performs a structurally proven "
                f"non-invertible transform; information is irreversibly lost "
                f"before reaching the protocol boundary."
            )
        return (
            f"RTL datapath to {_s} contains a width or invertibility "
            f"violation that collapses distinct inputs to the same output."
        )

    if root_type == "PROTOCOL":
        cyc_str = f" at cycle {cyc}" if cyc is not None else ""
        return (
            f"Signal {_s} fails its {_r} handshake obligation{cyc_str}; "
            f"RTL driver conditions are structurally overwritten or never "
            f"reach an asserted state under valid stimulus."
        )

    return (
        "Available RTL and waveform evidence are insufficient to isolate "
        "a single deterministic root cause."
    )


def _functional_impact(root_type: str, classif: str, sig: str) -> str:
    if root_type == "TRANSPORT":
        return (
            "Writes land in incorrect byte lanes; readback data is undefined "
            "for all transactions using affected byte-strobe patterns."
        )
    if root_type == "DATAPATH":
        if classif == "SEMANTIC_STRUCTURAL":
            return (
                "Address aliasing means write operations to distinct logical "
                "addresses corrupt each other's data silently."
            )
        return (
            "Data fidelity is unrecoverable at the protocol boundary; "
            "downstream consumers receive collapsed or fabricated values."
        )
    if root_type == "PROTOCOL":
        return (
            f"Handshake on {sig or 'protocol signal'} stalls indefinitely; "
            f"transactions cannot complete, blocking dependent bus agents and "
            f"potentially locking the interconnect."
        )
    return "Impact scope is undetermined; assume full data-path unreliability as a conservative bound."


def _determinism_risk(root_type: str, confidence: str) -> str:
    if root_type == "TRANSPORT":
        return (
            "Defect is structurally deterministic; reproduces on every write "
            "transaction exercising the affected byte-lane assignment."
        )
    if root_type == "DATAPATH":
        if confidence == "HIGH":
            return (
                "Defect is structurally proven in RTL; observable on any legal "
                "transaction exercising the flagged assignment regardless of stimulus."
            )
        return (
            "Defect is probable; requires a transaction that exercises the "
            "specific RTL assignment path identified."
        )
    if root_type == "PROTOCOL":
        if confidence == "HIGH":
            return (
                "Defect is reproducible under any stimulus that asserts the "
                "enabling condition; FSM masking is structural, not timing-dependent."
            )
        return (
            "Defect is stimulus-dependent; specific valid/ready assertion "
            "ordering is required to expose the handshake failure."
        )
    return (
        "Reproducibility cannot be established without extended waveform "
        "coverage and additional RTL analysis."
    )
