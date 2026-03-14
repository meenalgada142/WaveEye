"""
Tool Differentiator
====================
Summarises what WaveEye does that traditional waveform viewers and protocol
checkers cannot. Maximum 5 bullet points. No hype language.

Audience: verification engineers deciding whether this replaces part of their
          debug workflow.
Focus   : reasoning capability differences, not feature lists.

Usage:
    from reports.tool_differentiator import generate_tool_differentiator
    text = generate_tool_differentiator(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List

_SEP  = "=" * 79
_DASH = "-" * 79

# Evidence flags used to personalise the 5 bullets to the actual analysis
_BULLET_TEMPLATES = {
    # (condition_key, short_label, full_text)
    "transport": (
        "Byte-lane steering verification",
        "Traditional protocol checkers confirm that WSTRB is a valid bitmask and "
        "that WVALID precedes BVALID. They do NOT verify that the steering expression "
        "applied to WDATA is algebraically consistent with WSTRB. WaveEye statically "
        "analyses the RTL expression driving WDATA and the RTL expression driving WSTRB "
        "as a matched pair — flagging mismatches the protocol checker never sees.",
    ),
    "datapath_bijectivity": (
        "Data-path bijectivity proof",
        "Waveform viewers show what value appears on RDATA. They cannot determine whether "
        "that value faithfully represents the source, or whether distinct writes produce "
        "the same readback due to a width collapse or reduction operator in the RTL. "
        "WaveEye traces the RTL combinational function from source to protocol boundary "
        "and checks whether the function is injective — a property no waveform tool expresses.",
    ),
    "fsm_masking": (
        "Intra-always-block NBA overwrite detection",
        "Protocol checkers observe that ARREADY stays deasserted and report a timeout. "
        "They cannot determine whether the fault is in the testbench stimulus, in protocol "
        "ordering, or in an RTL always-block where a later non-blocking assignment cancels "
        "an earlier one within the same delta. WaveEye models NBA semantics explicitly: "
        "it identifies which driver wins, why, and what the structural fix location is.",
    ),
    "causal_binding": (
        "Transaction-to-RTL causal binding",
        "Traditional tools report a violation at a cycle. WaveEye resolves which "
        "specific AXI transaction (identified by address and accept-cycle) exercised "
        "the defective RTL assignment. This narrows the reproduction stimulus to a "
        "single targeted write or read sequence rather than a full regression run.",
    ),
    "structural_proof": (
        "Structural vs. stimulus-dependent distinction",
        "A protocol checker cannot distinguish between a defect that reproduces on every "
        "legal transaction and one that requires a specific ordering of handshakes. "
        "WaveEye's confidence level (HIGH/MEDIUM/LOW) and determinism score encode this: "
        "HIGH means the defect is in RTL static structure and reproduces unconditionally; "
        "MEDIUM means a specific stimulus pattern is needed. This directly informs "
        "whether a one-shot repro or an exhaustive sweep is needed for silicon debug.",
    ),
}


def generate_tool_differentiator(payload: Dict[str, Any]) -> str:
    """Return a ≤5-bullet tool differentiator statement."""

    rca      = payload.get("final_rca") or {}
    tv       = payload.get("transport_violations") or []
    dv       = payload.get("datapath_violations")  or []
    binding  = payload.get("binding_result") or {}
    findings = payload.get("findings") or []

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification") or ""
    pev       = rca.get("primary_evidence") or []

    # Select which bullets apply to this analysis
    selected: List[str] = []

    if tv:
        selected.append("transport")
    if dv:
        selected.append("datapath_bijectivity")
    if any(
        f.get("classification") in ("SCHEDULING_CANCELLATION", "TEMPORAL_VIOLATION")
        for f in findings
    ) or root_type == "PROTOCOL":
        selected.append("fsm_masking")
    if binding.get("causal_bindings"):
        selected.append("causal_binding")
    # Always include the structural vs stimulus-dependent bullet
    selected.append("structural_proof")

    # Deduplicate and cap at 5
    seen = set()
    ordered = []
    for k in selected:
        if k not in seen:
            seen.add(k)
            ordered.append(k)
    ordered = ordered[:5]

    # If fewer than 3 bullets selected, add generic ones in fixed order
    all_keys = list(_BULLET_TEMPLATES.keys())
    for k in all_keys:
        if len(ordered) >= 5:
            break
        if k not in seen:
            ordered.append(k)
            seen.add(k)

    hdr = [
        _SEP,
        "  TOOL DIFFERENTIATOR",
        _SEP,
        "  What WaveEye provides that traditional waveform viewers and protocol",
        "  checkers do not. Audience: verification engineers evaluating workflow fit.",
        _SEP,
        "",
    ]

    body: List[str] = []
    for i, key in enumerate(ordered, 1):
        label, text = _BULLET_TEMPLATES[key]
        body.append(f"  [{i}] {label}")
        body.append(f"      {_DASH[:70]}")
        # Word-wrap body text at 75 chars with 6-char indent
        words = text.split()
        curr  = "      "
        for w in words:
            if len(curr) + len(w) + 1 > 77:
                body.append(curr.rstrip())
                curr = "      " + w + " "
            else:
                curr += w + " "
        if curr.strip():
            body.append(curr.rstrip())
        body.append("")

    footer = [
        _DASH,
        "  These capabilities operate on RTL drivers and waveform CSV; they do",
        "  not require a formal tool license or a complete testbench environment.",
        _SEP,
    ]

    return "\n".join(hdr + body + footer)
