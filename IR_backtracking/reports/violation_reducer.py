"""
Violation Reducer — Static Analysis De-duplication
=====================================================
Groups violations by shared root mechanism. When multiple violations reference
the same signal and invariant they are collapsed to a single entry with an
occurrence count, a one-line cause, and impact.

Output format per group:

    VIOLATION_CLASS (N occurrences)
    Cause    : <why repetitions occur>
    Impact   : <one-line consequence>
    Signals  : <comma-separated affected signals>

Usage:
    from reports.violation_reducer import reduce_violations
    text = reduce_violations(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Set, Tuple

_SEP  = "=" * 79
_DASH = "-" * 79

# ── Mechanism grouping rules ───────────────────────────────────────────────────
# Map subtype → (cause_template, impact_template)
# {sig} is replaced with the primary signal name.

_SUBTYPE_CAUSE: Dict[str, str] = {
    "WIDTH_TRUNCATION":
        "Multiple RTL assignments share a truncating slice expression; "
        "each LHS assignment triggers the same width invariant check.",
    "WIDTH_DUPLICATION_WITHOUT_MAPPING":
        "A single source expression is replicated to fill a wider destination "
        "without lane-specific steering; all instances share one root defect.",
    "WIDTH_EXTENSION_WITHOUT_SEMANTIC":
        "Constant zero-padding is applied across pipeline stages without a "
        "corresponding semantic justification; each stage flags independently.",
    "NON_INVERTIBLE_COLLAPSE":
        "Bitwise reduction operators (^, &, |) on multi-bit data are applied "
        "at multiple assignment sites; each collapses distinct information.",
    "NON_INVERTIBLE_DUPLICATION":
        "Replication concat ({N{x}}) or identical-segment concat ({A,A}) "
        "creates aliased lanes; each assignment site flags the same pattern.",
    "SYNTHETIC_DATA":
        "Constant literals embedded in a concat expression manufacture data "
        "that was never in the source; flagged once per destination register.",
    "INFORMATION_LOSS":
        "Left-shift drops high-order bits across multiple pipeline registers; "
        "each shift site is an independent occurrence of the same defect.",
    "BYTE_LANE_COLLAPSE":
        "Multiple WDATA assignments write to the same byte lane without "
        "independent strobe gating; each write path triggers the check.",
    "WRITE_ALIASING_BUG":
        "Address computation aliases distinct logical addresses to one "
        "physical location; repeated across every write transaction.",
    "LANE_BIJECTION_VIOLATION":
        "Loop-generated assignments write a constant slice; the loop body "
        "instantiates the pattern once per iteration.",
    "WSTRB_DATA_MISALIGNMENT":
        "WDATA is steered without a matching WSTRB transformation; "
        "flagged for each always-block that performs the mismatched assignment.",
    "MISSING_STROBE_TRANSFORM":
        "WSTRB bits are not transformed to track WDATA rearrangement; "
        "one violation per assignment that rearranges WDATA.",
    "ADDRESS_COLLAPSE":
        "Address transform reduces all inputs to a constant (A=0); "
        "every assignment using this expression triggers the invariant.",
    "ORDER_REVERSAL":
        "Negating affine address transform reverses the natural address order; "
        "observed once per address signal driven by the reversed expression.",
    "NON_MONOTONIC_UNKNOWN":
        "Address expression uses modulo, XOR, shift, or table lookup; "
        "monotonicity cannot be verified — each such expression flags once.",
}

_SUBTYPE_IMPACT: Dict[str, str] = {
    "WIDTH_TRUNCATION":
        "High-order bits of the source are silently dropped; "
        "downstream logic receives an aliased representation.",
    "WIDTH_DUPLICATION_WITHOUT_MAPPING":
        "Two distinct source values produce identical protocol-boundary output; "
        "readback cannot distinguish them.",
    "WIDTH_EXTENSION_WITHOUT_SEMANTIC":
        "Fabricated zero bits inflate the apparent data width; "
        "protocol partners may misinterpret the value.",
    "NON_INVERTIBLE_COLLAPSE":
        "Distinct input words hash to the same output; "
        "the original data is unrecoverable from the protocol-boundary value.",
    "NON_INVERTIBLE_DUPLICATION":
        "Aliased lanes cannot be individually addressed; "
        "a write to one lane is silently mirrored to the other.",
    "SYNTHETIC_DATA":
        "Protocol-boundary data contains fabricated constants; "
        "the receiver cannot identify which bits reflect real source data.",
    "INFORMATION_LOSS":
        "Every shift operation destroys one bit of precision; "
        "accumulated across pipeline stages this is irreversible.",
    "BYTE_LANE_COLLAPSE":
        "Multiple write paths contend for the same byte lane; "
        "final value is non-deterministic under concurrent access.",
    "WRITE_ALIASING_BUG":
        "Writes to different logical addresses corrupt each other; "
        "data integrity cannot be maintained.",
    "LANE_BIJECTION_VIOLATION":
        "All loop iterations write the same physical slice; "
        "only the last write survives — earlier iterations are lost.",
    "WSTRB_DATA_MISALIGNMENT":
        "Active byte strobe does not correspond to the rearranged WDATA lane; "
        "the receiving agent writes to the wrong byte.",
    "MISSING_STROBE_TRANSFORM":
        "WSTRB no longer tracks WDATA after rearrangement; "
        "byte enable semantics are violated for every affected write.",
    "ADDRESS_COLLAPSE":
        "All transactions resolve to address zero regardless of AWADDR; "
        "the entire address space aliases to one location.",
    "ORDER_REVERSAL":
        "Sequential address increments map to decrements at the slave; "
        "burst and sequential access patterns are inverted.",
    "NON_MONOTONIC_UNKNOWN":
        "Address mapping is unpredictable; spatial locality guarantees are lost.",
}

_DEFAULT_CAUSE  = "Multiple RTL assignments trigger the same structural invariant check independently."
_DEFAULT_IMPACT = "Structural integrity of the data path cannot be guaranteed for affected transactions."


def reduce_violations(payload: Dict[str, Any]) -> str:
    """Return a deduplicated, mechanism-grouped violation summary string."""

    tv   : List[Dict[str, Any]] = payload.get("transport_violations") or []
    dv   : List[Dict[str, Any]] = payload.get("datapath_violations")  or []
    fins : List[Dict[str, Any]] = payload.get("findings")             or []

    lines: List[str] = [
        _SEP,
        "  VIOLATION REDUCTION — COLLAPSED BY ROOT MECHANISM",
        _SEP,
        "",
    ]

    # ── 1. Structural violations (transport + datapath) ────────────────────
    structural = tv + dv
    if structural:
        lines.append("STRUCTURAL VIOLATIONS:")
        lines.append("")
        groups = _group_structural(structural)
        for (cls, sub), instances in sorted(groups.items()):
            lines += _format_structural_group(cls, sub, instances)
    else:
        lines += ["  No structural violations in this analysis.", ""]

    # ── 2. Protocol findings ───────────────────────────────────────────────
    if fins:
        lines.append("PROTOCOL FINDINGS:")
        lines.append("")
        fin_groups = _group_findings(fins)
        for (rule, cls2, sig), instances in sorted(fin_groups.items()):
            lines += _format_finding_group(rule, cls2, sig, instances)
    else:
        lines += ["  No protocol findings in this analysis.", ""]

    lines.append(_SEP)
    return "\n".join(lines)


# ── Grouping helpers ───────────────────────────────────────────────────────────

def _group_structural(
    violations: List[Dict[str, Any]],
) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for v in violations:
        cls = v.get("class") or "UNKNOWN"
        sub = v.get("subtype") or ""
        groups.setdefault((cls, sub), []).append(v)
    return groups


def _group_findings(
    findings: List[Dict[str, Any]],
) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for f in findings:
        rule = f.get("rule_id") or ""
        cls  = f.get("classification") or ""
        sig  = f.get("signal") or f.get("rtl_sig") or ""
        groups.setdefault((rule, cls, sig), []).append(f)
    return groups


# ── Formatters ─────────────────────────────────────────────────────────────────

def _format_structural_group(
    cls: str,
    sub: str,
    instances: List[Dict[str, Any]],
) -> List[str]:
    n     = len(instances)
    label = f"{cls}/{sub}" if sub else cls
    first = instances[0]

    cause  = _SUBTYPE_CAUSE.get(sub, "")
    impact = _SUBTYPE_IMPACT.get(sub, "")

    # Fallback: extract first sentence from raw impact/explanation
    if not cause:
        raw = (
            first.get("impact")
            or first.get("explanation")
            or first.get("bug_pattern")
            or ""
        )
        cause = _first_sentence(raw) or _DEFAULT_CAUSE
    if not impact:
        impact = _DEFAULT_IMPACT

    # Collect unique affected signals across all instances
    ev_sigs: Set[str] = set()
    for inst in instances:
        for field in ("destination_signal", "source_signal", "signal", "lhs", "memory"):
            v = inst.get(field)
            if v:
                ev_sigs.add(v)
        for s in inst.get("signals_involved") or []:
            if s:
                ev_sigs.add(s)

    sigs_str = ", ".join(sorted(ev_sigs)) if ev_sigs else "unresolved"
    s_plural = "s" if n != 1 else ""

    return [
        f"  {label} ({n} occurrence{s_plural})",
        f"    Cause   : {cause}",
        f"    Impact  : {impact}",
        f"    Signals : {sigs_str}",
        "",
    ]


def _format_finding_group(
    rule: str,
    cls: str,
    sig: str,
    instances: List[Dict[str, Any]],
) -> List[str]:
    n = len(instances)
    cycles = sorted(
        {f.get("analysis_cycle") for f in instances if f.get("analysis_cycle") is not None}
    )
    if not cycles:
        cyc_str = "cycle unknown"
    elif len(cycles) == 1:
        cyc_str = f"cycle {cycles[0]}"
    elif len(cycles) <= 3:
        cyc_str = "cycles " + ", ".join(str(c) for c in cycles)
    else:
        cyc_str = f"cycles {cycles[0]}..{cycles[-1]} ({len(cycles)} distinct)"

    label = f"{rule}/{cls}" if cls else rule
    sig_str = sig or "signal unresolved"
    s_plural = "s" if n != 1 else ""

    # One-line impact for protocol findings
    _cls_impact: Dict[str, str] = {
        "TEMPORAL_VIOLATION":
            "Handshake signal fails to assert; dependent transactions stall.",
        "SCHEDULING_CANCELLATION":
            "An intra-cycle overwrite prevents the signal from reaching its "
            "intended value; the transaction window closes without acceptance.",
        "DESIGN_STRUCTURAL_BLOCKAGE":
            "FSM remains in a blocking state; no legal transition unblocks it "
            "under the observed waveform.",
    }
    impact = _cls_impact.get(cls, "Protocol obligation is not met.")

    return [
        f"  {label} ({n} occurrence{s_plural}) — {sig_str} at {cyc_str}",
        f"    Impact  : {impact}",
        "",
    ]


# ── Utility ────────────────────────────────────────────────────────────────────

def _first_sentence(text: str) -> str:
    """Return the first non-empty sentence of text."""
    for part in text.replace("\n", " ").split("."):
        part = part.strip()
        if part:
            return part + "."
    return ""
