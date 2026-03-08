"""
Structural Root Cause Report
=============================
Answers three questions only:
  1. What RTL construct is wrong?
  2. Where is it?
  3. Why is it structurally unsafe?

Collapses all violations into ONE structural defect per shared RTL origin
(same always_block_id or same signal/location).  Does not restate the
causal chain (that is backtracking_trace.txt) or the fix (fix_guidance.txt).

Output:
    ==================== STRUCTURAL DEFECT ====================
    Defect class   : <class>/<subtype>
    RTL location   : <file:line | always_block_id | signal>
    Failing signal : <signal>
    Rule violated  : <rule_id>  (AXI-Lite <section>)
    Analysis cycle : <cycle>
    Confidence     : <HIGH|MEDIUM|LOW>
    -----------------------------------------------------------
    WHAT IS WRONG
      <one paragraph, plain language>
    WHY IT IS STRUCTURALLY UNSAFE
      <one paragraph, plain language>
    EVIDENCE (<N> violation(s), <M> finding(s))
      [V1] <class>/<subtype>  <signal>  <source>
      ...
      [F1] <rule_id> <classification>  cycle <cyc>
      ...
    ===========================================================

Usage:
    from reports.structural_root_cause import generate_structural_root_cause
    text = generate_structural_root_cause(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

_HDR = "==================== STRUCTURAL DEFECT ===================="
_SEP = "-----------------------------------------------------------"
_FTR = "==========================================================="


# ── AXI-Lite rule → spec section quick-ref ────────────────────────────────────
_RULE_SPEC = {
    "RULE_5":  "A3.4.1 — WVALID must not deassert until WREADY",
    "RULE_6":  "A3.4.1 — AWVALID must not deassert until AWREADY",
    "RULE_9":  "A3.4.2 — ARVALID must not deassert until ARREADY",
    "RULE_10": "A3.4.3 — RVALID must not assert without prior ARVALID+ARREADY",
    "RULE_11": "A3.4.4 — BVALID must not assert without prior AWVALID+AWREADY",
    "RULE_12": "A3.3.1 — BVALID must assert after AWVALID+AWREADY+WVALID+WREADY",
    "RULE_13": "A3.3.1 — RVALID must assert after ARVALID+ARREADY",
}


def generate_structural_root_cause(payload: Dict[str, Any]) -> str:
    """Return a minimal structural defect report string."""

    rca      = payload.get("final_rca") or {}
    findings = payload.get("findings") or []
    dv       = payload.get("datapath_violations") or []
    tv       = payload.get("transport_violations") or []

    root_type  = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif    = rca.get("classification") or "UNKNOWN"
    confidence = rca.get("confidence") or "LOW"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0 = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig  = pev0.get("signal") or pev0.get("expected_signal") or "(unknown)"
    rule = pev0.get("rule_id") or "(unknown)"
    cyc  = pev0.get("analysis_cycle")

    # ── Primary violation (the defect source) ─────────────────────────────────
    primary_viol = _pick_primary_violation(root_type, dv, tv, findings)
    rtl_loc      = _rtl_location(primary_viol)
    defect_class = _defect_class(root_type, classif, primary_viol)

    # ── Group violations by RTL origin ────────────────────────────────────────
    grouped = _group_by_origin(dv, tv)

    # ── Build the three prose sections ───────────────────────────────────────
    what_wrong    = _what_wrong(root_type, classif, sig, primary_viol, rca)
    why_unsafe    = _why_unsafe(root_type, classif, primary_viol, sig)

    # ── Evidence list ─────────────────────────────────────────────────────────
    ev_lines = _evidence_lines(grouped, findings)

    spec_ref = _RULE_SPEC.get(str(rule).upper(), "AXI-Lite specification")

    # ── Assemble output ───────────────────────────────────────────────────────
    lines: List[str] = [
        "",
        _HDR,
        f"Defect class   : {defect_class}",
        f"RTL location   : {rtl_loc}",
        f"Failing signal : {sig}",
        f"Rule violated  : {rule}  ({spec_ref})",
        f"Analysis cycle : {cyc if cyc is not None else 'N/A'}",
        f"Confidence     : {confidence}",
        _SEP,
        "WHAT IS WRONG",
    ]
    lines += _wrap(what_wrong, indent=2)
    lines += ["", "WHY IT IS STRUCTURALLY UNSAFE"]
    lines += _wrap(why_unsafe, indent=2)
    lines += [
        "",
        f"EVIDENCE ({len(dv) + len(tv)} violation(s), {len(findings)} finding(s))",
    ]
    lines += ev_lines
    lines.append(_FTR)
    return "\n".join(lines)


# ── Helper: pick the primary violation ────────────────────────────────────────

def _pick_primary_violation(
    root_type: str,
    dv: List[Dict],
    tv: List[Dict],
    findings: List[Dict],
) -> Dict[str, Any]:
    if root_type == "TRANSPORT" and tv:
        return tv[0]
    if root_type in ("DATAPATH", "SEMANTIC_STRUCTURAL") and dv:
        return dv[0]
    if findings:
        return findings[0]
    return {}


def _rtl_location(v: Dict[str, Any]) -> str:
    loc = v.get("rtl_line") or v.get("source_location") or v.get("source")
    if loc:
        return str(loc)
    blk = v.get("always_block_id")
    if blk is not None:
        return f"always_block {blk}"
    sig = v.get("destination_signal") or v.get("signal") or v.get("expected_signal")
    if sig:
        return f"driver of {sig}"
    return "(see findings)"


def _defect_class(root_type: str, classif: str, v: Dict[str, Any]) -> str:
    sub = v.get("subtype") or v.get("semantic_type") or classif
    if sub and sub != root_type:
        return f"{root_type}/{sub}"
    return root_type


# ── Helper: group violations by RTL origin ────────────────────────────────────

def _group_by_origin(
    dv: List[Dict], tv: List[Dict]
) -> Dict[str, List[Dict]]:
    groups: Dict[str, List[Dict]] = {}
    for v in list(dv) + list(tv):
        key = (
            str(v.get("rtl_line") or "")
            or str(v.get("always_block_id") or "")
            or str(v.get("destination_signal") or v.get("signal") or "unknown")
        )
        groups.setdefault(key, []).append(v)
    return groups


# ── Helper: evidence line list ────────────────────────────────────────────────

def _evidence_lines(
    grouped: Dict[str, List[Dict]],
    findings: List[Dict],
) -> List[str]:
    lines: List[str] = []
    idx = 1
    for origin, vlist in grouped.items():
        rep = vlist[0]
        cls = rep.get("class") or rep.get("subtype") or "VIOLATION"
        sub = rep.get("subtype") or ""
        sig = rep.get("destination_signal") or rep.get("signal") or "(sig?)"
        loc = rep.get("rtl_line") or rep.get("source_location") or origin
        tag = f"{cls}/{sub}" if sub and sub != cls else cls
        n   = f"  x{len(vlist)}" if len(vlist) > 1 else ""
        lines.append(f"  [V{idx}] {tag:<40s}  {sig}  @ {loc}{n}")
        idx += 1
    for f in findings:
        cls = f.get("classification") or "FINDING"
        rid = f.get("rule_id") or ""
        cyc = f.get("analysis_cycle")
        cyc_s = f"  cycle {cyc}" if cyc is not None else ""
        lines.append(f"  [F{idx}] {rid} {cls}{cyc_s}")
        idx += 1
    return lines


# ── Prose generators ──────────────────────────────────────────────────────────

def _what_wrong(
    root_type: str,
    classif: str,
    sig: str,
    v: Dict[str, Any],
    rca: Dict[str, Any],
) -> str:
    if root_type == "TRANSPORT":
        dst  = v.get("destination_signal") or "WDATA"
        strb = v.get("strobe_signal") or "WSTRB"
        return (
            f"The RTL assignment to {dst} applies a byte-lane steering transform "
            f"(shift, replication, or permutation) that is not mirrored in the "
            f"expression driving {strb}. As a result, the strobe enables a lane "
            f"that does not contain the intended byte — the written data is "
            f"committed to the wrong memory location on every affected transaction."
        )
    if root_type in ("DATAPATH", "SEMANTIC_STRUCTURAL"):
        dst  = v.get("destination_signal") or v.get("signal") or sig
        src  = v.get("source_signal") or "the source register"
        sub  = v.get("subtype") or "WIDTH_TRUNCATION"
        sw   = v.get("inferred_src_width")
        dw   = v.get("inferred_dst_width")
        lost = f"  {sw - dw} bit(s) are silently discarded." if (sw and dw) else ""
        return (
            f"The RTL expression driving {dst} applies a {sub.lower().replace('_',' ')} "
            f"to data from {src}.{lost}  "
            f"The function is not injective: two distinct values written to "
            f"{src} can produce the same value on {dst}, making reads "
            f"indistinguishable from each other and causing silent data corruption."
        )
    # PROTOCOL
    chain  = str(rca.get("causal_chain") or "")
    pev    = rca.get("primary_evidence") or []
    pev0   = pev[0] if pev and isinstance(pev[0], dict) else {}
    en_c   = ""
    ow_c   = ""
    findings_ref = rca.get("primary_evidence") or []
    canc   = {}
    if findings_ref:
        pass  # evidence detail lives in findings, not rca directly
    return (
        f"The RTL always-block driving {sig} contains two assignments to the "
        f"same register. The enabling assignment (rhs=1) is overwritten by a "
        f"second assignment (rhs=0) in the same always-block before the clock "
        f"edge captures the value. Because the overwrite condition is a "
        f"superset of the enable condition, the second assignment always fires "
        f"when the first does — the register never commits the enabled value."
    )


def _why_unsafe(
    root_type: str,
    classif: str,
    v: Dict[str, Any],
    sig: str,
) -> str:
    if root_type == "TRANSPORT":
        return (
            "AXI-Lite requires that each set WSTRB[i] bit corresponds to the "
            "byte in lane i of WDATA. When the steering expressions for the "
            "two signals diverge, that invariant is violated unconditionally — "
            "on every transaction regardless of address or data value. The "
            "defect is structural: it cannot be avoided by stimulus selection "
            "or testbench adjustment."
        )
    if root_type in ("DATAPATH", "SEMANTIC_STRUCTURAL"):
        return (
            "A bijective (one-to-one) mapping between written values and "
            "read-back values is required for correct register semantics. "
            "A width-truncating or non-invertible RTL expression breaks "
            "bijectivity permanently: every write that uses the discarded "
            "bits silently corrupts the stored value. The corruption is "
            "unconditional — it does not depend on the value written or "
            "the sequence of transactions."
        )
    # PROTOCOL
    return (
        "SystemVerilog NBA semantics guarantee that the LAST non-blocking "
        "assignment to a register in a given time step wins. When a broader "
        "deassert condition is evaluated after a narrower assert condition in "
        "the same always-block, the deassert always prevails — the asserted "
        "value is never registered. This is a structural ordering defect: "
        "it reproduces on every legal trigger handshake, regardless of "
        "waveform ordering or testbench stimulus."
    )


# ── Formatter ─────────────────────────────────────────────────────────────────

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
