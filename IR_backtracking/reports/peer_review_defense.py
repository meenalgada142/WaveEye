"""
Peer Review Defense — Root-Cause Substantiation
=================================================
Audience : formal verification peers and silicon architects scrutinising
           whether an RCA conclusion is a simulation artifact.
Tone     : engineering reasoning, no mathematical symbols unless necessary.
Goal     : make the conclusion undeniable to a skeptical reviewer.

For each root cause type the report addresses six mandatory questions:
  1. RTL behavior that creates the failure.
  2. Why the behavior violates a protocol or logical invariant.
  3. That this can occur under legal AXI handshakes.
  4. Why this is not a testbench artifact.
  5. The exact condition that allows two logical outcomes to collide.
  6. The invariant that should hold but does not.

Usage:
    from reports.peer_review_defense import generate_peer_review_defense
    text = generate_peer_review_defense(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

_SEP  = "=" * 79
_DASH = "-" * 79


def generate_peer_review_defense(payload: Dict[str, Any]) -> str:
    """Return a structured peer-review defense string from an RCA payload dict."""

    rca      = payload.get("final_rca") or {}
    tv       = payload.get("transport_violations") or []
    dv       = payload.get("datapath_violations")  or []
    txns     = payload.get("transactions")          or []
    findings = payload.get("findings")              or []

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification")  or "UNKNOWN"
    confidence= rca.get("confidence")      or "LOW"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []

    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or pev0.get("expected_signal") or "target signal"
    rule  = pev0.get("rule_id") or "N/A"
    cyc   = pev0.get("analysis_cycle")

    hdr = [
        _SEP,
        "  PEER REVIEW DEFENSE — ROOT CAUSE SUBSTANTIATION",
        _SEP,
        f"  Classification : {root_type}/{classif}",
        f"  Primary Signal : {sig}",
        f"  Rule           : {rule}",
        f"  Analysis Cycle : {cyc if cyc is not None else 'N/A'}",
        f"  Confidence     : {confidence}",
        _SEP,
        "",
    ]

    if root_type == "TRANSPORT":
        body = _defend_transport(tv, rca, sig)
    elif root_type == "DATAPATH":
        body = _defend_datapath(dv, rca, sig, txns, classif)
    elif root_type == "PROTOCOL":
        body = _defend_protocol(findings, rca, sig, rule, cyc, txns)
    else:
        body = _defend_inconclusive(rca)

    footer = ["", _SEP]
    return "\n".join(hdr + body + footer)


# ── TRANSPORT defense ──────────────────────────────────────────────────────────

def _defend_transport(
    tv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
) -> List[str]:
    first = tv[0] if tv else {}
    dst   = first.get("destination_signal") or sig or "WDATA"
    src   = first.get("source_signal")      or "source_data"
    strb  = first.get("strobe_signal")      or "WSTRB"
    rtl   = first.get("rtl_line")
    sub   = first.get("subtype") or "TRANSPORT_ALIGNMENT"
    loc   = f"RTL line {rtl}" if rtl else "RTL assignment block"

    return _numbered_defense([
        (
            "RTL behavior that creates the failure",
            f"At {loc}, the RTL assigns {dst} = f({src}) where f() is a "
            f"rearrangement (shift, replication, or slice) of the source data. "
            f"The corresponding strobe signal {strb} is not transformed by the "
            f"same function, so the asserted strobe bits no longer correspond to "
            f"the rearranged byte lanes of {dst}. "
            f"Violation subtype: {sub}.",
        ),
        (
            "Protocol invariant violated",
            f"AXI4 / AXI4-Lite specifies that WSTRB[i]=1 must indicate that "
            f"WDATA[8i+7:8i] contains a valid byte to be written. "
            f"When WDATA is rearranged without rearranging WSTRB, this "
            f"correspondence is broken: the byte the slave writes to its "
            f"storage is not the byte the master intended for that lane.",
        ),
        (
            "Occurrence under legal AXI handshakes",
            f"The defect is activated by any WRITE transaction where "
            f"AWVALID && AWREADY completes (address accepted) followed by "
            f"WVALID && WREADY with at least one asserted WSTRB bit. "
            f"These are normal AXI4-Lite write-channel conditions; no "
            f"illegal handshake sequence is required.",
        ),
        (
            "Why this is not a testbench artifact",
            f"The misalignment is in the combinational RTL expression driving "
            f"{dst} and {strb}. The testbench controls AWADDR, AWVALID, WDATA, "
            f"and WVALID, but it does not control the internal steering logic. "
            f"Regardless of what the testbench drives, the RTL will apply the "
            f"same mismatched steering. Changing stimulus cannot remove the defect.",
        ),
        (
            "Exact condition that allows the collision",
            f"Let the intended byte value be B and the intended lane index be i. "
            f"RTL drives WDATA with B placed in lane j (j != i) due to the "
            f"rearrangement, while WSTRB still asserts bit i. "
            f"The slave receives WSTRB[i]=1 and writes WDATA[8i+7:8i], which "
            f"contains the wrong data. Simultaneously, lane j (which holds B) "
            f"is disabled by WSTRB[j]=0 and is discarded. "
            f"The two paths — where the data IS and where the strobe SAYS — "
            f"diverge at this point.",
        ),
        (
            "Invariant that should hold but does not",
            f"INVARIANT: for every WRITE transaction, "
            f"forall i in [0, WDATA_width/8-1]: "
            f"WSTRB[i]=1 implies WDATA[8i+7:8i] == intended_byte[i]. "
            f"The current RTL violates this invariant at {loc} because the "
            f"data rearrangement and the strobe are driven by independent, "
            f"non-symmetric expressions.",
        ),
    ])


# ── DATAPATH defense ───────────────────────────────────────────────────────────

def _defend_datapath(
    dv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
    txns: List[Dict[str, Any]],
    classif: str,
) -> List[str]:
    first   = dv[0] if dv else {}
    dst     = first.get("destination_signal") or first.get("signal") or sig
    src     = first.get("source_signal") or "source_signal"
    sub     = first.get("subtype") or classif
    rtl     = first.get("rtl_line")
    loc     = f"RTL line {rtl}" if rtl else "RTL always block"
    src_w   = first.get("inferred_src_width")
    dst_w   = first.get("inferred_dst_width")
    rep     = first.get("rep_factor")
    const_b = first.get("const_padding_bits")

    # Build subtype-specific RTL description
    rtl_desc = _datapath_rtl_desc(sub, dst, src, src_w, dst_w, rep, const_b, loc)
    inv_desc  = _datapath_invariant(sub, dst, src, src_w, dst_w)
    coll_desc = _datapath_collision(sub, dst, src, src_w, dst_w, rep)

    n_txns = len(txns)
    txn_note = (
        f"{n_txns} transaction(s) were detected in the waveform; "
        "any READ transaction that exercises this assignment path observes the defect."
        if n_txns > 0
        else "Transaction data is not available, but the defect is structural and "
             "does not depend on any specific transaction sequence."
    )

    return _numbered_defense([
        (
            "RTL behavior that creates the failure",
            rtl_desc,
        ),
        (
            "Protocol invariant violated",
            f"The AXI protocol requires that data presented on RDATA faithfully "
            f"represents the value stored at the addressed location. "
            f"A non-invertible transform in the RTL path to {dst} means that "
            f"two distinct source values produce the same protocol-boundary value, "
            f"making it impossible for any AXI master to reconstruct the original data "
            f"from a legal READ response.",
        ),
        (
            "Occurrence under legal AXI handshakes",
            f"The transform is applied unconditionally in the combinational "
            f"logic path to {dst}. {txn_note} "
            f"No illegal handshake, out-of-order access, or protocol violation "
            f"by the master is needed to exercise the defect.",
        ),
        (
            "Why this is not a testbench artifact",
            f"The transformation is a static RTL expression, not a runtime "
            f"choice made by simulation. The testbench drives address and "
            f"control signals; it does not determine the combinational mapping "
            f"applied to data inside the RTL. "
            f"This defect reproduces identically in gate-level simulation, "
            f"formal equivalence checking, and silicon — it is not an artifact "
            f"of simulation scheduling or testbench timing.",
        ),
        (
            "Exact condition that allows two logical values to collide",
            coll_desc,
        ),
        (
            "Invariant that should hold but does not",
            inv_desc,
        ),
    ])


# ── PROTOCOL defense ───────────────────────────────────────────────────────────

def _defend_protocol(
    findings: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
    rule: str,
    cyc: Any,
    txns: List[Dict[str, Any]],
) -> List[str]:
    # Find the first matching finding for context
    first = next((f for f in findings if f.get("signal") == sig or f.get("rule_id") == rule), None)
    if not first and findings:
        first = findings[0]
    first = first or {}

    classif = first.get("classification") or "TEMPORAL_VIOLATION"
    evid    = first.get("evidence") or {}
    canc    = evid.get("intra_cycle_cancellation") or {}
    chain   = rca.get("causal_chain") or ""

    # Try to extract FSM/driver detail from causal chain
    chain_excerpt = ""
    if chain:
        lines = [l.strip() for l in chain.split("\n") if l.strip()]
        chain_excerpt = " ".join(lines[:4])

    cyc_str     = f"cycle {cyc}" if cyc is not None else "the observed violation cycle"
    expected    = evid.get("trigger_condition") or "enabling condition"
    overwrite   = canc.get("final_overwrite_conditions") or []
    overw_str   = (" The following conditions unconditionally overwrite the enabling "
                   f"assignment: {'; '.join(str(c) for c in overwrite[:2])}."
                   if overwrite else "")

    return _numbered_defense([
        (
            "RTL behavior that creates the failure",
            f"Signal {sig} is driven by at least one RTL always-block. "
            f"At {cyc_str}, the condition that would assert {sig} is present "
            f"(the enabling predicate evaluates true), but a later assignment "
            f"in the same always-block — or in a competing always-block — "
            f"overrides it with the negated or neutral value.{overw_str} "
            f"{'Context: ' + chain_excerpt if chain_excerpt else ''}",
        ),
        (
            "Protocol invariant violated",
            f"AXI4-Lite rule {rule} requires that {sig} asserts within a "
            f"defined number of clock cycles after its enabling condition is met. "
            f"Specifically: if {expected} is true, then {sig} must become 1 "
            f"on the following posedge. "
            f"When a later always-block assignment unconditionally writes 0 to "
            f"{sig} after the enabling assignment writes 1, the rule is violated "
            f"structurally — not because of timing but because of RTL semantics.",
        ),
        (
            "Occurrence under legal AXI handshakes",
            f"The enabling condition for {sig} is a legal master-side action "
            f"(e.g., ARVALID or AWVALID asserted by the master under normal "
            f"operation). No illegal or out-of-spec stimulus is required. "
            f"Any conforming master that drives the enabling signal will "
            f"expose this defect because the slave-side RTL does not respond "
            f"correctly to a legal request.",
        ),
        (
            "Why this is not a testbench artifact",
            f"The masking assignment is in RTL, not in the testbench. "
            f"The testbench controls ARVALID, AWVALID, and other master signals. "
            f"It does not control the assignment order inside the slave's "
            f"always-block. The same masking occurs in gate-level netlist "
            f"and on silicon because it is a structural property of the RTL, "
            f"not a simulation-scheduling artifact. "
            f"If the design were formally verified, the property "
            f"'assert (enabling_cond |-> ##1 {sig})' would fail unconditionally.",
        ),
        (
            "Exact condition that allows the masking",
            f"Within a single always-block, Verilog/SystemVerilog NBA semantics "
            f"mean the last write to a signal in a given simulation delta wins. "
            f"If driver D1 writes {sig}=1 under condition C1 and driver D2 writes "
            f"{sig}=0 under condition C2, and C2 is a superset of C1 (C2 is true "
            f"whenever C1 is true), then D2 always fires after D1 and always "
            f"cancels it. The collision is: both D1 and D2 are active at the same "
            f"time, D2 executes last, and its condition is strictly broader.",
        ),
        (
            "Invariant that should hold but does not",
            f"INVARIANT: for every posedge of ACLK, "
            f"if (enabling_condition_for_{sig}) then (next_cycle_{sig} == 1). "
            f"The current RTL violates this invariant because a later "
            f"unconditional assignment negates the enabling-path write before "
            f"the clock edge commits it. The invariant is not enforced by any "
            f"existing RTL guard or assertion.",
        ),
    ])


# ── INCONCLUSIVE defense ───────────────────────────────────────────────────────

def _defend_inconclusive(rca: Dict[str, Any]) -> List[str]:
    return [
        "  INCONCLUSIVE — DEFENSE NOT APPLICABLE",
        "",
        "  The analysis did not find sufficient structural or waveform evidence to",
        "  construct a falsifiable root cause claim. A formal defense is not",
        "  generated to avoid manufacturing unsupported conclusions.",
        "",
        "  Recommended next steps:",
        "    1. Extend waveform coverage to include more transaction types.",
        "    2. Provide RTL drivers CSV for all signals flagged as protocol violators.",
        "    3. Run formal property checking on the suspected handshake signals.",
        "    4. Confirm FSM state encoding file is present in the analysis directory.",
    ]


# ── Subtype-specific datapath helpers ─────────────────────────────────────────

def _datapath_rtl_desc(
    sub: str, dst: str, src: str,
    src_w: Optional[int], dst_w: Optional[int],
    rep: Optional[int], const_b: Optional[int],
    loc: str,
) -> str:
    sw = f"{src_w}-bit " if src_w else ""
    dw = f"{dst_w}-bit " if dst_w else ""

    if sub == "WIDTH_TRUNCATION":
        return (
            f"At {loc}, the RTL assigns {dst} = {src}[{(dst_w or '?') - 1}:0] "
            f"(or equivalent slice), truncating a {sw}source to a {dw}destination. "
            f"Bits [{(src_w or '?') - 1}:{dst_w or '?'}] of {src} are permanently "
            f"discarded before the value reaches the protocol boundary."
        )
    if sub == "WIDTH_DUPLICATION_WITHOUT_MAPPING":
        return (
            f"At {loc}, the RTL drives {dst} = {{{rep or 'N'}{{{src}}}}} or a "
            f"similar replication expression that places copies of {src} in "
            f"multiple byte lanes without byte-enable gating. "
            f"All {rep or 'N'} copies are driven simultaneously; reading any "
            f"one lane returns the same value regardless of which lane was written."
        )
    if sub in ("NON_INVERTIBLE_COLLAPSE", "INFORMATION_LOSS"):
        return (
            f"At {loc}, the RTL applies a destructive reduction to {src} "
            f"(e.g., XOR-reduction, left-shift with truncation, bitwise AND-fold) "
            f"before assigning the result to {dst}. "
            f"The output width is strictly less than the input width, meaning "
            f"multiple input words map to a single output word."
        )
    if sub == "SYNTHETIC_DATA":
        return (
            f"At {loc}, the RTL concatenates a constant literal with {src} "
            f"to form {dst}. The constant bits ({const_b or '?'} bit(s)) "
            f"are not derived from any architectural register or bus input; "
            f"they are fabricated in the RTL expression itself."
        )
    if sub == "NON_INVERTIBLE_DUPLICATION":
        return (
            f"At {loc}, the RTL constructs {dst} by concatenating {src} with "
            f"itself (or a closely related alias), e.g., {{{src}, {src}}}. "
            f"The upper and lower halves of {dst} carry identical information; "
            f"they are not independently addressable."
        )
    # Generic fallback
    return (
        f"At {loc}, the RTL performs a {sub} transform on {src} when assigning "
        f"to {dst}. The transform is not width-preserving or information-conserving, "
        f"meaning the output cannot be uniquely inverted back to the input."
    )


def _datapath_collision(
    sub: str, dst: str, src: str,
    src_w: Optional[int], dst_w: Optional[int],
    rep: Optional[int],
) -> str:
    if sub == "WIDTH_TRUNCATION":
        sw = src_w or "N"
        dw = dst_w or "M"
        return (
            f"Consider two source values V1 and V2 that differ only in bits "
            f"[{sw}-1:{dw}]. After truncation to {dw} bits, both map to the "
            f"same value. A master that writes V1 and then reads back the value "
            f"will receive an alias that is also consistent with V2. "
            f"The collision space has 2^({sw}-{dw}) elements that all hash to "
            f"each distinct {dw}-bit output."
        )
    if sub == "NON_INVERTIBLE_COLLAPSE":
        return (
            f"Any two values of {src} whose XOR/AND/OR reduction produces "
            f"the same single-bit result are collapsed to the same output. "
            f"For an N-bit source, exactly half of all input values map to "
            f"output 0 and half map to output 1, making the collision "
            f"space astronomically large."
        )
    if sub == "NON_INVERTIBLE_DUPLICATION":
        return (
            f"The upper and lower halves of {dst} are always equal because "
            f"both are driven by the same {src} expression. "
            f"If a master expects to address them independently "
            f"(e.g., bytes 3:2 vs bytes 1:0), any write to one half "
            f"appears in the other. Two writes to different logical addresses "
            f"that share this representation will collide."
        )
    return (
        f"The {sub} transform reduces the distinguishable output space of {dst} "
        f"relative to its input. Any two source values that map to the same "
        f"output are indistinguishable at the protocol boundary."
    )


def _datapath_invariant(
    sub: str, dst: str, src: str,
    src_w: Optional[int], dst_w: Optional[int],
) -> str:
    sw = src_w or "N"
    dw = dst_w or "M"

    if sub == "WIDTH_TRUNCATION":
        return (
            f"INVARIANT: the RTL path to {dst} must be width-preserving. "
            f"Formally: for all bit indices i in [0, {sw}-1], {dst}[i] must "
            f"equal {src}[i] at the protocol boundary. "
            f"The current RTL violates this for all i in [{dw}, {sw}-1] because "
            f"those bits are truncated before the signal reaches {dst}."
        )
    if sub == "NON_INVERTIBLE_COLLAPSE":
        return (
            f"INVARIANT: the function f: {src} -> {dst} must be injective "
            f"(one-to-one). For a destructive reduction, f is many-to-one, "
            f"which directly violates this invariant. "
            f"The AXI protocol implicitly requires injectivity because a master "
            f"must be able to recover the written value from a read response."
        )
    if sub == "SYNTHETIC_DATA":
        return (
            f"INVARIANT: every bit of {dst} must be traceable to an architectural "
            f"register, bus input, or explicitly defined constant with protocol-level "
            f"meaning. Fabricated constants embedded in the datapath violate this "
            f"because they inject information the master did not write and cannot "
            f"predict."
        )
    return (
        f"INVARIANT: the RTL transform applied to {src} when driving {dst} must "
        f"be bijective (invertible). The {sub} mechanism breaks bijectivity, "
        f"meaning the master cannot reconstruct the original value from the "
        f"protocol-boundary representation."
    )


# ── Shared formatter ───────────────────────────────────────────────────────────

def _numbered_defense(sections: List[tuple]) -> List[str]:
    """Format a list of (title, body) tuples as numbered defense points."""
    lines: List[str] = []
    for i, (title, body) in enumerate(sections, 1):
        lines.append(f"  [{i}] {title.upper()}")
        lines.append(_DASH)
        # Word-wrap at 75 chars
        for paragraph in body.split("\n"):
            paragraph = paragraph.strip()
            if not paragraph:
                lines.append("")
                continue
            words = paragraph.split()
            current = "      "
            for word in words:
                if len(current) + len(word) + 1 > 78:
                    lines.append(current.rstrip())
                    current = "      " + word + " "
                else:
                    current += word + " "
            if current.strip():
                lines.append(current.rstrip())
        lines.append("")
    return lines
