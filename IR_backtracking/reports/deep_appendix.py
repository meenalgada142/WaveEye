"""
Deep Technical Appendix
========================
For engine-soundness validation by a formal verification reviewer.
NOT presentation-facing — includes everything.

Covers:
  - Full invariant reasoning per violation class
  - All violation instances (not collapsed)
  - Dependency chains
  - Structural tracebacks
  - Mathematical justification where applicable

Usage:
    from reports.deep_appendix import generate_deep_appendix
    text = generate_deep_appendix(payload)
"""

from __future__ import annotations
import json
from typing import Any, Dict, List, Optional

_SEP  = "=" * 79
_DASH = "-" * 79
_SUB  = "~" * 79


def generate_deep_appendix(payload: Dict[str, Any]) -> str:
    """Return a complete technical appendix string."""

    rca       = payload.get("final_rca") or {}
    tv        = payload.get("transport_violations") or []
    dv        = payload.get("datapath_violations")  or []
    findings  = payload.get("findings")              or []
    txns      = payload.get("transactions")          or []
    binding   = payload.get("binding_result")        or {}
    proto     = (payload.get("protocol") or "unknown").upper()
    max_cycle = payload.get("waveform_max_cycle") or 0

    root_type  = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif    = rca.get("classification")  or "UNKNOWN"
    confidence = rca.get("confidence")      or "LOW"
    chain      = rca.get("causal_chain")    or ""
    expl       = rca.get("explanation")     or ""

    sections: List[str] = []

    sections += [
        _SEP,
        "  DEEP TECHNICAL APPENDIX — ENGINE SOUNDNESS VALIDATION",
        _SEP,
        f"  Protocol       : {proto}",
        f"  Max Cycle      : {max_cycle:,}",
        f"  Root Cause     : {root_type}/{classif}  [{confidence}]",
        f"  Transactions   : {len(txns)}",
        f"  Structural Viol: {len(tv)} transport + {len(dv)} datapath",
        f"  Protocol Finds : {len(findings)}",
        _SEP,
        "",
    ]

    # ── Section 1: Invariant Reasoning ───────────────────────────────────
    sections += _invariant_section(root_type, classif, tv, dv, findings)

    # ── Section 2: All Violation Instances (unfiltered) ──────────────────
    sections += _all_violations_section(tv, dv)

    # ── Section 3: Protocol Findings (all) ───────────────────────────────
    sections += _all_findings_section(findings)

    # ── Section 4: Dependency Chains ──────────────────────────────────────
    sections += _dependency_section(rca, chain)

    # ── Section 5: Structural Traceback ───────────────────────────────────
    sections += _structural_traceback_section(rca, binding)

    # ── Section 6: Mathematical Justification ─────────────────────────────
    sections += _math_section(root_type, classif, tv, dv)

    # ── Section 7: Raw Resolver JSON (ground truth) ───────────────────────
    sections += _raw_json_section("RESOLVER OUTPUT (final_rca)", rca)

    # ── Section 8: Causal Binding Detail ─────────────────────────────────
    if binding:
        sections += _raw_json_section("CAUSAL BINDING RESULT", binding)

    sections.append(_SEP)
    return "\n".join(sections)


# ── Section builders ───────────────────────────────────────────────────────────

def _invariant_section(
    root_type: str,
    classif: str,
    tv: List[Dict[str, Any]],
    dv: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> List[str]:
    lines = [
        "  [1] INVARIANT REASONING",
        _DASH,
        "",
    ]

    if root_type == "TRANSPORT":
        lines += _wrap("""\
INVARIANT (AXI4-Lite Write Channel):
  forall t in WRITE_TRANSACTIONS:
    forall i in [0, DATA_WIDTH/8 - 1]:
      WSTRB[i] == 1  =>  WDATA[8*i + 7 : 8*i] == INTENDED_BYTE[i]

Basis: AXI4-Lite specification section on WSTRB semantics. WSTRB bit i enables
byte lane i. The slave samples WDATA at the lane indicated by WSTRB, NOT at the
lane where the source data physically resides after any rearrangement.

Violation mechanism: the RTL applies a steering transform to WDATA without
applying the same transform to WSTRB. The invariant is broken at the assignment
site identified by the transport violation detector (transport_semantic_analysis.py).

Falsifying instance: any WRITE transaction with at least one asserted WSTRB bit
and a non-identity byte-lane arrangement in WDATA.
""")
    elif root_type == "DATAPATH":
        if classif == "STRUCTURAL_CAUSAL":
            lines += _wrap("""\
INVARIANT (Data Path Bijectivity):
  Let f: Source_Domain -> Dest_Domain be the RTL combinational function.
  f must be injective: forall x1 != x2 in Source_Domain, f(x1) != f(x2).

Basis: the AXI protocol requires that a master can reconstruct the written value
from a read response. If f is not injective, two distinct source values x1 and x2
produce f(x1) == f(x2), making the original write value unrecoverable.

Width truncation case: f truncates the N-bit source to M bits (M < N). The
kernel of f has size 2^(N-M), i.e., 2^(N-M) distinct source values map to every
single destination value. The invariant is violated because the mapping is
|Source_Domain| / |Dest_Domain| = 2^(N-M) -to-one.

Non-invertible reduction case: f applies XOR, AND, or OR reduction to all bits.
The output is 1 bit regardless of input width N. The kernel size is 2^(N-1) for
XOR reduction; the mapping is maximally non-injective.
""")
        elif classif == "SEMANTIC_STRUCTURAL":
            lines += _wrap("""\
INVARIANT (Address Uniqueness / Write Non-Aliasing):
  forall a1 != a2 in ADDRESS_SPACE:
    WRITE(a1, v1) followed by WRITE(a2, v2) =>
      READ(a1) == v1 AND READ(a2) == v2.

Violation mechanism: the RTL address computation f(addr) collapses two distinct
logical addresses a1 != a2 to the same physical location. The invariant is
broken because the second write silently overwrites the first.

The WaveEye detector (memory_write_semantic_analysis.py) identifies aliasing when
the RTL assign statement for the memory LHS uses an address expression whose
image under f is smaller than its domain — i.e., f is not surjective onto
distinct memory locations.
""")
        else:
            lines += _wrap("""\
INVARIANT (General Datapath Conservation):
  The bit-width of information at the protocol boundary must be >= the
  bit-width of architecturally significant source data.

Any RTL operator that reduces effective information width without architectural
justification violates this invariant. Width conservation analysis checks all
assignments whose destination width is less than the source effective width.
""")
    elif root_type == "PROTOCOL":
        lines += _wrap("""\
INVARIANT (AXI4-Lite Handshake Liveness):
  forall VALID_assertion events on channel C:
    eventually (READY on C == 1).

For RVALID specifically (RULE_10 context):
  ARVALID && ARREADY => ##[1:TIMEOUT] RVALID.

Violation mechanism: the RTL driver for RVALID (or ARREADY) contains a later
assignment that unconditionally cancels the enabling write. The property
'assert (enabling_cond |-> ##1 target_sig)' fails under formal verification.

The WaveEye detector (predicate_backtrack.py + analyse_interactive.py) identifies
this via NBA semantics analysis: within a single always-block, the last write to
a signal in a given simulation delta commits. If a broader condition fires after
a narrower enabling condition, the broader driver wins.
""")
    else:
        lines += ["  Insufficient evidence for invariant reasoning.", ""]

    return lines


def _all_violations_section(
    tv: List[Dict[str, Any]],
    dv: List[Dict[str, Any]],
) -> List[str]:
    lines = [
        "  [2] ALL VIOLATION INSTANCES (unfiltered)",
        _DASH,
        "",
    ]

    if not tv and not dv:
        lines += ["  None.", ""]
        return lines

    lines.append(f"  Transport violations: {len(tv)}")
    for i, v in enumerate(tv):
        lines += _violation_block(i + 1, v, "TRANSPORT")

    lines.append(f"  Datapath violations: {len(dv)}")
    for i, v in enumerate(dv):
        lines += _violation_block(i + 1, v, "DATAPATH")

    return lines


def _all_findings_section(findings: List[Dict[str, Any]]) -> List[str]:
    lines = [
        "  [3] ALL PROTOCOL FINDINGS (unfiltered)",
        _DASH,
        "",
        f"  Count: {len(findings)}",
        "",
    ]

    for i, f in enumerate(findings):
        rule  = f.get("rule_id") or "?"
        cls   = f.get("classification") or "?"
        sig   = f.get("signal") or "?"
        cyc   = f.get("analysis_cycle")
        v     = f.get("verdict") or "?"
        detail= (f.get("detail") or "").strip()
        lines += [
            f"  [{i+1}]  {rule} / {cls}",
            f"       Signal  : {sig}",
            f"       Verdict : {v}   Cycle : {cyc if cyc is not None else 'N/A'}",
        ]
        if detail:
            for dl in detail.split("\n")[:4]:
                lines.append(f"       {dl.strip()}")
        # Evidence sub-dict
        evid = f.get("evidence") or {}
        canc = evid.get("intra_cycle_cancellation") or {}
        if canc.get("detected"):
            oc  = canc.get("occurrence_count") or 1
            econd = canc.get("expected_driver_conditions") or []
            fcond = canc.get("final_overwrite_conditions") or []
            lines.append(f"       [INTRA_CYCLE_CANCEL]  occurrences={oc}")
            if econd:
                lines.append(f"         enabling : {'; '.join(str(c) for c in econd[:2])}")
            if fcond:
                lines.append(f"         overwrite: {'; '.join(str(c) for c in fcond[:2])}")
        cycle_r = evid.get("cycle_report") or {}
        if cycle_r.get("cycle_detected"):
            lines.append(f"       [CYCLIC_ENABLE]  blocking={cycle_r.get('blocking_signal', '?')}")
        lines.append("")

    return lines


def _dependency_section(rca: Dict[str, Any], chain: str) -> List[str]:
    lines = [
        "  [4] DEPENDENCY CHAINS",
        _DASH,
        "",
    ]

    if chain:
        for cl in chain.split("\n"):
            lines.append(f"  {cl}")
        lines.append("")
    else:
        lines.append("  No dependency chain available for this root cause type.")
        lines.append("")

    # Transform nodes (RULE 2)
    tnodes = rca.get("transform_nodes") or []
    if tnodes:
        lines.append(f"  TRANSFORM NODES ({len(tnodes)} node(s)):")
        for n in tnodes:
            nid  = n.get("node_id") or "?"
            nlhs = n.get("lhs") or "?"
            prop = n.get("property") or "?"
            bij  = n.get("bijective") or False
            rtl  = n.get("rtl_line")
            lines.append(
                f"    {nid}: lhs={nlhs}  prop={prop}  "
                f"bijective={'YES' if bij else 'NO'}  "
                f"line={rtl or 'N/A'}"
            )
        lines.append("")

    # Causal links (RULE 1)
    cl_list = rca.get("causal_links") or []
    if cl_list:
        lines.append(f"  CAUSAL LINKS ({len(cl_list)} link(s)):")
        for lk in cl_list:
            sig = lk.get("signal") or "?"
            mem = lk.get("memory") or "?"
            rtl = lk.get("rtl_line")
            lines.append(f"    {sig} → {mem}  (line {rtl or 'N/A'})")
        lines.append("")

    return lines


def _structural_traceback_section(
    rca: Dict[str, Any],
    binding: Dict[str, Any],
) -> List[str]:
    lines = [
        "  [5] STRUCTURAL TRACEBACK",
        _DASH,
        "",
    ]

    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    if pev:
        lines.append(f"  Primary evidence ({len(pev)} item(s)):")
        for pe in pev:
            rule  = pe.get("rule_id") or "?"
            sig   = pe.get("signal") or pe.get("expected_signal") or "?"
            cyc   = pe.get("analysis_cycle")
            cls   = pe.get("classification") or "?"
            lines.append(
                f"    [{rule}] {sig}  cls={cls}  cycle={cyc if cyc is not None else 'N/A'}"
            )
        lines.append("")

    sec: List[Dict[str, Any]] = rca.get("secondary_effects") or []
    if sec:
        lines.append(f"  Secondary effects ({len(sec)} item(s)):")
        for sv in sec:
            sc  = sv.get("class") or sv.get("classification") or "?"
            ss  = sv.get("signal") or sv.get("destination_signal") or "?"
            soc = sv.get("occurrence_count")
            occ = f"  ×{soc}" if soc and soc > 1 else ""
            lines.append(f"    [{sc}] {ss}{occ}")
        lines.append("")

    cb = binding.get("causal_bindings") or []
    if cb:
        lines.append(f"  Causal bindings ({len(cb)} transaction(s)):")
        for b in cb:
            tx   = b.get("transaction_type") or "?"
            addr = b.get("address") or "?"
            bcyc = b.get("cycle") or "?"
            bsig = b.get("assignment_signal") or "?"
            vidx = b.get("violation_index")
            lines.append(
                f"    [{tx}] addr={addr}  cycle={bcyc}  signal={bsig}"
                f"  viol_idx={vidx if vidx is not None else 'N/A'}"
            )
        lines.append("")

    if not pev and not sec and not cb:
        lines.append("  No structural traceback data available.")
        lines.append("")

    return lines


def _math_section(
    root_type: str,
    classif: str,
    tv: List[Dict[str, Any]],
    dv: List[Dict[str, Any]],
) -> List[str]:
    lines = [
        "  [6] MATHEMATICAL JUSTIFICATION",
        _DASH,
        "",
    ]

    if root_type == "TRANSPORT":
        first = tv[0] if tv else {}
        lines += _wrap("""\
Transport Alignment — Information Theory Argument:

Let W = DATA_WIDTH / 8 (number of byte lanes).
Let S = WSTRB[W-1:0] be the write-strobe bit vector.
Let D = WDATA[DATA_WIDTH-1:0] be the write-data word.
Let pi be the permutation applied to D by the RTL steering expression.

The slave writes byte lane i if S[i] == 1.
After the RTL steering, D[8*i+7:8*i] = original_data[8*pi(i)+7:8*pi(i)].

For the transfer to be correct:
  S[i] == 1  iff  original_data[8*pi(i)+7:8*pi(i)] is the intended byte for lane i.

If the RTL does NOT apply pi to S:
  S[i] reflects the pre-steering lane assignment,
  while D[i] carries the post-steering value.
  =>  S and D are inconsistent with probability 1 - 1/2^(W-1) for random data.
""")

    elif root_type == "DATAPATH":
        first = dv[0] if dv else {}
        sub   = first.get("subtype") or classif
        sw    = first.get("inferred_src_width")
        dw    = first.get("inferred_dst_width")

        if "TRUNCAT" in sub and sw and dw:
            sw, dw = int(sw), int(dw)
            collision_factor = 2 ** (sw - dw)
            lines += _wrap(f"""\
Width Truncation — Collision Set Size:

Source width   : {sw} bits  =>  |Domain|   = 2^{sw} = {2**sw}
Dest width     : {dw} bits  =>  |Codomain| = 2^{dw} = {2**dw}
Collision factor: 2^({sw}-{dw}) = {collision_factor}

For every distinct {dw}-bit output value O, there are exactly {collision_factor}
source values that map to O. A master that reads back value O cannot determine
which of the {collision_factor} possible original values was written.

Pigeon-hole principle: since |Domain| > |Codomain|, no injective function exists
that maps {sw}-bit inputs to {dw}-bit outputs. The truncation is necessarily non-injective.
""")
        elif "COLLAPSE" in sub or "INVERTIB" in sub:
            lines += _wrap("""\
Non-Invertible Reduction — Information Content:

Shannon entropy H(X) of a uniformly distributed N-bit source: H(X) = N bits.
Entropy of the XOR-reduction output Y = XOR(X[N-1], ..., X[0]): H(Y) = 1 bit.

Mutual information I(X; Y) = H(Y) - H(Y|X) = H(Y) = 1 bit.

Information lost = H(X) - I(X; Y) = N - 1 bits.
For a 32-bit source: 31 bits are irreversibly lost per transfer.

This is not a rounding error — it is a near-total information collapse.
No post-processing can recover the dropped N-1 bits from the 1-bit output.
""")
        else:
            lines += _wrap(f"""\
{sub} — Injectivity Argument:

A function f is injective iff: forall x1, x2: f(x1) == f(x2) => x1 == x2.
The {sub} transform violates injectivity because the output domain is smaller
than the input domain, or because the transform maps multiple inputs to one output.

Without injectivity, a READ-after-WRITE test cannot confirm correctness —
different write values produce identical readback, making data verification
impossible at the protocol boundary.
""")

    elif root_type == "PROTOCOL":
        lines += _wrap("""\
Handshake Liveness — Temporal Logic:

AXI4-Lite RULE (RULE_10 / RULE_13):
  G(ARVALID && ARREADY  ->  F RVALID)
  G(AWVALID && AWREADY && WVALID && WREADY  ->  F BVALID)

Where G = "globally" and F = "eventually" in LTL notation.

The RTL driver masking creates a situation where:
  ARVALID && ARREADY is TRUE (condition is met)
  but RVALID is NEVER asserted (F RVALID is FALSE)

This constitutes a violation of the LTL formula above.
Formally, the counterexample trace is the waveform window around the
violation cycle where: ARVALID=1, ARREADY=1, and RVALID stays 0 indefinitely.

The FSM masking causes a reachability failure: the state that drives RVALID=1
is never reachable from the current state under any input sequence, because
the enabling signal (ARREADY) is permanently overwritten to 0.
""")

    else:
        lines += ["  Mathematical justification not applicable for INCONCLUSIVE findings.", ""]

    return lines


def _raw_json_section(title: str, data: Any) -> List[str]:
    lines = [
        f"  [RAW] {title}",
        _DASH,
        "",
    ]
    try:
        raw = json.dumps(data, indent=2, default=str)
        for line in raw.split("\n"):
            lines.append(f"  {line}")
    except Exception as e:
        lines.append(f"  (serialisation error: {e})")
    lines.append("")
    return lines


def _violation_block(idx: int, v: Dict[str, Any], category: str) -> List[str]:
    cls  = v.get("class") or "UNKNOWN"
    sub  = v.get("subtype") or ""
    dst  = v.get("destination_signal") or v.get("signal") or "?"
    src  = v.get("source_signal") or "?"
    rtl  = v.get("rtl_line")
    loc  = f" @ line {rtl}" if rtl else ""
    ab   = v.get("always_block_id")
    imp  = (v.get("impact") or v.get("explanation") or "").strip()
    imp1 = imp.split("\n")[0][:100] if imp else ""

    lines = [
        f"  [{idx}] {category}/{cls}/{sub}{loc}",
        f"       dst={dst}  src={src}  block={ab or 'N/A'}",
    ]
    if imp1:
        lines.append(f"       impact: {imp1}")
    # Mathematical reason if present
    mr = v.get("mathematical_reason") or ""
    if mr:
        lines.append(f"       math  : {mr[:120]}")
    # Violated invariant if present
    vi = v.get("violated_invariant") or ""
    if vi:
        lines.append(f"       inv   : {vi[:120]}")
    lines.append("")
    return lines


def _wrap(text: str, indent: int = 4) -> List[str]:
    """Indent a multiline string block."""
    prefix = " " * indent
    lines = []
    for line in text.split("\n"):
        lines.append(prefix + line if line.strip() else "")
    lines.append("")
    return lines
