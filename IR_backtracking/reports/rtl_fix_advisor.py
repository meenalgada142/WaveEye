"""
RTL Fix Advisor — Surgical Correction Guidance
================================================
Audience : experienced RTL engineers.
Goal     : propose a minimal, targeted RTL fix for the proven root cause.
           Does NOT rewrite the module — addresses only the flagged assignment.

For each root cause type and subtype the report covers:
  1. Design mistake in plain language.
  2. Safe design rule being violated.
  3. Concrete RTL correction strategy.
  4. Guarded-code example (short).
  5. Why this fix removes the failure mechanism.
  6. Tradeoffs (latency, area, alignment constraints).

Usage:
    from reports.rtl_fix_advisor import generate_rtl_fix
    text = generate_rtl_fix(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

_SEP  = "=" * 79
_DASH = "-" * 79


def generate_rtl_fix(payload: Dict[str, Any]) -> str:
    """Return a surgical RTL correction guidance string from an RCA payload dict."""

    rca       = payload.get("final_rca") or {}
    tv        = payload.get("transport_violations") or []
    dv        = payload.get("datapath_violations")  or []
    findings  = payload.get("findings")              or []

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification")  or "UNKNOWN"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or pev0.get("expected_signal") or "target signal"
    rule  = pev0.get("rule_id") or "N/A"
    cyc   = pev0.get("analysis_cycle")

    # Build canonical rule label for header
    from .console_diagnosis import _RULE_CANON
    canon, spec_ref = _RULE_CANON.get(str(rule).upper(), ("", ""))
    rule_display = f"{canon}  ({spec_ref})" if canon else rule

    hdr = [
        _SEP,
        "  RTL FIX ADVISOR — SURGICAL CORRECTION GUIDANCE",
        _SEP,
        f"  Root Cause     : {root_type}/{classif}",
        f"  Primary Signal : {sig}",
        f"  Rule           : {rule_display}",
        f"  Cycle          : {cyc if cyc is not None else 'N/A'}",
        _SEP,
        "",
    ]

    if root_type == "TRANSPORT":
        body = _fix_transport(tv, rca, sig)
    elif root_type == "DATAPATH":
        body = _fix_datapath(dv, rca, sig, classif)
    elif root_type == "PROTOCOL":
        body = _fix_protocol(findings, rca, sig, rule, cyc)
    else:
        body = _fix_inconclusive()

    footer = ["", _SEP]
    return "\n".join(hdr + body + footer)


# ── Detected RTL Pattern helper (PART 4) ───────────────────────────────────────

def _detected_pattern(
    location: str,
    faulty_rtl: str,
    issue: str,
    fix_hint: str,
) -> List[str]:
    """Return a '0. Detected RTL Pattern' section with concrete RTL snippets."""
    lines = ["  0. Detected RTL Pattern", "  " + _DASH]
    lines.append(f"    Location   : {location}")
    lines.append(f"    Faulty RTL : {faulty_rtl}")
    lines.append(f"    Issue      : {issue}")
    lines.append("")
    lines.append("    Recommended fix:")
    for ln in fix_hint.splitlines():
        lines.append(f"    {ln}")
    lines.append("")
    return lines


def _width_analysis_table(
    src_w: Optional[int],
    dst_w: Optional[int],
    sub: str,
) -> List[str]:
    """
    Return a 'Width Analysis' table section when width information is available.
    Shows destination width, source width, bits lost, and a bijection verdict.
    """
    if not (src_w and dst_w):
        return []
    bits_lost = src_w - dst_w
    lost_range = f"[{src_w - 1}:{dst_w}]" if bits_lost > 0 else "none"
    bijective  = bits_lost <= 0

    lines = [
        "  Width Analysis",
        "  " + "─" * 57,
        f"    Destination width : {dst_w} bit{'s' if dst_w != 1 else ''}",
        f"    Source width      : {src_w} bit{'s' if src_w != 1 else ''}",
        f"    Bits lost         : {lost_range} ({max(bits_lost, 0)} bit{'s' if bits_lost != 1 else ''})",
        f"    Non-bijective mapping — information loss confirmed." if not bijective else
        f"    Bijective — no information lost.",
        "",
    ]
    return lines


# ── TRANSPORT fix ──────────────────────────────────────────────────────────────

def _fix_transport(
    tv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
) -> List[str]:
    first  = tv[0] if tv else {}
    dst    = first.get("destination_signal") or "WDATA"
    src    = first.get("source_signal") or "src_data"
    strb   = first.get("strobe_signal") or "WSTRB"
    rtl    = first.get("rtl_line") or first.get("source_location") or first.get("source")
    sub    = first.get("subtype") or "WSTRB_DATA_MISALIGNMENT"
    shift  = first.get("shift_expression") or ""
    loc    = str(rtl) if rtl else "the flagged assignment block"

    # Derive shift amount heuristic
    shift_note = f" by `{shift}`" if shift else ""

    body = _detected_pattern(
        location  = loc,
        faulty_rtl= f"assign {dst} = {src} << byte_offset * 8;\n"
                    f"    assign {strb} = orig_wstrb;   // ← missing steering",
        issue     = f"{dst} byte-lane steering applied without matching {strb} shift.",
        fix_hint  = f"assign {dst} = {src} << byte_offset * 8;\n"
                    f"assign {strb} = orig_wstrb << byte_offset;   // mirror the shift",
    )

    body += _section("1. Design Mistake", f"""\
At {loc}, {dst} is steered{shift_note} while {strb} is assigned without an \
equivalent steering expression. The byte-enable bits no longer correspond to the \
actual byte positions in the rearranged WDATA word.""")

    body += _section("2. Safe Design Rule Violated", """\
AXI4 / AXI4-Lite rule: WSTRB[i]=1 must always mean that WDATA[8i+7:8i] \
carries a valid write byte for lane i. Any rearrangement of WDATA must be \
accompanied by an identical rearrangement of WSTRB, or WSTRB must be \
recomputed to track the new lane positions.""")

    body += _section("3. Correction Strategy", f"""\
Apply the same steering transform to {strb} that is applied to {dst}. \
Do not touch any other logic in the module. \
If the steering is a left-shift by K bytes, shift {strb} left by K bits as well. \
If the steering is a lane-swap, apply the same permutation to {strb}.""")

    body += _section("4. Guarded-Code Example", f"""\
// BEFORE (defective):
assign {dst}  = {src} << (byte_offset * 8);
assign {strb} = orig_wstrb;                 // <-- missing steering

// AFTER (corrected):
assign {dst}  = {src} << (byte_offset * 8);
assign {strb} = orig_wstrb << byte_offset;  // mirror the same shift

// Formal guard (add as SVA assertion):
// assert property (@(posedge ACLK) disable iff (!ARESETn)
//   WVALID |->
//     forall(int i=0; i<(DATA_WIDTH/8); i++)
//       (WSTRB[i] == 1) |-> (WDATA[8*i+:8] == intended_byte[i]));""")

    body += _section("5. Why This Fix Removes the Failure", f"""\
After the fix, every steering transformation that moves data from lane i to \
lane j simultaneously moves the strobe enable from bit i to bit j. \
The invariant WSTRB[j]=1 iff WDATA[8j+7:8j] is the intended byte for lane j \
is restored by construction. The slave receives the correct byte enable and \
writes the right data to the right storage location.""")

    body += _section("6. Tradeoffs", """\
- Latency  : zero additional cycles; the strobe steering is purely combinational.
- Area     : one barrel-shifter or permutation network on the WSTRB path \
             (typically < 50 LUTs for a 32-bit interface).
- Alignment: the byte_offset signal must be the same signal used to steer WDATA; \
             verify this is a registered value (not combinationally derived \
             from WDATA itself) to avoid hold-time violations.""")

    return body


# ── DATAPATH fix ───────────────────────────────────────────────────────────────

def _fix_datapath(
    dv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
    classif: str,
) -> List[str]:
    first  = dv[0] if dv else {}
    dst    = first.get("destination_signal") or first.get("signal") or sig
    src    = first.get("source_signal") or "source_signal"
    sub    = first.get("subtype") or classif
    rtl    = first.get("rtl_line") or first.get("source_location") or first.get("source")
    src_w  = first.get("inferred_src_width")
    dst_w  = first.get("inferred_dst_width")
    rep    = first.get("rep_factor")
    const_b= first.get("const_padding_bits")
    loc    = str(rtl) if rtl else "the flagged assignment block"

    # Build concrete faulty RTL snippet from violation fields
    sw_str = f"{src_w}" if src_w else "N"
    dw_str = f"{dst_w}" if dst_w else "M"
    if sub == "WIDTH_TRUNCATION" or "TRUNCATION" in str(sub).upper():
        faulty  = f"{dst} <= {src}[{dw_str}-1:0];"
        issue   = f"{sw_str}-bit source truncated to {dw_str} bits — non-bijective mapping."
        fix     = f"{dst} <= {src};   // widen destination to {sw_str} bits"
    elif sub == "NON_INVERTIBLE_COLLAPSE" or "COLLAPSE" in str(sub).upper():
        faulty  = f"{dst} <= ^{src};   // XOR-reduction discards all but 1 bit"
        issue   = f"Reduction operator destroys all information — non-invertible."
        fix     = f"{dst} <= {src};   // direct assignment preserves all bits"
    elif sub == "SYNTHETIC_DATA" or "SYNTHETIC" in str(sub).upper():
        cb = const_b or 8
        faulty  = f"{dst} <= {{{cb}'d0, {src}}};   // constant padding"
        issue   = f"{cb} fabricated constant bits in data path — not traceable to architecture."
        fix     = f"{dst} <= {{upper_field_reg, {src}}};   // drive from architectural register"
    else:
        faulty  = f"{dst} <= non_invertible_expr({src});"
        issue   = f"{sub} — distinct inputs may produce identical stored values."
        fix     = f"{dst} <= {src};   // direct bijective assignment"

    pattern = _detected_pattern(loc, faulty, issue, fix)
    width_tbl = _width_analysis_table(src_w, dst_w, sub)
    return pattern + width_tbl + _fix_dispatch_datapath(sub, dst, src, loc, src_w, dst_w, rep, const_b)


def _fix_dispatch_datapath(
    sub: str, dst: str, src: str, loc: str,
    src_w: Optional[int], dst_w: Optional[int],
    rep: Optional[int], const_b: Optional[int],
) -> List[str]:
    sw = src_w or "N"
    dw = dst_w or "M"

    if sub == "WIDTH_TRUNCATION":
        return (
            _section("1. Design Mistake", f"""\
At {loc}, {dst} is assigned from a slice of {src} (e.g., {src}[{dw}-1:0]), \
discarding bits [{sw}-1:{dw}]. The destination register is narrower than the \
source, and no semantic justification exists for dropping the upper bits.""")

            + _section("2. Safe Design Rule Violated", """\
Data-path rule: every bit in the source that carries architectural information \
must be representable at the protocol boundary. If the destination is narrower \
than the source, the design must either (a) prove those bits are always zero, \
or (b) declare them as explicitly don't-care with a waveeye suppression comment.""")

            + _section("3. Correction Strategy", f"""\
Option A (preferred): widen {dst} to match {src}. Propagate the wider width \
through the downstream logic. This is the zero-risk fix.
Option B: if the upper bits are architecturally guaranteed to be zero, add an \
assertion at the source: `assert (src[{sw}-1:{dw}] == 0)` and suppress the \
WaveEye warning with `// waveeye: intentional_encoding`.
Do NOT silently truncate without one of these two safeguards.""")

            + _section("4. Guarded-Code Example", f"""\
// BEFORE (defective truncation):
assign {dst} = {src}[{dw}-1:0];

// AFTER — Option A (widen destination):
// (change the port/register width of {dst} from {dw} to {sw})
assign {dst} = {src};   // full-width, no truncation

// AFTER — Option B (assert upper bits are zero):
assign {dst} = {src}[{dw}-1:0];
// waveeye: intentional_encoding
`ifdef SIMULATION
  always @(posedge clk)
    assert ({src}[{sw}-1:{dw}] === {sw-dw if isinstance(sw,int) and isinstance(dw,int) else 'N-M'}'d0)
      else $error("Width truncation: upper bits are non-zero at %0t", $time);
`endif""")

            + _section("5. Why This Fix Removes the Failure", f"""\
Option A makes {dst} carry all bits of {src}, restoring injectivity (distinct \
inputs produce distinct outputs). Option B provides a formal proof obligation \
that the discarded bits are always zero, making the truncation semantically safe \
while acknowledging the narrowing is intentional.""")

            + _section("6. Tradeoffs", f"""\
- Option A: area increases by ({sw}-{dw}) flip-flops and associated routing. \
  Downstream AXI data bus width may need updating — check interconnect constraints.
- Option B: zero area change but adds a simulation-only assertion overhead. \
  The assertion must be verified exhaustively (formal or constrained-random) \
  before the waveeye suppression can be considered safe.
- Latency: neither option adds pipeline stages.""")
        )

    if sub == "NON_INVERTIBLE_COLLAPSE":
        return (
            _section("1. Design Mistake", f"""\
At {loc}, a reduction operator (^, &, or |) is applied to {src} before \
assigning to {dst}. This deliberately discards all but one bit of information, \
making the transform non-invertible by construction.""")

            + _section("2. Safe Design Rule Violated", """\
Datapath rule: operators that reduce a multi-bit value to a single bit must \
only appear in control-path logic (e.g., parity checks, flag generation), \
never in a data-path driving a protocol-boundary register.""")

            + _section("3. Correction Strategy", f"""\
Determine what {dst} is actually supposed to carry:
  (a) If it is a parity/flag — separate it from the data register. Drive a \
      dedicated parity register with the reduction, and pass {src} unmodified \
      to {dst}.
  (b) If the reduction was a mistake (copy-paste error) — replace the reduction \
      with a direct assignment: {dst} = {src}.""")

            + _section("4. Guarded-Code Example", f"""\
// BEFORE (defective collapse):
assign {dst} = ^{src};   // XOR-reduction: all information lost

// AFTER — case (a): separate data and parity:
assign {dst}      = {src};          // full data preserved
assign parity_out = ^{src};         // parity kept separate

// AFTER — case (b): direct assignment (if reduction was accidental):
assign {dst} = {src};               // no reduction""")

            + _section("5. Why This Fix Removes the Failure", f"""\
In case (a), {dst} now carries the full bit-width of {src}; the function \
{dst} = f({src}) is the identity, which is trivially bijective. \
In case (b), the accidental reduction is removed.""")

            + _section("6. Tradeoffs", """\
- Case (a): adds a separate 1-bit register for parity. Negligible area.
- Case (b): no tradeoff — this is a pure bug fix.
- Neither option adds latency.""")
        )

    if sub == "SYNTHETIC_DATA":
        return (
            _section("1. Design Mistake", f"""\
At {loc}, {dst} is driven by a concat expression that includes one or more \
constant literals, e.g., {{{const_b or '8'}'d0, {src}}}. These fabricated \
bits are not derived from any architectural source and cannot be predicted or \
interpreted by an AXI master.""")

            + _section("2. Safe Design Rule Violated", """\
Datapath rule: every bit of a protocol-boundary signal must be traceable to \
an architected register, a bus input, or a constant whose value is specified \
in the programmer's model. Unspecified constants in RDATA are a protocol \
violation because the master cannot distinguish them from real data.""")

            + _section("3. Correction Strategy", f"""\
Replace the constant padding with the appropriate source signal. \
If the upper bits represent a valid architectural field, drive them from the \
corresponding register. If they are defined as reserved/zero in the programmer's \
model, keep the constant but add `// waveeye: intentional_encoding` and a \
cross-reference to the spec section that defines them as fixed.""")

            + _section("4. Guarded-Code Example", f"""\
// BEFORE (fabricated constant in data path):
assign {dst} = {{{const_b or '8'}'d0, {src}}};

// AFTER — option A: drive from architectural register:
assign {dst} = {{upper_field_reg, {src}}};

// AFTER — option B: reserved field, spec-defined as zero:
assign {dst} = {{{const_b or '8'}'d0, {src}}};  // waveeye: intentional_encoding
// Ref: Programmer's Model Section 3.2 — bits [{const_b or 'N'}-1:0] are RES0.""")

            + _section("5. Why This Fix Removes the Failure", """\
Option A: the upper bits now carry real data, making the entire output \
traceable. Option B: the fabricated constant is explicitly sanctioned by the \
spec, so the assertion is suppressed with justification.""")

            + _section("6. Tradeoffs", """\
- Option A may require adding new architectural registers — assess RTL impact scope.
- Option B: zero RTL change, but requires spec review to confirm reserved-field semantics.
- Neither option affects timing or area materially.""")
        )

    # Generic datapath fallback
    return (
        _section("1. Design Mistake", f"""\
At {loc}, the {sub} transform on {src} → {dst} is not width-preserving or \
information-conserving. The specific mechanism ({sub}) means distinct input \
values can produce identical outputs.""")

        + _section("2. Safe Design Rule Violated", """\
Datapath rule: the RTL function mapping source data to a protocol-boundary \
register must be bijective (one-to-one) unless the designer explicitly proves \
the collapsed values are architecturally equivalent.""")

        + _section("3. Correction Strategy", f"""\
Replace the {sub} expression with a width-preserving direct assignment or a \
semantically justified transform that is documented and suppressed in WaveEye \
with `// waveeye: intentional_encoding`.""")

        + _section("4. Guarded-Code Example", f"""\
// BEFORE (defective — {sub}):
assign {dst} = non_invertible_expr({src});

// AFTER (corrected — direct assignment):
assign {dst} = {src};   // if widths match
// OR
assign {dst} = {src}[{dw}-1:0];  // waveeye: intentional_encoding
// Ref: upper bits are architecturally don't-care per <spec section>.""")

        + _section("5. Why This Fix Removes the Failure", f"""\
The direct assignment is the identity function, which is trivially bijective. \
The suppressed version requires external justification that the dropped bits \
are don't-care, making the intent auditable.""")

        + _section("6. Tradeoffs", """\
- Direct assignment: may require widening downstream paths — check interface widths.
- Suppressed version: zero RTL change; adds maintenance obligation to keep the \
  spec cross-reference current.""")
    )


# ── PROTOCOL fix ───────────────────────────────────────────────────────────────

def _fix_protocol(
    findings: List[Dict[str, Any]],
    rca: Dict[str, Any],
    sig: str,
    rule: str,
    cyc: Any,
) -> List[str]:
    pev  = rca.get("primary_evidence") or []
    pev0 = pev[0] if pev and isinstance(pev[0], dict) else {}
    evid = pev0.get("evidence") or {}
    canc = evid.get("intra_cycle_cancellation") or {}
    overw_conds = canc.get("final_overwrite_conditions") or []
    enab_conds  = canc.get("expected_driver_conditions") or []
    chain = rca.get("causal_chain") or ""

    ow_str = overw_conds[0] if overw_conds else "superset condition"
    en_str = enab_conds[0] if enab_conds else "enabling condition"

    cyc_str = f"cycle {cyc}" if cyc is not None else "the violation cycle"

    # Locate RTL from primary evidence
    rtl_loc = pev0.get("source_location") or pev0.get("rtl_line") or "the always-block"

    body = _detected_pattern(
        location  = str(rtl_loc),
        faulty_rtl= f"{sig} <= 0;               // D2: broad — overwrites D1\n"
                    f"    if ({en_str}) {sig} <= 1; // D1: specific — LOST to D2",
        issue     = f"D2 (broad) executes after D1 (specific) in the same delta — D1's "
                    f"assignment is always overwritten by D2.",
        fix_hint  = f"if ({en_str}) {sig} <= 1;   // D1: specific — evaluated first\n"
                    f"else              {sig} <= 0;   // D2: default — only when D1 does not fire",
    )

    body += _section("1. Design Mistake", f"""\
The RTL always-block contains two drivers for {sig}. The enabling driver (D1) \
correctly asserts {sig}=1 under condition `{en_str}`. However, a later driver \
(D2) assigns {sig}=0 under `{ow_str}`, which is a superset of `{en_str}`. \
Because D2 is evaluated after D1 in the same always-block, D2's assignment \
always wins, making {sig} permanently stuck at 0 whenever `{en_str}` is true.""")

    body += _section("2. Safe Design Rule Violated", """\
RTL coding rule: within a single always-block, never assign a signal in a \
broader condition after assigning it in a narrower sub-condition that must take \
precedence. Priority must flow from most-specific (narrowest condition) to \
least-specific (broadest condition), with the most-specific assignment appearing \
LAST so it wins. Alternatively, structure the conditions as mutually exclusive \
branches using if-else chains.""")

    body += _section("3. Correction Strategy", f"""\
Option A — Reorder assignments: place the specific enabling assignment (D1) \
AFTER the default/broad assignment (D2). The specific case overrides the default.
Option B — Use if-else to make the conditions mutually exclusive: restructure \
the code so that `{en_str}` is in an else-if branch that is only reached when \
`{ow_str}` does not override it.
Option C — Merge conditions: combine D1 and D2 into a single expression that \
computes the correct output in one assignment.
Do NOT add a separate always-block for {sig} — that would create a race condition.""")

    body += _section("4. Guarded-Code Example", f"""\
// BEFORE (defective — D2 overwrites D1):
always_ff @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn) {sig} <= 0;
    else begin
        {sig} <= 0;               // D2: broad condition (always active in IDLE)
        if ({en_str}) {sig} <= 1; // D1: specific (IDLE && ARVALID) — OVERWRITTEN by D2
    end
end

// AFTER — Option A (reorder: D1 last = highest priority):
always_ff @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn) {sig} <= 0;
    else begin
        if ({en_str}) {sig} <= 1; // D1: specific case — evaluated first
        else           {sig} <= 0; // D2: default — only when D1 does not apply
    end
end

// AFTER — Option B (if-else, mutually exclusive):
always_ff @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn)
        {sig} <= 0;
    else if ({en_str})       // specific condition takes priority
        {sig} <= 1;
    else if ({ow_str})       // broad default — only when specific does not apply
        {sig} <= 0;
end""")

    body += _section("5. Why This Fix Removes the Failure", f"""\
Option A restores correct NBA (non-blocking assignment) semantics: the last \
write within a single delta wins, and D1 (specific) is now the last write when \
`{en_str}` is true. D2 (broad) only takes effect when D1 does not apply. \
The masking mechanism is eliminated by construction. \
Under Option B, the if-else structure makes the conditions structurally \
exclusive — it is impossible for both branches to fire in the same delta.""")

    body += _section("6. Tradeoffs", """\
- Option A: zero area and timing impact. Risk: requires careful review of all \
  drivers for {sig} to ensure no other broad-before-specific ordering exists.
- Option B: slightly more verbose but more readable and tool-friendly for \
  coverage measurement (each branch is an independent coverpoint).
- Option C: reduces code lines but may obscure intent for reviewers; prefer A or B.
- All options: run regression and check that ARREADY (or the affected signal) \
  deasserts correctly on reset and after the transaction completes — the fix \
  must not prevent the default-low behavior for other states.""")

    return body


# ── INCONCLUSIVE ───────────────────────────────────────────────────────────────

def _fix_inconclusive() -> List[str]:
    return [
        "  INCONCLUSIVE — FIX GUIDANCE NOT AVAILABLE",
        "",
        "  No structural root cause was isolated. Fix guidance requires a proven",
        "  defect. Provide the following inputs and re-run the analysis:",
        "",
        "    1. RTL drivers CSV covering all signals reported as stuck or violated.",
        "    2. FSM state encoding file (.fsm_encodings.json) in the analysis directory.",
        "    3. Extended waveform covering at least 3 complete transactions.",
        "    4. Violations JSON from axil4 (or equivalent protocol checker).",
    ]


# ── Shared formatter ───────────────────────────────────────────────────────────

def _section(title: str, body: str) -> List[str]:
    """Format a titled section with word-wrapped body."""
    lines = [f"  {title}", "  " + _DASH]
    for paragraph in body.split("\n"):
        paragraph = paragraph.rstrip()
        if not paragraph.strip():
            lines.append("")
            continue
        # Preserve indentation for code blocks
        indent = len(paragraph) - len(paragraph.lstrip())
        prefix = "    " + " " * indent
        words  = paragraph.lstrip().split()
        current = prefix
        for word in words:
            if len(current) + len(word) + 1 > 78:
                lines.append(current.rstrip())
                current = prefix + word + " "
            else:
                current += word + " "
        if current.strip():
            lines.append(current.rstrip())
    lines.append("")
    return lines
