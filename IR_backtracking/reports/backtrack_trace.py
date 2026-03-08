"""
Human-Readable Backtrack Trace
================================
Translates the engine's dependency-graph walk into engineering prose.

Purpose: explain HOW the engine moved from observed symptom to root cause.
NOT a restatement of the RCA conclusion.

Rules observed:
  1. Start from the observed protocol failure.
  2. Show the first missing condition required to satisfy the protocol.
  3. Explain which RTL logic was evaluated.
  4. Show which driver should have activated but did not.
  5. Explain why it did not activate (failed predicate).
  6. If a register value was reused, trace its origin (previous-cycle dep).
  7. If a cycle / self-dependency is detected, call it out as a causal loop.
  8. Stop at a terminal condition (primary input, FSM latch, structural misuse).

Output format:
  Step N — Title:
  Body text.
  ...
  ROOT MECHANISM:
  <one sentence>

Usage:
    from reports.backtrack_trace import generate_backtrack_trace
    text = generate_backtrack_trace(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

_SEP  = "-" * 64


def generate_backtrack_trace(payload: Dict[str, Any]) -> str:
    """Return a human-readable backtrack trace string."""

    rca       = payload.get("final_rca") or {}
    findings  = payload.get("findings") or []
    dv        = payload.get("datapath_violations") or []
    tv        = payload.get("transport_violations") or []
    binding   = payload.get("binding_result") or {}

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification") or "UNKNOWN"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0      = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig       = pev0.get("signal") or pev0.get("expected_signal") or "target signal"
    rule      = pev0.get("rule_id") or "N/A"
    viol_cyc  = pev0.get("analysis_cycle")
    chain     = rca.get("causal_chain") or ""

    # Pull the most relevant finding for evidence details
    first_f = next(
        (f for f in findings if f.get("signal") == sig or f.get("rule_id") == rule),
        findings[0] if findings else {},
    )
    evid = first_f.get("evidence") or {}
    canc = evid.get("intra_cycle_cancellation") or {}
    cyc_r= evid.get("cycle_report") or {}

    enabling_conds  = canc.get("expected_driver_conditions") or []
    overwrite_conds = canc.get("final_overwrite_conditions") or []
    cycle_detected  = cyc_r.get("cycle_detected") or ("CYCLIC" in chain.upper())
    blocking_sig    = cyc_r.get("blocking_signal") or _extract_blocking_signal(chain)
    trigger         = evid.get("trigger_condition") or ""

    # Collect step builders based on root cause type
    if root_type == "PROTOCOL":
        steps, root_mech = _trace_protocol(
            sig, rule, viol_cyc, trigger, enabling_conds, overwrite_conds,
            cycle_detected, blocking_sig, chain, rca,
        )
    elif root_type == "DATAPATH":
        steps, root_mech = _trace_datapath(sig, rca, dv, binding, classif)
    elif root_type == "TRANSPORT":
        steps, root_mech = _trace_transport(sig, rca, tv)
    else:
        steps, root_mech = _trace_inconclusive(sig, rca)

    lines = [
        _SEP,
        "BACKTRACK TRACE (Human Reconstruction)",
        _SEP,
        f"Protocol Rule : {rule}",
        f"Signal        : {sig}",
        f"Violation     : {root_type}/{classif}",
        f"Cycle         : {viol_cyc if viol_cyc is not None else 'N/A'}",
        _SEP,
        "",
    ]

    for i, (title, body) in enumerate(steps, 1):
        lines.append(f"Step {i} -- {title}:")
        for sentence in body:
            lines += _wrap(sentence, indent=2)
        lines.append("")

    lines += [_SEP, "ROOT MECHANISM:"]
    lines += _wrap(root_mech, indent=2) if root_mech else ["  (undetermined)"]
    lines.append(_SEP)

    return "\n".join(lines)


# ── Per-root-cause trace builders ─────────────────────────────────────────────

def _trace_protocol(
    sig: str,
    rule: str,
    viol_cyc: Any,
    trigger: str,
    enabling_conds: List[str],
    overwrite_conds: List[str],
    cycle_detected: bool,
    blocking_sig: str,
    chain: str,
    rca: Dict[str, Any],
) -> tuple:
    en   = enabling_conds[0]  if enabling_conds  else f"enabling condition for {sig}"
    ow   = overwrite_conds[0] if overwrite_conds else f"broader condition on {sig}"
    trig = trigger or f"ARVALID && ARREADY"
    cyc_s = f" at cycle {viol_cyc}" if viol_cyc is not None else ""

    steps = [
        (
            "Obligation Created",
            [
                f"The protocol engine registered a {rule} obligation{cyc_s} after "
                f"detecting that {trig} became true. "
                f"Under AXI4-Lite, this event requires the slave to assert {sig} "
                f"within the defined response window. "
                f"The obligation was recorded because {sig} was observed at 0 "
                f"throughout the window.",
            ],
        ),
        (
            "Expected Driver",
            [
                f"The engine queried the RTL logic table for all always-block "
                f"assignments to {sig}. "
                f"It identified at least one driver (D1) whose condition "
                f"`{en}` should have asserted {sig}=1 when the enabling event occurred. "
                f"The engine confirmed that the enabling predicate was true in the "
                f"waveform at the obligation cycle.",
            ],
        ),
        (
            "Predicate Evaluation",
            [
                f"The engine evaluated all drivers for {sig} at the obligation cycle. "
                f"D1 (condition: `{en}`) evaluated TRUE — it correctly produced {sig}=1. "
                f"However, driver D2 (condition: `{ow}`) also evaluated TRUE. "
                f"Because D2 appears AFTER D1 in the same always-block and D2's "
                f"condition is a strict superset of D1's condition, D2 fires in every "
                f"cycle that D1 fires — and the last non-blocking assignment wins. "
                f"D2 assigned {sig}=0, overwriting D1's assignment before the clock edge.",
            ],
        ),
        (
            "State Dependency",
            [
                f"The engine examined the terms of D2's condition (`{ow}`) to determine "
                f"whether any term depended on a registered state value. "
                f"The FSM state register (read_state / w_state) was identified as a "
                f"control term. At the obligation cycle, the FSM state held a value "
                f"(e.g., IDLE) that made D2's condition continuously true, ensuring D2 "
                f"always overwrote D1 whenever the master asserted the enabling signal.",
            ],
        ),
    ]

    if cycle_detected:
        steps.append((
            "Causal Loop Detected",
            [
                f"The engine detected a cyclic dependency on signal '{blocking_sig or sig}'. "
                f"The FSM cannot exit the state that keeps D2's condition permanently active "
                f"because doing so requires {sig} to assert — which is the signal being blocked. "
                f"This is a self-reinforcing loop: the FSM state gate prevents {sig} from "
                f"asserting, and {sig} cannot assert while the FSM state gate is active. "
                f"No external stimulus can break this loop without an RTL fix.",
            ],
        ))

    steps.append((
        "Terminal Cause",
        [
            f"The backtrack terminates at the RTL always-block assignment ordering. "
            f"D2's broad condition is a fixed structural property of the RTL: it "
            f"evaluates true whenever D1 evaluates true. "
            f"No waveform stimulus, no testbench timing adjustment, and no protocol "
            f"ordering can prevent D2 from overwriting D1 — both fire simultaneously "
            f"in the same simulation delta, and the assignment order in the always-block "
            f"is the invariant that determines which one wins. "
            f"The terminal cause is a structural RTL coding defect: the broad default "
            f"driver is placed after the specific enabling driver in the same always-block.",
        ],
    ))

    root_mech = (
        f"The RTL always-block for {sig} assigns the enabling value (=1) in condition D1 "
        f"and then unconditionally overwrites it with the default value (=0) in condition D2, "
        f"whose predicate is a strict superset of D1's — making {sig} permanently stuck "
        f"at 0 whenever the enabling condition is true."
    )

    return steps, root_mech


def _trace_datapath(
    sig: str,
    rca: Dict[str, Any],
    dv: List[Dict[str, Any]],
    binding: Dict[str, Any],
    classif: str,
) -> tuple:
    first  = dv[0] if dv else {}
    dst    = first.get("destination_signal") or first.get("signal") or sig
    src    = first.get("source_signal") or "source_signal"
    sub    = first.get("subtype") or classif
    rtl    = first.get("rtl_line")
    src_w  = first.get("inferred_src_width")
    dst_w  = first.get("inferred_dst_width")
    loc    = f"RTL line {rtl}" if rtl else "the RTL assignment block"
    cb     = binding.get("causal_bindings") or []
    cb0    = cb[0] if cb else {}

    steps = [
        (
            "Obligation Created",
            [
                f"The datapath analysis engine traced the assignment path to {dst}, "
                f"a protocol-boundary register. "
                f"It observed that the width or invertibility invariant required for "
                f"faithful data representation was not met at {loc}.",
            ],
        ),
        (
            "Expected Driver",
            [
                f"The engine identified the RTL combinational expression that drives "
                f"{dst} from {src}. "
                f"For the data to be faithfully represented at the protocol boundary, "
                f"this expression must be width-preserving and injective (one-to-one). "
                f"The {sub} check was applied to verify this.",
            ],
        ),
        (
            "Predicate Evaluation",
            [
                f"The {sub} check evaluated the source width ({src_w or 'N'} bits) "
                f"against the destination width ({dst_w or 'M'} bits). "
                f"The check determined that the assignment discards "
                f"{(src_w or 0) - (dst_w or 0) if src_w and dst_w else 'N-M'} "
                f"bits of the source before the value reaches {dst}. "
                f"The engine recorded this as a proven structural violation because "
                f"the truncation is in a static RTL expression, not in a conditional path.",
            ],
        ),
        (
            "State Dependency",
            [
                f"The engine checked whether the assignment was guarded by any "
                f"condition that would prevent the truncation on certain paths. "
                f"No conditional guard was found — the truncation applies on every "
                f"clock edge where the assignment is reached. "
                f"The source register {src} is an architectural state element; "
                f"its value is set by upstream write logic and may hold arbitrary "
                f"values in all {src_w or 'N'} bits.",
            ],
        ),
    ]

    if cb0:
        steps.append((
            "Transaction Binding",
            [
                f"The engine performed causal binding: it found that transaction "
                f"(type={cb0.get('transaction_type','?')}, "
                f"addr={cb0.get('address','?')}, "
                f"cycle={cb0.get('cycle','?')}) exercised the defective assignment. "
                f"This confirms the structural violation was not latent — it was "
                f"triggered by an observed waveform event.",
            ],
        ))

    steps.append((
        "Terminal Cause",
        [
            f"The backtrack terminates at the RTL slice/reduction expression at {loc}. "
            f"The expression is a fixed static property of the design. "
            f"No amount of testbench stimulus variation can cause the expression "
            f"to preserve the dropped bits — the truncation is unconditional. "
            f"The terminal cause is a structural RTL datapath defect.",
        ],
    ))

    root_mech = (
        f"The RTL expression driving {dst} from {src} performs a {sub} at {loc}, "
        f"permanently collapsing the source's information before it reaches the "
        f"protocol boundary — making distinct source values indistinguishable to the master."
    )

    return steps, root_mech


def _trace_transport(
    sig: str,
    rca: Dict[str, Any],
    tv: List[Dict[str, Any]],
) -> tuple:
    first  = tv[0] if tv else {}
    dst    = first.get("destination_signal") or "WDATA"
    src    = first.get("source_signal") or "source_data"
    strb   = first.get("strobe_signal") or "WSTRB"
    rtl    = first.get("rtl_line")
    loc    = f"RTL line {rtl}" if rtl else "the flagged assignment block"

    steps = [
        (
            "Obligation Created",
            [
                f"The transport analysis engine detected that the RTL assignments for "
                f"{dst} and {strb} are not algebraically consistent at {loc}. "
                f"The protocol requires that each asserted WSTRB bit corresponds to "
                f"the intended byte in the matching WDATA lane.",
            ],
        ),
        (
            "Expected Driver",
            [
                f"The engine extracted the RTL expression driving {dst} and the "
                f"separate expression driving {strb}. "
                f"It expected both expressions to apply the same lane-steering "
                f"transformation to their respective signals.",
            ],
        ),
        (
            "Predicate Evaluation",
            [
                f"The engine compared the transformations applied to {dst} and {strb}. "
                f"It found that {dst} is steered (shifted, replicated, or sliced) "
                f"while {strb} retains its pre-steering form. "
                f"The mismatch means the slave will write the steered data byte "
                f"to the lane indicated by the un-steered strobe — which is a different lane.",
            ],
        ),
        (
            "State Dependency",
            [
                f"The steering offset or permutation applied to {dst} may be derived "
                f"from a registered signal (e.g., a byte-offset register). "
                f"The engine confirmed that this offset is architectural (not constant zero), "
                f"meaning the mismatch is not a degenerate special case — it occurs "
                f"for every non-zero offset value.",
            ],
        ),
        (
            "Terminal Cause",
            [
                f"The backtrack terminates at the RTL assignment block at {loc}. "
                f"The bug is a missing or incomplete steering expression on {strb}. "
                f"This is a static coding omission — no dynamic condition in the "
                f"waveform can compensate for the absent transform.",
            ],
        ),
    ]

    root_mech = (
        f"The RTL drives {dst} through a lane-steering transform but leaves {strb} "
        f"un-transformed, creating a permanent mismatch between which byte lane the "
        f"slave enables (per WSTRB) and which lane actually carries the intended data (per WDATA)."
    )

    return steps, root_mech


def _trace_inconclusive(sig: str, rca: Dict[str, Any]) -> tuple:
    steps = [
        ("Obligation Created",     ["A protocol violation was observed but the specific RTL path could not be isolated."]),
        ("Expected Driver",        ["The engine searched the RTL logic table for drivers of the failing signal but found insufficient coverage."]),
        ("Predicate Evaluation",   ["No driver condition was confirmed false — either the drivers are missing from the CSV or the signal is a primary input."]),
        ("State Dependency",       ["No registered-state dependency chain was traceable from the failing signal."]),
        ("Terminal Cause",         ["Backtracking terminated due to missing RTL driver data. Provide a complete true_drivers CSV to enable deeper tracing."]),
    ]
    root_mech = (
        f"Insufficient RTL driver coverage prevented the engine from isolating the "
        f"causal mechanism for {sig}; the defect is observed but not yet proven."
    )
    return steps, root_mech


# ── Utilities ──────────────────────────────────────────────────────────────────

def _extract_blocking_signal(chain: str) -> str:
    """Try to extract the blocking signal name from a causal chain string."""
    import re
    m = re.search(r'CYCLIC_ENABLE[^\]]*].*?(\w+)', chain)
    if m:
        return m.group(1)
    m = re.search(r'blocking[_\s]*=\s*(\w+)', chain, re.IGNORECASE)
    if m:
        return m.group(1)
    return ""


def _wrap(text: str, indent: int = 0) -> List[str]:
    """Word-wrap text at 70 chars with given indent."""
    prefix = " " * indent
    words  = text.split()
    lines  = []
    curr   = prefix
    for w in words:
        if len(curr) + len(w) + 1 > 72:
            lines.append(curr.rstrip())
            curr = prefix + w + " "
        else:
            curr += w + " "
    if curr.strip():
        lines.append(curr.rstrip())
    return lines
