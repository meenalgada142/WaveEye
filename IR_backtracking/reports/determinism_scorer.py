"""
Determinism Risk Scorer
========================
Assigns a 0-10 determinism risk score to the analysis result.

Scoring criteria:
  0-3  = cosmetic or always-detectable failure
  4-6  = functional risk under stress or specific stimulus ordering
  7-8  = silent corruption possible; may escape automated checks
  9-10 = non-deterministic or synthesis-sensitive architectural failure

Justification covers:
  - Observability of the bug
  - Dependence on ordering (stimulus or simulation scheduling)
  - Whether behavior is synthesis-sensitive
  - Debug difficulty if the defect escapes to silicon

Usage:
    from reports.determinism_scorer import score_determinism_risk
    text = score_determinism_risk(payload)
"""

from __future__ import annotations
from typing import Any, Dict, List, Tuple

_SEP  = "=" * 79
_DASH = "-" * 79

# Risk category bands
_BANDS = [
    (0,  3,  "COSMETIC / DETECTABLE",
     "Failure produces an observable symptom (wrong data, protocol error response) "
     "that is readily captured by functional simulation or protocol checkers. "
     "No silent corruption; the defect announces itself."),
    (4,  6,  "FUNCTIONAL RISK — STIMULUS-DEPENDENT",
     "Failure occurs only under specific stimulus sequences (partial strobes, "
     "particular address patterns, or ordering of valid/ready assertion). "
     "Standard regression may miss it; targeted coverage or constrained-random "
     "is required."),
    (7,  8,  "SILENT CORRUPTION RISK",
     "Failure corrupts data without generating a protocol error response. "
     "BRESP / RRESP reports OKAY while the data at the protocol boundary is wrong. "
     "May pass all protocol-layer checks and escape to silicon undetected."),
    (9,  10, "NON-DETERMINISTIC ARCHITECTURAL FAILURE",
     "Failure depends on simulation-scheduling order, synthesis netlist decisions, "
     "or runtime state that is not reproducible across tools or environments. "
     "On silicon, behavior may differ from simulation; debug is extremely difficult."),
]


def score_determinism_risk(payload: Dict[str, Any]) -> str:
    """Return a determinism risk score report string."""

    rca       = payload.get("final_rca") or {}
    tv        = payload.get("transport_violations") or []
    dv        = payload.get("datapath_violations")  or []
    findings  = payload.get("findings")              or []
    binding   = payload.get("binding_result")        or {}

    root_type  = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif    = rca.get("classification")  or "UNKNOWN"
    confidence = rca.get("confidence")      or "LOW"
    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or "target signal"

    score, justification, factors = _compute_score(
        root_type, classif, confidence, tv, dv, findings, binding, rca, sig
    )

    category = _band_for_score(score)

    hdr = [
        _SEP,
        "  DETERMINISM RISK SCORE",
        _SEP,
        "",
        f"  Score           :  {score} / 10",
        f"  Risk Category   :  {category}",
        "",
        "  Justification:",
    ]

    just_lines = []
    for line in justification:
        # Word-wrap each justification sentence at 72 chars
        words = line.split()
        curr  = "    "
        for w in words:
            if len(curr) + len(w) + 1 > 76:
                just_lines.append(curr.rstrip())
                curr = "    " + w + " "
            else:
                curr += w + " "
        if curr.strip():
            just_lines.append(curr.rstrip())
        just_lines.append("")

    factor_lines = ["", "  Contributing Factors:", ""]
    for tag, detail in factors:
        factor_lines.append(f"    [{tag}]  {detail}")
    factor_lines.append("")

    band_desc = _band_description(score)
    footer = [
        _DASH,
        f"  Score Interpretation: {band_desc}",
        _SEP,
    ]

    return "\n".join(hdr + just_lines + factor_lines + footer)


# ── Score computation ──────────────────────────────────────────────────────────

def _compute_score(
    root_type: str,
    classif: str,
    confidence: str,
    tv: List[Dict[str, Any]],
    dv: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    binding: Dict[str, Any],
    rca: Dict[str, Any],
    sig: str,
) -> Tuple[int, List[str], List[Tuple[str, str]]]:
    """Return (score, [justification lines], [factors])."""

    score   = 0
    factors : List[Tuple[str, str]] = []

    # ── Base score from root cause type ──────────────────────────────────
    if root_type == "TRANSPORT":
        score += 6
        factors.append(("ROOT_TYPE", "TRANSPORT: byte-lane mismatch is structurally enforced by RTL."))
    elif root_type == "DATAPATH":
        if classif in ("STRUCTURAL_CAUSAL", "SEMANTIC_STRUCTURAL"):
            score += 7
            factors.append(("ROOT_TYPE", "DATAPATH/STRUCTURAL: non-bijective transform is deterministic but silently corrupts data."))
        else:
            score += 6
            factors.append(("ROOT_TYPE", "DATAPATH: data-path width or invertibility violation present."))
    elif root_type == "PROTOCOL":
        score += 5
        factors.append(("ROOT_TYPE", "PROTOCOL: handshake failure is observable via protocol-layer checking."))
    else:
        score += 2
        factors.append(("ROOT_TYPE", "INCONCLUSIVE: insufficient evidence to assess risk reliably."))

    # ── Confidence modifier ────────────────────────────────────────────
    if confidence == "HIGH":
        score += 1
        factors.append(("CONFIDENCE", "HIGH: structurally proven — defect is not stimulus-dependent."))
    elif confidence == "MEDIUM":
        factors.append(("CONFIDENCE", "MEDIUM: probable but requires specific stimulus to exercise."))
    elif confidence == "LOW":
        score -= 1
        factors.append(("CONFIDENCE", "LOW: evidence is weak; actual risk may be lower than base score."))

    # ── Synthesis sensitivity ──────────────────────────────────────────
    has_nbk = any(
        f.get("classification") == "SCHEDULING_CANCELLATION"
        for f in findings
    )
    if has_nbk:
        score += 2
        factors.append(("SYNTHESIS_RISK", "SCHEDULING_CANCELLATION: intra-delta overwrite is simulator-scheduling-dependent."))

    # ── Silent corruption modifier ─────────────────────────────────────
    subtypes_silent = {
        "WIDTH_TRUNCATION", "NON_INVERTIBLE_COLLAPSE",
        "NON_INVERTIBLE_DUPLICATION", "SYNTHETIC_DATA", "INFORMATION_LOSS",
    }
    silent = any((v.get("subtype") or "") in subtypes_silent for v in dv)
    if silent:
        score += 1
        factors.append(("OBSERVABILITY", "Silent data corruption: RDATA value is wrong but RRESP=OKAY masks it."))
    elif tv:
        factors.append(("OBSERVABILITY", "WSTRB mismatch produces wrong byte in storage; no explicit error response."))
    elif root_type == "PROTOCOL":
        factors.append(("OBSERVABILITY", "Handshake stall is observable as a timeout or bus hang."))

    # ── Debug difficulty on silicon ───────────────────────────────────
    causal = (binding.get("causal_bindings") or [])
    if causal:
        factors.append(("DEBUG", "Causal binding confirmed: the defect was exercised in an observed transaction — reproducible."))
    else:
        score += 1
        factors.append(("DEBUG", "No transaction binding: defect is latent — harder to reproduce on silicon without targeted stimulus."))

    # ── Cap at 10 ─────────────────────────────────────────────────────
    score = min(score, 10)
    score = max(score, 0)

    # ── Build justification lines (3 max) ─────────────────────────────
    just = _build_justification(root_type, classif, confidence, silent, has_nbk, causal, sig)

    return score, just, factors


def _build_justification(
    root_type: str,
    classif: str,
    confidence: str,
    silent: bool,
    has_nbk: bool,
    causal: list,
    sig: str,
) -> List[str]:
    lines = []

    # Line 1: observability
    if root_type == "TRANSPORT":
        lines.append(
            f"Observability: byte-lane writes to incorrect lanes; "
            f"readback reveals corruption only if the master reads back and checks. "
            f"BRESP=OKAY does not signal the defect."
        )
    elif root_type == "DATAPATH" and silent:
        lines.append(
            f"Observability: {sig} carries a collapsed or truncated value at the "
            f"protocol boundary; RRESP=OKAY while data is wrong — "
            f"the defect is invisible to protocol-layer monitors."
        )
    elif root_type == "PROTOCOL":
        lines.append(
            f"Observability: {sig} is stuck; a protocol checker will flag the "
            f"handshake timeout, making the symptom detectable but the root cause "
            f"(structural overwrite) is not shown by standard tools."
        )
    else:
        lines.append("Observability: insufficient evidence to assess independently.")

    # Line 2: ordering / synthesis sensitivity
    if has_nbk:
        lines.append(
            "Ordering dependence: intra-cycle write cancellation is simulator-scheduling-dependent; "
            "synthesis may produce different results than RTL simulation — "
            "behavior on gate-level netlist must be verified separately."
        )
    elif confidence == "HIGH" and root_type in ("TRANSPORT", "DATAPATH"):
        lines.append(
            "Ordering dependence: none — the defect is structurally present in the RTL "
            "and manifests on every transaction that exercises the flagged assignment, "
            "regardless of stimulus ordering."
        )
    else:
        lines.append(
            "Ordering dependence: specific valid/ready assertion ordering or partial "
            "strobe patterns are required; standard regression may not cover the "
            "triggering condition."
        )

    # Line 3: debug difficulty on silicon
    if causal:
        lines.append(
            "Silicon debug: defect was exercised in an observed waveform transaction "
            "(causal binding confirmed); reproducible under the same stimulus. "
            "RTL-level fix location is identified."
        )
    else:
        lines.append(
            "Silicon debug: no transaction binding; defect is latent — "
            "the exact stimulus sequence that triggers it on silicon is unknown, "
            "significantly increasing debug cost if it escapes."
        )

    return lines


# ── Helpers ────────────────────────────────────────────────────────────────────

def _band_for_score(score: int) -> str:
    for lo, hi, label, _ in _BANDS:
        if lo <= score <= hi:
            return label
    return "UNKNOWN"


def _band_description(score: int) -> str:
    for lo, hi, _, desc in _BANDS:
        if lo <= score <= hi:
            return desc
    return "Risk level could not be determined."
