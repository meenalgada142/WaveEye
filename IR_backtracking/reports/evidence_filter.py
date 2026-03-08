"""
Evidence Filter — Presentation-Grade Output
=============================================
Filters the RCA payload to retain ONLY evidence that:
  - Directly supports the root cause
  - Helps an engineer reproduce the issue
  - Differentiates this from a plain protocol checker output

Removes:
  - Internal debug messages and engine state
  - Passed checks and satisfied obligations
  - Redundant rule confirmations (same rule, multiple cycles)
  - Raw waveform statistics

Target: ≥70% volume reduction while preserving proof integrity.

Usage:
    from reports.evidence_filter import filter_evidence
    text = filter_evidence(payload)
    filtered_payload = filter_payload(payload)   # returns dict for programmatic use
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set

_SEP  = "=" * 79
_DASH = "-" * 79

# Classifications that represent passed/satisfied checks — exclude these
_PASSED_CLASSES = {
    "SATISFIED",
    "COMPLIANT",
    "NO_VIOLATION",
    "PASS",
    "OK",
    "INCONCLUSIVE",   # keep root-level INCONCLUSIVE but drop it from findings
}

# Finding fields to strip from individual findings (internal engine state)
_FINDING_STRIP_FIELDS = {
    "raw_mechanism",
    "eval_locals",
    "build_locals_time",
    "graph_depth_reached",
    "search_iterations",
    "dg_node_count",
    "dg_edge_count",
    "raw_waveform_rows",
    "full_scan_rows",
    "obligation_index",
    "mechanism_score",
}

# Violation fields to strip
_VIOLATION_STRIP_FIELDS = {
    "raw_rhs",
    "raw_lhs",
    "parse_tokens",
    "regex_match",
    "scan_window",
    "debug_trace",
}


def filter_evidence(payload: Dict[str, Any]) -> str:
    """Return a filtered, presentation-ready evidence summary string."""

    filtered = filter_payload(payload)
    rca       = payload.get("final_rca") or {}
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    classif   = rca.get("classification") or "UNKNOWN"
    confidence= rca.get("confidence") or "LOW"

    pev: List[Dict[str, Any]] = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    sig   = pev0.get("signal") or "target signal"
    cyc   = pev0.get("analysis_cycle")

    # Volume reduction stats
    orig_findings = len(payload.get("findings") or [])
    filt_findings = len(filtered.get("findings") or [])
    orig_dv       = len(payload.get("datapath_violations") or [])
    filt_dv       = len(filtered.get("datapath_violations") or [])
    orig_tv       = len(payload.get("transport_violations") or [])
    filt_tv       = len(filtered.get("transport_violations") or [])

    total_orig = orig_findings + orig_dv + orig_tv
    total_filt = filt_findings + filt_dv + filt_tv
    pct = 0
    if total_orig > 0:
        pct = round(100 * (1 - total_filt / total_orig))

    hdr = [
        _SEP,
        "  FILTERED EVIDENCE — PRESENTATION GRADE",
        _SEP,
        f"  Root Cause     : {root_type}/{classif}  [{confidence}]",
        f"  Primary Signal : {sig}",
        f"  Cycle          : {cyc if cyc is not None else 'N/A'}",
        f"  Volume reduction: {total_orig} → {total_filt} items  ({pct}% removed)",
        _SEP,
        "",
    ]

    body: List[str] = []

    # ── Structural violations ──────────────────────────────────────────
    tv_f = filtered.get("transport_violations") or []
    dv_f = filtered.get("datapath_violations") or []
    if tv_f or dv_f:
        body.append("  STRUCTURAL VIOLATIONS (retained):")
        body.append("")
        for v in tv_f:
            body += _fmt_violation(v)
        for v in dv_f:
            body += _fmt_violation(v)

    # ── Protocol findings ──────────────────────────────────────────────
    fins_f = filtered.get("findings") or []
    if fins_f:
        body.append("  PROTOCOL FINDINGS (retained):")
        body.append("")
        for f in fins_f:
            body += _fmt_finding(f)

    # ── Root cause summary ────────────────────────────────────────────
    body.append("  ROOT CAUSE EVIDENCE:")
    body.append("")
    expl = (rca.get("explanation") or "").strip()
    if expl:
        for line in expl.split("\n")[:6]:   # keep first 6 lines
            body.append(f"    {line.strip()}")
        body.append("")

    # Causal chain excerpt
    chain = rca.get("causal_chain") or ""
    if chain:
        chain_lines = [l for l in chain.split("\n") if l.strip()][:8]
        body.append("  CAUSAL CHAIN (excerpt):")
        for cl in chain_lines:
            body.append(f"    {cl}")
        body.append("")

    # Causal bindings
    binding = filtered.get("binding_result") or {}
    cb = binding.get("causal_bindings") or []
    if cb:
        body.append(f"  CAUSAL BINDINGS ({len(cb)} transaction(s)):")
        for b in cb[:3]:
            tx_type = b.get("transaction_type") or "?"
            addr    = b.get("address") or "?"
            bcyc    = b.get("cycle") or "?"
            bsig    = b.get("assignment_signal") or "?"
            body.append(f"    [{tx_type}] addr={addr}  cycle={bcyc}  signal={bsig}")
        body.append("")

    # Removed items note
    removed = total_orig - total_filt
    body += [
        _DASH,
        f"  REMOVED: {removed} item(s) — passed checks, redundant confirmations, raw stats.",
        _SEP,
    ]

    return "\n".join(hdr + body)


def filter_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a filtered payload dict suitable for programmatic downstream use."""

    rca       = payload.get("final_rca") or {}
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"

    # Filter findings: remove PASSED and deduplicate by (rule_id, classification, signal)
    findings  = payload.get("findings") or []
    fins_f    = _filter_findings(findings, root_type)

    # Filter violations: remove debug fields, keep only causally relevant ones
    tv   = payload.get("transport_violations") or []
    dv   = payload.get("datapath_violations")  or []
    tv_f = _filter_violations(tv)
    dv_f = _filter_violations(dv)

    # Filter binding: keep causal bindings, drop raw latent detail
    binding   = payload.get("binding_result") or {}
    binding_f = _filter_binding(binding)

    return {
        "protocol":             payload.get("protocol"),
        "waveform_max_cycle":   payload.get("waveform_max_cycle"),
        "transport_violations": tv_f,
        "datapath_violations":  dv_f,
        "findings":             fins_f,
        "binding_result":       binding_f,
        "final_rca":            _filter_rca(rca),
        "transactions":         _summarise_transactions(payload.get("transactions") or []),
    }


# ── Internal filters ───────────────────────────────────────────────────────────

def _filter_findings(
    findings: List[Dict[str, Any]],
    root_type: str,
) -> List[Dict[str, Any]]:
    """Remove passed checks; deduplicate by (rule, classification, signal)."""
    seen: Set[tuple] = set()
    out: List[Dict[str, Any]] = []

    for f in findings:
        cls = f.get("classification") or ""
        if cls.upper() in _PASSED_CLASSES:
            continue
        verdict = (f.get("verdict") or "").upper()
        if verdict in ("SATISFIED", "COMPLIANT", "PASS"):
            continue

        key = (
            f.get("rule_id") or "",
            cls,
            f.get("signal") or f.get("rtl_sig") or "",
        )
        if key in seen:
            continue
        seen.add(key)

        # Strip internal fields
        clean = {k: v for k, v in f.items() if k not in _FINDING_STRIP_FIELDS}
        # Strip passed evidence sub-keys
        evid = clean.get("evidence") or {}
        evid = {k: v for k, v in evid.items() if k not in ("raw_waveform_slice", "scan_rows")}
        clean["evidence"] = evid
        out.append(clean)

    return out


def _filter_violations(violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove internal debug fields from each violation."""
    out = []
    for v in violations:
        clean = {k: vv for k, vv in v.items() if k not in _VIOLATION_STRIP_FIELDS}
        out.append(clean)
    return out


def _filter_binding(binding: Dict[str, Any]) -> Dict[str, Any]:
    """Keep causal bindings and summary; drop raw latent detail."""
    return {
        "causal_bindings": binding.get("causal_bindings") or [],
        "summary":         binding.get("summary") or {},
        # Latent violations kept as count only — not full list
        "latent_count":    len(binding.get("latent_violations") or []),
    }


def _filter_rca(rca: Dict[str, Any]) -> Dict[str, Any]:
    """Keep human-facing RCA fields; drop internal plumbing."""
    _keep = {
        "root_cause_type", "classification", "confidence", "explanation",
        "primary_evidence", "secondary_effects", "causal_chain",
        "rule_id", "analysis_cycle", "rtl_line", "signals_involved",
        "storage_element", "subtype",
    }
    return {k: v for k, v in rca.items() if k in _keep}


def _summarise_transactions(txns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return a compact summary of transactions (drop raw signal snapshots)."""
    _keep = {"type", "address", "accept_cycle", "cycle", "awaddr", "araddr", "id"}
    return [{k: v for k, v in t.items() if k in _keep} for t in txns]


# ── Formatters ─────────────────────────────────────────────────────────────────

def _fmt_violation(v: Dict[str, Any]) -> List[str]:
    cls   = v.get("class") or "UNKNOWN"
    sub   = v.get("subtype") or ""
    dst   = v.get("destination_signal") or v.get("signal") or ""
    src   = v.get("source_signal") or ""
    rtl   = v.get("rtl_line")
    loc   = f" @ line {rtl}" if rtl else ""
    label = f"{cls}/{sub}" if sub else cls
    sig_str = f"{dst} ← {src}" if src else dst
    return [f"    [{label}]{loc}  {sig_str}", ""]


def _fmt_finding(f: Dict[str, Any]) -> List[str]:
    rule  = f.get("rule_id") or "?"
    cls   = f.get("classification") or "?"
    sig   = f.get("signal") or f.get("rtl_sig") or "?"
    cyc   = f.get("analysis_cycle")
    cyc_s = f" @ cycle {cyc}" if cyc is not None else ""
    return [f"    [{rule}/{cls}]{cyc_s}  signal={sig}", ""]
