#!/usr/bin/env python3
"""
rca_resolver.py
===============
Causation-binding RCA resolver.

Converts multi-engine outputs (protocol RCA + structural datapath analysis +
transport-path semantic analysis) into a single hierarchical causal conclusion
by tracing failing protocol signals through the driver table to find memory
dependencies, then matching those memories against structural violations.

Resolution rules are hierarchical (NOT additive):
  RULE 0 — Transport Dominance (highest priority)
    AXI transport-path misalignment (WSTRB/WDATA mismatch) detected in RTL:
      → TRANSPORT / TRANSPORT_ALIGNMENT / HIGH
  RULE 1 — Structural Dominance (causally bound)
    Failing signal traces to a memory with a structural violation → DATAPATH/HIGH
  RULE 2 — Structural Dominance (unbound)
    Structural violations exist but no causal path found → DATAPATH/MEDIUM
  RULE 3 — Protocol Primary
    No structural violations → protocol finding is root cause
  RULE 4 — Inconclusive
    No evidence from either engine → INCONCLUSIVE/LOW

This module is the ONLY place allowed to declare the final root cause.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from rca_core.causal_graph import (
    TransformNode,
    build_transform_nodes,
    find_nonbijective_paths,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_TRACE_DEPTH = 8

# Matches array-read patterns: identifier immediately before '['
_MEM_READ_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\[')
_IDENT_RE    = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')
_KW = frozenset({
    "and", "or", "not", "if", "else", "begin", "end",
    "true", "false", "posedge", "negedge", "reg", "wire",
    "input", "output", "inout", "assign",
})

# AXI signal pattern for detail-text extraction
_AXI_SIG_RE = re.compile(r'\b((?:s|m)_axil?_\w+)\b', re.IGNORECASE)

# rule_id → canonical AXI signal suffix hint
_RULE_SIGNAL_HINTS: Dict[str, str] = {
    "RULE_1":  "awvalid",
    "RULE_2":  "awready",
    "RULE_3":  "wvalid",
    "RULE_4":  "bvalid",
    "RULE_5":  "rvalid",    # RVALID persistence
    "RULE_6":  "bvalid",    # BVALID persistence
    "RULE_7":  "rvalid",
    "RULE_8":  "rready",
    "RULE_9":  "bresp",     # Write response stability
    "RULE_10": "rvalid",    # RVALID asserted without AR handshake
    "RULE_11": "bvalid",    # BVALID asserted before AW+W complete
    "RULE_12": "bvalid",    # Write response missing
    "RULE_13": "rvalid",    # Read response missing
    "RULE_14": "wstrb",
    "RULE_15": "bresp",
}

# Read-channel rule IDs (for causal chain description)
_READ_RULES = frozenset({"RULE_6", "RULE_7", "RULE_8", "RULE_9", "RULE_10", "RULE_12"})


# ---------------------------------------------------------------------------
# Signal name utilities
# ---------------------------------------------------------------------------

def _normalize_signal(name: str) -> str:
    """Strip module path prefix and bus indices, return lowercase leaf name."""
    name = re.sub(r'\[.*?\]', '', name)
    if '.' in name:
        return name.rsplit('.', 1)[-1].lower()
    return name.lower()


def _find_in_logic_table(
    signal: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
) -> Optional[str]:
    """
    Locate the actual logic_table key for *signal*, tolerating:
      - missing module prefix  (e.g. "rdata" → "s_axil_rdata_reg")
      - bus indices            (e.g. "s_axil_rdata[31:0]")
      - case differences
    Returns the matching key, or None.
    """
    if signal in logic_table:
        return signal
    norm = _normalize_signal(signal)
    if norm in logic_table:
        return norm
    for key in logic_table:
        kn = _normalize_signal(key)
        if kn == norm or kn.endswith(norm) or norm.endswith(kn):
            return key
    return None


# ---------------------------------------------------------------------------
# Memory read extraction
# ---------------------------------------------------------------------------

def _extract_memory_reads(text: str) -> Set[str]:
    """
    Return all identifiers that appear immediately before '[' in *text*.
    These represent array (memory) read/write accesses.
    """
    return set(_MEM_READ_RE.findall(text or ""))


# ---------------------------------------------------------------------------
# Signal → memory dependency tracing
# ---------------------------------------------------------------------------

def _trace_signal_to_memories(
    signal: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
    visited: Optional[Set[str]] = None,
    depth: int = 0,
) -> Tuple[Set[str], Dict[str, str]]:
    """
    Recursively walk the driver table from *signal* to find all memory reads.

    STEP 2 of resolve_root_cause:
      1. Identify the driver expression for *signal*.
      2. Determine whether it ultimately depends on a memory read (mem[index]).
      3. Record memory names involved.

    Returns:
        memories      -- set of memory names that *signal* ultimately reads from
        driver_exprs  -- {memory_name: rhs_expression_that_references_it}
    """
    if visited is None:
        visited = set()

    key = _find_in_logic_table(signal, logic_table)
    if key is None or key in visited or depth > _MAX_TRACE_DEPTH:
        return set(), {}

    visited.add(key)
    memories: Set[str] = set()
    driver_exprs: Dict[str, str] = {}

    for drv in (logic_table.get(key) or []):
        rhs  = str(drv.get("rhs",  "") or "")
        cond = str(drv.get("cond", "") or "")

        # ── Direct memory reads in RHS ──────────────────────────────────────
        for mem in _extract_memory_reads(rhs):
            if mem not in memories:
                memories.add(mem)
                driver_exprs[mem] = rhs

        # ── Recurse on intermediate signals in RHS ──────────────────────────
        for tok in _IDENT_RE.findall(rhs):
            if tok.lower() in _KW or tok in _extract_memory_reads(rhs):
                continue
            sub_key = _find_in_logic_table(tok, logic_table)
            if sub_key and sub_key not in visited:
                sub_mems, sub_exprs = _trace_signal_to_memories(
                    sub_key, logic_table, visited, depth + 1
                )
                for mem in sub_mems:
                    if mem not in memories:
                        memories.add(mem)
                        driver_exprs[mem] = sub_exprs.get(mem, rhs)

        # ── Recurse through guard/condition expressions ─────────────────────
        for tok in _IDENT_RE.findall(cond):
            if tok.lower() in _KW:
                continue
            sub_key = _find_in_logic_table(tok, logic_table)
            if sub_key and sub_key not in visited:
                sub_mems, sub_exprs = _trace_signal_to_memories(
                    sub_key, logic_table, visited, depth + 1
                )
                for mem in sub_mems:
                    if mem not in memories:
                        memories.add(mem)
                        driver_exprs[mem] = sub_exprs.get(mem, cond)

    return memories, driver_exprs


# ---------------------------------------------------------------------------
# Failing signal extraction from protocol findings
# ---------------------------------------------------------------------------

def _extract_failing_signal(finding: Dict[str, Any]) -> Optional[str]:
    """
    Extract the primary failing signal name from a protocol finding.

    STEP 1 of resolve_root_cause. Tries in order:
      1. Explicit 'failure_signal' / 'signal' / 'failing_signal' field
      2. AXI signal name pattern in 'detail' text
      3. rule_id → canonical AXI signal suffix hint (bare name)
    """
    for key in ("failure_signal", "signal", "failing_signal"):
        val = finding.get(key)
        if val and str(val).strip():
            return str(val).strip()

    detail = str(finding.get("detail", "") or "")
    m = _AXI_SIG_RE.search(detail)
    if m:
        return m.group(1)

    rule_id = str(finding.get("rule_id", "") or "").upper()
    suffix = _RULE_SIGNAL_HINTS.get(rule_id)
    if suffix:
        return suffix   # bare suffix; _find_in_logic_table handles prefix matching

    return None


# ---------------------------------------------------------------------------
# Causal chain string builder
# ---------------------------------------------------------------------------

def _build_causal_chain(
    rule_id: str,
    failing_signal: str,
    driver_expr: Optional[str],
    memory_name: str,
    dv_class: str,
) -> str:
    """Format the vertical-arrow causal chain as required by STEP 5."""
    channel = "read channel" if rule_id.upper() in _READ_RULES else "write channel"
    lines = [
        f"Protocol Rule: {rule_id} ({channel})",
        "    ↓",
        f"Failing Signal: {failing_signal}",
        "    ↓",
        f"Driver: {driver_expr or f'{memory_name}[addr]'}",
        "    ↓",
        f"Structural Defect: {dv_class} in {memory_name} write path",
        "    ↓",
        "ROOT CAUSE: DATAPATH_PRIMARY",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Final report printer
# ---------------------------------------------------------------------------

def _fmt_evidence_line(ev: Dict[str, Any], *, indent: str = "  ") -> None:
    """Print a single evidence item as two lines: header + brief detail."""
    if not isinstance(ev, dict):
        return
    if ev.get("class") == "TRANSPORT_ALIGNMENT_VIOLATION":
        subtype = ev.get("subtype") or "TRANSPORT_ALIGNMENT"
        bid     = ev.get("always_block_id")
        line    = ev.get("rtl_line")
        parts   = [f"{indent}[TRANSPORT]  subtype={subtype}"]
        if bid is not None:
            parts.append(f"block={bid}")
        if line is not None:
            parts.append(f"line={line}")
        print(" ".join(parts))
        pattern = ev.get("bug_pattern") or ""
        if pattern:
            print(f"{indent}  {str(pattern)[:120]}")
    else:
        # Datapath violation OR protocol finding
        cls  = (ev.get("class") or ev.get("classification")
                or ev.get("rule_id") or "UNKNOWN")
        rid  = ev.get("rule_id") or ""
        mem  = ev.get("memory") or ev.get("destination_signal") or ""
        bid  = ev.get("always_block_id")
        cyc  = ev.get("analysis_cycle")
        detail = " ".join(
            str(ev.get("impact") or ev.get("detail") or "").split()
        )

        parts = [f"{indent}[{cls}]"]
        if rid and rid != cls:
            parts.append(f"rule={rid}")
        if mem:
            parts.append(f"memory={mem}")
        if bid is not None:
            parts.append(f"block={bid}")
        if cyc is not None:
            parts.append(f"cycle={cyc}")
        print(" ".join(parts))
        if detail:
            print(f"{indent}  {detail[:120]}")


# ---------------------------------------------------------------------------
# RCA-7 style output helpers (exported for rca_8.py import)
# ---------------------------------------------------------------------------

_CONFIDENCE_MAP: Dict[str, str] = {
    "HIGH":   "DETERMINISTIC",
    "MEDIUM": "PROBABLE",
    "LOW":    "INCONCLUSIVE",
}


def derive_authority(final_rca: Dict[str, Any]) -> str:
    """Derive the analysis authority label from the resolver result."""
    if final_rca.get("transform_nodes"):
        return "GRAPH_TRAVERSAL"
    if final_rca.get("causal_bindings"):
        return "TRANSACTION_BINDING"
    if final_rca.get("causal_links"):
        return "PREDICATE_PROOF"
    cls = str(final_rca.get("classification", ""))
    if cls == "TEMPORAL_VIOLATION":
        return "TEMPORAL_RULE_ENGINE"
    if cls == "SATISFIED":
        return "CONTRACT_ENGINE"
    cc = final_rca.get("causal_chain")
    if cc and cc != "not_available":
        return "PREDICATE_PROOF"
    return "CONTRACT_ENGINE"


def derive_responsibility(final_rca: Dict[str, Any]) -> str:
    """Derive the responsibility label: RTL / COMPLIANT / UNKNOWN."""
    rct = str(final_rca.get("root_cause_type", "")).upper()
    cls = str(final_rca.get("classification", "")).upper()
    if rct in ("DATAPATH", "TRANSPORT"):
        return "RTL"
    if rct == "PROTOCOL":
        return "COMPLIANT" if cls == "SATISFIED" else "RTL"
    if rct == "INCONCLUSIVE":
        return "UNKNOWN"
    return "RTL"


def print_final_rca(final_rca: Dict[str, Any]) -> None:
    """
    Print the single unified RCA conclusion in rca-7 appendix style.

    Fields: CLASSIFICATION, AUTHORITY, CONFIDENCE, RESPONSIBILITY,
    ROOT_CAUSE, VERDICT, SIGNAL, RULE, ANALYSIS_CYCLE,
    STRUCTURAL PROOF, ADDITIONAL_PROVEN_FINDINGS.
    """
    sep  = "=" * 79
    dash = "-" * 79

    authority      = derive_authority(final_rca)
    responsibility = derive_responsibility(final_rca)
    confidence_raw = str(final_rca.get("confidence", "UNKNOWN"))
    confidence     = _CONFIDENCE_MAP.get(confidence_raw, confidence_raw)

    print("")
    print(sep)
    print("  FINAL ROOT CAUSE ANALYSIS")
    print(sep)
    print(f"CLASSIFICATION : {final_rca.get('classification', 'UNKNOWN')}")
    print(f"AUTHORITY      : {authority}")
    print(f"CONFIDENCE     : {confidence}")
    print(f"RESPONSIBILITY : {responsibility}")
    print("")

    explanation = final_rca.get("explanation", "")
    if explanation:
        print("ROOT_CAUSE:")
        for line in str(explanation).splitlines():
            print(f"  {line}")
        print("")

    # VERDICT / SIGNAL / RULE / ANALYSIS_CYCLE from the primary finding
    primary = final_rca.get("primary_evidence", []) or []
    if primary and isinstance(primary[0], dict):
        pev     = primary[0]
        verdict = pev.get("verdict") or "VIOLATED"
        signal  = (pev.get("signal") or pev.get("failure_signal")
                   or pev.get("destination_signal") or "not_available")
        rule_id = (pev.get("rule_id") or final_rca.get("rule_id")
                   or "not_available")
        cycle   = pev.get("analysis_cycle") or final_rca.get("analysis_cycle")
        print(f"VERDICT        : {verdict}")
        print(f"SIGNAL         : {signal}")
        print(f"RULE           : {rule_id}")
        if cycle is not None:
            print(f"ANALYSIS_CYCLE : {cycle}")
        print("")

    # Transport-specific signals
    sigs = final_rca.get("signals_involved")
    if sigs and final_rca.get("root_cause_type") == "TRANSPORT":
        print(f"SIGNALS INVOLVED: {', '.join(sigs)}")
        rtl_line = final_rca.get("rtl_line")
        if rtl_line:
            print(f"RTL LINE: {rtl_line}")
        print("")

    # STRUCTURAL PROOF (causal chain)
    chain = final_rca.get("causal_chain")
    if chain:
        print("STRUCTURAL PROOF:")
        for cl in str(chain).splitlines():
            print(f"  {cl}")
        print("")

    # OVERWRITE PROOF (MODE-A / MODE-B from predicate analysis)
    pred = final_rca.get("predicate_analysis")
    if isinstance(pred, dict):
        mode = pred.get("mode_analysis")
        if isinstance(mode, dict) and mode:
            print("OVERWRITE PROOF:")
            m = str(mode.get("mode") or "")
            st = str(mode.get("subtype") or "")
            if m and st:
                print(f"  Mode            : {m} ({st})")
            elif m:
                print(f"  Mode            : {m}")

            ad_idx = mode.get("asserting_driver_idx")
            ad_cond = mode.get("asserting_driver_cond")
            if ad_idx is not None or ad_cond:
                print(f"  Asserting driver: D{ad_idx}  if ({ad_cond or 'not_available'}) -> 1")

            wd_idx = mode.get("winning_driver_idx")
            wd_cond = mode.get("winning_driver_cond")
            wd_rhs = mode.get("winning_driver_rhs")
            if wd_idx is not None or wd_cond or wd_rhs is not None:
                print(
                    f"  Winning driver  : D{wd_idx}  if ({wd_cond or 'not_available'}) "
                    f"-> {wd_rhs if wd_rhs is not None else 'not_available'}"
                )

            ac_idx = mode.get("active_driver_idx")
            ac_cond = mode.get("active_driver_cond")
            ac_rhs = mode.get("active_driver_rhs")
            if ac_idx is not None or ac_cond or ac_rhs is not None:
                print(
                    f"  Active driver   : D{ac_idx}  if ({ac_cond or 'not_available'}) "
                    f"-> {ac_rhs if ac_rhs is not None else 'not_available'}"
                )

            bterm = mode.get("blocking_term")
            if bterm:
                print(f"  Blocking term   : {bterm}")

            print("")

    # ADDITIONAL_PROVEN_FINDINGS (secondary effects)
    secondary = [s for s in (final_rca.get("secondary_effects", []) or [])
                 if isinstance(s, dict)]
    if secondary:
        print(dash)
        print(f"  ADDITIONAL_PROVEN_FINDINGS ({len(secondary)} item(s))")
        print(dash)
        for sv in secondary:
            cls   = (sv.get("classification") or sv.get("class")
                     or sv.get("rule_id") or "UNKNOWN")
            rid   = sv.get("rule_id") or ""
            sverd = sv.get("verdict") or ""
            cyc   = sv.get("analysis_cycle")
            cnt   = sv.get("occurrence_count")
            hparts = [f"  [{cls}]"]
            if rid and rid != cls:
                hparts.append(f"rule={rid}")
            if sverd:
                hparts.append(f"verdict={sverd}")
            if cyc is not None:
                hparts.append(f"cycle={cyc}")
            if cnt and int(cnt) > 1:
                hparts.append(f"x{cnt}")
            print(" ".join(hparts))

            ev      = sv.get("evidence") if isinstance(sv.get("evidence"), dict) else {}
            exp_sig = ev.get("expected_signal") or ""
            trigger = ev.get("trigger_condition") or ""
            sparts  = []
            if exp_sig:
                sparts.append(f"Signal: {exp_sig}")
            if trigger:
                sparts.append(f"Trigger: {trigger[:60]}")
            if sparts:
                print("    " + " | ".join(sparts))

            cparts = [p for p in (sv.get("cause") or "",
                                  sv.get("semantic_type") or "",
                                  sv.get("responsibility") or "") if p]
            if cparts:
                print("    " + " / ".join(cparts))

            icc = ev.get("intra_cycle_cancellation") if ev else {}
            if isinstance(icc, dict) and icc.get("detected"):
                exp_sig_name = ev.get("expected_signal") or "signal"
                exp_val      = icc.get("expected_value", 1)
                fin_val      = icc.get("final_value",    0)
                set_conds    = icc.get("expected_driver_conditions") or []
                over_conds   = icc.get("final_overwrite_conditions") or []
                if set_conds:
                    print(f"    Sets {exp_sig_name}={exp_val} when: {set_conds[0]}")
                if over_conds:
                    print(f"    Overwrites {exp_sig_name}={fin_val} when: {over_conds[0]}")
            else:
                detail = " ".join(str(sv.get("detail") or "").split())
                if detail:
                    print(f"    {detail[:120]}")
            print("")

        print("  (Full evidence, dependency graphs and waveform traces in appendix)")
        print("")

    print(sep)


# ---------------------------------------------------------------------------
# Public resolver — the ONLY place that declares the final root cause
# ---------------------------------------------------------------------------

def resolve_root_cause(
    protocol_findings: List[Dict[str, Any]],
    datapath_violations: List[Dict[str, Any]],
    logic_table: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    transport_violations: Optional[List[Dict[str, Any]]] = None,
    semantic_violations: Optional[List[Dict[str, Any]]] = None,
    causal_bindings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Convert multi-engine outputs into a single causal conclusion.

    This is the ONLY place allowed to declare the final root cause.

    Resolution rules (hierarchical, NOT additive):

    RULE 0 — Transport Dominance (highest priority)
      AXI transport-path misalignment detected (WSTRB/WDATA mismatch in RTL).
      These are statically proven RTL bugs — no waveform evidence needed:
        → TRANSPORT / TRANSPORT_ALIGNMENT / HIGH

    RULE 1 — Structural Dominance (causally bound via logic_table)
      If any datapath violation is causally upstream of a failing protocol
      signal (signal depends on memory → memory has structural violation):
        → DATAPATH / STRUCTURAL_CAUSAL / HIGH

    RULE 1.5 — Structural Dominance (causally bound via transaction binding)
      The binding pass proved a violating RTL transform participated in an
      observed AXI transaction (no logic_table required):
        → DATAPATH / STRUCTURAL_CAUSAL / HIGH

    RULE 2 — Structural Dominance (unbound)
      Structural violations exist but no causal link from either approach:
        → DATAPATH / STRUCTURAL_UNBOUND / MEDIUM

    RULE 3 — Temporal Causality (pure protocol)
      No structural violations:
        → PROTOCOL / <classification> / HIGH

    RULE 4 — No Evidence
      Both engines found nothing:
        → INCONCLUSIVE / NO_EVIDENCE / LOW

    Args:
        protocol_findings:    findings list from the contract/protocol engine
        datapath_violations:  structural violations from memory_write_analysis
        logic_table:          driver table {signal -> [{rhs, cond, ...}]}
                              required for causal binding (RULE 1)
        transport_violations: AXI transport-path misalignment violations from
                              transport_semantic_analysis (highest priority)
        semantic_violations:  protocol-agnostic datapath semantic violations from
                              rca_core.semantic_datapath_analysis (RULE 0.5)
        causal_bindings:      binding pass results from transaction_binding
                              (RULE 1.5 — transaction-proven causal path)

    Returns:
        dict with keys: root_cause_type, classification, confidence,
                        explanation, primary_evidence, secondary_effects,
                        causal_chain (str | None), [causal_links]
    """

    # ── RULE 0: Transport Dominance — statically proven RTL transport bug ─────
    if transport_violations:
        tv       = transport_violations[0]
        subtype  = tv.get("subtype") or "TRANSPORT_ALIGNMENT"
        src      = tv.get("source_signal") or "not_available"
        dst      = tv.get("destination_signal") or "not_available"
        strobe   = tv.get("strobe_signal") or "not_available"
        shift    = tv.get("shift_expression") or "not_available"
        offset   = tv.get("affine_offset")
        rtl_line = tv.get("rtl_line")

        if subtype == "WSTRB_DATA_MISALIGNMENT":
            chain = (
                f"RTL line {rtl_line}: WDATA '{dst}' ← replication of '{src}'\n"
                "    ↓\n"
                f"WSTRB '{strobe}' steered by shift '{shift}'"
                + (f" (offset={offset})" if offset is not None else "") + "\n"
                "    ↓\n"
                "Byte-lane mismatch: strobe enables wrong lanes for replicated data\n"
                "    ↓\n"
                "ROOT CAUSE: TRANSPORT_PRIMARY"
            )
        elif subtype == "MISSING_STROBE_TRANSFORM":
            chain = (
                f"RTL line {rtl_line}: WDATA '{dst}' ← replication of '{src}'\n"
                "    ↓\n"
                "No WSTRB steering found in same always block\n"
                "    ↓\n"
                "All byte lanes receive identical strobe → incorrect lane masking\n"
                "    ↓\n"
                "ROOT CAUSE: TRANSPORT_PRIMARY"
            )
        else:
            chain = (
                f"RTL transport-path defect detected (subtype={subtype})\n"
                "    ↓\n"
                "ROOT CAUSE: TRANSPORT_PRIMARY"
            )

        return {
            "root_cause_type":   "TRANSPORT",
            "classification":    "TRANSPORT_ALIGNMENT",
            "confidence":        "HIGH",
            "explanation":       tv.get("explanation") or tv.get("bug_pattern") or "Transport-path semantic mismatch detected in RTL.",
            "primary_evidence":  transport_violations,
            "secondary_effects": protocol_findings + datapath_violations,
            "causal_chain":      chain,
            "rtl_line":          rtl_line,
            "signals_involved":  tv.get("signals_involved", [dst, strobe, src]),
        }

    # ── RULE 0.5: Semantic Dominance — statically proven math violations ──────
    # Fires ONLY for confirmed STRUCTURAL_FATAL violations (lane bijection,
    # mask conservation, invertibility) when no transport violation dominates.
    # Non-fatal semantic violations (e.g. WIDTH_EXTENSION, WIDTH_TRUNCATION
    # without causal binding) are co-existing defects, NOT the root cause of
    # observed protocol failures — they must fall through to RULE 1/2/3 so
    # the real protocol mechanism (e.g. SCHEDULING_CANCELLATION) is surfaced.
    if semantic_violations:
        fatal = [v for v in semantic_violations
                 if v.get("severity") == "STRUCTURAL_FATAL"
                 and v.get("confidence") in ("HIGH", "MEDIUM")]
        if fatal:
            sv      = fatal[0]
            subtype = sv.get("subtype") or "SEMANTIC_DEFECT"
            storage = sv.get("storage_element") or "not_available"
            rtl_loc = sv.get("source_location") or str(sv.get("rtl_line") or "not_available")
            chain = (
                f"RTL {rtl_loc}: '{sv.get('destination') or 'not_available'}'"
                f" ← {sv.get('source_expression') or 'not_available'}\n"
                "    ↓\n"
                f"Violated invariant: {sv.get('violated_invariant', subtype)}\n"
                "    ↓\n"
                f"Storage element '{storage}' receives mathematically incorrect data\n"
                "    ↓\n"
                "ROOT CAUSE: DATAPATH_STRUCTURAL"
            )
            return {
                "root_cause_type":   "DATAPATH",
                "classification":    "SEMANTIC_STRUCTURAL",
                "confidence":        sv.get("confidence", "MEDIUM"),
                "explanation":       sv.get("mathematical_reason", sv.get("violated_invariant", "")),
                "primary_evidence":  fatal,
                "secondary_effects": protocol_findings + datapath_violations,
                "causal_chain":      chain,
                "storage_element":   storage,
                "subtype":           subtype,
            }
        # non-fatal semantic violations — fall through to RULE 1/2/3

    # ── RULE 4: No evidence from either engine ───────────────────────────────
    if not protocol_findings and not datapath_violations:
        return {
            "root_cause_type": "INCONCLUSIVE",
            "classification":  "NO_EVIDENCE",
            "confidence":      "LOW",
            "explanation":     "No protocol violations or structural defects detected.",
            "primary_evidence":  [],
            "secondary_effects": [],
            "causal_chain":    None,
        }

    # ── Binding-pass veto ────────────────────────────────────────────────────
    # When the transaction binding pass ran (causal_bindings is not None) AND
    # found zero causal connections despite protocol failures being present,
    # that is authoritative evidence that the structural violations are NOT
    # causally upstream of the observed protocol failures.
    # RULE 1 and RULE 2 heuristics (logic_table traversal + graph BFS) are
    # less precise; they find ANY logic path, not just paths that carry causal
    # responsibility for the observed violation.  The binding pass overrides them.
    _binding_veto = (
        causal_bindings is not None
        and len(causal_bindings) == 0
        and bool(protocol_findings)
    )

    # ── RULE 1: Structural Dominance with signal→memory causal binding ───────
    if datapath_violations and logic_table and not _binding_veto:

        # STEP 1: collect failing signals from all protocol findings
        failing_signal_map: Dict[str, Dict[str, Any]] = {}
        for f in protocol_findings:
            sig = _extract_failing_signal(f)
            if sig and sig not in failing_signal_map:
                failing_signal_map[sig] = f

        # STEP 2: trace each failing signal to storage sources
        implicated_memories: Dict[str, str] = {}   # mem_name → failing_signal
        memory_driver_exprs: Dict[str, str] = {}   # mem_name → driver rhs

        for sig in list(failing_signal_map.keys()):
            mems, exprs = _trace_signal_to_memories(sig, logic_table)
            for mem in mems:
                if mem not in implicated_memories:
                    implicated_memories[mem] = sig
                    memory_driver_exprs[mem] = exprs.get(mem, "")

        # STEP 3: match against structural violations
        relevant_structural: List[Dict[str, Any]] = []
        causal_links:        List[Dict[str, Any]] = []

        for dv in datapath_violations:
            dv_mem = dv.get("memory")
            if dv_mem and dv_mem in implicated_memories:
                relevant_structural.append(dv)
                failing_sig = implicated_memories[dv_mem]
                causal_links.append({
                    "datapath_violation": dv,
                    "failing_signal":     failing_sig,
                    "memory":             dv_mem,
                    "driver_expr":        memory_driver_exprs.get(dv_mem, ""),
                    "protocol_finding":   failing_signal_map.get(failing_sig, {}),
                })

        # STEP 4: arbitration
        if relevant_structural:
            link    = causal_links[0]
            dv      = link["datapath_violation"]
            finding = link["protocol_finding"]
            chain   = _build_causal_chain(
                rule_id        = str(finding.get("rule_id", "UNKNOWN")),
                failing_signal = link["failing_signal"],
                driver_expr    = link["driver_expr"] or None,
                memory_name    = link["memory"],
                dv_class       = str(dv.get("class", "STRUCTURAL_BUG")),
            )
            return {
                "root_cause_type": "DATAPATH",
                "classification":  "STRUCTURAL_CAUSAL",
                "confidence":      "HIGH",
                "explanation": (
                    f"Failing signal '{link['failing_signal']}' depends on memory "
                    f"'{link['memory']}' which has a verified structural defect "
                    f"({dv.get('class', 'UNKNOWN')}). "
                    "Protocol behavior is derived from structurally invalid data."
                ),
                "primary_evidence":  relevant_structural,
                "secondary_effects": protocol_findings,
                "causal_links":      causal_links,
                "causal_chain":      chain,
            }

    # ── RULE 1.5: Binding pass confirmed causal path via transaction evidence ─
    # Fires when: datapath violations exist AND the binding pass proved that
    # at least one violation's RTL transform participated in an observed
    # transaction (no logic_table traversal required).
    if datapath_violations and causal_bindings:
        # Collect the de-duplicated set of exercised violations
        seen_idx: set = set()
        exercised: List[Dict[str, Any]] = []
        for cb in causal_bindings:
            idx = cb.get("violation_index")
            if idx is not None and idx not in seen_idx:
                seen_idx.add(idx)
                exercised.append(cb.get("violation") or datapath_violations[0])

        # Build causal chain from the first confirmed binding
        cb0     = causal_bindings[0]
        txn_id  = cb0.get("transaction_id", "unknown")
        t_type  = cb0.get("transaction_type", "unknown")
        addr    = cb0.get("address")
        asn_sig = cb0.get("assignment_signal") or "data_bus"
        viol    = cb0.get("violation") or {}
        v_cls   = viol.get("class") or viol.get("subtype") or "STRUCTURAL_BUG"
        cycle   = cb0.get("cycle", "?")
        chain   = (
            f"Transaction: {txn_id} ({t_type})"
            + (f" addr=0x{addr:X}" if isinstance(addr, int) else "") + "\n"
            "    ↓\n"
            f"RTL assignment: {asn_sig} (cycle {cycle})\n"
            "    ↓\n"
            f"Structural defect: {v_cls}\n"
            "    ↓\n"
            "ROOT CAUSE: DATAPATH_CAUSAL (transaction-proven)"
        )
        return {
            "root_cause_type": "DATAPATH",
            "classification":  "STRUCTURAL_CAUSAL",
            "confidence":      "HIGH",
            "explanation": (
                f"Binding pass confirmed: {len(seen_idx)} violation(s) exercised "
                f"during observed AXI transactions. "
                f"Violation type: {v_cls}."
            ),
            "primary_evidence":  exercised,
            "secondary_effects": protocol_findings,
            "causal_chain":      chain,
            "causal_bindings":   causal_bindings,
        }

    # ── RULE 2: NON_BIJECTIVE_TRANSFORM graph traversal ──────────────────────
    # Build TransformNodes from every WIDTH_CONSERVATION / INVERTIBILITY
    # violation and BFS backward from each failing protocol signal through the
    # logic_table driver graph.  If any TransformNode's lhs is reachable from
    # a failing signal the violation is proven causal → STRUCTURAL_CAUSAL/HIGH.
    # If no path exists the violations are latent (not causally upstream of the
    # observed failure) so we fall through to RULE 3 and treat the failure as
    # protocol-primary.  STRUCTURAL_UNBOUND is no longer emitted.
    # Binding-pass veto also applies: if binding ran and found nothing, skip.
    if datapath_violations and not _binding_veto:
        transform_nodes = build_transform_nodes(datapath_violations)

        if transform_nodes and logic_table:
            # Collect failing signals from protocol findings
            failing_sigs: Set[str] = set()
            for pf in protocol_findings:
                sig = _extract_failing_signal(pf)
                if sig:
                    failing_sigs.add(sig)

            crossed = find_nonbijective_paths(
                logic_table, failing_sigs, transform_nodes
            )

            if crossed:
                tn0   = crossed[0]
                v_cls = tn0.violation.get("subtype") or tn0.violation.get("class") or "STRUCTURAL_BUG"
                src_loc = tn0.source_location or (
                    f"RTL line {tn0.rtl_line}" if tn0.rtl_line else "unknown"
                )
                chain = (
                    f"Failing protocol signal(s): {', '.join(sorted(failing_sigs))}\n"
                    "    |  (logic_table BFS)\n"
                    f"    v\n"
                    f"NON_BIJECTIVE_TRANSFORM at '{tn0.lhs}' ({src_loc})\n"
                    f"  property  = {tn0.property}\n"
                    f"  lhs       = {tn0.lhs}\n"
                    f"  rhs       = {tn0.rhs}\n"
                    f"  bijective = {tn0.bijective} | "
                    f"entropy_preserved = {tn0.entropy_preserved} | "
                    f"reversible = {tn0.reversible}\n"
                    "    |\n"
                    "    v\n"
                    f"Structural defect: {v_cls}\n"
                    "    |\n"
                    "    v\n"
                    "ROOT CAUSE: DATAPATH_CAUSAL (graph-proven via NON_BIJECTIVE_TRANSFORM)"
                )
                return {
                    "root_cause_type": "DATAPATH",
                    "classification":  "STRUCTURAL_CAUSAL",
                    "confidence":      "HIGH",
                    "explanation": (
                        f"Causal graph traversal found {len(crossed)} "
                        f"NON_BIJECTIVE_TRANSFORM node(s) causally upstream of "
                        f"failing protocol signal(s). "
                        f"First: {tn0.property} violation at '{tn0.lhs}' ({src_loc})."
                    ),
                    "primary_evidence":  [tn.violation for tn in crossed],
                    "secondary_effects": protocol_findings,
                    "causal_chain":      chain,
                    "transform_nodes":   [tn.to_graph_node() for tn in crossed],
                }
            # No causal path found — violations are latent; fall to RULE 3.

    # ── RULE 3: Pure protocol path ────────────────────────────────────────────
    _priority = {
        "SCHEDULING_CANCELLATION":    0,
        "DESIGN_STRUCTURAL_BLOCKAGE": 1,
        "INCONCLUSIVE":               2,
    }
    non_sat = [
        f for f in protocol_findings
        if str(f.get("verdict", "")) != "SATISFIABLE"
    ]

    if not non_sat:
        return {
            "root_cause_type": "PROTOCOL",
            "classification":  "SATISFIED",
            "confidence":      "HIGH",
            "explanation":     "All AXI4-Lite protocol contracts were satisfiable.",
            "primary_evidence":  protocol_findings,
            "secondary_effects": [],
            "causal_chain":      None,
        }

    root = sorted(
        non_sat,
        key=lambda f: (
            int(f.get("analysis_cycle", 10**9)),
            _priority.get(str(f.get("classification", "")), 9),
        ),
    )[0]

    return {
        "root_cause_type": "PROTOCOL",
        "classification":  str(root.get("classification", "UNKNOWN")),
        "confidence":      "HIGH",
        "explanation":     str(root.get("detail", "Protocol rule violation detected.")),
        "primary_evidence":  [root],
        "secondary_effects": [f for f in non_sat if f is not root],
        "rule_id":         root.get("rule_id"),
        "analysis_cycle":  root.get("analysis_cycle"),
        "causal_chain":    None,
    }
