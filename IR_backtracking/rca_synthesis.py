"""
rca_synthesis.py
================
Correlates and synthesises outputs from three diagnostic engines:
  1. run_waveeye_rca()       — structural/protocol RCA (rca_8.py)
  2. run_fsm_illegal_state_check() — FSM encoding/transition analysis
  3. run_inter_fsm_analysis()      — inter-channel FSM dependency gaps

Produces one unified, actionable verdict for verification engineers:
  • Which signal failed, on which cycle
  • The upstream RTL root cause (FSM, datapath, or protocol)
  • Exact fix recommendation (RTL file + construct)
  • Confidence rating

Usage (called from cli.py after all three analyses complete):
    from rca_synthesis import synthesise_rca
    verdict = synthesise_rca(rca_result, fsm_result, inter_fsm_result)
    print_synthesis_verdict(verdict)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# AXI rule → channel/signal mapping
# ---------------------------------------------------------------------------

# Map rule IDs to the primary AXI signal they govern
_RULE_SIGNAL_MAP: Dict[str, List[str]] = {
    'RULE_1':  ['AWVALID', 'AWREADY'],
    'RULE_2':  ['ARVALID', 'ARREADY'],
    'RULE_3':  ['WVALID',  'WREADY'],
    'RULE_4':  ['BVALID',  'BREADY'],
    'RULE_5':  ['RVALID',  'RREADY'],
    'RULE_6':  ['AWVALID', 'WVALID'],
    'RULE_7':  ['ARVALID', 'ARREADY'],
    'RULE_8':  ['ARVALID', 'ARADDR'],
    'RULE_9':  ['ARVALID', 'ARREADY'],
    'RULE_10': ['RVALID',  'RREADY'],
    'RULE_11': ['BVALID',  'BREADY'],
    'RULE_12': ['RVALID',  'RREADY'],
    'RULE_13': ['AWVALID', 'WVALID', 'BVALID'],
}

# FSM classification priority (higher = more actionable for engineer)
_FSM_CLASS_PRIORITY = {
    'PROTOCOL_ILLEGAL':     5,
    'ENCODING_ILLEGAL':     4,
    'EXECUTION_ORDER':      3,
    'UNREACHABLE_TRANSITION': 3,
    'RESET_VIOLATION':      2,
    'DEAD_STATE':           1,
}

# Cycle proximity window: FSM violation at cycle N is "upstream" of a
# protocol violation at cycle M if N <= M <= N + _CYCLE_WINDOW
_CYCLE_WINDOW = 60


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CausalLink:
    """One confirmed causal chain: FSM violation → protocol violation."""
    fsm_signal:       str
    fsm_cycle:        int
    fsm_class:        str           # ENCODING_ILLEGAL, PROTOCOL_ILLEGAL, etc.
    fsm_illegal_val:  str
    fsm_fix:          str
    protocol_rule:    str           # e.g. RULE_2
    protocol_cycles:  List[int]
    affected_signals: List[str]
    confidence:       str           # HIGH / MEDIUM / LOW


@dataclass
class SynthesisVerdict:
    """Unified, engineer-facing diagnosis."""
    # --- Primary failure ---
    primary_failure_rule:   str
    primary_failure_signal: str
    primary_failure_cycles: List[int]

    # --- Root cause ---
    root_cause_type:   str          # FSM_ILLEGAL / DATAPATH / PROTOCOL / INCONCLUSIVE
    root_cause_detail: str          # one-line human summary
    confidence:        str

    # --- Causal chain (ordered upstream→downstream) ---
    causal_links: List[CausalLink] = field(default_factory=list)

    # --- Fix recommendations ---
    fixes: List[str] = field(default_factory=list)

    # --- Supporting evidence ---
    rca_root_cause_type: str = ''   # from rca_8 (PROTOCOL / DATAPATH / etc.)
    rca_summary:         str = ''
    fsm_finding_count:   int = 0
    inter_fsm_matched:   int = 0
    unresolved_rules:    List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_protocol_violation_cycles(rca_result: Dict) -> Dict[str, List[int]]:
    """
    Returns {rule_id: [cycle, ...]} from rca_result['findings'].
    Falls back to parsing the appendix text if structured data is missing.
    """
    rule_cycles: Dict[str, List[int]] = {}
    findings = rca_result.get('findings') or []
    for f in findings:
        rule = f.get('rule_id') or f.get('rule') or f.get('violation_type') or ''
        cycle = f.get('cycle') or f.get('analysis_cycle')
        if rule and cycle is not None:
            try:
                rule_cycles.setdefault(rule, []).append(int(cycle))
            except (ValueError, TypeError):
                pass
    return rule_cycles


def _fsm_cycle(finding: Dict) -> Optional[int]:
    """Safely extract integer cycle from an FSM finding dict."""
    raw = finding.get('cycle')
    if raw is None or str(raw).upper() in ('N/A', 'NONE', ''):
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _pick_primary_failure(rule_cycles: Dict[str, List[int]]) -> Tuple[str, List[int]]:
    """
    Select the most prominent protocol rule violation.
    Priority: highest occurrence count, then lowest rule number.
    """
    if not rule_cycles:
        return ('UNKNOWN', [])
    best = max(rule_cycles.items(), key=lambda kv: (len(kv[1]), -int(kv[0].replace('RULE_', '') or 99)))
    return best


def _signals_for_rule(rule_id: str) -> List[str]:
    return _RULE_SIGNAL_MAP.get(rule_id, [])


def _correlate_fsm_to_violations(
    fsm_findings: List[Dict],
    rule_cycles:  Dict[str, List[int]],
) -> List[CausalLink]:
    """
    For each FSM finding (with a real cycle number), find protocol violations
    that occur within _CYCLE_WINDOW cycles after the FSM event.
    Returns confirmed causal links sorted by FSM priority then cycle.
    """
    links: List[CausalLink] = []

    for fsm_f in fsm_findings:
        fc = _fsm_cycle(fsm_f)
        if fc is None:
            continue
        fsm_cls  = fsm_f.get('classification', '')
        priority = _FSM_CLASS_PRIORITY.get(fsm_cls, 0)
        if priority == 0:
            continue   # RESET_VIOLATION at cycle 0 is pre-simulation noise

        # Find all protocol rules with violations in [fc, fc + WINDOW]
        downstream: Dict[str, List[int]] = {}
        for rule, cycles in rule_cycles.items():
            nearby = [c for c in cycles if fc <= c <= fc + _CYCLE_WINDOW]
            if nearby:
                downstream[rule] = sorted(nearby)

        if not downstream:
            continue

        # Build one CausalLink per downstream rule
        for rule, dcycles in downstream.items():
            confidence = 'HIGH' if priority >= 4 else 'MEDIUM'
            links.append(CausalLink(
                fsm_signal      = fsm_f.get('fsm_signal', '?'),
                fsm_cycle       = fc,
                fsm_class       = fsm_cls,
                fsm_illegal_val = str(fsm_f.get('illegal_value', '?')),
                fsm_fix         = fsm_f.get('fix_suggestion', ''),
                protocol_rule   = rule,
                protocol_cycles = dcycles,
                affected_signals= _signals_for_rule(rule),
                confidence      = confidence,
            ))

    # Deduplicate by (fsm_signal, protocol_rule), keep highest-priority entry
    seen: Dict[Tuple[str, str], CausalLink] = {}
    for lnk in links:
        key = (lnk.fsm_signal, lnk.protocol_rule)
        if key not in seen or _FSM_CLASS_PRIORITY.get(lnk.fsm_class, 0) > \
                              _FSM_CLASS_PRIORITY.get(seen[key].fsm_class, 0):
            seen[key] = lnk

    return sorted(seen.values(),
                  key=lambda l: (-_FSM_CLASS_PRIORITY.get(l.fsm_class, 0), l.fsm_cycle))


# ---------------------------------------------------------------------------
# Main synthesis function
# ---------------------------------------------------------------------------

def synthesise_rca(
    rca_result:       Optional[Dict],
    fsm_result:       Optional[Dict],
    inter_fsm_result: Optional[Dict],
) -> SynthesisVerdict:
    """
    Correlate all three analysis results into one SynthesisVerdict.

    Parameters
    ----------
    rca_result       : return value of run_waveeye_rca()
    fsm_result       : return value of run_fsm_illegal_state_check()
                       {'findings': List[Dict], 'count': int}
    inter_fsm_result : return value of run_inter_fsm_analysis()
                       {'all_issues', 'matched', 'rule_coverage', 'violations', 'success'}
    """
    # ── Unpack inputs safely ──────────────────────────────────────────────────
    rca_final      = (rca_result or {}).get('final_rca') or {}
    rca_findings   = (rca_result or {}).get('findings') or []
    fsm_findings   = (fsm_result or {}).get('findings') or []
    inter_matched  = (inter_fsm_result or {}).get('matched') or []
    inter_issues   = (inter_fsm_result or {}).get('all_issues') or []

    rca_root_type  = rca_final.get('root_cause_type', 'INCONCLUSIVE')
    rca_summary    = rca_final.get('summary', '') or rca_final.get('explanation', '')

    # ── Step 1: Build rule→cycles map from protocol findings ─────────────────
    rule_cycles = _extract_protocol_violation_cycles(rca_result or {})

    # ── Step 2: Pick the primary protocol failure ─────────────────────────────
    primary_rule, primary_cycles = _pick_primary_failure(rule_cycles)
    primary_signals = _signals_for_rule(primary_rule)
    primary_signal  = primary_signals[0] if primary_signals else primary_rule

    # ── Step 3: Correlate FSM illegal states → protocol violations ────────────
    causal_links = _correlate_fsm_to_violations(fsm_findings, rule_cycles)

    # ── Step 4: Determine root cause type and detail ──────────────────────────
    # Priority: confirmed FSM causal link > inter-FSM match > RCA datapath > protocol
    fixes: List[str] = []
    unresolved = [r for r in rule_cycles if r not in
                  {lnk.protocol_rule for lnk in causal_links}]

    if causal_links:
        top = causal_links[0]
        root_type   = 'FSM_ILLEGAL'
        root_detail = (
            f"{top.fsm_signal} escapes to illegal value {top.fsm_illegal_val} "
            f"at cycle {top.fsm_cycle} ({top.fsm_class}), causing "
            f"{top.protocol_rule} violations at cycles "
            f"{', '.join(str(c) for c in top.protocol_cycles)}"
        )
        confidence  = top.confidence
        for lnk in causal_links:
            if lnk.fsm_fix and lnk.fsm_fix not in fixes:
                fixes.append(f"[{lnk.fsm_signal} / {lnk.fsm_class}] {lnk.fsm_fix}")

    elif inter_matched:
        item   = inter_matched[0]
        issue  = item[0]
        rule   = item[1]
        count  = item[2]
        root_type   = 'INTER_FSM'
        root_detail = (
            f"Missing inter-FSM dependency on {issue.get('fsm','?')} "
            f"({issue.get('channel','?')} channel) — "
            f"{issue.get('result', {}).get('explanation', '')} "
            f"({count} occurrence(s) of {rule})"
        )
        confidence  = 'MEDIUM'
        expl = issue.get('result', {}).get('explanation', '')
        if expl:
            fixes.append(f"[Inter-FSM / {rule}] {expl}")

    elif rca_root_type in ('DATAPATH', 'TRANSPORT'):
        root_type   = rca_root_type
        root_detail = rca_summary or f"RTL datapath defect detected ({rca_root_type})"
        confidence  = rca_final.get('confidence', 'MEDIUM')
        ev = rca_final.get('primary_evidence') or []
        for e in ev[:2]:
            s = e.get('fix') or e.get('description') or ''
            if s and s not in fixes:
                fixes.append(f"[Datapath] {s}")

    elif rca_root_type == 'PROTOCOL':
        root_type   = 'PROTOCOL'
        root_detail = rca_summary or f"Pure protocol handshake violation — no upstream RTL defect found"
        confidence  = 'MEDIUM'
        if not fixes:
            fixes.append(
                f"Review {primary_signal} driver logic and ensure AXI handshake "
                f"persistence rules are met (signal must hold until READY is asserted)"
            )

    else:
        root_type   = 'INCONCLUSIVE'
        root_detail = 'No causal root cause identified across all analysis engines'
        confidence  = 'LOW'
        fixes.append('Run interactive analysis (commands: v, vp, vs) for manual inspection')

    # ── Step 5: Collect RESET_VIOLATION fixes separately ─────────────────────
    for fsm_f in fsm_findings:
        if fsm_f.get('classification') == 'RESET_VIOLATION':
            fix = fsm_f.get('fix_suggestion', '')
            sig = fsm_f.get('fsm_signal', '')
            entry = f"[{sig} / RESET] {fix}" if fix else ''
            if entry and entry not in fixes:
                fixes.append(entry)

    return SynthesisVerdict(
        primary_failure_rule    = primary_rule,
        primary_failure_signal  = primary_signal,
        primary_failure_cycles  = sorted(primary_cycles),
        root_cause_type         = root_type,
        root_cause_detail       = root_detail,
        confidence              = confidence,
        causal_links            = causal_links,
        fixes                   = fixes,
        rca_root_cause_type     = rca_root_type,
        rca_summary             = rca_summary,
        fsm_finding_count       = len(fsm_findings),
        inter_fsm_matched       = len(inter_matched),
        unresolved_rules        = sorted(unresolved),
    )


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

_SEP  = '=' * 72
_SEP2 = '-' * 72

_CONFIDENCE_TAG = {
    'HIGH':   '[HIGH]  ',
    'MEDIUM': '[MED]   ',
    'LOW':    '[LOW]   ',
}

_ROOT_EMOJI = {
    'FSM_ILLEGAL':  '[FSM]',
    'INTER_FSM':    '[FSM-DEP]',
    'DATAPATH':     '[RTL]',
    'TRANSPORT':    '[RTL]',
    'PROTOCOL':     '[PROTO]',
    'INCONCLUSIVE': '[?]',
}


def print_synthesis_verdict(v: SynthesisVerdict) -> None:
    """Print the unified synthesis verdict to stdout."""
    tag  = _ROOT_EMOJI.get(v.root_cause_type, '[?]')
    ctag = _CONFIDENCE_TAG.get(v.confidence, '[???]   ')

    print()
    print(_SEP)
    print('  UNIFIED ROOT CAUSE SYNTHESIS')
    print(_SEP)

    # --- Primary failure ---
    print(f"\n  Primary Failure  :  {v.primary_failure_rule}"
          + (f"  (signal: {v.primary_failure_signal})" if v.primary_failure_signal != v.primary_failure_rule else ''))
    if v.primary_failure_cycles:
        cyc_str = ', '.join(str(c) for c in v.primary_failure_cycles[:8])
        if len(v.primary_failure_cycles) > 8:
            cyc_str += f'  ... (+{len(v.primary_failure_cycles)-8} more)'
        print(f"  Violation cycles :  {cyc_str}")

    # --- Root cause ---
    print(f"\n  Root Cause {tag}")
    print(f"  {ctag}{v.root_cause_detail}")

    # --- Causal chain ---
    if v.causal_links:
        print(f"\n{_SEP2}")
        print('  CAUSAL CHAIN')
        print(_SEP2)
        for i, lnk in enumerate(v.causal_links, 1):
            state_str  = f"  -> illegal value {lnk.fsm_illegal_val}"
            dcyc_str   = ', '.join(str(c) for c in lnk.protocol_cycles[:6])
            print(f"\n  [{i}] {lnk.fsm_signal} at cycle {lnk.fsm_cycle}  [{lnk.fsm_class}]")
            print(f"       FSM escapes{state_str}")
            print(f"       Downstream violation: {lnk.protocol_rule}  "
                  f"(cycles {dcyc_str})")
            if lnk.affected_signals:
                print(f"       Affected AXI signals: {', '.join(lnk.affected_signals)}")

    # --- Fix recommendations ---
    if v.fixes:
        print(f"\n{_SEP2}")
        print('  FIX RECOMMENDATIONS')
        print(_SEP2)
        for i, fix in enumerate(v.fixes, 1):
            # Word-wrap at 68 chars
            words = fix.split()
            line, lines = '', []
            for w in words:
                if len(line) + len(w) + 1 > 68:
                    lines.append(line)
                    line = w
                else:
                    line = f'{line} {w}' if line else w
            if line:
                lines.append(line)
            print(f"\n  {i}. {lines[0]}")
            for ln in lines[1:]:
                print(f"     {ln}")

    # --- Unresolved violations ---
    if v.unresolved_rules:
        print(f"\n{_SEP2}")
        print('  UNRESOLVED VIOLATIONS  (no causal FSM link found)')
        print(_SEP2)
        for rule in v.unresolved_rules:
            print(f"  - {rule}  -> likely intra-FSM logic or testbench stimulus")
        print('    Use interactive analysis (commands: v, vp, vs) to investigate.')

    # --- Summary line ---
    print(f"\n{_SEP2}")
    print(f"  Evidence summary : "
          f"FSM findings={v.fsm_finding_count}  "
          f"inter-FSM matched={v.inter_fsm_matched}  "
          f"RCA engine={v.rca_root_cause_type}  "
          f"confidence={v.confidence}")
    print(_SEP)
    print()
