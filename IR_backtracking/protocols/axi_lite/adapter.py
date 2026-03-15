from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from rca_core.contracts import CausalContract, CausalResult, ContractStatus, TemporalWindow
from rca_core.io import WaveformView

from protocols.base import ProtocolAdapter

from .rules import AXI_LITE_RULES, ObligationRule
from .signal_map import (
    AXI_LITE_SIGNAL_ALIASES,
    resolve_signal,
    RULE_SIGNAL_MAP,
    RULE_ACCEPT_CHANNEL,
    RULE_STABILITY_SIGNAL_MAP,
    STABILITY_RULES,
)

try:
    from amba_axi_lite_rules import AXI_LITE_RULE_DB
except Exception:
    AXI_LITE_RULE_DB = {}


_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_RESERVED = {"and", "or", "not", "true", "false"}
_RULE_PRIMARY_SIGNAL = {
    "RULE_12": "RVALID",
    "RULE_13": "BVALID",
    "RULE_5": "BVALID",
    "RULE_6": "BVALID",
    "RULE_7": "ARREADY",
    "RULE_8": "ARREADY",
    "RULE_9": "AWREADY",
    "RULE_10": "RVALID",
    "RULE_11": "BVALID",
    "RULE_14": "AWREADY",
}

_READY_TO_VALID_BASE = {
    "AWREADY": "AWVALID",
    "WREADY": "WVALID",
    "ARREADY": "ARVALID",
    "RREADY": "RVALID",
    "BREADY": "BVALID",
}
_DEP_PREFIXES = ("s_axi_", "m_axi_", "s_axil_", "m_axil_", "axi_", "axil_")

_SEMANTIC_HANDSHAKE_ROOT_CAUSE_TYPE = "HANDSHAKE_SEMANTIC_VIOLATION"
_SEMANTIC_HANDSHAKE_EXPLANATION = (
    "READY is generated from previously observed VALID activity instead of the "
    "current ability to accept a transfer. This converts the AXI level-sensitive "
    "handshake into an edge/history-driven protocol and can cause missed or "
    "non-deterministic transactions."
)
_SEMANTIC_HANDSHAKE_INTENT_MISMATCH = (
    "READY used as state flag rather than acceptance qualifier."
)


def _first_signal(expr: str) -> str:
    for t in _IDENT_RE.findall(str(expr or "")):
        if t.lower() not in _RESERVED:
            return t
    return ""


def _amba_ref(rule_id: str) -> Dict[str, str]:
    rid = str(rule_id or "").strip()
    ref = AXI_LITE_RULE_DB.get(rid, {}) if isinstance(AXI_LITE_RULE_DB, dict) else {}
    return {
        "standard": str(ref.get("amba_spec", "AMBA AXI4-Lite Specification") or "AMBA AXI4-Lite Specification"),
        "section": str(ref.get("section", "Unmapped (adapter rule)") or "Unmapped (adapter rule)"),
        "requirement": str(ref.get("requirement", "No adapter AMBA mapping configured.") or "No adapter AMBA mapping configured."),
    }


def _pick_root(findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    non_sat = [f for f in findings if str(f.get("verdict", "SATISFIABLE")) != "SATISFIABLE"]
    if not non_sat:
        return None
    priority = {
        "DESIGN_STRUCTURAL_BLOCKAGE": 0,
        "SCHEDULING_CANCELLATION": 1,
        "INCONCLUSIVE": 2,
    }
    return sorted(
        non_sat,
        key=lambda f: (
            priority.get(str(f.get("classification", "")), 9),
            int(f.get("analysis_cycle", 10**9)),
        ),
    )[0]


def _render_full_trace(root: Dict[str, Any], signal: str) -> List[str]:
    lines: List[str] = []
    ev = root.get("evidence", {}) if isinstance(root.get("evidence", {}), dict) else {}
    cls = str(root.get("classification", "")).strip()
    ver = str(root.get("verdict", "")).strip()

    cancel = ev.get("intra_cycle_cancellation", {}) if isinstance(ev, dict) else {}
    if cls == "SCHEDULING_CANCELLATION" and isinstance(cancel, dict) and cancel.get("detected"):
        anchor = cancel.get("anchor_cycle")
        analysis = cancel.get("analysis_cycle")
        expected_v = cancel.get("expected_value")
        final_v = cancel.get("final_value")
        conflict = cancel.get("conflict_values", [])
        expc = cancel.get("expected_driver_conditions", [])
        finc = cancel.get("final_overwrite_conditions", [])
        ready = cancel.get("ready_signals_high_next_cycle", [])
        active = list(cancel.get("active_drivers", []) or [])

        lines.append("ROOT LEAF: " + str(signal))
        lines.append("ROOT CAUSE: Scheduling cancellation detected.")
        lines.append("Signal transition was logically enabled but cancelled by conflicting assignments.")
        lines.append(f"Cancellation detail: expected={expected_v} final={final_v} conflict={conflict}")
        lines.append(f"Expected-driver conditions: {expc}")
        lines.append(f"Final overwrite conditions: {finc}")
        lines.append(f"READY high at next cycle: {ready}")
        lines.append(f"Cancellation timing: lookahead next cycle={analysis} (anchor={anchor})")
        lines.append(f"Classification: {cls}")
        lines.append(f"Verdict: {ver}")
        if active:
            lines.append("Active drivers:")
            for d in active[:8]:
                lines.append(
                    f"  - D{d.get('driver_idx')}: if ({d.get('condition')}) -> {d.get('rhs')} "
                    f"(rhs_val={d.get('rhs_value')}, eval_cycle={d.get('eval_cycle')})"
                )
        return lines

    cyc = ev.get("cycle_report", {}) if isinstance(ev, dict) else {}
    if cls == "DESIGN_STRUCTURAL_BLOCKAGE" and ver == "CYCLIC_ENABLE_DEPENDENCY" and isinstance(cyc, dict):
        path = list(cyc.get("cycle_path", []) or [])
        dg = ev.get("dependency_graph", {}) if isinstance(ev.get("dependency_graph", {}), dict) else {}
        en = ev.get("enable_condition", {}) if isinstance(ev.get("enable_condition", {}), dict) else {}
        lines.append(f"ROOT LEAF: {signal}")
        lines.append("ROOT CAUSE: Cyclic enable dependency detected.")
        lines.append(str(cyc.get("explanation", "Enable condition forms a causal cycle.")))
        if path:
            lines.append(f"Cycle path: {' -> '.join([str(p) for p in path])}")
        if en:
            lines.append(
                f"Enable condition probe: {en.get('expr', '')} @ analysis={en.get('value_at_analysis_cycle', 'N/A')}"
            )
        if dg:
            lines.append(
                f"Dependency graph: depth={dg.get('depth_reached', 'N/A')}, "
                f"nodes={len(dg.get('nodes', []) or [])}, edges={len(dg.get('edges', []) or [])}"
            )
        lines.append(f"Classification: {cls}")
        lines.append(f"Verdict: {ver}")
        return lines

    lines.append(f"ROOT LEAF: {signal}")
    lines.append(f"ROOT CAUSE: {root.get('detail', 'No detail available.')}")
    lines.append(f"Classification: {cls or 'UNKNOWN'}")
    lines.append(f"Verdict: {ver or 'UNDETERMINED'}")
    return lines


def _idents(expr: str) -> Set[str]:
    return {t for t in _IDENT_RE.findall(expr or "") if t.lower() not in _RESERVED}


def _find_logic_key_ci(sig: str, logic_table: Dict[str, List[Dict[str, Any]]]) -> Optional[str]:
    if not isinstance(logic_table, dict):
        return None
    s = str(sig or "").strip()
    if not s:
        return None
    if s in logic_table:
        return s
    sl = s.lower()
    for k in logic_table.keys():
        if str(k).lower() == sl:
            return str(k)
    # Fallback for canonical protocol names (e.g., ARREADY -> s_axi_arready).
    cands = [sl] + [p + sl for p in _DEP_PREFIXES]
    for cand in cands:
        for k in logic_table.keys():
            if str(k).lower() == cand:
                return str(k)
    for cand in cands:
        for k in logic_table.keys():
            kl = str(k).lower()
            if kl.endswith(cand):
                return str(k)
    return None


def _dep_present_in_text(dep: str, text: str) -> bool:
    for d in _dep_variants(dep):
        if re.search(r"\b" + re.escape(d.lower()) + r"\b", str(text or "").lower()) is not None:
            return True
    return False


def _dep_variants(dep: str) -> List[str]:
    d = str(dep or "").strip().lower()
    if not d:
        return []
    out = [d]
    out.extend([p + d for p in _DEP_PREFIXES])
    return out


def _ready_base_to_valid_base(sig: str) -> Optional[Tuple[str, str]]:
    s = str(sig or "").strip().upper()
    for ready_base, valid_base in _READY_TO_VALID_BASE.items():
        if s.endswith(ready_base):
            return ready_base, valid_base
    return None


def _semantic_is_explicit_reset_driver(drv: Dict[str, Any]) -> bool:
    cond = str((drv or {}).get("cond", (drv or {}).get("condition", "")) or "").strip().lower()
    if not cond:
        return False
    if cond in {"true", "1", "1'b1"}:
        return False
    return any(tok in cond for tok in ("rst", "reset", "aresetn"))


def _signal_refs_from_driver(drv: Dict[str, Any]) -> List[str]:
    cond = str((drv or {}).get("cond", (drv or {}).get("condition", "")) or "")
    rhs = str((drv or {}).get("rhs", "") or "")
    refs = list(_idents(cond)) + list(_idents(rhs))
    out: List[str] = []
    for r in refs:
        if r not in out:
            out.append(r)
    return out


def _signal_depends_on_token(
    signal: str,
    token: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
    max_depth: int = 6,
) -> bool:
    key = _find_logic_key_ci(signal, logic_table)
    if key is None:
        return False
    target = str(token or "").strip()
    if not target:
        return False

    q: List[Tuple[str, int]] = [(key, 0)]
    seen: Set[str] = set()
    while q:
        cur, depth = q.pop(0)
        cur_l = cur.lower()
        if cur_l in seen:
            continue
        seen.add(cur_l)
        if depth > max_depth:
            continue
        for drv in list((logic_table or {}).get(cur, []) or []):
            cond = str(drv.get("cond", drv.get("condition", "")) or "")
            rhs = str(drv.get("rhs", "") or "")
            if _dep_present_in_text(target, f"{cond} {rhs}"):
                return True
            for ref in _signal_refs_from_driver(drv):
                nxt = _find_logic_key_ci(ref, logic_table)
                if nxt is not None and nxt.lower() not in seen:
                    q.append((nxt, depth + 1))
    return False


def _collect_transitive_cone_text(
    signal: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
    max_depth: int = 8,
) -> str:
    key = _find_logic_key_ci(signal, logic_table)
    if key is None:
        return ""
    q: List[Tuple[str, int]] = [(key, 0)]
    seen: Set[str] = set()
    parts: List[str] = []
    while q:
        cur, depth = q.pop(0)
        cur_l = cur.lower()
        if cur_l in seen:
            continue
        seen.add(cur_l)
        if depth > max_depth:
            continue
        for drv in list((logic_table or {}).get(cur, []) or []):
            cond = str(drv.get("cond", drv.get("condition", "")) or "").strip()
            rhs = str(drv.get("rhs", "") or "").strip()
            if cond:
                parts.append(cond)
            if rhs:
                parts.append(rhs)
            for ref in _signal_refs_from_driver(drv):
                nxt = _find_logic_key_ci(ref, logic_table)
                if nxt is not None and nxt.lower() not in seen:
                    q.append((nxt, depth + 1))
    return " ".join(parts)


def _contains_handshake_term(text: str, valid_base: str, ready_base: str) -> bool:
    t = str(text or "").lower()
    if not t:
        return False
    for vv in _dep_variants(valid_base):
        for rr in _dep_variants(ready_base):
            v = re.escape(vv.lower())
            r = re.escape(rr.lower())
            pats = [
                rf"\b{v}\b\s*&&\s*\b{r}\b",
                rf"\b{r}\b\s*&&\s*\b{v}\b",
                rf"\b{v}\b\s*&\s*\b{r}\b",
                rf"\b{r}\b\s*&\s*\b{v}\b",
            ]
            if any(re.search(p, t) for p in pats):
                return True
    return False


def _finding_has_missing_or_history_flag(finding: Dict[str, Any]) -> bool:
    verdict = str(finding.get("verdict", "") or "").upper()
    cls = str(finding.get("classification", "") or "").upper()
    detail = str(finding.get("detail", "") or "").lower()
    ev = finding.get("evidence", {}) if isinstance(finding.get("evidence", {}), dict) else {}
    if "MISSING" in verdict or "MISSING" in cls:
        return True
    if "missing dependency" in detail or "register_history" in detail or "registered latch history" in detail:
        return True
    for k in ("missing_dependency_terms", "missing_deps", "missing_signals"):
        vv = ev.get(k, [])
        if isinstance(vv, list) and vv:
            return True
    return False


def _infer_failing_signal_from_finding(finding: Dict[str, Any]) -> str:
    rid = str(finding.get("rule_id", "") or "")
    ev = finding.get("evidence", {}) if isinstance(finding.get("evidence", {}), dict) else {}
    req = str(ev.get("required_observation", "") or "")
    expected = str(ev.get("expected_signal", "") or "")
    return _RULE_PRIMARY_SIGNAL.get(rid) or expected or _first_signal(req) or ""


def _detect_history_driven_ready_semantic(
    finding: Dict[str, Any],
    logic_table: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    signal = _infer_failing_signal_from_finding(finding)
    pair = _ready_base_to_valid_base(signal)
    if pair is None:
        return {}
    ready_base, valid_base = pair
    ready_key = _find_logic_key_ci(signal, logic_table)
    if ready_key is None:
        return {}

    drivers = list((logic_table or {}).get(ready_key, []) or [])
    non_reset_drivers = [d for d in drivers if not _semantic_is_explicit_reset_driver(d)]
    if not non_reset_drivers:
        return {}

    driver_text_parts: List[str] = []
    internal_terms: Set[str] = set()
    for drv in non_reset_drivers:
        cond = str(drv.get("cond", drv.get("condition", "")) or "").strip()
        rhs = str(drv.get("rhs", "") or "").strip()
        if cond:
            driver_text_parts.append(cond)
        if rhs:
            driver_text_parts.append(rhs)
        for ref in _signal_refs_from_driver(drv):
            ref_key = _find_logic_key_ci(ref, logic_table)
            if ref_key is None:
                continue
            if ref_key.lower() == ready_key.lower():
                continue
            if "reset" in ref_key.lower() or "aresetn" in ref_key.lower():
                continue
            internal_terms.add(ref_key)

    # 1) READY purely from internal state (no same-cycle VALID dep).
    direct_valid_dep = _dep_present_in_text(valid_base, " ".join(driver_text_parts))
    condition_1 = (not direct_valid_dep) and bool(internal_terms)
    if not condition_1:
        return {}

    # 2) Internal state derived from VALID sampling.
    condition_2 = any(
        _signal_depends_on_token(term, valid_base, logic_table)
        for term in sorted(internal_terms)
    )
    if not condition_2:
        return {}

    # 3) No explicit handshake term in READY cone.
    cone_text = _collect_transitive_cone_text(ready_key, logic_table, max_depth=8)
    condition_3 = not _contains_handshake_term(cone_text, valid_base, ready_base)
    if not condition_3:
        return {}

    # 4) RCA has missing-dependency or register-history style evidence.
    condition_4 = _finding_has_missing_or_history_flag(finding)
    if not condition_4:
        return {}

    return {
        "root_cause_type": _SEMANTIC_HANDSHAKE_ROOT_CAUSE_TYPE,
        "human_explanation": _SEMANTIC_HANDSHAKE_EXPLANATION,
        "design_intent_mismatch": _SEMANTIC_HANDSHAKE_INTENT_MISMATCH,
        "matched_signal": ready_key,
        "paired_valid_signal": valid_base,
        "pattern": "HISTORY_DRIVEN_READY",
    }


def _subst_expr(expr: str, mapping: Dict[str, str]) -> str:
    if not expr:
        return expr

    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        return mapping.get(token, token)

    return _IDENT_RE.sub(repl, expr)


class Adapter(ProtocolAdapter):
    def __init__(
        self,
        violations: Optional[List[Dict[str, Any]]] = None,
        max_window_cycles: Optional[int] = None,
    ) -> None:
        self.violations = violations or []
        self.max_window_cycles = max_window_cycles
        self._resolved_signals: Dict[str, str] = {}
        self._logic_table: Dict[str, List[Dict[str, Any]]] = {}

    def attach_logic_table(self, logic_table: Dict[str, List[Dict[str, Any]]]) -> None:
        self._logic_table = dict(logic_table or {})

    def annotate_findings(self, findings: List[Dict[str, Any]]) -> None:
        if not isinstance(findings, list):
            return
        if not isinstance(self._logic_table, dict) or not self._logic_table:
            return
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            semantic = _detect_history_driven_ready_semantic(finding, self._logic_table)
            if semantic:
                finding["semantic_interpretation"] = semantic

    def get_rule_signal_groups(self, rule_id: str) -> Dict[str, List[str]]:
        """
        Return primary/secondary signal grouping for `rule_id`.

        Mirrors rca_7's step1_grouping fallback table.  The orchestrator uses
        this to drive backtracking for ALL grouped signals, not just one primary.
        """
        return dict(RULE_SIGNAL_MAP.get(str(rule_id).upper(), {}))

    def get_stability_signal(
        self, rule_id: str
    ) -> Optional[Tuple[str, str, str]]:
        """
        Return the MODE-C stability triple for a stability rule, or None.

        Returns (stability_signal, valid_signal, ready_signal).
          stability_signal — the payload that must not change during the window
          valid_signal     — opens the stability window
          ready_signal     — closes the window (handshake)

        Returns None for non-stability rules (MODE-A / MODE-B / MODE-D).
        """
        return RULE_STABILITY_SIGNAL_MAP.get(str(rule_id).upper())

    def is_stability_rule(self, rule_id: str) -> bool:
        """Return True if rule_id is a stability (MODE-C) rule."""
        return str(rule_id).upper() in STABILITY_RULES

    def compute_t_eval(
        self,
        rule_id: str,
        t_violation: Optional[int],
        view: WaveformView,
    ) -> Optional[int]:
        """
        Return the correct evaluation cycle for predicate backtracking.

        t_eval = last cycle < t_violation where the rule's accept-channel
        handshake (VALID && READY) == 1, then + 1.

        Mirrors rca_7's step2_75 t_eval derivation:  the evaluation point is
        anchored to the proven protocol obligation start (t_accept + 1), NOT
        to the raw violation cycle reported by axil4.

        Falls back to t_violation when:
          - the rule has no mapped accept channel
          - the accept signals are not found in the waveform
          - no handshake is observed before t_violation
        """
        pair = RULE_ACCEPT_CHANNEL.get(str(rule_id).upper())
        if pair is None or t_violation is None or view is None:
            return t_violation

        v_proto, r_proto = pair
        sig_map = self._resolve_axi_signals(view)
        v_col = sig_map.get(v_proto) or resolve_signal(v_proto, view.signals)
        r_col = sig_map.get(r_proto) or resolve_signal(r_proto, view.signals)

        if not v_col or not r_col:
            return t_violation

        # Scan forward for the LAST handshake cycle strictly before t_violation.
        # Also track the last cycle where VALID was asserted without READY —
        # this is the "attempted handshake" cycle used as a fallback when no
        # full handshake ever completed (e.g. ARREADY masked by FSM overwrite).
        t_accept: Optional[int] = None
        t_valid_only: Optional[int] = None  # last cycle where VALID=1, READY=0
        for cyc in range(0, int(t_violation)):
            try:
                v_val = view.signal_value(v_col, cyc)
                r_val = view.signal_value(r_col, cyc)
                if v_val == 1 and r_val == 1:
                    t_accept = cyc
                elif v_val == 1 and r_val != 1:
                    t_valid_only = cyc
            except Exception:
                continue

        if t_accept is not None:
            # Full handshake found — anchor to t_accept + 1 (proven obligation start)
            return t_accept + 1
        if t_valid_only is not None:
            # VALID was asserted but READY never responded — the masking bug is
            # visible at this cycle (when VALID=1 and the READY driver should fire
            # but is being overwritten).  Use t_valid_only as t_eval so that
            # predicate backtracking sees the FSM_OUTPUT_MASKED condition.
            return t_valid_only
        return t_violation

    def _resolve_axi_signals(self, waveform: WaveformView) -> Dict[str, str]:
        if self._resolved_signals:
            return dict(self._resolved_signals)
        mapping: Dict[str, str] = {}
        for canonical in AXI_LITE_SIGNAL_ALIASES.keys():
            hit = resolve_signal(canonical, waveform.signals)
            if hit:
                mapping[canonical] = hit
        self._resolved_signals = mapping
        return dict(mapping)

    def _violation_cycles(self, waveform: WaveformView, rule_id: str) -> List[int]:
        cycles: List[int] = []
        for item in self.violations:
            if str(item.get("rule_id", "")).strip() != rule_id:
                continue
            raw = item.get("cycle")
            if raw is None:
                continue
            try:
                in_value = int(float(str(raw)))
            except ValueError:
                continue
            resolved = waveform.resolve_cycle(in_value)
            cycles.append(resolved.cycle)
        return sorted(set(cycles))

    def _select_accept_cycles(
        self,
        all_accept_cycles: List[int],
        violation_cycles: List[int],
    ) -> List[int]:
        if not all_accept_cycles:
            return []
        if not violation_cycles:
            return all_accept_cycles
        out: List[int] = []
        for vcyc in violation_cycles:
            prior = [c for c in all_accept_cycles if c <= vcyc]
            pick = max(prior) if prior else min(all_accept_cycles)
            out.append(pick)
        return sorted(set(out))

    def detect_transactions(self, waveform: WaveformView) -> List[Dict[str, Any]]:
        signal_map = self._resolve_axi_signals(waveform)
        txs: List[Dict[str, Any]] = []

        for rule in AXI_LITE_RULES:
            required = _idents(rule.trigger_expr) | _idents(rule.required_observation_expr) | _idents(rule.enable_condition)
            if any(sig not in signal_map for sig in required if sig in AXI_LITE_SIGNAL_ALIASES):
                continue

            trigger_expr = _subst_expr(rule.trigger_expr, signal_map)
            required_expr = _subst_expr(rule.required_observation_expr, signal_map)
            enable_expr = _subst_expr(rule.enable_condition, signal_map)
            expected_sig = _subst_expr(rule.expected_signal, signal_map)
            ready_signals = [_subst_expr(s, signal_map) for s in rule.ready_signals]

            accept_cycles: List[int] = []
            for cycle, _ in waveform.iter_cycles(0, waveform.max_cycle):
                if waveform.condition_true(trigger_expr, cycle) is True:
                    accept_cycles.append(cycle)

            selected_accept_cycles = self._select_accept_cycles(
                all_accept_cycles=accept_cycles,
                violation_cycles=self._violation_cycles(waveform, rule.rule_id),
            )

            for accept_cycle in selected_accept_cycles:
                txs.append(
                    {
                        "rule": rule,
                        "rule_id": rule.rule_id,
                        "accept_cycle": accept_cycle,
                        "trigger_expr": trigger_expr,
                        "required_expr": required_expr,
                        "enable_expr": enable_expr,
                        "expected_signal": expected_sig,
                        "ready_signals": ready_signals,
                    }
                )
        return txs

    def define_obligations(self, transactions: List[Dict[str, Any]]) -> List[CausalContract]:
        obligations: List[CausalContract] = []
        for idx, tx in enumerate(transactions):
            rule: ObligationRule = tx["rule"]
            anchor = int(tx["accept_cycle"]) + 1
            max_window = self.max_window_cycles if self.max_window_cycles is not None else rule.max_window_cycles
            obligations.append(
                CausalContract(
                    contract_id=f"{rule.rule_id}_{idx}",
                    trigger_condition=tx["trigger_expr"],
                    required_observation=tx["required_expr"],
                    temporal_window=TemporalWindow(start_cycle=anchor, end_cycle=anchor + int(max_window)),
                    anchor_cycle=anchor,
                    expected_signal=tx["expected_signal"],
                    expected_value=1,
                    enable_condition=tx["enable_expr"],
                    metadata={
                        "rule_id": rule.rule_id,
                        "ready_signals": list(tx["ready_signals"]),
                        "lookahead_cycles": int(rule.lookahead_cycles),
                        "protocol": "axi_lite",
                    },
                )
            )
        return obligations

    def required_observations(self, obligation: CausalContract) -> List[str]:
        return sorted(_idents(obligation.required_observation))

    def classify_violation(self, causal_result: CausalResult) -> Dict[str, Any]:
        status = causal_result.status
        evidence = dict(causal_result.evidence or {})
        evidence.setdefault("expected_signal", str(causal_result.contract.expected_signal or ""))
        evidence.setdefault("enable_condition", str(causal_result.contract.enable_condition or ""))
        rule_id = causal_result.contract.metadata.get("rule_id", "UNKNOWN")

        if status == ContractStatus.SATISFIABLE:
            return {
                "rule_id": rule_id,
                "classification": "SATISFIED",
                "verdict": "SATISFIABLE",
                "detail": causal_result.detail,
                "analysis_cycle": causal_result.analysis_cycle,
                "evidence": evidence,
            }

        if status == ContractStatus.CANCELLED:
            cancel = evidence.get("intra_cycle_cancellation", {}) if isinstance(evidence, dict) else {}
            verdict = "READY_INTERFERENCE_OVERWRITE"
            detail = "Expected transition was cancelled by same-step conflicting assignments."
            if isinstance(cancel, dict) and cancel.get("ready_signals_high_next_cycle"):
                detail = (
                    "Signal was enabled, then overwritten in immediate next cycle while READY was high: "
                    + ", ".join(cancel.get("ready_signals_high_next_cycle", []))
                )
            return {
                "rule_id": rule_id,
                "classification": "SCHEDULING_CANCELLATION",
                "cause": "MULTIPLE_TRUE_DRIVERS_SAME_CYCLE",
                "semantic_type": "NONBLOCKING_ASSIGNMENT_CONFLICT",
                "responsibility": "RTL_IMPLEMENTATION",
                "verdict": verdict,
                "detail": detail,
                "analysis_cycle": causal_result.analysis_cycle,
                "evidence": evidence,
            }

        if status == ContractStatus.CYCLIC:
            return {
                "rule_id": rule_id,
                "classification": "DESIGN_STRUCTURAL_BLOCKAGE",
                "verdict": "CYCLIC_ENABLE_DEPENDENCY",
                "detail": causal_result.detail,
                "analysis_cycle": causal_result.analysis_cycle,
                "evidence": evidence,
            }

        if status == ContractStatus.BLOCKED:
            return {
                "rule_id": rule_id,
                "classification": "DESIGN_STRUCTURAL_BLOCKAGE",
                "verdict": "MISSING_INTERLOCK",
                "detail": causal_result.detail,
                "analysis_cycle": causal_result.analysis_cycle,
                "evidence": evidence,
            }

        return {
            "rule_id": rule_id,
            "classification": "INCONCLUSIVE",
            "verdict": "UNDETERMINED",
            "detail": causal_result.detail,
            "analysis_cycle": causal_result.analysis_cycle,
            "evidence": evidence,
        }

    def render_report(self, payload: Dict[str, Any]) -> bool:
        findings = list(payload.get("findings", []) or [])
        transactions = list(payload.get("transactions", []) or [])
        obligations = list(payload.get("obligations", []) or [])
        max_cycle = payload.get("waveform_max_cycle", "N/A")

        root = _pick_root(findings)
        banner = "=" * 56
        print(banner)
        print("ROOT CAUSE SUMMARY")
        print(banner)

        if root is None:
            print("Violation        : NONE")
            print("Failure Signal   : N/A")
            print("Failure Type     : SATISFIABLE")
            print("")
            print("What Happened:")
            print("All adapter contracts were satisfiable in their temporal windows.")
            print("")
            print("Per-Rule RCA:")
            print("- RULE_12: no violation in this run.")
            print("- RULE_13: no violation in this run.")
            print("- RULE_5: no violation in this run.")
            print("- RULE_6: no violation in this run.")
            print(banner)
            return True

        rid = str(root.get("rule_id", "UNKNOWN"))
        ev = root.get("evidence", {}) if isinstance(root.get("evidence", {}), dict) else {}
        req = str(ev.get("required_observation", "")).strip()
        expected = str(ev.get("expected_signal", "")).strip()
        signal = _RULE_PRIMARY_SIGNAL.get(rid) or expected or _first_signal(req) or "UNKNOWN"
        amba = _amba_ref(rid)

        print(f"Violation        : {rid}")
        print(f"Failure Signal   : {signal}")
        print(f"Failure Type     : {root.get('verdict', root.get('classification', 'UNKNOWN'))}")
        print(f"AMBA Spec        : {amba['standard']} | {amba['section']}")
        print(f"AMBA Requirement : {amba['requirement']}")
        print("")
        print("What Happened:")
        print(str(root.get("detail", "No detail available.")))
        semantic = root.get("semantic_interpretation", {}) if isinstance(root.get("semantic_interpretation", {}), dict) else {}
        if semantic:
            print("")
            print(f"SEMANTIC ROOT CAUSE: {str(semantic.get('human_explanation', '')).strip()}")
            mismatch = str(semantic.get("design_intent_mismatch", "")).strip()
            if mismatch:
                print(f"Design Intent Mismatch: {mismatch}")
        print("")
        print("Where To Look In RTL:")
        print(f"- Signal: {signal}")
        en = str(ev.get("enable_condition", "")).strip()
        if en:
            print(f"- Enable condition: {en}")
        if req:
            print(f"- Required observation: {req}")
        trig = str(ev.get("trigger_condition", "")).strip()
        if trig:
            print(f"- Trigger condition: {trig}")
        print("")
        print("Minimal Causal Chain:")
        if trig and req:
            print(f"{trig} -> {req} -> {rid}")
        elif signal:
            print(f"{signal} -> {rid}")
        else:
            print(rid)
        print("")
        print("Final RootCause Chain:")
        print(f"- {signal}")
        if en:
            print(f"- enable: {en}")
        if trig:
            print(f"- trigger: {trig}")
        if req:
            print(f"- obligation: {req}")

        print("")
        print("Final RootCause Chain (Full Trace):")
        for ln in _render_full_trace(root, signal):
            print(ln)

        print("")
        print("Adapter Coverage:")
        print(f"- Transactions detected: {len(transactions)}")
        print(f"- Contracts generated: {len(obligations)}")
        print(f"- Waveform cycles: 0..{max_cycle}")

        # Additional proven findings (top non-root entries).
        extra = [f for f in findings if f is not root and str(f.get("verdict", "")) != "SATISFIABLE"]
        if extra:
            print("")
            print("Additional Proven Findings:")
            for f in sorted(extra, key=lambda x: int(x.get("analysis_cycle", 10**9)))[:3]:
                print(
                    f"- {f.get('rule_id')}/{_RULE_PRIMARY_SIGNAL.get(str(f.get('rule_id','')), _first_signal(str((f.get('evidence') or {}).get('required_observation','')) or 'UNKNOWN'))}"
                    f"@{f.get('analysis_cycle')}: {f.get('classification')} | {f.get('detail')}"
                )

        # Per-rule summary.
        per_rule: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            rid2 = str(f.get("rule_id", "UNKNOWN"))
            if rid2 not in per_rule or int(f.get("analysis_cycle", 10**9)) < int(per_rule[rid2].get("analysis_cycle", 10**9)):
                per_rule[rid2] = f

        print("")
        print("Per-Rule RCA:")
        for rid2 in ["RULE_12", "RULE_13", "RULE_5", "RULE_6"]:
            f = per_rule.get(rid2)
            if not f:
                print(f"- {rid2}: no violation in this run.")
                continue
            ev2 = f.get("evidence", {}) if isinstance(f.get("evidence", {}), dict) else {}
            sig2 = _RULE_PRIMARY_SIGNAL.get(rid2) or str(ev2.get("expected_signal", "")).strip() or _first_signal(str(ev2.get("required_observation", ""))) or "UNKNOWN"
            print(
                f"- {rid2}/{sig2}@{f.get('analysis_cycle')}: {f.get('verdict', f.get('classification'))}"
                f" | {f.get('detail')}"
            )

        print(banner)
        return True


def build_adapter(**kwargs: Any) -> Adapter:
    return Adapter(**kwargs)
