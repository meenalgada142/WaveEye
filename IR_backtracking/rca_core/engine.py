from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .contracts import CausalContract, CausalResult, ContractStatus
from .cyclic_dependency_analyzer import detect_cyclic_enable
from .deep_backtrack import build_dependency_graph
from .io import WaveformView
from .scheduling import detect_intra_cycle_cancellation, find_first_cancellation
from .temporal_predicate_analysis import analyze_temporal_reachability
from .predicate_backtrack import (
    evaluate_all_drivers     as _pb_eval_all,
    build_causal_chain_trace as _pb_chain,
)


def _as_bool(value: Any) -> Optional[bool]:
    if value in (True, 1):
        return True
    if value in (False, 0):
        return False
    return None


class RCACoreEngine:
    def __init__(
        self,
        waveform: WaveformView,
        logic_table: Dict[str, List[Dict[str, Any]]],
        max_graph_depth: int = 8,
        temporal_window_cycles: int = 20,
    ) -> None:
        self.waveform = waveform
        self.logic_table = logic_table
        self.max_graph_depth = max_graph_depth
        self.temporal_window_cycles = temporal_window_cycles

    def build_causal_graph(self, signal: str) -> Dict[str, Any]:
        return build_dependency_graph(
            target_signal=signal,
            logic_table=self.logic_table,
            max_depth=self.max_graph_depth,
        )

    def detect_enable_cycle(self, signal: str, dependency_graph: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return detect_cyclic_enable(
            root_signal=signal,
            dependency_graph=dependency_graph,
            eval_trace={},
        )

    def _first_cycle_with_condition(
        self,
        condition_expr: str,
        start_cycle: int,
        end_cycle: Optional[int],
    ) -> Optional[int]:
        stop = self.waveform.max_cycle if end_cycle is None else min(end_cycle, self.waveform.max_cycle)
        for cycle in range(max(0, start_cycle), stop + 1):
            ok = self.waveform.condition_true(condition_expr, cycle)
            if ok is True:
                return cycle
        return None

    def _window_rows(self, start_cycle: int, end_cycle: Optional[int]) -> List[Dict[str, Any]]:
        stop = self.waveform.max_cycle if end_cycle is None else min(end_cycle, self.waveform.max_cycle)
        rows: List[Dict[str, Any]] = []
        for cycle in range(max(0, start_cycle), stop + 1):
            _, row = self.waveform.row_at_cycle(cycle)
            row_copy = dict(row)
            row_copy["__cycle__"] = cycle
            rows.append(row_copy)
        return rows

    def _evaluate_blockage(self, contract: CausalContract) -> CausalResult:
        analysis_cycle = max(contract.anchor_cycle, contract.temporal_window.start_cycle)
        evidence: Dict[str, Any] = {
            "trigger_condition": contract.trigger_condition,
            "required_observation": contract.required_observation,
            "analysis_cycle": analysis_cycle,
        }

        # ── MODE-A / MODE-B classification (mirrors rca_7) ──────────────────
        # observed_transition: the signal IS already at expected_value at
        #   analysis_cycle — some driver drove it there.
        # expected_transition: an asserting driver (rhs == expected_value)
        #   EXISTS in the logic table for this signal.
        #
        # MODE_A: observed but not expected → wrong driver fired
        # MODE_B: expected but not observed → enable condition blocked
        _analysis_mode: Optional[str] = None
        if contract.expected_signal:
            try:
                _sig_val = self.waveform.signal_value(
                    contract.expected_signal, analysis_cycle
                )
            except Exception:
                _sig_val = None
            _drvs = _pb_eval_all(
                contract.expected_signal, self.logic_table, self.waveform, analysis_cycle
            )
            _observed_transition = (_sig_val == contract.expected_value)
            _expected_transition = any(d["is_asserting"] for d in _drvs)

            if _observed_transition and not _expected_transition:
                _analysis_mode = "MODE_A"
            elif _expected_transition and not _observed_transition:
                _analysis_mode = "MODE_B"

            evidence["analysis_mode"] = _analysis_mode
            if _analysis_mode:
                evidence["predicate_chain"] = _pb_chain(
                    contract.expected_signal,
                    self.logic_table,
                    self.waveform,
                    analysis_cycle,
                )

        if contract.expected_signal:
            lookahead = int(contract.metadata.get("lookahead_cycles", 0) or 0)
            gate_signals = list(contract.metadata.get("ready_signals", []) or [])
            cancel = detect_intra_cycle_cancellation(
                waveform=self.waveform,
                logic_table=self.logic_table,
                signal=contract.expected_signal,
                t_eval=analysis_cycle,
                expected_value=contract.expected_value,
                lookahead_cycles=lookahead,
                gate_signals=gate_signals,
            )
            evidence["intra_cycle_cancellation"] = cancel
            if cancel.get("detected"):
                detail = "Signal transition was logically enabled but cancelled by execution ordering."
                return CausalResult(
                    contract=contract,
                    status=ContractStatus.CANCELLED,
                    analysis_cycle=analysis_cycle,
                    detail=detail,
                    evidence=evidence,
                )

            graph = self.build_causal_graph(contract.expected_signal)
            cycle_report = self.detect_enable_cycle(contract.expected_signal, graph)
            evidence["dependency_graph"] = graph
            if cycle_report:
                evidence["cycle_report"] = cycle_report
                return CausalResult(
                    contract=contract,
                    status=ContractStatus.CYCLIC,
                    analysis_cycle=analysis_cycle,
                    detail="Enable condition forms a causal cycle.",
                    evidence=evidence,
                )

        if contract.enable_condition:
            enabled = _as_bool(self.waveform.condition_true(contract.enable_condition, analysis_cycle))
            evidence["enable_condition"] = {
                "expr": contract.enable_condition,
                "value_at_analysis_cycle": enabled,
            }
            if enabled is not True:
                rows = self._window_rows(
                    max(contract.temporal_window.start_cycle, analysis_cycle - self.temporal_window_cycles),
                    analysis_cycle,
                )
                temporal = analyze_temporal_reachability(
                    condition_str=contract.enable_condition,
                    waveform_rows=rows,
                    cycle_window=max(1, self.temporal_window_cycles),
                )
                evidence["temporal_reachability"] = temporal
                return CausalResult(
                    contract=contract,
                    status=ContractStatus.BLOCKED,
                    analysis_cycle=analysis_cycle,
                    detail="Enable condition was not satisfiable at obligation time.",
                    evidence=evidence,
                )

        return CausalResult(
            contract=contract,
            status=ContractStatus.BLOCKED,
            analysis_cycle=analysis_cycle,
            detail="Required observation was not reached within the contract window.",
            evidence=evidence,
        )

    def evaluate_contract(self, contract: CausalContract) -> CausalResult:
        seen_at = self._first_cycle_with_condition(
            condition_expr=contract.required_observation,
            start_cycle=contract.temporal_window.start_cycle,
            end_cycle=contract.temporal_window.end_cycle,
        )
        if seen_at is not None:
            return CausalResult(
                contract=contract,
                status=ContractStatus.SATISFIABLE,
                analysis_cycle=seen_at,
                detail="Required observation occurred within the contract window.",
                evidence={"observed_cycle": seen_at},
            )
        return self._evaluate_blockage(contract)

    def evaluate_contracts(self, contracts: Iterable[CausalContract]) -> List[CausalResult]:
        return [self.evaluate_contract(c) for c in contracts]

    def find_first_scheduling_cancellation(
        self,
        signal: str,
        expected_value: int = 1,
        start_cycle: int = 0,
        end_cycle: Optional[int] = None,
        lookahead_cycles: int = 0,
    ) -> Dict[str, Any]:
        return find_first_cancellation(
            waveform=self.waveform,
            logic_table=self.logic_table,
            signal=signal,
            expected_value=expected_value,
            start_cycle=start_cycle,
            end_cycle=end_cycle,
            lookahead_cycles=lookahead_cycles,
        )

