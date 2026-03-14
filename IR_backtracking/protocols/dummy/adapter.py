from __future__ import annotations

from typing import Any, Dict, List

from protocols.base import ProtocolAdapter
from rca_core.contracts import CausalContract, CausalResult, TemporalWindow
from rca_core.io import WaveformView


class Adapter(ProtocolAdapter):
    def detect_transactions(self, waveform: WaveformView) -> List[Dict[str, Any]]:
        return [{"accept_cycle": 0}]

    def define_obligations(self, transactions: List[Dict[str, Any]]) -> List[CausalContract]:
        return [
            CausalContract(
                contract_id="DUMMY_0",
                trigger_condition="1",
                required_observation="1",
                temporal_window=TemporalWindow(0, 0),
                anchor_cycle=0,
            )
        ]

    def required_observations(self, obligation: CausalContract) -> List[str]:
        return []

    def classify_violation(self, causal_result: CausalResult) -> Dict[str, Any]:
        return {
            "classification": str(causal_result.status),
            "detail": causal_result.detail,
            "analysis_cycle": causal_result.analysis_cycle,
        }


def build_adapter(**_: Any) -> Adapter:
    return Adapter()

