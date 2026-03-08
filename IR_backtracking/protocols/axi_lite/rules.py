from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ObligationRule:
    rule_id: str
    trigger_expr: str
    required_observation_expr: str
    expected_signal: str
    ready_signals: List[str]
    enable_condition: str
    lookahead_cycles: int = 1
    max_window_cycles: int = 256


AXI_LITE_RULES: List[ObligationRule] = [
    ObligationRule(
        rule_id="RULE_13",
        trigger_expr="(AWVALID && AWREADY) && (WVALID && WREADY)",
        required_observation_expr="BVALID && BREADY",
        expected_signal="BVALID",
        ready_signals=["BREADY"],
        enable_condition="write_state == RESP",
        lookahead_cycles=1,
        max_window_cycles=512,
    ),
    ObligationRule(
        rule_id="RULE_12",
        trigger_expr="ARVALID && ARREADY",
        required_observation_expr="RVALID && RREADY",
        expected_signal="RVALID",
        ready_signals=["RREADY"],
        enable_condition="read_state == RESP",
        lookahead_cycles=1,
        max_window_cycles=512,
    ),
]

