from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from rca_core.contracts import CausalContract, CausalResult
from rca_core.io import WaveformView


class ProtocolAdapter(ABC):
    @abstractmethod
    def detect_transactions(self, waveform: WaveformView) -> List[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def define_obligations(self, transactions: List[Dict[str, Any]]) -> List[CausalContract]:
        raise NotImplementedError

    @abstractmethod
    def required_observations(self, obligation: CausalContract) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def classify_violation(self, causal_result: CausalResult) -> Dict[str, Any]:
        raise NotImplementedError

    # Optional protocol-owned reporting hook.
    # Return True when report was fully rendered by adapter.
    def render_report(self, payload: Dict[str, Any]) -> bool:
        return False

    def get_rule_signal_groups(self, rule_id: str) -> Dict[str, List[str]]:
        """
        Return the primary/secondary signal grouping for a rule.

        {"primary": ["RVALID"], "secondary": ["ARVALID", "ARREADY"]}

        primary  = violated slave-driven signal(s) to backtrack.
        secondary = required dependency signals per the protocol spec.

        Defaults to empty dict — override in protocol adapters.
        """
        return {}

    def compute_t_eval(
        self,
        rule_id: str,
        t_violation: Optional[int],
        view: Any,
    ) -> Optional[int]:
        """
        Return the correct evaluation cycle for predicate backtracking.

        Anchors to t_accept + 1 (cycle after the protocol handshake) rather
        than the raw violation cycle.  Falls back to t_violation when no
        accept handshake is observed in the waveform.

        Override in protocol adapters to provide handshake scanning.
        """
        return t_violation
