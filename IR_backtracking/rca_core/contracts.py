from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ContractStatus(str, Enum):
    SATISFIABLE = "SATISFIABLE"
    BLOCKED = "BLOCKED"
    CYCLIC = "CYCLIC"
    CANCELLED = "CANCELLED"
    UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True)
class TemporalWindow:
    start_cycle: int
    end_cycle: Optional[int] = None


@dataclass(frozen=True)
class CausalContract:
    contract_id: str
    trigger_condition: str
    required_observation: str
    temporal_window: TemporalWindow
    anchor_cycle: int
    expected_signal: Optional[str] = None
    expected_value: int = 1
    enable_condition: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CausalResult:
    contract: CausalContract
    status: ContractStatus
    analysis_cycle: int
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)

