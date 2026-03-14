"""Protocol-agnostic RCA core package."""

from .contracts import CausalContract, CausalResult, ContractStatus, TemporalWindow
from .engine import RCACoreEngine
from .io import WaveformView, load_driver_table, load_violations_file, load_waveform_file
from .semantic_datapath_analysis import detect_semantic_datapath_violations
from .causal_graph import (
    TransformNode,
    build_transform_nodes,
    find_nonbijective_paths,
    PROP_WIDTH_LOSS,
    PROP_FABRICATED_BITS,
    PROP_DUPLICATION,
)

__all__ = [
    "CausalContract",
    "CausalResult",
    "ContractStatus",
    "TemporalWindow",
    "RCACoreEngine",
    "WaveformView",
    "load_driver_table",
    "load_violations_file",
    "load_waveform_file",
    "detect_semantic_datapath_violations",
    "TransformNode",
    "build_transform_nodes",
    "find_nonbijective_paths",
    "PROP_WIDTH_LOSS",
    "PROP_FABRICATED_BITS",
    "PROP_DUPLICATION",
]

