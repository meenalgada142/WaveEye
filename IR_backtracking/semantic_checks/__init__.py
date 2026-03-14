# semantic_checks — IR-level semantic analysis detectors
# All detectors run purely on IR records; no waveform required.
#
# Public API (also importable from each submodule directly):
from .memory_write_analysis import (
    detect_memory_write_semantic_mismatch,
    detect_lane_bijection_violation,
    detect_mask_conservation_violation,
    detect_width_conservation_violation,
)
from .transport_semantic_analysis import (
    detect_transport_semantic_mismatch,
    detect_address_monotonicity_violation,
)
from .invertibility import detect_invertibility_violation

__all__ = [
    "detect_memory_write_semantic_mismatch",
    "detect_lane_bijection_violation",
    "detect_mask_conservation_violation",
    "detect_width_conservation_violation",
    "detect_transport_semantic_mismatch",
    "detect_address_monotonicity_violation",
    "detect_invertibility_violation",
]
