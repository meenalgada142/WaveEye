"""
WaveEye RCA Post-Analysis Report Generators
============================================
All generators accept the payload dict produced by run_waveeye_rca()
/ _write_proof_artifacts() and return a formatted string.

Primary outputs (always written):
    generate_console_diagnosis  — 12-line precision root-cause console report
    generate_backtrack_trace    — protocol trigger → signal walk → RTL defect
    generate_rtl_fix            — surgical RTL correction guidance

Available generators (debug-internal)
--------------------------------------
Presentation reports (conference / review):
    generate_executive_summary  — 12-line exec report for silicon architects
    reduce_violations           — collapse repeated violations by root mechanism
    generate_failure_timeline   — 6-10 step causality chain

Defensive / justification reports:
    generate_peer_review_defense — formal root-cause defence against dismissal
    score_determinism_risk       — 0-10 determinism risk score with justification
    generate_tool_differentiator — what WaveEye does that checkers cannot (5 bullets)

Engineering reports (RTL engineer audience):
    generate_structural_root_cause — grouped defect report (WHAT/WHY/EVIDENCE)
    filter_evidence             — presentation-grade filtered evidence (70% reduction)
    filter_payload              — same as above but returns a filtered dict
    generate_rca_explanation    — plain-language 6-field walkback (engineer-facing)
    extract_signal_set          — minimal closed causal chain (4 signals max)

Deep review (engine soundness validation):
    generate_deep_appendix      — full invariant reasoning + all instances

Quick usage
-----------
    from reports import generate_console_diagnosis
    print(generate_console_diagnosis(payload))
"""

from .console_diagnosis   import generate_console_diagnosis
from .backtrack_trace     import generate_backtrack_trace
from .rtl_fix_advisor     import generate_rtl_fix
from .executive_summary   import generate_executive_summary
from .violation_reducer   import reduce_violations
from .peer_review_defense import generate_peer_review_defense
from .failure_timeline    import generate_failure_timeline
from .determinism_scorer  import score_determinism_risk
from .evidence_filter     import filter_evidence, filter_payload
from .deep_appendix       import generate_deep_appendix
from .tool_differentiator import generate_tool_differentiator
from .causal_pruner       import generate_causal_path, prune_payload
from .rca_explanation     import generate_rca_explanation
from .signal_set          import extract_signal_set
from .structural_root_cause import generate_structural_root_cause
from .llm_rca_prompt        import generate_rca_analysis, generate_llm_rca_prompt, SYSTEM_PROMPT

__all__ = [
    # Primary outputs
    "generate_console_diagnosis",
    "generate_backtrack_trace",
    "generate_rtl_fix",
    # Presentation
    "generate_executive_summary",
    "reduce_violations",
    "generate_failure_timeline",
    # Defensive / justification
    "generate_peer_review_defense",
    "score_determinism_risk",
    "generate_tool_differentiator",
    # Engineering (debug)
    "generate_structural_root_cause",
    "generate_causal_path",
    "prune_payload",
    "filter_evidence",
    "filter_payload",
    "generate_rca_explanation",
    "extract_signal_set",
    # Deep review
    "generate_deep_appendix",
    # LLM handoff
    "generate_rca_analysis",
    "generate_llm_rca_prompt",
    "SYSTEM_PROMPT",
]
