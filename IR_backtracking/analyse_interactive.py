#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FSM-Aware Interactive Root Cause Analysis Tool
Excludes: All reset-related X analysis
"""
import csv
import sys
import io
import os
import importlib.util
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
import re
import json
from runtime_paths import resource_path

# Safe UTF-8 output on Windows (does NOT replace stream objects)
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ============================================================
# PROTOCOL <-> RTL SIGNAL NORMALIZATION
# ============================================================

PROTOCOL_SIGNAL_MAP = {
    # READ ADDRESS
    'ARVALID': ['s_axil_arvalid', 'm_axil_arvalid'],
    'ARREADY': ['s_axil_arready', 'm_axil_arready'],

    # READ DATA
    'RVALID': ['s_axil_rvalid', 'm_axil_rvalid'],
    'RREADY': ['s_axil_rready', 'm_axil_rready'],

    # WRITE RESPONSE
    'BVALID': ['s_axil_bvalid', 'm_axil_bvalid'],
    'BREADY': ['s_axil_bready', 'm_axil_bready'],
    'BRESP':  ['s_axil_bresp',  'm_axil_bresp'],
}

# Import all the analysis functions
from utils import (
    parse_literal_token,
    eval_expr,
    expand_row_with_aliases,
    split_conditions,
    get_signal_value,
    strip_outer_parens,
    get_edge_type,
    is_posedge,
    detect_clock,
    eval_rhs_expression
)

# Predicate backtracking (rca_7 MODE-A/MODE-B engine — optional)
try:
    def _load_predicate_backtrack_py():
        """Load the Python source module explicitly to avoid stale compiled extensions."""
        _pb_path = os.path.join(os.path.dirname(__file__), "rca_core", "predicate_backtrack.py")
        spec = importlib.util.spec_from_file_location("waveeye_predicate_backtrack_py", _pb_path)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod

    _predicate_backtrack_py = _load_predicate_backtrack_py()
    _pb_eval_all  = _predicate_backtrack_py.evaluate_all_drivers
    _pb_chain     = _predicate_backtrack_py.build_causal_chain_trace
    _pb_full_trace = _predicate_backtrack_py.format_full_trace
    _PREDICATE_BACKTRACK_AVAILABLE = True
except ImportError:
    _PREDICATE_BACKTRACK_AVAILABLE = False

# ── Mode constants (mirrors rca_7) ──────────────────────────────────────────
MODE_A = "MODE_A"
MODE_B = "MODE_B"


def classify_analysis_mode(sig, logic, view, cycle, expected_value=1):
    """
    Return MODE_A, MODE_B, or None for a given signal at a specific cycle.

    observed_transition: the signal IS at expected_value at this cycle
                         (a driver drove it there).
    expected_transition: an asserting driver (rhs == expected_value) EXISTS
                         in the logic table — the protocol REQUIRES a
                         transition to expected_value.

    MODE_A: signal is at expected_value but no asserting driver claims it
            → wrong driver fired unexpectedly.
    MODE_B: asserting driver exists but signal did NOT reach expected_value
            → enable condition is false or assignment was overwritten.
    """
    if not _PREDICATE_BACKTRACK_AVAILABLE or view is None or logic is None:
        return None
    try:
        sig_val = view.signal_value(sig, cycle)
    except Exception:
        return None

    observed_transition = (sig_val == expected_value)

    driver_evals = _pb_eval_all(sig, logic, view, cycle)
    expected_transition = any(d["is_asserting"] for d in driver_evals)

    if observed_transition and not expected_transition:
        return MODE_A
    elif expected_transition and not observed_transition:
        return MODE_B
    return None


def trace_unexpected_driver_activation(sig, logic, view, cycle, rule_id="?"):
    """
    MODE-A: The signal is at expected_value but the asserting driver did not
    fire. Backtrack the TRUE terms of the winning (wrong) driver to find
    why it fired unexpectedly.

    Mirrors rca_7 MODE_A_INCORRECT_TRANSITION_HAPPENED.

    Returns dict:
        analysis_mode      "MODE_A"
        case_analysis      "MODE_A_INCORRECT_TRANSITION_HAPPENED"
        verdict            "UNEXPECTED_DRIVER_ACTIVATION"
        root_cause_type    "structural_root_cause"
        hard_stop          True   (rca_7: no further backtrack needed)
        formatted_trace    str    (full driver table + causal chain)
        chain              ChainNode dict
    """
    chain = _pb_chain(sig, logic, view, cycle)
    return {
        "analysis_mode":   MODE_A,
        "case_analysis":   "MODE_A_INCORRECT_TRANSITION_HAPPENED",
        "verdict":         "UNEXPECTED_DRIVER_ACTIVATION",
        "root_cause_type": "structural_root_cause",
        "hard_stop":       True,
        "formatted_trace": _pb_full_trace(sig, cycle, logic, view, rule_id),
        "chain":           chain,
    }


def trace_enable_failure(sig, logic, view, cycle, rule_id="?"):
    """
    MODE-B: The expected transition did not occur. The asserting driver exists
    but its enable condition is FALSE (or a subsequent driver overwrote it).
    Backtrack the first FALSE predicate term to find the blocking cause.

    Mirrors rca_7 MODE_B_EXPECTED_TRANSITION_NOT_OCCURRED.

    Returns dict:
        analysis_mode      "MODE_B"
        case_analysis      "MODE_B_EXPECTED_TRANSITION_NOT_OCCURRED"
        verdict            "ENABLE_CONDITION_FAILURE"
        root_cause_type    "structural_root_cause"
        hard_stop          False  (continue backtracking the chain)
        formatted_trace    str    (full driver table + causal chain)
        chain              ChainNode dict
    """
    chain = _pb_chain(sig, logic, view, cycle)
    return {
        "analysis_mode":   MODE_B,
        "case_analysis":   "MODE_B_EXPECTED_TRANSITION_NOT_OCCURRED",
        "verdict":         "ENABLE_CONDITION_FAILURE",
        "root_cause_type": "structural_root_cause",
        "hard_stop":       False,
        "formatted_trace": _pb_full_trace(sig, cycle, logic, view, rule_id),
        "chain":           chain,
    }


# ============================================================
# VERDICT TIER SYSTEM
# ============================================================
def normalize_rtl_signal(sig):
    """
    Convert RTL signal to protocol-level canonical name.
    Example: s_axil_arvalid_reg -> ARVALID
    """
    s = sig.lower()
    s = s.replace('_reg', '').replace('_next', '')

    for proto, rtl_list in PROTOCOL_SIGNAL_MAP.items():
        for rtl in rtl_list:
            if rtl in s:
                return proto

    return None
def normalize_violation_signals(sig_string):
    """
    Parse 'ARVALID, RVALID' -> {'ARVALID', 'RVALID'}
    """
    if not sig_string:
        return set()
    return {s.strip().upper() for s in sig_string.split(',')}

VERDICT_TIERS = {
    # TIER 2: Structural Bugs
    'CROSS_BLOCK_RACE': 2,
    'MIXED_BLOCKING_NONBLOCKING': 2,
    
    # TIER 3: FSM-Specific Execution Order
    'FSM_OUTPUT_MASKED': 3,
    'FSM_DEFAULT_OVERRIDE': 3,
    'FSM_EDGE_OVERLAP': 3,
    
    # TIER 4: General Execution Order
    'EXECUTION_ORDER_BUG': 4,
    'SUBSET_OVERWRITE': 4,
    

    'DERIVED_SIGNAL': 6,
    'DESIGNER_INTENT': 7,
    'NO_WAVEFORM_DATA': 99,
    'NO_RTL_DRIVERS': 99,
}

TIER_PREFIXES = {
    2: "[STRUCTURAL]",
    3: "[FSM-BUG]",
    4: "[RACE]",
    5: "[INFO]",
    6: "[DERIVED]",
    7: "[INFO]",
    99: "[ERROR]",
}

def build_transition_index(wave, sig):
    """
    Return list of row indices where signal value changes.
    """
    transitions = []
    prev_val = None

    for i, row in enumerate(wave):
        raw = get_signal_value(sig, row)
        val = parse_literal_token(raw)

        if val is None:
            continue

        if prev_val is None:
            prev_val = val
            continue

        if val != prev_val:
            transitions.append(i)
            prev_val = val

    return transitions

def protocol_to_rtl_signals(proto_sig, logic):
    """
    Map protocol-level AXI signal (e.g. ARREADY)
    -> RTL signal names present in backtracking (logic keys)
    """
    if not proto_sig:
        return []

    proto_sig = proto_sig.upper()
    rtl_matches = []

    # 1. Exact protocol -> RTL mapping
    if proto_sig in PROTOCOL_SIGNAL_MAP:
        for rtl in PROTOCOL_SIGNAL_MAP[proto_sig]:
            if rtl in logic:
                rtl_matches.append(rtl)

    # 2. Defensive fallback (substring match)
    if not rtl_matches:
        proto_l = proto_sig.lower()
        for rtl_sig in logic.keys():
            if proto_l in rtl_sig.lower():
                rtl_matches.append(rtl_sig)

    return sorted(set(rtl_matches))

def load_violation_signal_csv(csv_path):
    """Load signals from AXI analyzer signals.csv format"""
    violations = {}

    try:
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # AXI analyzer format: violation_num, cycle, rule_id, primary_signals, secondary_signals
                viol_num = row.get("violation_num", "").strip()
                rule_id = row.get("rule_id", "").strip()
                
                # Use violation_num as key
                v = viol_num if viol_num else rule_id
                
                if v not in violations:
                    violations[v] = {
                        "primary_signals": [],
                        "secondary_signals": [],
                        "eligibility_bundle": []
                    }
                
                # Parse primary_signals (comma-separated)
                primary_str = row.get("primary_signals", "").strip()
                if primary_str:
                    for sig in primary_str.split(','):
                        sig = sig.strip()
                        if sig:
                            violations[v]["primary_signals"].append(sig)
                
                # Parse secondary_signals (comma-separated)
                secondary_str = row.get("secondary_signals", "").strip()
                if secondary_str:
                    for sig in secondary_str.split(','):
                        sig = sig.strip()
                        if sig:
                            violations[v]["secondary_signals"].append(sig)
        
        return violations
    
    except FileNotFoundError:
        print(f"[INFO] signals.csv not found: {csv_path} (signal grouping skipped -- using true_drivers.csv only)")
        return {}
    except Exception as e:
        print(f"[ERROR] Failed to load signals.csv: {e}")
        return {}

# Load violations from signals.csv
signals_csv = sys.argv[3] if len(sys.argv) > 3 else "signals.csv"
VIOLATION_SPECS = load_violation_signal_csv(signals_csv)

# ============================================================
# FSM-AWARENESS ENHANCEMENT LAYER
# ============================================================

def extract_fsm_references(condition: str, fsm_signals: Set[str]) -> List[Tuple[str, str]]:
    """Extract FSM state comparisons from a condition."""
    if not condition or not fsm_signals:
        return []
    
    references = []
    patterns = [
        r'(\w+)\s*==\s*(\w+)',
        r'(\w+)\s*!=\s*(\w+)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, condition)
        for sig, val in matches:
            if sig in fsm_signals:
                references.append((sig, val))
    
    return references

def is_fsm_related_condition(condition: str, fsm_signals: Set[str]) -> bool:
    """Check if a condition references any FSM state signals."""
    return len(extract_fsm_references(condition, fsm_signals)) > 0

def categorize_fsm_bug_pattern(
    bug_info: dict,
    drivers: list,
    fsm_signals: Set[str],
    wave: list,
    cycle: int
) -> Optional[str]:
    """Categorize the FSM-specific bug pattern."""
    if not fsm_signals:
        return None
    
    overwritten = bug_info.get('overwritten_drivers', [])
    winner = bug_info.get('winner')
    subset_overwrites = bug_info.get('subset_overwrites', [])
    
    if not winner or not overwritten:
        return None
    
    winner_idx = winner.get('driver_idx')
    winner_cond = drivers[winner_idx].get('cond', '') if winner_idx is not None else ''
    
    overwritten_conds = []
    for drv in overwritten:
        drv_idx = drv.get('driver_idx')
        if drv_idx is not None:
            overwritten_conds.append(drivers[drv_idx].get('cond', ''))
    
    winner_has_fsm = is_fsm_related_condition(winner_cond, fsm_signals)
    overwritten_has_fsm = any(is_fsm_related_condition(c, fsm_signals) for c in overwritten_conds)
    
    if not (winner_has_fsm or overwritten_has_fsm):
        return None
    
    if overwritten_has_fsm and subset_overwrites:
        for so in subset_overwrites:
            earlier_idx = so['earlier'].get('driver_idx')
            if earlier_idx is not None:
                earlier_cond = drivers[earlier_idx].get('cond', '')
                if is_fsm_related_condition(earlier_cond, fsm_signals):
                    return 'FSM_OUTPUT_MASKED'
    
    if overwritten_has_fsm and not winner_has_fsm:
        if is_simple_condition(winner_cond):
            return 'FSM_DEFAULT_OVERRIDE'
    
    if winner_has_fsm and overwritten_has_fsm and subset_overwrites:
        return 'FSM_EDGE_OVERLAP'
    
    return None

def generate_fsm_aware_explanation(
    sig: str,
    bug_info: dict,
    drivers: list,
    fsm_signals: Set[str],
    fsm_pattern: Optional[str],
    wave: list,
    cycle: int,
    next_cycle: int,
    observed_next: any
) -> str:
    """Generate FSM-aware explanation for execution order bugs."""
    winner = bug_info.get('winner')
    overwritten = bug_info.get('overwritten_drivers', [])
    subset_overwrites = bug_info.get('subset_overwrites', [])
    block_id = bug_info.get('block_id')
    is_inferred = bug_info.get('inferred_from_pattern', False)
    external_signals = bug_info.get('external_signals', [])
    
    all_fsm_refs = []
    for drv in overwritten + [winner]:
        drv_idx = drv.get('driver_idx')
        if drv_idx is not None:
            cond = drivers[drv_idx].get('cond', '')
            refs = extract_fsm_references(cond, fsm_signals)
            all_fsm_refs.extend(refs)
    
    if fsm_pattern == 'FSM_OUTPUT_MASKED':
        return _explain_fsm_output_masked(
            sig, winner, overwritten, subset_overwrites, drivers,
            all_fsm_refs, cycle, next_cycle, observed_next, block_id,
            is_inferred, external_signals
        )
    elif fsm_pattern == 'FSM_DEFAULT_OVERRIDE':
        return _explain_fsm_default_override(
            sig, winner, overwritten, drivers,
            all_fsm_refs, cycle, next_cycle, observed_next, block_id,
            is_inferred
        )
    elif fsm_pattern == 'FSM_EDGE_OVERLAP':
        return _explain_fsm_edge_overlap(
            sig, winner, overwritten, subset_overwrites, drivers,
            all_fsm_refs, cycle, next_cycle, observed_next, block_id,
            is_inferred, external_signals
        )
    else:
        return _explain_fsm_generic(
            sig, winner, overwritten, subset_overwrites, drivers,
            all_fsm_refs, cycle, next_cycle, observed_next, block_id,
            is_inferred, external_signals
        )
def format_improved_execution_order_explanation(
    sig: str,
    bug_info: dict,
    drivers: list,
    cycle: int,
    next_cycle: int,
    observed_next: any
) -> str:
    """Generate improved execution order explanation with better reasoning."""
    
    winner = bug_info.get('winner')
    overwritten = bug_info.get('overwritten_drivers', [])
    subset_overwrites = bug_info.get('subset_overwrites', [])
    block_id = bug_info.get('block_id')
    
    winner_idx = winner.get('driver_idx')
    winner_cond = drivers[winner_idx].get('cond', '')
    winner_rhs = drivers[winner_idx].get('rhs', '')
    
    explanation = f"""
+===========================================================================+
| EXECUTION ORDER BUG: Superset Condition Overwrites Specific Logic        |
+===========================================================================+

Signal: {sig}
Always Block: {block_id}
Bug Occurs At: Cycle {cycle}

---------------------------------------------------------------------------
 STEP 1: Understanding the RTL Structure
---------------------------------------------------------------------------

This signal has {len(overwritten) + 1} non-blocking assignments (<=) in the SAME always block:

"""
    
    # Show all drivers with visual hierarchy
    for idx, drv in enumerate(overwritten, 1):
        drv_idx = drv.get('driver_idx')
        cond = drivers[drv_idx].get('cond', '')
        rhs = drivers[drv_idx].get('rhs', '')
        
        explanation += f"""  [{idx}] if ({cond})
        {sig} <= {rhs};
"""
    
    explanation += f"""  [{len(overwritten) + 1}] if ({winner_cond})           <- BROADER CONDITION
        {sig} <= {winner_rhs};

---------------------------------------------------------------------------
 STEP 2: What Happens at Cycle {cycle}
---------------------------------------------------------------------------

At the clock edge, the simulator evaluates ALL conditions in source order:

"""
    
    # Show evaluation sequence
    for idx, drv in enumerate(overwritten, 1):
        drv_idx = drv.get('driver_idx')
        cond = drivers[drv_idx].get('cond', '')
        rhs_val = drv.get('rhs_val', '?')
        
        explanation += f"""  +- Evaluation {idx}: ({cond})
  |  Result: TRUE [OK]
  |  Action: SCHEDULE {sig} <= {rhs_val}
  |  Status: Stored in NBA queue (will execute at end of timestep)
  `---

"""
    
    explanation += f"""  +- Evaluation {len(overwritten) + 1}: ({winner_cond})
  |  Result: TRUE [OK]  <- ALSO TRUE (superset condition!)
  |  Action: SCHEDULE {sig} <= {observed_next}
  |  Status: OVERWRITES previous scheduled value in NBA queue
  `---

---------------------------------------------------------------------------
 STEP 3: The Superset Problem
---------------------------------------------------------------------------

Why do ALL conditions evaluate to TRUE at the same time?

"""
    
    # Explain superset relationships
    for so in subset_overwrites:
        earlier_idx = so['earlier'].get('driver_idx')
        later_idx = so['later'].get('driver_idx')
        earlier_cond = drivers[earlier_idx].get('cond', '')
        later_cond = drivers[later_idx].get('cond', '')
        
        explanation += f"""  Condition Relationship:
  
    {earlier_cond}  C  {later_cond}
    `--- more specific      `--- more general (SUPERSET)
  
  This means:
    * When "{earlier_cond}" is TRUE,
    * Then "{later_cond}" is ALSO TRUE (because it's less restrictive)
    * So BOTH drivers fire in the SAME cycle!

"""
    
    explanation += f"""---------------------------------------------------------------------------
 STEP 4: Non-Blocking Assignment (NBA) Semantics
---------------------------------------------------------------------------

When multiple NBA assignments target the same signal:

  1. All RHS expressions are evaluated using CURRENT values
  2. All assignments are SCHEDULED (not executed immediately)
  3. At end of timestep, assignments execute in SOURCE ORDER
  4. LAST assignment WINS (overwrites previous scheduled values)

In this case:

"""
    
    for idx, drv in enumerate(overwritten, 1):
        rhs_val = drv.get('rhs_val', '?')
        explanation += f"""  Time T:   Driver {idx} schedules: {sig} <= {rhs_val}
"""
    
    explanation += f"""  Time T:   Driver {len(overwritten) + 1} schedules: {sig} <= {observed_next}  <- LAST!
  
  Time T+delta: All assignments execute -> {sig} becomes {observed_next}

The earlier assignments are SILENTLY DISCARDED.

---------------------------------------------------------------------------
 STEP 5: The Bug
---------------------------------------------------------------------------

Expected Behavior:
"""
    
    for idx, drv in enumerate(overwritten, 1):
        drv_idx = drv.get('driver_idx')
        cond = drivers[drv_idx].get('cond', '')
        rhs_val = drv.get('rhs_val', '?')
        explanation += f"""  When {cond} -> {sig} should become {rhs_val}
"""
    
    explanation += f"""
Actual Behavior:
  {sig} = {observed_next} (the default/hold value)

Root Cause:
  The broader condition ({winner_cond}) executes AFTER the specific
  conditions, unconditionally overwriting their intended updates.

This is an EXECUTION ORDER BUG - the logic is structurally incorrect.

---------------------------------------------------------------------------
 RECOMMENDED FIX
---------------------------------------------------------------------------

Use MUTUALLY EXCLUSIVE conditions with priority chain (if-else-if):

  always_ff @(posedge clk) begin
    if (!rst_n)
      {sig} <= <reset_value>;
"""
    
    for idx, drv in enumerate(overwritten, 1):
        drv_idx = drv.get('driver_idx')
        cond = drivers[drv_idx].get('cond', '')
        rhs = drivers[drv_idx].get('rhs', '')
        
        # Extract the specific part of condition (remove rst_n)
        specific_cond = cond.replace('rst_n &&', '').replace('rst_n &', '').strip()
        
        explanation += f"""    else if ({specific_cond})
      {sig} <= {rhs};
"""
    
    explanation += f"""    // No 'else' needed - {sig} holds its value implicitly
  end

This ensures only ONE assignment executes per cycle.

+===========================================================================+
| KEY INSIGHT: Parallel conditions with superset relationships create      |
| race conditions. Use mutually exclusive if-else chains instead.          |
+===========================================================================+
"""
    
    return explanation
def _explain_fsm_output_masked(
    sig, winner, overwritten, subset_overwrites, drivers,
    fsm_refs, cycle, next_cycle, observed_next, block_id,
    is_inferred, external_signals
) -> str:
    """Explain FSM_OUTPUT_MASKED pattern."""
    
    explanation = f"""
===========================================================================
FSM BUG PATTERN: FSM_OUTPUT_MASKED
===========================================================================

Signal: {sig}
Pattern: State-specific output assignment was masked by broader condition
Confidence: {'INFERRED (Pattern-based)' if is_inferred else 'PROVEN (Waveform evidence)'}

===========================================================================

WHAT HAPPENED:

At cycle {cycle}, your FSM entered a specific state that should trigger an
output assignment, but a broader condition executed AFTER the state-specific
logic and overwrote its value.

Result at cycle {next_cycle}: {sig} = {observed_next} (NOT the state-specific value)

FSM States Referenced:
"""
    
    for fsm_sig, state_val in fsm_refs:
        explanation += f"  * {fsm_sig} = {state_val}\n"
    
    explanation += f"""
DRIVER EXECUTION ORDER:
"""
    
    for idx, drv in enumerate(overwritten, 1):
        drv_idx = drv.get('driver_idx')
        cond = drivers[drv_idx].get('cond', '')
        rhs_val = drv.get('rhs_val')
        
        explanation += f"""
  [{idx}] STATE-SPECIFIC DRIVER (Driver {drv_idx}):
      Condition: {cond}
      -> Scheduled: {sig} <= {rhs_val}
      Status: [X] OVERWRITTEN (executed first, then masked)
"""
    
    winner_idx = winner.get('driver_idx')
    winner_cond = drivers[winner_idx].get('cond', '')
    winner_rhs = winner.get('rhs_val')
    
    explanation += f"""
  [FINAL] BROADER CONDITION (Driver {winner_idx}):
      Condition: {winner_cond}
      -> Scheduled: {sig} <= {winner_rhs}
      Status: [OK] WINS (executed last, overwrites previous)

===========================================================================
"""
    
    return explanation

def _explain_fsm_default_override(
    sig, winner, overwritten, drivers,
    fsm_refs, cycle, next_cycle, observed_next, block_id,
    is_inferred
) -> str:
    """Explain FSM_DEFAULT_OVERRIDE pattern."""
    
    explanation = f"""
===========================================================================
FSM BUG PATTERN: FSM_DEFAULT_OVERRIDE
===========================================================================

Signal: {sig}
Pattern: FSM default/fallback logic executed after state-specific assignment
Confidence: {'INFERRED (Pattern-based)' if is_inferred else 'PROVEN (Waveform evidence)'}

===========================================================================

WHAT HAPPENED:

At cycle {cycle}, your FSM had state-specific logic that should update {sig},
but a DEFAULT or FALLBACK condition executed LAST and overwrote it.

Result at cycle {next_cycle}: {sig} = {observed_next} (default value, not state value)

===========================================================================
"""
    
    return explanation

def _explain_fsm_edge_overlap(
    sig, winner, overwritten, subset_overwrites, drivers,
    fsm_refs, cycle, next_cycle, observed_next, block_id,
    is_inferred, external_signals
) -> str:
    """Explain FSM_EDGE_OVERLAP pattern."""
    
    explanation = f"""
===========================================================================
FSM BUG PATTERN: FSM_EDGE_OVERLAP
===========================================================================

Signal: {sig}
Pattern: FSM state transition and output assignment overlapped at clock edge
Confidence: {'INFERRED (Timing pattern)' if is_inferred else 'PROVEN (Waveform evidence)'}

===========================================================================
"""
    
    return explanation

def _explain_fsm_generic(
    sig, winner, overwritten, subset_overwrites, drivers,
    fsm_refs, cycle, next_cycle, observed_next, block_id,
    is_inferred, external_signals
) -> str:
    """Generic FSM-aware explanation (fallback)."""
    
    explanation = f"""
===========================================================================
FSM-RELATED BUG: Non-Blocking Assignment Conflict
===========================================================================

Signal: {sig}
Confidence: {'INFERRED (Pattern-based)' if is_inferred else 'PROVEN (Waveform evidence)'}

===========================================================================
"""
    
    return explanation

# ============================================================
# CORE HELPER FUNCTIONS
# ============================================================

def convert_binary_fsm_states(row, fsm_regs):
    """Convert binary FSM state values to decimal for proper comparison."""
    if not fsm_regs:
        return row
    
    if isinstance(fsm_regs, tuple):
        fsm_regs = fsm_regs[0]
    
    if not isinstance(fsm_regs, (list, tuple)):
        return row
    
    converted = row.copy()
    
    for reg in fsm_regs:
        if reg in converted:
            val_str = str(converted[reg]).strip()
            if val_str and all(c in '01' for c in val_str):
                try:
                    decimal_val = int(val_str, 2)
                    converted[reg] = decimal_val
                except ValueError:
                    pass
    
    return converted

TRACE = False

def load_waveform_csv(path):
    with open(path, encoding='utf-8-sig', errors='replace') as f:
        rows = list(csv.reader(f))
    cls = rows[0]
    hdr = rows[1]
    wave = []
    for r in rows[2:]:
        r += [""] * (len(hdr) - len(r))
        wave.append({hdr[i]: r[i].strip() for i in range(len(hdr))})
    return wave, hdr, cls

def load_backtracking_csv(path):
    """Load backtracking CSV and include always_block_id"""
    logic = {}
    with open(path, encoding='utf-8-sig', errors='replace') as f:
        r = csv.DictReader(f)
        for row in r:
            sig = row.get("signal", "").strip()
            
            # FILTER OUT DELIMITER ROWS
            if not sig or sig.startswith("---") or sig == "NEXT DRIVER":
                continue
            
            block_id_str = row.get("always_block_id", "").strip()
            if block_id_str and block_id_str.isdigit():
                block_id = int(block_id_str)
            else:
                block_id = None
            
            logic.setdefault(sig, []).append({
                "cond": (row.get("condition") or "").strip(),
                "rhs": (row.get("rhs") or "").strip(),
                "assign_type": (row.get("assign_type") or "").strip(),
                "sensitivity": (row.get("sensitivity") or "").strip(),
                "always_block_id": block_id,
            })
    return logic

def build_cycle_to_row_map(wave, clock_sig):
    if not wave:
        return {i: i for i in range(len(wave))}, {i: i for i in range(len(wave))}

    class CycleRowMap(dict):
        """Dict-like map with optional timing metadata for cycle resolution."""
        pass

    first_row = wave[0] if wave else {}
    time_col = "time_ps" if "time_ps" in first_row else ("time_ns" if "time_ns" in first_row else None)

    def _parse_time_token(tok):
        s = str(tok or "").strip()
        if not s:
            return None
        try:
            return int(round(float(s)))
        except (TypeError, ValueError):
            return None

    # Build timestamp index (used as fallback and metadata source).
    time_to_row = {}
    if time_col is not None:
        for row_idx, row in enumerate(wave):
            t_key = _parse_time_token(row.get(time_col, ""))
            if t_key is None:
                continue
            time_to_row[t_key] = row_idx

    if not clock_sig:
        if time_to_row:
            c2r = CycleRowMap(time_to_row)
            r2c = {row_idx: cyc for cyc, row_idx in c2r.items()}
            return c2r, r2c
        return {i: i for i in range(len(wave))}, {i: i for i in range(len(wave))}

    cycle_only = {}
    row_to_cycle = {}
    posedge_times = []
    prev_clk = None
    cycle_num = -1

    for row_idx, row in enumerate(wave):
        clk_val = str(row.get(clock_sig, "")).strip()
        if clk_val == "":
            continue

        try:
            clk = int(clk_val)
        except ValueError:
            continue

        if prev_clk == 0 and clk == 1:
            cycle_num += 1
            cycle_only[cycle_num] = row_idx
            if time_col is not None:
                t_key = _parse_time_token(row.get(time_col, ""))
                if t_key is not None:
                    posedge_times.append(t_key)

        if cycle_num >= 0:
            row_to_cycle[row_idx] = cycle_num

        prev_clk = clk

    # If clock edges were not found, fall back to timestamp indexing.
    if not cycle_only:
        if time_to_row:
            c2r = CycleRowMap(time_to_row)
            r2c = {row_idx: cyc for cyc, row_idx in c2r.items()}
            return c2r, r2c
        return {i: i for i in range(len(wave))}, {i: i for i in range(len(wave))}

    # Keep cycle_to_row in pure clock-cycle axis.
    # Timestamp lookup is carried separately as metadata.
    cycle_to_row = CycleRowMap(cycle_only)
    if time_to_row:
        cycle_to_row._time_to_row = dict(time_to_row)

    # Attach optional metadata used by resolve_cycle_to_row().
    cycle_to_row._max_clock_cycle = max(cycle_only.keys())
    if len(posedge_times) >= 2:
        diffs = [b - a for a, b in zip(posedge_times[:-1], posedge_times[1:]) if b > a]
        if diffs:
            diffs_sorted = sorted(diffs)
            cycle_to_row._clk_period_ns = diffs_sorted[len(diffs_sorted) // 2]

    return cycle_to_row, row_to_cycle

def load_enum_encodings(enum_file):
    """Load FSM state encodings from .fsm_encodings.json file."""
    if not enum_file:
        return {}
    
    try:
        enum_path = os.fspath(enum_file)
        if not os.path.isabs(enum_path):
            enum_path = resource_path(enum_path)
        with open(enum_path, encoding='utf-8', errors='replace') as f:
            enums = json.load(f)
        
        encoding_map = {}
        for type_name, members in enums.items():
            encoding_map.update(members)
        
        return encoding_map
    
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}
    except Exception:
        return {}

def detect_fsm_regs(classifications, header):
    fsm_regs = []
    fsm_states = []
    for c, h in zip(classifications, header):
        if c.lower() == "fsm_control":
            fsm_regs.append(h)
        elif c.lower() == "fsm_state":
            fsm_states.append(h)
    return fsm_regs, fsm_states

def build_fsm_encodings(classifications, header, wave, enum_map=None):
    """Build FSM state encodings from waveform or enum file."""
    enc = {}
    enum_map = enum_map or {}
    
    if not wave:
        for c, h in zip(classifications, header):
            if c.lower() == "fsm_state":
                if h in enum_map:
                    enc[h] = enum_map[h]
                else:
                    enc[h] = 0
        return enc
    
    for c, h in zip(classifications, header):
        if c.lower() == "fsm_state":
            raw = wave[0].get(h, "")
            waveform_val = parse_literal_token(raw)
            
            if waveform_val is not None and waveform_val != 0:
                enc[h] = waveform_val
            elif raw and raw.strip():
                state_name = raw.strip()
                if state_name in enum_map:
                    enc[h] = enum_map[state_name]
                else:
                    enc[h] = 0
            else:
                if h in enum_map:
                    enc[h] = enum_map[h]
                else:
                    enc[h] = 0
    
    return enc

def is_simple_condition(cond):
    """Check if condition is simple (reset, single signal, constant, or else branch)."""
    if not cond:
        return True
    
    cond_stripped = strip_outer_parens(cond)
    
    if cond_stripped in ["TRUE", "true", "1'b1", "1", "1'b0", "0", "FALSE", "false"]:
        return True
    
    cond_clean = cond_stripped.replace(" ", "").lower()
    has_operators = any(op in cond_clean for op in ["&&", "||", "==", "!=", "<", ">", "+", "-"])
    
    if not has_operators:
        reset_patterns = [
            "!rst", "!rst_n", "!reset", "!reset_n", "!aresetn", "!nrst",
            "~rst", "~rst_n", "~reset", "~reset_n", "~aresetn", "~nrst",
            "aresetn", "rst_n", "reset_n", "nrst", "rst", "reset", "areset",
            "srst", "soft_reset", "hard_reset", "por", "pwron",
        ]
        if cond_clean in reset_patterns:
            return True
    
    if "!(" in cond and "||" in cond:
        neg_start = cond.find("!(")
        if neg_start != -1:
            paren_count = 0
            start_idx = neg_start + 2
            
            for i in range(start_idx, len(cond)):
                if cond[i] == '(':
                    paren_count += 1
                elif cond[i] == ')':
                    if paren_count == 0:
                        inner = cond[start_idx:i]
                        comparisons = re.findall(r'([a-zA-Z_][\w\[\]:]*)\s*==', inner)
                        
                        if len(comparisons) >= 2:
                            from collections import Counter
                            signal_counts = Counter(comparisons)
                            
                            for signal, count in signal_counts.items():
                                if count >= 2:
                                    return True
                        break
                    else:
                        paren_count -= 1
    
    return False

def should_skip_driver(drv, debug=False):
    """Skip pure reset drivers and defaults for analysis."""
    cond = drv.get("cond", "").strip()
    rhs = drv.get("rhs", "").strip()
    
    if is_simple_condition(cond):
        cond_clean = cond.replace(" ", "").lower()
        if any(pat in cond_clean for pat in ["aresetn", "rst", "reset", "nrst"]):
            rhs_val = parse_literal_token(rhs)
            if rhs_val == 0 or rhs == "":
                if debug:
                    print(f"    [SKIP] Simple reset/default '{cond}' -> {rhs}")
                return True
        else:
            if debug:
                print(f"    [SKIP] Simple condition '{cond}' -> {rhs}")
            return True
    
    if debug:
        print(f"    [KEEP] '{cond}' | rhs='{rhs}'")
    return False

# ============================================================
# MULTI-PHASE ANALYSIS SYSTEM
# ============================================================

class DriverCategory(Enum):
    """Categories for driver analysis"""
    PURE_RESET = "pure_reset"
    RESET_QUALIFIED = "reset_qualified"
    PURE_LOGIC = "pure_logic"
    SIMPLE_DEFAULT = "simple_default"

class AnalysisMode(Enum):
    """Analysis phases with different driver filtering"""
    STRUCTURAL = "structural"
    LOGICAL = "logical"
    RESET_DIAGNOSIS = "reset"
    FULL = "full"

def has_reset_term(cond: str) -> bool:
    """Check if condition contains reset-related terms"""
    if not cond:
        return False
    
    cond_clean = cond.replace(" ", "").lower()
    
    reset_patterns = [
        "!rst", "!rst_n", "!reset", "!reset_n", "!aresetn", "!nrst",
        "~rst", "~rst_n", "~reset", "~reset_n", "~aresetn", "~nrst",
        "aresetn", "rst_n", "reset_n", "nrst", "rst", "reset", "areset",
    ]
    
    return any(pat in cond_clean for pat in reset_patterns)

def has_non_reset_terms(cond: str) -> bool:
    """Check if condition has terms other than reset"""
    if not cond:
        return False
    
    terms = re.split(r'&&|\|\|', cond)
    
    for term in terms:
        term_clean = term.strip().replace(" ", "").lower()
        
        is_reset = any(
            pat in term_clean 
            for pat in ["rst", "reset", "aresetn", "nrst"]
        )
        
        if not is_reset and term_clean:
            return True
    
    return False

def categorize_driver(drv: Dict) -> DriverCategory:
    """Categorize driver based on condition and RHS."""
    cond = drv.get("cond", "").strip()
    rhs = drv.get("rhs", "").strip()
    
    has_reset = has_reset_term(cond)
    has_logic = has_non_reset_terms(cond)
    
    if has_reset and not has_logic:
        rhs_val = parse_literal_token(rhs)
        if rhs_val == 0 or rhs == "":
            return DriverCategory.PURE_RESET
    
    if has_reset and has_logic:
        return DriverCategory.RESET_QUALIFIED
    
    if is_simple_condition(cond) and not has_reset:
        return DriverCategory.SIMPLE_DEFAULT
    
    return DriverCategory.PURE_LOGIC

def should_include_driver(drv: Dict, mode: AnalysisMode) -> bool:
    """Mode-aware decision on whether to include driver in analysis."""
    category = categorize_driver(drv)
    
    if mode == AnalysisMode.STRUCTURAL:
        return True
    
    elif mode == AnalysisMode.LOGICAL:
        return category != DriverCategory.PURE_RESET
    
    elif mode == AnalysisMode.RESET_DIAGNOSIS:
        return True
    
    elif mode == AnalysisMode.FULL:
        return True
    
    return True

def filter_drivers(drivers: List[Dict], mode: AnalysisMode) -> List[Dict]:
    """Filter drivers based on analysis mode"""
    return [d for d in drivers if should_include_driver(d, mode)]

def group_by_block(drivers: List[Dict]) -> Dict[Optional[int], List[Dict]]:
    """Group drivers by always_block_id"""
    grouped = {}
    for drv in drivers:
        block_id = drv.get("always_block_id")
        if block_id not in grouped:
            grouped[block_id] = []
        grouped[block_id].append(drv)
    return grouped

# ============================================================
# ENHANCEMENT 1: DERIVED-SIGNAL DETECTION
# ============================================================

def is_simple_signal_reference(rhs: str) -> bool:
    """Check if RHS is a simple signal reference (no operations)."""
    if not rhs:
        return False
    rhs_clean = rhs.strip()
    operators = ['&', '|', '^', '~', '!', '+', '-', '*', '/', '%',
                 '==', '!=', '<', '>', '<=', '>=', '<<', '>>']
    for op in operators:
        if op in rhs_clean:
            return False
    if '?' in rhs_clean or '{' in rhs_clean:
        return False
    rhs_no_bits = re.sub(r'\[.*?\]', '', rhs_clean)
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', rhs_no_bits))

def detect_derived_signal(sig: str, drivers: List[Dict], logic: Dict) -> Optional[Dict]:
    """Detect if signal is purely derived from another signal."""
    non_reset_drivers = []
    for drv in drivers:
        cond = drv.get('cond', '').strip().lower().replace(' ', '')
        is_reset = any(pat in cond for pat in ['!rst', '~rst', '!reset', '~reset', '!aresetn', '~aresetn'])
        if not is_reset:
            non_reset_drivers.append(drv)
    if len(non_reset_drivers) != 1:
        return None
    drv = non_reset_drivers[0]
    rhs = drv.get('rhs', '').strip()
    if not is_simple_signal_reference(rhs):
        return None
    source_sig = re.sub(r'\[.*?\]', '', rhs).strip()
    if source_sig not in logic:
        return None
    return {'source_signal': source_sig, 'assignment': f'{sig} <= {rhs}'}

def format_derived_signal_explanation(sig: str, derived_info: Dict) -> str:
    """Format explanation for derived signal"""
    source = derived_info['source_signal']
    return f"""\n{'='*79}\nDERIVED SIGNAL: {sig} <= {source}\n{'='*79}\n"""





def analyze_conditional_drivers(
    sig: str,
    wave: list,
    drivers: List[Dict],
    x_cycle: int,
    logic: Dict,
    fsm_regs,
    fsm_enc
) -> Dict:
    """Check if X appeared because no conditional driver fired"""
    
    if x_cycle >= len(wave):
        return {"likely_cause": False}
    
    curr_row = expand_row_with_aliases(wave[x_cycle])
    curr_row = convert_binary_fsm_states(curr_row, fsm_regs)
    
    false_drivers = []
    
    for idx, drv in enumerate(drivers):
        cond = drv.get("cond", "").strip()
        
        if not cond:
            continue
        
        terms = split_conditions(cond)
        all_true = True
        false_terms = []
        
        for term in terms:
            val = eval_expr(term, curr_row, fsm_regs=fsm_regs, fsm_enc=fsm_enc)
            if not (val is True or val == 1):
                all_true = False
                false_terms.append(term)
        
        if not all_true:
            false_drivers.append({
                "idx": idx,
                "cond": cond,
                "false_terms": false_terms,
                "rhs": drv.get("rhs", "")
            })
    
    if len(false_drivers) == len(drivers):
        return {
            "likely_cause": True,
            "reason": "All drivers had false conditions",
            "false_drivers": false_drivers,
            "x_cycle": x_cycle
        }
    
    return {"likely_cause": False}



# ============================================================
# ENHANCED STRUCTURAL BUG DETECTION
# ============================================================

def detect_structural_bugs(
    drivers: List[Dict],
    sig: str
) -> Optional[Dict]:
    """
    Phase 1: Detect structural bugs that are ALWAYS wrong.
    
    Enhanced to include driver details for better explanations.
    """
    block_ids = {
        d.get("always_block_id")
        for d in drivers
        if d.get("always_block_id") is not None
    }
    
    if len(block_ids) > 1:
        drivers_by_block = {}
        for drv in drivers:
            block_id = drv.get("always_block_id")
            if block_id is not None:
                if block_id not in drivers_by_block:
                    drivers_by_block[block_id] = []
                drivers_by_block[block_id].append(drv)
        
        return {
            "type": "CROSS_BLOCK_RACE",
            "severity": "CRITICAL",
            "blocks": sorted(block_ids),
            "drivers_by_block": drivers_by_block,
            "drivers": drivers,
            "message": f"Multiple always blocks drive {sig} - undefined NBA ordering"
        }
    
    for block_id, block_drivers in group_by_block(drivers).items():
        if block_id is None:
            continue
        
        assign_types = {
            d.get("assign_type", "").lower()
            for d in block_drivers
        }
        
        if "blocking" in assign_types and "nonblocking" in assign_types:
            blocking_drivers = [d for d in block_drivers if d.get("assign_type", "").lower() == "blocking"]
            nonblocking_drivers = [d for d in block_drivers if d.get("assign_type", "").lower() == "nonblocking"]
            
            return {
                "type": "MIXED_BLOCKING_NONBLOCKING",
                "severity": "CRITICAL",
                "block_id": block_id,
                "blocking_drivers": blocking_drivers,
                "nonblocking_drivers": nonblocking_drivers,
                "message": f"Mixed blocking/nonblocking in block {block_id}"
            }
    
    return None

def format_structural_bug_explanation(bug: Dict, sig: str, drivers: List[Dict] = None) -> str:
    """Format critical structural bugs with detailed driver information"""
    
    if bug["type"] == "CROSS_BLOCK_RACE":
        explanation = f"""
===========================================================================
CRITICAL BUG: Cross-Always-Block Race
===========================================================================

Signal: {sig}
Blocks Involved: {bug['blocks']}

Multiple always blocks drive this signal. This is ALWAYS unsafe because:
* Non-blocking assignment ordering across blocks is undefined
* Simulator-dependent behavior  
* Conditions may overlap even if they appear exclusive

This bug exists regardless of reset or other conditions.

===========================================================================
"""
        return explanation
    
    elif bug["type"] == "MIXED_BLOCKING_NONBLOCKING":
        explanation = f"""
===========================================================================
CRITICAL BUG: Mixed Blocking/Non-Blocking Assignments
===========================================================================

Signal: {sig}
Block: {bug['block_id']}

Both blocking (=) and non-blocking (<=) assignments in the same always block.

This creates undefined behavior - execution order is not guaranteed.

RECOMMENDATION: Use ONLY non-blocking (<=) in always_ff blocks.

===========================================================================
"""
        return explanation
    
    return str(bug)

# ============================================================
# CONDITION ANALYSIS FUNCTIONS
# ============================================================

def find_external_signals(conditions: List[str], logic: Dict) -> List[str]:
    """Find signals in conditions that are NOT in RTL backtracking"""
    external = []
    
    for cond in conditions:
        signal_names = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', cond)
        
        for sig_name in signal_names:
            if sig_name in ['ARESETn', 'ACLK', 'clk', 'rst', 'rst_n', 'reset', 'reset_n']:
                continue
            
            if sig_name not in logic:
                if sig_name not in external:
                    external.append(sig_name)
    
    return external

def are_mutually_exclusive_conditions(cond1, cond2):
    """Check if two conditions are TRULY mutually exclusive."""
    if not cond1 or not cond2:
        return False
    
    if is_condition_subset(cond1, cond2):
        return False
    
    if is_condition_subset(cond2, cond1):
        return False
    
    c1 = cond1.replace(" ", "").lower()
    c2 = cond2.replace(" ", "").lower()
    
    state_matches1 = re.findall(r'(\w+)==(\w+)', c1)
    state_matches2 = re.findall(r'(\w+)==(\w+)', c2)
    
    if state_matches1 and state_matches2:
        for var1, val1 in state_matches1:
            for var2, val2 in state_matches2:
                if var1 == var2 and val1 != val2:
                    return True
    
    terms1 = set(re.split(r'&&', c1))
    terms2 = set(re.split(r'&&', c2))
    
    common = terms1 & terms2
    unique1 = terms1 - common
    unique2 = terms2 - common
    
    for u1 in unique1:
        u1_stripped = u1.strip('()')
        for u2 in unique2:
            u2_stripped = u2.strip('()')
            
            if u2_stripped.startswith('!'):
                u2_inner = u2_stripped[1:].strip('()')
                if u1_stripped == u2_inner:
                    return True
            if u1_stripped.startswith('!'):
                u1_inner = u1_stripped[1:].strip('()')
                if u2_stripped == u1_inner:
                    return True
    
    return False

def has_mutually_exclusive_drivers(drivers):
    """Check if a signal has drivers that are mutually exclusive."""
    if len(drivers) < 2:
        return False
    
    drivers_by_block = {}
    for drv in drivers:
        block_id = drv.get("always_block_id")
        if block_id not in drivers_by_block:
            drivers_by_block[block_id] = []
        drivers_by_block[block_id].append(drv)
    
    for block_id, block_drivers in drivers_by_block.items():
        if block_id is None:
            continue
        
        if len(block_drivers) < 2:
            continue
        
        all_mutex = True
        for i, drv1 in enumerate(block_drivers):
            for drv2 in block_drivers[i+1:]:
                cond1 = drv1.get("cond", "")
                cond2 = drv2.get("cond", "")
                
                if not are_mutually_exclusive_conditions(cond1, cond2):
                    all_mutex = False
                    break
            if not all_mutex:
                break
        
        if all_mutex:
            return True
    
    return False

def is_condition_subset(cond1, cond2):
    """Check if cond2 is a subset of cond1.

    Strips outer/unbalanced parentheses from each split term so that
    conditions like '((ARESETn) && (read_state == IDLE)) && ((ARVALID))'
    compare correctly against '(ARESETn) && (read_state == IDLE)'.
    """
    if not cond1 or not cond2:
        return False

    def _normalise_terms(cond: str) -> set:
        cond_clean = cond.replace(" ", "").lower()
        raw_terms = re.split(r'&&|\|\|', cond_clean)
        # Strip all leading/trailing parentheses from each term so that
        # nested groupings don't prevent string equality matching.
        return {t.strip("()") for t in raw_terms if t.strip("()")}

    terms1 = _normalise_terms(cond1)
    terms2 = _normalise_terms(cond2)

    return terms2.issubset(terms1)

def analyze_execution_order(true_drivers, drivers):
    """Analyze execution order within an always block."""
    if not true_drivers:
        return {
            "winner": None,
            "execution_order": [],
            "blocked_drivers": [],
            "race_type": "none"
        }
    
    drivers_by_block = {}
    for drv in true_drivers:
        block_id = drv.get("always_block_id")
        if block_id not in drivers_by_block:
            drivers_by_block[block_id] = []
        drivers_by_block[block_id].append(drv)
    
    if len(drivers_by_block) > 1:
        return {
            "winner": None,
            "execution_order": true_drivers,
            "blocked_drivers": [],
            "race_type": "cross_block",
            "num_blocks": len(drivers_by_block),
            "drivers_by_block": drivers_by_block
        }
    
    block_id = list(drivers_by_block.keys())[0]
    block_drivers = drivers_by_block[block_id]
    
    if len(block_drivers) == 1:
        return {
            "winner": block_drivers[0],
            "execution_order": block_drivers,
            "blocked_drivers": [],
            "race_type": "none",
            "block_id": block_id
        }
    
    winner = block_drivers[-1]
    overwritten = block_drivers[:-1]
    
    subset_pairs = []
    superset_pairs = []
    
    for i, drv_earlier in enumerate(block_drivers):
        for j, drv_later in enumerate(block_drivers):
            if i >= j:
                continue
            
            cond_earlier = drv_earlier.get('cond', '')
            cond_later = drv_later.get('cond', '')
            
            if is_condition_subset(cond_earlier, cond_later):
                subset_pairs.append({
                    'earlier': drv_earlier,
                    'earlier_idx': i,
                    'later': drv_later,
                    'later_idx': j,
                    'relationship': 'later_is_subset_of_earlier'
                })
            
            elif is_condition_subset(cond_later, cond_earlier):
                superset_pairs.append({
                    'earlier': drv_earlier,
                    'earlier_idx': i,
                    'later': drv_later,
                    'later_idx': j,
                    'relationship': 'later_is_superset_of_earlier'
                })
    
    if subset_pairs:
        return {
            "winner": winner,
            "execution_order": block_drivers,
            "overwritten_drivers": overwritten,
            "subset_overwrites": subset_pairs,
            "race_type": "within_block_unconditional_overwrite",
            "block_id": block_id,
            "note": "Later driver has SUBSET condition - unconditionally overwrites earlier driver"
        }
    
    elif superset_pairs:
        return {
            "winner": winner,
            "execution_order": block_drivers,
            "overwritten_drivers": overwritten,
            "superset_pairs": superset_pairs,
            "race_type": "within_block_default_override",
            "block_id": block_id,
            "note": "Default-then-override pattern detected"
        }
    
    else:
        return {
            "winner": winner,
            "execution_order": block_drivers,
            "overwritten_drivers": overwritten,
            "race_type": "within_block_sequential",
            "block_id": block_id,
            "note": "Sequential execution within block - no subset relationships"
        }

def get_expected_update_cycle(wave, drv, curr_i, clock_sig):
    assign_type = (drv.get("assign_type") or "").lower()

    if assign_type == "blocking" or not clock_sig:
        return curr_i

    edges = get_edge_type(drv)

    for j in range(curr_i + 1, len(wave)):
        if "posedge" in edges and is_posedge(wave, clock_sig, j):
            return j

    return None

def evaluate_driver_overwrite_conditions(
    sig,
    i,
    wave,
    drivers,
    fsm_regs,
    fsm_enc,
    clock_sig,
    row_to_cycle=None,
    enum_map=None
):
    rows = []
    observed = parse_literal_token(get_signal_value(sig, wave[i]))
    curr_row = expand_row_with_aliases(wave[i])
    curr_row = convert_binary_fsm_states(curr_row, fsm_regs)

    # ── CRITICAL: Inject FSM enum name→value mappings into curr_row ──
    # Without this, eval_expr cannot resolve state names like W_IDLE,
    # W_ADDR, W_RESP in comparisons like (w_state == W_RESP), causing
    # FSM equality checks to fail and produce impossible results.
    if enum_map:
        for name, val in enum_map.items():
            if name not in curr_row:
                curr_row[name] = val
    
    cycle_num = row_to_cycle.get(i, i) if row_to_cycle else i

    for d_idx, drv in enumerate(drivers):
        cond = drv.get("cond", "").strip()
        rhs  = drv.get("rhs", "").strip()

        terms = split_conditions(cond)
        cond_eval = True
        true_terms = []

        for t in terms:
            v = eval_expr(t, curr_row, fsm_regs=fsm_regs, fsm_enc=fsm_enc)
            v_bool = (v is True) or (v == 1)

            if v_bool:
                true_terms.append(t)
            else:
                cond_eval = False
                break

        rhs_val = None
        rhs_source = "unresolved"
        if cond_eval:
            rhs_val = eval_rhs_expression(rhs, curr_row)
            if rhs_val is not None:
                rhs_source = "eval_rhs_expression"
            
            if rhs_val is None:
                rhs_val = parse_literal_token(rhs)
                if rhs_val is not None:
                    rhs_source = "literal"
            
            if rhs_val is None:
                rhs_val = eval_expr(rhs, curr_row, fsm_regs=fsm_regs, fsm_enc=fsm_enc)
                if rhs_val is not None:
                    rhs_source = "eval_expr"

            # Normalize scalar RHS to 0/1 when the observed signal is scalar.
            # This avoids Python bitwise "~" artifacts like ~0 -> -1.
            if isinstance(rhs_val, bool):
                rhs_val = int(rhs_val)
            if (
                isinstance(rhs_val, int)
                and observed in (0, 1)
                and rhs_val not in (0, 1)
            ):
                rhs_val = rhs_val & 1

        rows.append({
            "driver_idx": d_idx,
            "cond": cond,
            "cond_eval": cond_eval,
            "true_terms": true_terms,
            "rhs": rhs,
            "rhs_val": rhs_val,
            "rhs_source": rhs_source,
            "observed": observed,
            "always_block_id": drv.get("always_block_id"),
        })

    true_rows = [r for r in rows if r["cond_eval"]]

    if not true_rows:
        return {
            "verdict": "NO_DRIVER_CONDITION_TRUE",
            "hit": False,
            "rows": rows
        }

    exec_order = analyze_execution_order(true_rows, drivers)
    exp_i = get_expected_update_cycle(wave, true_rows[0], i, clock_sig)

    if exp_i is not None and exp_i < len(wave):
        raw_value = get_signal_value(sig, wave[exp_i])
        observed_next = parse_literal_token(raw_value)
    else:
        observed_next = None

    # Waveform-consistent fallback for unresolved RHS:
    # if a condition is TRUE but RHS expression could not be numerically resolved,
    # use observed waveform value at expected update (or current observed) so RCA
    # can remain binary instead of collapsing to None.
    fallback_val = observed_next if observed_next is not None else observed
    if fallback_val is not None:
        by_idx = {r.get("driver_idx"): r for r in rows}
        for tr in true_rows:
            if tr.get("rhs_val") is None:
                tr["rhs_val"] = fallback_val
                tr["rhs_source"] = "waveform_observed_fallback"
                d_idx = tr.get("driver_idx")
                if d_idx in by_idx:
                    by_idx[d_idx]["rhs_val"] = fallback_val
                    by_idx[d_idx]["rhs_source"] = "waveform_observed_fallback"

    if len(true_rows) == 1:
        driver = true_rows[0]
        
        if (driver["rhs_val"] is not None and
            observed_next is not None and
            driver["rhs_val"] != observed_next):
            return {
                "verdict": "BUG_CANDIDATE",
                "hit": True,
                "winner": driver,
                "overwritten": [],
                "expected_cycle": exp_i,
                "observed_next": observed_next,
                "execution_order": exec_order,
                "rows": rows
            }
        else:
            return {
                "verdict": "CONSISTENT_UPDATE",
                "hit": True,
                "winner": driver,
                "expected_cycle": exp_i,
                "execution_order": exec_order,
                "rows": rows
            }
    
    matching_drivers = []
    non_matching_drivers = []
    
    for driver in true_rows:
        if driver["rhs_val"] == observed_next:
            matching_drivers.append(driver)
        else:
            non_matching_drivers.append(driver)
    
    assign_types = set()
    for driver in true_rows:
        drv_info = drivers[driver["driver_idx"]]
        assign_type = drv_info.get("assign_type", "").lower()
        if assign_type:
            assign_types.add(assign_type)
    
    if "blocking" in assign_types and "nonblocking" in assign_types:
        blocking_drivers = []
        nonblocking_drivers = []
        
        for driver in true_rows:
            drv_info = drivers[driver["driver_idx"]]
            assign_type = drv_info.get("assign_type", "").lower()
            
            if assign_type == "blocking":
                blocking_drivers.append(driver)
            elif assign_type == "nonblocking":
                nonblocking_drivers.append(driver)
        
        return {
            "verdict": "MIXED_BLOCKING_NONBLOCKING",
            "hit": True,
            "blocking_drivers": blocking_drivers,
            "nonblocking_drivers": nonblocking_drivers,
            "all_drivers": true_rows,
            "total_drivers": len(true_rows),
            "blocking_count": len(blocking_drivers),
            "nonblocking_count": len(nonblocking_drivers),
            "expected_cycle": exp_i,
            "observed_next": observed_next,
            "execution_order": exec_order,
            "rows": rows
        }
    
    race_type = exec_order.get('race_type')
    
    if race_type == 'within_block_unconditional_overwrite':
        winner = exec_order.get('winner')
        subset_overwrites = exec_order.get('subset_overwrites', [])
        
        if winner:
            return {
                "verdict": "EXECUTION_ORDER_BUG",
                "hit": True,
                "winner": winner,
                "overwritten_drivers": exec_order.get('overwritten_drivers', []),
                "subset_overwrites": subset_overwrites,
                "all_drivers": true_rows,
                "total_drivers": len(true_rows),
                "block_id": exec_order.get('block_id'),
                "expected_cycle": exp_i,
                "observed_next": observed_next,
                "execution_order": exec_order,
                "rows": rows
            }
    
    if race_type == 'within_block_sequential':
        return {
            "verdict": "CONSISTENT_UPDATE",
            "hit": True,
            "winner": exec_order.get('winner'),
            "expected_cycle": exp_i,
            "observed_next": observed_next,
            "execution_order": exec_order,
            "rows": rows
        }
    
    # default: treat as consistent update
    return {
        "verdict": "CONSISTENT_UPDATE",
        "hit": True,
        "winner": exec_order.get('winner'),
        "expected_cycle": exp_i,
        "observed_next": observed_next,
        "execution_order": exec_order,
        "rows": rows
    }


def resolve_waveform_signal(sig, wave, logic):
    """If sig has no waveform data, try its aliases."""
    vals = [
        parse_literal_token(get_signal_value(sig, row))
        for row in wave
        if parse_literal_token(get_signal_value(sig, row)) is not None
    ]
    if vals:
        return sig, vals

    for alias in logic.keys():
        alias_vals = [
            parse_literal_token(get_signal_value(alias, row))
            for row in wave
            if parse_literal_token(get_signal_value(alias, row)) is not None
        ]
        if alias_vals:
            return alias, alias_vals

    return None, []

# ============================================================
# MULTI-PHASE ANALYSIS WITH RUNTIME X ONLY
# ============================================================

def reason_stuck_signal_multi_phase(
    sig,
    wave,
    drivers,
    fsm_regs,
    fsm_enc,
    logic=None,
    hdr=None,
    *,
    cycle_to_row=None,
    row_to_cycle=None,
    clock_sig=None,
    target_cycle=None,
    cycle_window=10,
    enum_map=None,
    view=None,          # WaveformView — enables PHASE 4 predicate backtracking
    expected_value=1,   # protocol-expected value (1 for AXI assert signals)
):
    """
    Multi-phase analysis - COLLECT ALL ISSUES (don't early return to avoid hiding bugs).
    
    If target_cycle is provided, only analyze +/-cycle_window around that cycle.
    Otherwise, scan full waveform (backward compatible).
    """
    """Multi-phase analysis - COLLECT ALL ISSUES (don't early return to avoid hiding bugs)."""
    
    all_findings = []  # Collect all issues found across all phases
    
    
    # ========================================
    # PHASE 1: STRUCTURAL BUGS (TIER 2) - ALWAYS RUN
    # ========================================
    structural_bug = detect_structural_bugs(drivers, sig)
    
    if structural_bug:
        all_findings.append({
            "verdict": structural_bug["type"],
            "tier": VERDICT_TIERS.get(structural_bug["type"], 2),
            "severity": "CRITICAL",
            "confidence": "PROVEN",
            "explanation": format_structural_bug_explanation(structural_bug, sig, drivers=drivers),
            "phase": "STRUCTURAL"
        })
    
    # ========================================
    # PHASE 2: LOGICAL ANALYSIS (FILTERED) - ALWAYS RUN
    # ========================================
    logical_drivers = filter_drivers(drivers, mode=AnalysisMode.LOGICAL)
    
    if logical_drivers:
        # Delegate to original function for detailed analysis
# Delegate to original function for detailed analysis
        result = reason_stuck_signal(
            sig=sig,
            wave=wave,
            drivers=logical_drivers,
            fsm_regs=fsm_regs,
            fsm_enc=fsm_enc,
            logic=logic,
            cycle_to_row=cycle_to_row,
            row_to_cycle=row_to_cycle,
            clock_sig=clock_sig,
            target_cycle=target_cycle,  # Pass target cycle through
            cycle_window=cycle_window,
            enum_map=enum_map
        )
        
        # Only add non-trivial findings
        if result and result.get("verdict") not in ["DESIGNER_INTENT", "NO_WAVEFORM_DATA", "NO_RTL_DRIVERS"]:
            result["phase"] = "LOGICAL"
            all_findings.append(result)
    
    # ========================================
    # PHASE 3: DERIVED SIGNAL CHECK (INFORMATIONAL)
    # ========================================
    if logic:
        derived = detect_derived_signal(sig, drivers, logic)
        if derived:
            all_findings.append({
                "verdict": "DERIVED_SIGNAL",
                "tier": 6,
                "severity": "INFO",
                "confidence": "PROVEN",
                "explanation": format_derived_signal_explanation(sig, derived),
                "phase": "DERIVED"
            })
    
    # ========================================
    # PHASE 4: PREDICATE BACKTRACKING (MODE-A / MODE-B)
    # ========================================
    if _PREDICATE_BACKTRACK_AVAILABLE and view is not None and logic and target_cycle is not None:
        analysis_cycle  = target_cycle
        analysis_mode   = classify_analysis_mode(sig, logic, view, analysis_cycle, expected_value)

        if analysis_mode == MODE_A:
            mode_trace = trace_unexpected_driver_activation(sig, logic, view, analysis_cycle)
        elif analysis_mode == MODE_B:
            mode_trace = trace_enable_failure(sig, logic, view, analysis_cycle)
        else:
            mode_trace = None

        if mode_trace:
            all_findings.append({
                "verdict":       f"PREDICATE_BACKTRACK_{analysis_mode}",
                "tier":          3,        # same priority as FSM-BUG findings
                "severity":      "CRITICAL",
                "confidence":    "PROVEN",
                "explanation":   mode_trace["formatted_trace"],
                "phase":         "PREDICATE",
                "mode_analysis": mode_trace["analysis_mode"],
                "case_analysis": mode_trace["case_analysis"],
                "hard_stop":     mode_trace["hard_stop"],
                "chain":         mode_trace["chain"],
            })

    # ========================================
    # RETURN: Prioritize by tier, report ALL findings
    # ========================================
    if not all_findings:
        return {
            "verdict": "DESIGNER_INTENT",
            "tier": VERDICT_TIERS.get("DESIGNER_INTENT", 7),
            "severity": "INFO",
            "confidence": "PROVEN",
            "explanation": "No issues detected"
        }
    
    # Sort by tier (lower tier = more critical)
    all_findings.sort(key=lambda x: x.get("tier", 99))
    
    # Return the MOST CRITICAL issue as primary verdict
    primary = all_findings[0]
    
    # If multiple issues found, append summary of additional issues
    if len(all_findings) > 1:
        additional_summary = f"\n\n{'='*79}\n"
        additional_summary += f"  ADDITIONAL ISSUES DETECTED ({len(all_findings) - 1})\n"
        additional_summary += f"{'='*79}\n"
        additional_summary += "\nThis signal has multiple problems:\n\n"
        
        for idx, finding in enumerate(all_findings, 1):
            tier = finding.get('tier', 99)
            verdict = finding.get('verdict', 'UNKNOWN')
            severity = finding.get('severity', '')
            phase = finding.get('phase', '')
            prefix = TIER_PREFIXES.get(tier, "[?]")
            
            if idx == 1:
                additional_summary += f"  [{idx}] {prefix} {verdict} [{severity}] <- PRIMARY (Tier {tier})\n"
            else:
                additional_summary += f"  [{idx}] {prefix} {verdict} [{severity}] (Tier {tier})\n"
        
        additional_summary += f"\n{'-'*79}\n"
        additional_summary += "RECOMMENDATION:\n"
        additional_summary += "  * Address the PRIMARY issue first (lowest tier = highest priority)\n"
        additional_summary += "  * Re-run analysis after each fix to see remaining issues\n"
        additional_summary += "  * Some issues may be symptoms of the primary root cause\n"
        additional_summary += f"{'='*79}\n"
        
        # Append to primary explanation
        primary["explanation"] = primary.get("explanation", "") + additional_summary
        primary["additional_issues"] = len(all_findings) - 1
        primary["all_findings"] = all_findings  # Store all for programmatic access
    
    return primary


def reason_stuck_signal(
    sig,
    wave,
    drivers,
    fsm_regs,
    fsm_enc,
    logic=None,
    *,
    cycle_to_row=None,
    row_to_cycle=None,
    clock_sig=None,
    target_cycle=None,
    cycle_window=10,
    enum_map=None
):
    """
    FSM-AWARE ANALYSIS: Analyze a stuck signal and find root cause.
    Enhanced to provide FSM-specific explanations when applicable.
    
    Returns verdict with tier, severity, confidence.
    """
# Determine analysis range
    if target_cycle is not None:
        # Focused analysis: only analyze +/-cycle_window around target_cycle
        if cycle_to_row:
            # Convert target cycle to row index
            target_row = cycle_to_row.get(target_cycle, target_cycle)
        else:
            target_row = target_cycle
        
        start_i = max(0, target_row - cycle_window)
        end_i = min(len(wave) - 1, target_row + cycle_window)
    else:
        # Full waveform scan (backward compatible)
        start_i = 0
        end_i = len(wave) - 1
    
    resolved_sig, observed_vals = resolve_waveform_signal(sig, wave, logic)


    if not observed_vals:
        return {
            "verdict": "NO_WAVEFORM_DATA",
            "tier": VERDICT_TIERS.get("NO_WAVEFORM_DATA", 99),
            "severity": "ERROR",
            "confidence": "PROVEN",
            "explanation": f"No waveform data for {sig} or its aliases"
        }

    sig = resolved_sig

    stuck_val = observed_vals[0]
    expected_val = 1 - stuck_val

    candidate_drivers = []
    
    for d in drivers:
        if should_skip_driver(d, debug=False):
            continue
        candidate_drivers.append(d)
    
    if not candidate_drivers:
        return {
            "verdict": "NO_RTL_DRIVERS",
            "tier": VERDICT_TIERS.get("NO_RTL_DRIVERS", 99),
            "severity": "ERROR",
            "confidence": "PROVEN",
            "explanation": "No RTL drivers found after filtering"
        }
    
    # Build FSM signal set for detection
    fsm_signal_set = set()
    if fsm_regs:
        if isinstance(fsm_regs, tuple):
            fsm_signal_set.update(fsm_regs[0])
            if len(fsm_regs) > 1:
                fsm_signal_set.update(fsm_regs[1])
        else:
            fsm_signal_set.update(fsm_regs)
    
    # Check for cross-block races
    block_ids = {
        d.get("always_block_id")
        for d in candidate_drivers
        if d.get("always_block_id") is not None
    }

    if len(block_ids) > 1:
        return {
            "verdict": "CROSS_BLOCK_RACE",
            "tier": VERDICT_TIERS.get("CROSS_BLOCK_RACE", 2),
            "severity": "CRITICAL",
            "confidence": "PROVEN",
            "explanation": f"""
===========================================================================
CROSS-ALWAYS-BLOCK RACE DETECTED
===========================================================================

Signal: {sig}

Driven by multiple always blocks: {sorted(block_ids)}

This is unsafe because:
- Conditions may overlap
- NBA ordering across blocks is undefined
- Behavior is simulator-dependent

RECOMMENDATION:
- Merge logic into a single always_ff block

===========================================================================
"""
        }

    has_mutex_drivers = has_mutually_exclusive_drivers(drivers)

    designer_blocks = []
    execution_order_bugs = []
    overwritten_bugs = []
    candidate_bugs = []
    mixed_bugs = []
    
    driver_ever_true = {i: False for i in range(len(candidate_drivers))}
    driver_true_cycles = {i: set() for i in range(len(candidate_drivers))}

    for i in range(start_i, end_i + 1):
        cycle_num = row_to_cycle.get(i, i) if row_to_cycle else i
        base_driver = None
        superset_driver = None
        curr_observed = parse_literal_token(get_signal_value(sig, wave[i]))
        if curr_observed is None:
            continue



        overwrite_result = evaluate_driver_overwrite_conditions(
            sig=sig,
            i=i,
            wave=wave,
            drivers=candidate_drivers,
            fsm_regs=fsm_regs,
            fsm_enc=fsm_enc,
            clock_sig=clock_sig,
            row_to_cycle=row_to_cycle,
            enum_map=enum_map
        )
        
        if not overwrite_result.get("hit"):
            continue

        verdict = overwrite_result["verdict"]
        expected_cycle = overwrite_result.get("expected_cycle")
        observed_next = overwrite_result.get("observed_next")
        exec_order = overwrite_result.get("execution_order", {})

        if overwrite_result["rows"]:
            for r in overwrite_result["rows"]:
                if r["cond_eval"]:
                    driver_ever_true[r["driver_idx"]] = True
                    driver_true_cycles[r["driver_idx"]].add(cycle_num)

        if verdict == "EXECUTION_ORDER_BUG":
            execution_order_bugs.append({
                "cycle": cycle_num,
                "winner": overwrite_result.get("winner"),
                "overwritten_drivers": overwrite_result.get("overwritten_drivers", []),
                "subset_overwrites": overwrite_result.get("subset_overwrites", []),
                "total": overwrite_result.get("total_drivers", 0),
                "block_id": overwrite_result.get("block_id"),
                "observed_next": observed_next,
                "exec_order": exec_order
            })

        elif verdict == "MIXED_BLOCKING_NONBLOCKING":
            mixed_bugs.append({
                "cycle": cycle_num,
                "blocking_drivers": overwrite_result.get("blocking_drivers", []),
                "nonblocking_drivers": overwrite_result.get("nonblocking_drivers", []),
                "total": overwrite_result.get("total_drivers", 0),
                "blocking_count": overwrite_result.get("blocking_count", 0),
                "nonblocking_count": overwrite_result.get("nonblocking_count", 0),
                "observed_next": observed_next,
                "exec_order": exec_order
            })



        elif verdict == "BUG_CANDIDATE":
            if not has_mutex_drivers:
                all_drivers = overwrite_result.get("all_drivers", [])
                total_drivers = overwrite_result.get("total_drivers", 0)
                winner = overwrite_result.get("winner")
                
                candidate_bugs.append({
                    "cycle": cycle_num,
                    "all_drivers": all_drivers,
                    "total_drivers": total_drivers,
                    "winner": winner,
                    "expected_cycle": expected_cycle,
                    "observed_next": observed_next,
                    "exec_order": exec_order
                })

    # Check for drivers whose conditions were never true
    for drv_idx, drv in enumerate(candidate_drivers):
        if not driver_ever_true[drv_idx]:
            cond = drv.get("cond", "").strip()
            terms = split_conditions(cond)
            designer_blocks.append({
                "condition": cond,
                "blocked_terms": terms,
                "reason": "CONDITION_NEVER_TRUE"
            })
    
    # Inference for BUG_CANDIDATE -> EXECUTION_ORDER_BUG
    if not execution_order_bugs and candidate_bugs:
        for bug_candidate in candidate_bugs:
            winner = bug_candidate.get("winner")
            if not winner:
                continue
            
            winner_idx = winner.get("driver_idx")
            winner_cond = candidate_drivers[winner_idx].get("cond", "").strip()
            winner_terms = set(split_conditions(winner_cond))
            
            for other_idx, other_drv in enumerate(candidate_drivers):
                if other_idx == winner_idx:
                    continue
                
                other_cond = other_drv.get("cond", "").strip()
                other_terms = set(split_conditions(other_cond))
                base_driver = None
                superset_driver = None
                subset_relation = None

                if winner_terms < other_terms:
                    base_driver = winner
                    base_cond = winner_cond
                    superset_driver = {
                        "driver_idx": other_idx,
                        "cond": other_cond,
                        "rhs_val": parse_literal_token(other_drv.get("rhs", ""))
                    }
                    subset_relation = {
                        "earlier": {"driver_idx": winner_idx, "cond": winner_cond},
                        "later": {"driver_idx": other_idx, "cond": other_cond}
                    }
                elif other_terms < winner_terms:
                    base_driver = {
                        "driver_idx": other_idx,
                        "cond": other_cond,
                        "rhs_val": parse_literal_token(other_drv.get("rhs", ""))
                    }
                    base_cond = other_cond
                    superset_driver = winner
                    subset_relation = {
                        "earlier": {"driver_idx": other_idx, "cond": other_cond},
                        "later": {"driver_idx": winner_idx, "cond": winner_cond}
                    }
                else:
                    continue
                
                if is_simple_condition(base_cond):
                    continue
                
                external_signals = []
                for cond in [base_cond, superset_driver['cond']]:
                    signal_names = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', cond)
                    for sig_name in signal_names:
                        if logic and sig_name not in logic and sig_name not in ['ARESETn', 'ACLK', 'clk']:
                            if sig_name not in external_signals:
                                external_signals.append(sig_name)
                
                if len(external_signals) == 0:
                    continue
                
                if driver_true_cycles[winner_idx].isdisjoint(
                    driver_true_cycles[other_idx]
                ):
                    continue

                execution_order_bugs.append({
                    "cycle": bug_candidate["cycle"],
                    "winner": superset_driver,
                    "overwritten_drivers": [base_driver],
                    "subset_overwrites": [subset_relation],
                    "total": 2,
                    "block_id": candidate_drivers[winner_idx].get("always_block_id"),
                    "observed_next": bug_candidate.get("observed_next"),
                    "expected_cycle": bug_candidate.get("expected_cycle"),
                    "exec_order": bug_candidate.get("exec_order", {}),
                    "inferred_from_pattern": True,
                    "external_signals": external_signals
                })
                break
            
            if execution_order_bugs:
                break
# Priority 0: EXECUTION_ORDER_BUG (with FSM awareness)
    if execution_order_bugs:
        bug = execution_order_bugs[0]
        is_inferred = bug.get('inferred_from_pattern', False)
        
        fsm_pattern = categorize_fsm_bug_pattern(
            bug, candidate_drivers, fsm_signal_set, wave, bug['cycle']
        )
        
        # =====================================================
        # FILTER: Check if FSM_OUTPUT_MASKED is valid handshake
        # =====================================================
        if fsm_pattern == 'FSM_OUTPUT_MASKED':
            # Check if the overwritten driver's value EVER appeared in waveform
            overwritten_drivers = bug.get('overwritten_drivers', [])
            if overwritten_drivers:
                base_drv = overwritten_drivers[0]
                base_rhs_val = base_drv.get('rhs_val')
                
                # Check if this value EVER appeared in waveform
                value_ever_appeared = False
                for check_i in range(start_i, end_i + 1):
                    check_val = parse_literal_token(get_signal_value(sig, wave[check_i]))
                    if check_val == base_rhs_val:
                        value_ever_appeared = True
                        break
                
                if value_ever_appeared:
                    # Value DID appear! This is VALID sequential behavior!
                    fsm_pattern = None  # Clear FSM pattern
                    
                    # Build explanation
                    explanation = f"""
===========================================================================
VALID HANDSHAKE PATTERN (Not a Bug)
===========================================================================

Signal: {sig}

This signal correctly transitions through multiple states:
  - Base condition sets signal to {base_rhs_val} (value appeared in waveform)
  - Extended condition clears/changes signal (handshake complete)

This is INTENTIONAL sequential behavior, not a race condition.

Drivers fire at DIFFERENT clock edges (not simultaneously):
  - Cycle {bug['cycle']}: Base driver fired, signal went to {base_rhs_val}
  - Later cycle: Extended driver fired, signal transitioned

This is correct FSM output sequencing.

===========================================================================
"""
                    
                    return {
                        "verdict": "DESIGNER_INTENT",
                        "tier": VERDICT_TIERS.get("DESIGNER_INTENT", 7),
                        "severity": "INFO",
                        "confidence": "PROVEN",
                        "explanation": explanation
                    }
                # else: value never appeared -> continue to flag as bug
        
        # Determine verdict and tier
        if fsm_pattern:
            verdict = fsm_pattern
            tier = VERDICT_TIERS.get(fsm_pattern, 3)
            
            explanation = generate_fsm_aware_explanation(
                sig=sig,
                bug_info=bug,
                drivers=candidate_drivers,
                fsm_signals=fsm_signal_set,
                fsm_pattern=fsm_pattern,
                wave=wave,
                cycle=bug['cycle'],
                next_cycle=bug.get('expected_cycle', bug['cycle'] + 1),
                observed_next=bug['observed_next']
            )
        else:
            verdict = "EXECUTION_ORDER_BUG"
            tier = VERDICT_TIERS.get("EXECUTION_ORDER_BUG", 4)
            
            current_cycle = bug['cycle']
            next_cycle = bug.get('expected_cycle', current_cycle + 1)
            
            # NEW IMPROVED EXPLANATION
            explanation = format_improved_execution_order_explanation(
                sig=sig,
                bug_info=bug,
                drivers=candidate_drivers,
                cycle=current_cycle,
                next_cycle=next_cycle,
                observed_next=bug['observed_next']
            )
                
        return {
            "verdict": verdict,
            "tier": tier,
            "severity": "HIGH",
            "confidence": "INFERRED" if is_inferred else "PROVEN",
            "explanation": explanation
        }
    
    if mixed_bugs:
        bug = mixed_bugs[0]
        explanation = f"""
===========================================================================
ROOT CAUSE: Mixed Blocking/Non-Blocking (CRITICAL!)
===========================================================================

Signal: {sig}
Cycle: {bug['cycle']}

BLOCKING: {bug['blocking_count']} driver(s)
NON-BLOCKING: {bug['nonblocking_count']} driver(s)

PROBLEM: Undefined behavior - simulator-dependent!
FIX: Use ONLY <= in always_ff blocks.

===========================================================================
"""
        return {
            "verdict": "MIXED_BLOCKING_NONBLOCKING",
            "tier": VERDICT_TIERS.get("MIXED_BLOCKING_NONBLOCKING", 2),
            "severity": "CRITICAL",
            "confidence": "PROVEN",
            "explanation": explanation
        }

    # =====================================================
    # FILTER: Valid priority overwrite (not a bug)
    # =====================================================
    if overwritten_bugs:
        bug = overwritten_bugs[0]

        base_drv = bug.get('base_driver') or {}
        overwrite_drv = bug.get('overwrite_driver') or {}

        # -------------------------------------------------
        # NEW: If drivers are mutually exclusive → designer intent
        # -------------------------------------------------
        if base_drv and overwrite_drv:
            cond1 = base_drv.get('cond', '')
            cond2 = overwrite_drv.get('cond', '')

            if are_mutually_exclusive_conditions(cond1, cond2):
                return {
                    "verdict": "DESIGNER_INTENT",
                    "tier": VERDICT_TIERS.get("DESIGNER_INTENT", 7),
                    "severity": "INFO",
                    "confidence": "PROVEN",
                    "explanation": "Designer intent (mutually exclusive conditions)"
                }

        # -------------------------------------------------
        # Intentional priority overwrite (handshake sequencing)
        # -------------------------------------------------
        if base_drv and overwrite_drv:
            if bug.get('is_subset_relation') and bug.get('same_block'):

                base_rhs = base_drv.get('rhs_val')
                over_rhs = overwrite_drv.get('rhs_val')

                base_seen = False
                over_seen = False

                for check_i in range(start_i, end_i + 1):
                    val = parse_literal_token(get_signal_value(sig, wave[check_i]))
                    if val == base_rhs:
                        base_seen = True
                    if val == over_rhs:
                        over_seen = True
                    if base_seen and over_seen:
                        break

                if base_seen and over_seen:
                    return {
                        "verdict": "DESIGNER_INTENT",
                        "tier": VERDICT_TIERS.get("DESIGNER_INTENT", 7),
                        "severity": "INFO",
                        "confidence": "PROVEN",
                        "explanation": "Designer intent"
                    }

        # -------- real overwrite case --------
        explanation = f"""
    ===========================================================================
    [RACE] OVERWRITTEN_UPDATE
    ===========================================================================

    Signal: {sig}
    Cycle: {bug['cycle']}

    Base driver fired:
    Condition: {base_drv.get('cond')}
    RHS: {base_drv.get('rhs_val')}

    Overwriting driver fired:
    Condition: {overwrite_drv.get('cond')}
    RHS: {overwrite_drv.get('rhs_val')}

    Observed waveform value: {bug.get('observed_val')}

    ===========================================================================
    """

        return {
            "verdict": "OVERWRITTEN_UPDATE",
            "tier": VERDICT_TIERS.get("OVERWRITTEN_UPDATE", 5),
            "severity": "LOW",
            "confidence": "PROVEN",
            "explanation": explanation
        }


    if candidate_bugs:
        bug = candidate_bugs[0]
        if bug['total_drivers'] > 1:
            explanation = f"""
===========================================================================
ROOT CAUSE: Race + Value Mismatch
===========================================================================

Signal: {sig}
Cycle: {bug['cycle']}

{bug['total_drivers']} drivers fired, NONE matched!

===========================================================================
"""
            return {
                "verdict": "BUG_CANDIDATE",
                "tier": 4,
                "severity": "MEDIUM",
                "confidence": "PROVEN",
                "explanation": explanation
            }

    if designer_blocks:
        explanation = f"""
===========================================================================
DESIGNER_INTENT: Conditions Never True
===========================================================================

Signal: {sig}

Some driver conditions were never true during simulation.

===========================================================================
"""
        return {
            "verdict": "DESIGNER_INTENT",
            "tier": VERDICT_TIERS.get("DESIGNER_INTENT", 7),
            "severity": "INFO",
            "confidence": "PROVEN",
            "explanation": explanation
        }

    return {
        "verdict": "DESIGNER_INTENT",
        "tier": VERDICT_TIERS.get("DESIGNER_INTENT", 7),
        "severity": "INFO",
        "confidence": "PROVEN",
        "explanation": "No issues detected"
    }

# ============================================================
# INTERACTIVE MENU SYSTEM
# ============================================================

def clear_screen():
    """Clear the console screen."""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the tool header."""
    print("=" * 80)
    print("   FSM-AWARE INTERACTIVE ROOT CAUSE ANALYSIS TOOL")
    print("   Deterministic Structural + FSM Root Cause Analysis")

    print("=" * 80)
    print()

def list_signals_with_drivers(logic, wave, hdr):
    """List all signals with their driver counts and waveform status."""
    signals_info = []
    
    for sig in sorted(logic.keys()):
        driver_count = 0
        for drv in logic[sig]:
            if not should_skip_driver(drv):
                driver_count += 1
        
        in_waveform = sig in hdr
        
        value_info = ""
        if in_waveform and wave:
            values = set()
            for row in wave:
                val = parse_literal_token(get_signal_value(sig, row))
                if val is not None:
                    values.add(val)
            if values:
                value_info = f" (values: {sorted(values)})"
        
        signals_info.append({
            'name': sig,
            'drivers': driver_count,
            'in_waveform': in_waveform,
            'value_info': value_info
        })
    
    return signals_info

def display_signal_list(signals_info, page=0, page_size=20):
    """Display a paginated list of signals."""
    total_signals = len(signals_info)
    total_pages = (total_signals + page_size - 1) // page_size

    start_idx = page * page_size
    end_idx = min(start_idx + page_size, total_signals)

    print(f"\nSignals with RTL Drivers (Page {page+1}/{total_pages}):")
    print("-" * 80)
    print(f"{'#':<5} {'Signal':<30} {'Drivers':<10} {'Status':<30}")
    print("-" * 80)

    for i in range(start_idx, end_idx):
        sig_info = signals_info[i]
        num = i + 1
        name = sig_info['name']
        drivers = sig_info['drivers']

        if sig_info['in_waveform']:
            status = "[OK] In waveform"
        else:
            status = "[--] Not in waveform"

        print(f"{num:<5} {name:<30} {drivers:<10} {status:<30}")

    print("-" * 80)
    print(f"Total: {total_signals} signals")
    print()


def analyze_single_signal(sig, wave, logic, fsm_regs, fsm_enc, cycle_to_row, row_to_cycle, clock_sig, hdr, use_multi_phase=True, enum_map=None):
    """Analyze a single signal and display results."""
    print("\n" + "=" * 80)
    print(f"   ANALYZING: {sig}")
    print("=" * 80)
    print()
    
    if sig not in logic:
        print("[ERROR] No RTL drivers found for this signal.")
        return
    
    drivers = logic[sig]
    candidate_drivers = [d for d in drivers if not should_skip_driver(d)]
    
    print(f"Driver Information:")
    print(f"   Total drivers: {len(drivers)}")
    print(f"   Active drivers (non-skip): {len(candidate_drivers)}")
    print()
    
    if candidate_drivers:
        print("Active Drivers:")
        for idx, drv in enumerate(candidate_drivers):
            block_id = drv.get('always_block_id', '?')
            cond = drv.get('cond', '')
            rhs = drv.get('rhs', '')
            assign_type = drv.get('assign_type', '')
            print(f"   [{idx}] Block {block_id} ({assign_type})")
            print(f"       Condition: {cond if cond else '(always)'}")
            print(f"       RHS: {rhs}")
        print()
    
    print("Running analysis...")
    print()
    
    res = reason_stuck_signal_multi_phase(
        sig,
        wave,
        drivers,
        fsm_regs,
        fsm_enc,
        logic,
        hdr,
        cycle_to_row=cycle_to_row,
        row_to_cycle=row_to_cycle,
        clock_sig=clock_sig,
        enum_map=enum_map
    )
    
    # Get verdict details
    verdict = res.get("verdict", "UNKNOWN")
    tier = res.get("tier", 99)
    severity = res.get("severity", "")
    confidence = res.get("confidence", "")
    
    # Format prefix by tier
    prefix = TIER_PREFIXES.get(tier, "[UNKNOWN]")
    
    # Display verdict
    print(f"{prefix} {verdict} [{severity}] [{confidence}]")
    print()
    
    # Display explanation
    explanation = res.get("explanation", "No explanation available")
    print(explanation)
    print()


def interactive_menu():
    """Main interactive menu."""
    if len(sys.argv) < 3:
        print("Usage: python analyse_interactive_runtime_x_only.py <waveform.csv> <backtracking.csv>")
        sys.exit(1)

    print("Loading data...")
    wave, hdr, cls = load_waveform_csv(sys.argv[1])
    logic = load_backtracking_csv(sys.argv[2])
    clock_sig = detect_clock(sys.argv[1])

    # ============================================================
    # NEW: Extract signals from VIOLATION_SPECS (already loaded)
    # ============================================================
    violation_signals = set()
    primary_signals = set()
    secondary_signals = set()
        
    if VIOLATION_SPECS:
        for viol_id, viol_data in VIOLATION_SPECS.items():

            # PRIMARY signals (protocol -> RTL)
            for proto_sig in viol_data.get('primary_signals', []):
                rtl_sigs = protocol_to_rtl_signals(proto_sig, logic)
                for rtl in rtl_sigs:
                    primary_signals.add(rtl)
                    violation_signals.add(rtl)

            # SECONDARY signals (protocol -> RTL)
            for proto_sig in viol_data.get('secondary_signals', []):
                rtl_sigs = protocol_to_rtl_signals(proto_sig, logic)
                for rtl in rtl_sigs:
                    secondary_signals.add(rtl)
                    violation_signals.add(rtl)


        
        print(f"  Primary signals: {len(primary_signals)}")
        print(f"  Secondary signals: {len(secondary_signals)}")
        print(f"  Total unique signals: {len(violation_signals)}")

    backtracking_file = os.path.splitext(os.path.basename(sys.argv[2]))[0]
    rtl_name = backtracking_file
    for suffix in ['_backtracking', '_true_drivers', '_rtl', '_drivers', '_logic']:
        rtl_name = rtl_name.replace(suffix, '')
    
    enum_file = f"{rtl_name}.fsm_encodings.json"
    
    enum_map = {}
    if os.path.exists(enum_file):
        print(f"Found FSM encodings file: {enum_file}")
        enum_map = load_enum_encodings(enum_file)

    fsm_regs, fsm_states = detect_fsm_regs(cls, hdr)
    fsm_enc = build_fsm_encodings(cls, hdr, wave, enum_map=enum_map)
    cycle_to_row, row_to_cycle = build_cycle_to_row_map(wave, clock_sig)

    signals_info = list_signals_with_drivers(logic, wave, hdr)
    if not signals_info:
        print("No signals found with RTL drivers!")
        return

    current_page = 0
    page_size = 20

    while True:
        clear_screen()
        print_header()
        
        # Show violation info if available
        if VIOLATION_SPECS:
            print(f"[AXI MODE] {len(violation_signals)} violation signals loaded")
            print()
        else:
            print("[GENERIC RTL MODE] Analyzing true drivers only (no protocol violations)")
            print()
        
        display_signal_list(signals_info, current_page, page_size)

        print("Commands:")
        print("  <numbers> - Analyze signal(s): 4  OR  1,3,5  OR  2-6")
        print("  s <name>  - Search for signal by name")
        if VIOLATION_SPECS:
            print("  v         - Smart analysis: PRIMARY first, stop on bug")
            print("  vp        - Analyze PRIMARY violation signals only")
            print("  vs        - Analyze SECONDARY violation signals only")
        print("  n         - Next page")
        print("  p         - Previous page")
        print("  a         - Analyze ALL signals")
        print("  q         - Quit")
        print()

        choice = input("Enter command: ").strip()

        if choice.lower() == 'q':
            print("\nGoodbye!")
            return

        # ============================================================
        # NEW: Smart violation analysis - PRIMARY first, stop on bug
        # ============================================================
        elif choice.lower() == 'v' and VIOLATION_SPECS:
            print("\n" + "="*80)
            print("  SMART VIOLATION ANALYSIS")
            print("="*80)
            print("\nStrategy: Analyze PRIMARY signals first, stop on first bug found")
            print("          Only analyze SECONDARY if all primary signals are OK\n")
            
            # Step 1: Analyze PRIMARY signals
            primary_valid = [sig for sig in sorted(primary_signals) if sig in logic]
            primary_missing = [sig for sig in primary_signals if sig not in logic]
            
            if primary_missing:
                print(f"[WARNING] {len(primary_missing)} primary signal(s) not in backtracking:")
                for sig in primary_missing:
                    print(f"  - {sig}")
                print()
            
            if not primary_valid:
                print("[ERROR] No primary signals found in backtracking!")
                input("\nPress Enter to continue...")
                continue
            
            print(f"PHASE 1: Analyzing {len(primary_valid)} PRIMARY signal(s)...")
            print("-"*80 + "\n")
            
            bug_found = False
            bug_signal = None
            bug_result = None
            
            for idx, sig in enumerate(primary_valid, 1):
                print(f"[PRIMARY {idx}/{len(primary_valid)}] Analyzing {sig}")
                print("-" * 80)
                
                # Run analysis
                if sig not in logic:
                    print(f"  [SKIP] No drivers in backtracking")
                    print()
                    continue
                
                drivers = logic[sig]
                res = reason_stuck_signal_multi_phase(
                    sig, wave, drivers, fsm_regs, fsm_enc,
                    logic, hdr,
                    cycle_to_row=cycle_to_row,
                    row_to_cycle=row_to_cycle,
                    clock_sig=clock_sig,
                    enum_map=enum_map
                )
                
                verdict = res.get("verdict", "UNKNOWN")
                tier = res.get("tier", 99)
                severity = res.get("severity", "")
                confidence = res.get("confidence", "")
                prefix = TIER_PREFIXES.get(tier, "[?]")
                
                print(f"  {prefix} {verdict} [{severity}] [{confidence}]")
                
                # Check if this is a real bug (not DESIGNER_INTENT)
                if verdict not in ["DESIGNER_INTENT", "NO_WAVEFORM_DATA", "NO_RTL_DRIVERS"]:
                    print("\n" + "="*80)
                    print("   ROOT CAUSE FOUND IN PRIMARY SIGNAL!")
                    print("="*80)
                    bug_found = True
                    bug_signal = sig
                    bug_result = res
                    break  # STOP - found the root cause!
                else:
                    print(f"  [OK] OK - No issues detected")
                
                print()
            
            # If bug found in primary, show details and exit
            if bug_found:
                print(f"\nROOT CAUSE: {bug_signal}")
                print("="*80)
                print(bug_result.get("explanation", ""))
                print("="*80)
                print(f"\n[OK] Analysis stopped - root cause identified")
                input("\nPress Enter to continue...")
                continue
            
            # Step 2: If all primary OK, analyze SECONDARY
            print("="*80)
            print("  [OK] ALL PRIMARY SIGNALS OK")
            print("="*80)
            print("\nPHASE 2: Analyzing SECONDARY signals...")
            print("-"*80 + "\n")
            
            secondary_valid = [sig for sig in sorted(secondary_signals) if sig in logic]
            secondary_missing = [sig for sig in secondary_signals if sig not in logic]
            
            if secondary_missing:
                print(f"[WARNING] {len(secondary_missing)} secondary signal(s) not in backtracking:")
                for sig in secondary_missing:
                    print(f"  - {sig}")
                print()
            
            if not secondary_valid:
                print("[INFO] No secondary signals to analyze")
                print("\n" + "="*80)
                print("  [OK] ALL VIOLATION SIGNALS OK - NO ROOT CAUSE FOUND")
                print("="*80)
                input("\nPress Enter to continue...")
                continue
            
            for idx, sig in enumerate(secondary_valid, 1):
                print(f"[SECONDARY {idx}/{len(secondary_valid)}] Analyzing {sig}")
                print("-" * 80)
                
                if sig not in logic:
                    print(f"  [SKIP] No drivers in backtracking")
                    print()
                    continue
                
                drivers = logic[sig]
                res = reason_stuck_signal_multi_phase(
                    sig, wave, drivers, fsm_regs, fsm_enc,
                    logic, hdr,
                    cycle_to_row=cycle_to_row,
                    row_to_cycle=row_to_cycle,
                    clock_sig=clock_sig,
                    enum_map=enum_map
                )
                
                verdict = res.get("verdict", "UNKNOWN")
                tier = res.get("tier", 99)
                severity = res.get("severity", "")
                confidence = res.get("confidence", "")
                prefix = TIER_PREFIXES.get(tier, "[?]")
                
                print(f"  {prefix} {verdict} [{severity}] [{confidence}]")
                
                # Check if this is a real bug
                if verdict not in ["DESIGNER_INTENT", "NO_WAVEFORM_DATA", "NO_RTL_DRIVERS"]:
                    print("\n" + "="*80)
                    print("  [!] ROOT CAUSE FOUND IN SECONDARY SIGNAL!")
                    print("="*80)
                    bug_found = True
                    bug_signal = sig
                    bug_result = res
                    break  # STOP - found the root cause!
                else:
                    print(f"  [OK] OK - No issues detected")
                
                print()
            
            # Final report
            if bug_found:
                print(f"\nROOT CAUSE: {bug_signal}")
                print("="*80)
                print(bug_result.get("explanation", ""))
                print("="*80)
                print(f"\n[OK] Analysis stopped - root cause identified")
            else:
                print("\n" + "="*80)
                print("  [OK] ALL VIOLATION SIGNALS OK - NO ROOT CAUSE FOUND")
                print("="*80)
            
            input("\nPress Enter to continue...")
            continue
        
        elif choice.lower() == 'vp' and VIOLATION_SPECS:
            # Analyze PRIMARY signals only (still stop on first bug)
            valid_signals = [sig for sig in sorted(primary_signals) if sig in logic]
            
            if not valid_signals:
                print("\n[ERROR] No primary signals found in backtracking!")
                input("\nPress Enter to continue...")
                continue
            
            print(f"\nAnalyzing {len(valid_signals)} PRIMARY violation signal(s)...")
            print("(Will stop on first bug found)\n")
            
            bug_found = False
            
            for idx, sig in enumerate(valid_signals, 1):
                print(f"[{idx}/{len(valid_signals)}] Analyzing {sig}")
                print("-" * 80)
                
                drivers = logic[sig]
                res = reason_stuck_signal_multi_phase(
                    sig, wave, drivers, fsm_regs, fsm_enc,
                    logic, hdr,
                    cycle_to_row=cycle_to_row,
                    row_to_cycle=row_to_cycle,
                    clock_sig=clock_sig,
                    enum_map=enum_map
                )
                
                verdict = res.get("verdict", "UNKNOWN")
                tier = res.get("tier", 99)
                severity = res.get("severity", "")
                confidence = res.get("confidence", "")
                prefix = TIER_PREFIXES.get(tier, "[?]")
                
                print(f"  {prefix} {verdict} [{severity}] [{confidence}]")
                
                # Show explanation if bug found
                if verdict not in ["DESIGNER_INTENT", "NO_WAVEFORM_DATA", "NO_RTL_DRIVERS"]:
                    print()
                    print(res.get("explanation", ""))
                    bug_found = True
                    print("\n[OK] ROOT CAUSE FOUND - Stopping analysis")
                    break
                else:
                    print(f"  [OK] OK - No issues detected")
                
                print()
            
            if not bug_found:
                print("\n[OK] All primary signals OK - no bugs found")
            
            print("="*80)
            input("\nPress Enter to continue...")
            continue
        
        elif choice.lower() == 'vs' and VIOLATION_SPECS:
            # Analyze SECONDARY signals only (stop on first bug)
            valid_signals = [sig for sig in sorted(secondary_signals) if sig in logic]
            
            if not valid_signals:
                print("\n[ERROR] No secondary signals found in backtracking!")
                input("\nPress Enter to continue...")
                continue
            
            print(f"\nAnalyzing {len(valid_signals)} SECONDARY violation signal(s)...")
            print("(Will stop on first bug found)\n")
            
            bug_found = False
            
            for idx, sig in enumerate(valid_signals, 1):
                print(f"[{idx}/{len(valid_signals)}] Analyzing {sig}")
                print("-" * 80)
                
                drivers = logic[sig]
                res = reason_stuck_signal_multi_phase(
                    sig, wave, drivers, fsm_regs, fsm_enc,
                    logic, hdr,
                    cycle_to_row=cycle_to_row,
                    row_to_cycle=row_to_cycle,
                    clock_sig=clock_sig,
                    enum_map=enum_map
                )
                
                verdict = res.get("verdict", "UNKNOWN")
                tier = res.get("tier", 99)
                severity = res.get("severity", "")
                confidence = res.get("confidence", "")
                prefix = TIER_PREFIXES.get(tier, "[?]")
                
                print(f"  {prefix} {verdict} [{severity}] [{confidence}]")
                
                # Show explanation if bug found
                if verdict not in ["DESIGNER_INTENT", "NO_WAVEFORM_DATA", "NO_RTL_DRIVERS"]:
                    print()
                    print(res.get("explanation", ""))
                    bug_found = True
                    print("\n[OK] ROOT CAUSE FOUND - Stopping analysis")
                    break
                else:
                    print(f"  [OK] OK - No issues detected")
                
                print()
            
            if not bug_found:
                print("\n[OK] All secondary signals OK - no bugs found")
            
            print("="*80)
            input("\nPress Enter to continue...")
            continue

        elif choice.lower() == 'n':
            total_pages = (len(signals_info) + page_size - 1) // page_size
            if current_page < total_pages - 1:
                current_page += 1
            continue

        elif choice.lower() == 'p':
            if current_page > 0:
                current_page -= 1
            continue

        elif choice.lower().startswith('s '):
            search_term = choice[2:].strip().lower()
            matches = [s for s in signals_info if search_term in s['name'].lower()]

            if not matches:
                print(f"\n[ERROR] No signals found matching '{search_term}'")
                input("\nPress Enter to continue...")
                continue

            sig = matches[0]['name']
            analyze_single_signal(
                sig, wave, logic, fsm_regs, fsm_enc,
                cycle_to_row, row_to_cycle, clock_sig, hdr,
                enum_map=enum_map
            )
            input("\nPress Enter to continue...")
            continue

        elif ',' in choice or '-' in choice or choice.isdigit():
            try:
                selected = []
                for part in choice.split(','):
                    if '-' in part:
                        a, b = map(int, part.split('-'))
                        selected.extend(range(a, b + 1))
                    else:
                        selected.append(int(part))

                selected = sorted(set(n for n in selected if 1 <= n <= len(signals_info)))
                if not selected:
                    print("[ERROR] Invalid selection")
                    input("\nPress Enter to continue...")
                    continue

                for idx, num in enumerate(selected, 1):
                    sig = signals_info[num - 1]['name']
                    print(f"\n[{idx}/{len(selected)}] Analyzing {sig}")
                    print("-" * 80)
                    analyze_single_signal(
                        sig, wave, logic, fsm_regs, fsm_enc,
                        cycle_to_row, row_to_cycle, clock_sig, hdr,
                        enum_map=enum_map
                    )

                print(f"\nAnalysis complete! ({len(selected)} signal(s))")
                input("\nPress Enter to continue...")
                continue

            except Exception as e:
                print(f"[ERROR] Invalid format: {e}")
                input("\nPress Enter to continue...")
                continue

        elif choice.lower() == 'a':
            confirm = input("Analyze ALL signals? (y/n): ").strip().lower()
            if confirm != 'y':
                continue

            for idx, s in enumerate(signals_info, 1):
                sig = s['name']
                print(f"[{idx}/{len(signals_info)}] {sig}")
                res = reason_stuck_signal_multi_phase(
                    sig, wave, logic[sig], fsm_regs, fsm_enc,
                    logic, hdr,
                    cycle_to_row=cycle_to_row,
                    row_to_cycle=row_to_cycle,
                    clock_sig=clock_sig,
                    enum_map=enum_map
                )
                verdict = res.get("verdict", "UNKNOWN")
                tier = res.get("tier", 99)
                severity = res.get("severity", "")
                confidence = res.get("confidence", "")
                
                prefix = TIER_PREFIXES.get(tier, "[?]")
                print(f"  {prefix} {verdict} [{severity}] [{confidence}]")

            input("\nBatch analysis complete. Press Enter to continue...")
            continue

if __name__ == "__main__":
    interactive_menu()
