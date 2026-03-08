#!/usr/bin/env python3
"""
fsm_illegal_state.py - Illegal FSM State Detection & Root-Cause Analysis
=========================================================================

Enhanced 5-Step deterministic algorithm:
  Step 1A: Encoding detection - compare waveform vs legal encodings (X/Z, out-of-range)
  Step 1B: Transition detection - build RTL transition graph, flag illegal edges + dead states
  Step 2:  Winning driver    - reuse evaluate_driver_overwrite_conditions()
  Step 3:  Condition eval    - reuse eval_expr() results from Step 2
  Step 4:  Expected deps     - reuse get_all_interfsm_requirements() + check_requirements()
  Step 5:  Actual vs Reqd    - missing_dependencies = required - conditions_checked

Classification (derived from evidence):
  Case 1: ENCODING_ILLEGAL       - value not in legal set
  Case 2: UNREACHABLE_TRANSITION - legal encoding, but prev→curr not in RTL graph
  Case 3: PROTOCOL_ILLEGAL       - valid transition, missing inter-FSM dep
  Case 4: EXECUTION_ORDER        - multiple active drivers, NBA overwrote
  Case 5: RESET_VIOLATION        - illegal during reset, reset not dominant
  Case 6: DEAD_STATE             - state defined in RTL but never visited in waveform

Output: Exactly 9 fields per finding.
"""

import csv
import json
import re
import sys
import os
from collections import defaultdict
from runtime_paths import resource_path


# ============================================================
# IMPORTS: existing pipeline modules (MANDATORY reuse)
# ============================================================

from utils import (
    parse_literal_token, eval_expr, get_signal_value,
    expand_row_with_aliases, split_conditions, detect_clock,
    eval_rhs_expression
)

from analyse_interactive import (
    load_waveform_csv, load_backtracking_csv,
    build_cycle_to_row_map, load_enum_encodings,
    detect_fsm_regs, build_fsm_encodings,
    evaluate_driver_overwrite_conditions,
    should_skip_driver, filter_drivers, AnalysisMode,
    has_reset_term, has_non_reset_terms,
    convert_binary_fsm_states
)

from inter_fsm import (
    discover_fsms, get_all_interfsm_requirements,
    check_requirements, extract_signal_references,
    load_drivers_csv as ifsm_load_drivers
)


# ============================================================
# FSM ENCODING LOADING (from extract_fsm_encodings.py output)
# ============================================================

def load_fsm_encodings_full(json_path):
    """
    Load the JSON produced by extract_fsm_encodings.py.
    Returns: {"enums": {name: {member: val}}, "localparams": {name: val}}
    """
    if not json_path:
        return {"enums": {}, "localparams": {}}

    resolved_path = os.fspath(json_path)
    if not os.path.isabs(resolved_path):
        resolved_path = resource_path(resolved_path)
    if not os.path.exists(resolved_path):
        return {"enums": {}, "localparams": {}}

    with open(resolved_path, encoding='utf-8') as f:
        data = json.load(f)
    if "enums" in data:
        return data
    # Legacy flat dict -> treat as single enum
    return {"enums": {"states": data}, "localparams": {}}


def build_legal_state_map(encodings):
    """
    Build:
      legal_sets  = {encoding_group_name: set(int values)}
      name_to_val = {state_name: int_val}   (for symbolic lookup)
      val_to_name = {int_val: state_name}   (for display)
    """
    legal_sets = {}
    name_to_val = {}
    val_to_name = {}

    # 1. Enums -> each enum is one legal set
    for enum_name, members in encodings.get("enums", {}).items():
        legal_sets[enum_name] = set(members.values())
        name_to_val.update(members)
        for mname, mval in members.items():
            if mval not in val_to_name:
                val_to_name[mval] = mname

    # 2. Localparams -> group by common prefix (2+ members = FSM encoding)
    params = encodings.get("localparams", {})
    groups = defaultdict(dict)
    for pname, pval in params.items():
        parts = pname.rsplit('_', 1)
        prefix = parts[0] if len(parts) == 2 else '_ungrouped'
        groups[prefix][pname] = pval

    for prefix, members in groups.items():
        if len(members) >= 2:
            legal_sets[prefix] = set(members.values())
            name_to_val.update(members)
            for mname, mval in members.items():
                if mval not in val_to_name:
                    val_to_name[mval] = mname

    # Also add all localparams individually for name lookup
    name_to_val.update(params)

    # Union set
    all_vals = set()
    for vs in legal_sets.values():
        all_vals.update(vs)
    legal_sets["_all"] = all_vals

    return legal_sets, name_to_val, val_to_name


def match_signal_to_legal_set(sig, legal_sets):
    """
    Match FSM signal name to its most specific encoding set.
    Returns: (set_of_legal_values, encoding_set_name)
    """
    sig_lower = sig.lower()
    sig_base = sig_lower
    for sfx in ('_reg', '_next', '_ff', '_d', '_q', '_r'):
        if sig_base.endswith(sfx):
            sig_base = sig_base[:-len(sfx)]
            break

    # Exact match
    for enc_name in legal_sets:
        if enc_name == '_all':
            continue
        if enc_name.lower() == sig_lower or enc_name.lower() == sig_base:
            return legal_sets[enc_name], enc_name

    # Containment
    for enc_name in legal_sets:
        if enc_name == '_all':
            continue
        enc_base = enc_name.lower()
        for sfx in ('_t', '_type', '_e', '_enum'):
            if enc_base.endswith(sfx):
                enc_base = enc_base[:-len(sfx)]
                break
        if enc_base and sig_base and (enc_base in sig_base or sig_base in enc_base):
            return legal_sets[enc_name], enc_name

    # Fallback
    if '_all' in legal_sets and legal_sets['_all']:
        return legal_sets['_all'], '_all'
    return set(), 'none'


# ============================================================
# STEP 1A: BUILD STATE TRANSITION GRAPH FROM RTL DRIVERS
# ============================================================

def build_transition_graph_from_drivers(sig, drivers, legal_values, name_to_val):
    """
    Parse RTL drivers for FSM signal to build legal transition graph.
    
    For each driver: extract "from" state from condition (sig == VALUE),
    extract "to" state from RHS.
    
    Returns:
        graph: {from_int: set(to_int)} — legal transitions per RTL
        reset_targets: set(int) — states reachable via reset
        default_targets: set(int) — states reachable via default/else
    """
    graph = defaultdict(set)
    reset_targets = set()
    default_targets = set()
    
    # Build reverse lookup: name -> value (case-insensitive)
    name_lower = {k.lower(): v for k, v in name_to_val.items()}
    
    sig_lower = sig.lower()
    # Patterns to match state comparisons in conditions
    # e.g., "b_state == B_IDLE", "b_state == 0", "b_state == 2'd0"
    state_cmp_patterns = [
        re.compile(rf'\b{re.escape(sig)}\s*==\s*(\S+)', re.IGNORECASE),
        re.compile(rf'\b{re.escape(sig)}\s*===\s*(\S+)', re.IGNORECASE),
    ]
    # Also match stripped variants
    for sfx in ('_reg', '_next', '_ff', '_d', '_q'):
        base = sig[:-len(sfx)] if sig.endswith(sfx) else None
        if base:
            state_cmp_patterns.append(
                re.compile(rf'\b{re.escape(base)}\s*==\s*(\S+)', re.IGNORECASE)
            )
    
    for drv in drivers:
        cond = drv.get('cond', '') or ''
        rhs = drv.get('rhs', '') or ''
        
        # Resolve RHS to integer
        to_val = _resolve_state_value(rhs.strip(), name_to_val, name_lower)
        if to_val is None:
            continue  # Can't determine target state
        
        # Check if this is a reset driver
        if has_reset_term(cond) and not has_non_reset_terms(cond):
            reset_targets.add(to_val)
            continue
        
        # Extract "from" states from condition
        from_states = set()
        for pat in state_cmp_patterns:
            for m in pat.finditer(cond):
                from_val = _resolve_state_value(m.group(1).strip().rstrip(')'), 
                                                 name_to_val, name_lower)
                if from_val is not None:
                    from_states.add(from_val)
        
        if from_states:
            for f in from_states:
                graph[f].add(to_val)
        else:
            # No specific state comparison found — this is a default/else branch
            # or an unconditional assignment; it can apply from any state
            default_targets.add(to_val)
    
    return dict(graph), reset_targets, default_targets


def _resolve_state_value(token, name_to_val, name_lower):
    """Resolve a token to an integer state value."""
    if not token:
        return None
    
    # Direct integer
    v = parse_literal_token(token)
    if v is not None:
        return v
    
    # Symbolic name (exact)
    if token in name_to_val:
        return name_to_val[token]
    
    # Case-insensitive
    if token.lower() in name_lower:
        return name_lower[token.lower()]
    
    # Strip trailing punctuation
    stripped = token.rstrip(');,}')
    if stripped in name_to_val:
        return name_to_val[stripped]
    if stripped.lower() in name_lower:
        return name_lower[stripped.lower()]
    
    return None


# ============================================================
# STEP 1B: DETECT TRANSITION VIOLATIONS + UNREACHABLE STATES
# ============================================================

def detect_transition_violations(wave, hdr, cls, legal_sets, name_to_val,
                                  row_to_cycle, logic):
    """
    For each FSM signal:
      1. Build transition graph from RTL drivers
      2. Scan waveform for every state change
      3. Flag transitions not in the legal graph
      4. Flag states in legal set that are never visited (dead states)
    
    Returns: list of detection dicts (same format as detect_illegal_states)
    """
    fsm_signals = []
    for c, h in zip(cls, hdr):
        if c.lower() in ('fsm_state', 'fsm_control'):
            fsm_signals.append(h)
    
    if not fsm_signals:
        return [], []
    
    transition_detections = []
    dead_state_warnings = []
    
    name_lower = {k.lower(): v for k, v in name_to_val.items()}
    
    for sig in fsm_signals:
        legal_values, enc_name = match_signal_to_legal_set(sig, legal_sets)
        if not legal_values:
            continue
        
        # Get drivers for this signal
        drivers = logic.get(sig, [])
        if not drivers:
            # Try common variants
            for sfx in ('_reg', '_next', '_ff'):
                if sig + sfx in logic:
                    drivers = logic[sig + sfx]
                    break
                if sig.endswith(sfx) and sig[:-len(sfx)] in logic:
                    drivers = logic[sig[:-len(sfx)]]
                    break
        
        if not drivers:
            continue
        
        # Build transition graph
        graph, reset_targets, default_targets = build_transition_graph_from_drivers(
            sig, drivers, legal_values, name_to_val
        )
        
        if not graph and not default_targets:
            continue  # Can't analyze without a graph
        
        # Scan waveform for transitions
        prev_int = None
        prev_raw = ''
        prev_row = 0
        visited_states = set()
        seen_transitions = set()  # track unique (from, to) already reported
        
        for row_idx, row in enumerate(wave):
            raw = row.get(sig, '').strip()
            if not raw:
                continue
            
            # Parse value
            is_xz = 'x' in raw.lower() or 'z' in raw.lower()
            if is_xz:
                prev_int = None
                prev_raw = raw
                prev_row = row_idx
                continue
            
            int_val = parse_literal_token(raw)
            if int_val is None and raw in name_to_val:
                int_val = name_to_val[raw]
            elif int_val is None and raw.upper() in name_to_val:
                int_val = name_to_val[raw.upper()]
            
            if int_val is None:
                prev_raw = raw
                prev_row = row_idx
                continue
            
            visited_states.add(int_val)
            
            # Check transition (only if we have a valid previous state)
            if prev_int is not None and int_val != prev_int:
                # State changed! Check if this is a legal transition
                from_st = prev_int
                to_st = int_val
                
                is_legal = False
                # Check explicit graph
                if from_st in graph and to_st in graph[from_st]:
                    is_legal = True
                # Check default targets (reachable from any state)
                elif to_st in default_targets:
                    is_legal = True
                # Check reset targets (if near reset)
                elif to_st in reset_targets:
                    cycle = row_to_cycle.get(row_idx, row_idx) if row_to_cycle else row_idx
                    if cycle <= 10:  # Near reset
                        is_legal = True
                
                if not is_legal:
                    key = (from_st, to_st)
                    if key not in seen_transitions:
                        seen_transitions.add(key)
                        cycle = row_to_cycle.get(row_idx, row_idx) if row_to_cycle else row_idx
                        
                        transition_detections.append({
                            'signal': sig,
                            'value_raw': raw,
                            'value_int': int_val,
                            'is_xz': False,
                            'row_idx': row_idx,
                            'cycle': cycle,
                            'prev_value': prev_raw,
                            'prev_row': prev_row,
                            'legal_set': legal_values,
                            'enc_name': enc_name,
                            # Transition-specific fields
                            'is_transition_violation': True,
                            'from_state': from_st,
                            'to_state': to_st,
                            'transition_graph': graph,
                            'default_targets': default_targets,
                        })
            
            prev_int = int_val
            prev_raw = raw
            prev_row = row_idx
        
        # Check for dead/unreachable states
        unvisited = legal_values - visited_states
        if unvisited:
            # Check which unvisited states are reachable per the graph
            for st in sorted(unvisited):
                # Is this state a target in any transition?
                is_target = any(st in targets for targets in graph.values())
                is_default_target = st in default_targets
                is_reset_target = st in reset_targets
                
                if not is_target and not is_default_target and not is_reset_target:
                    dead_state_warnings.append({
                        'signal': sig,
                        'state_value': st,
                        'enc_name': enc_name,
                        'legal_values': legal_values,
                        'visited': visited_states,
                        'graph': graph,
                    })
    
    return transition_detections, dead_state_warnings


# ============================================================
# STEP 1 (ORIGINAL): ILLEGAL STATE DETECTION (trigger only, no RCA)
# ============================================================

def detect_illegal_states(wave, hdr, cls, legal_sets, name_to_val, row_to_cycle):
    """
    For each FSM state signal, compare every cycle against legal encodings.
    Record (fsm_signal, observed_state, cycle T) for each violation.
    Returns list of detection dicts.
    """
    # Find FSM state signals from classification row
    fsm_signals = []
    for c, h in zip(cls, hdr):
        if c.lower() in ('fsm_state', 'fsm_control'):
            fsm_signals.append(h)

    if not fsm_signals:
        return []

    detections = []

    for sig in fsm_signals:
        legal_values, enc_name = match_signal_to_legal_set(sig, legal_sets)
        if not legal_values:
            continue

        seen_illegal = set()  # track unique (type, value) already reported
        prev_raw = ''
        prev_row = 0

        for row_idx, row in enumerate(wave):
            raw = row.get(sig, '').strip()
            if not raw:
                continue

            # Parse value
            is_xz = False
            int_val = None

            if raw.lower() in ('x', 'z') or 'x' in raw.lower() or 'z' in raw.lower():
                is_xz = True
            else:
                int_val = parse_literal_token(raw)
                if int_val is None and raw in name_to_val:
                    int_val = name_to_val[raw]
                elif int_val is None and raw.upper() in name_to_val:
                    int_val = name_to_val[raw.upper()]

            # Check legality
            if is_xz:
                key = ('xz', raw)
            elif int_val is not None and int_val not in legal_values:
                key = ('encoding', int_val)
            else:
                prev_raw = raw
                prev_row = row_idx
                continue

            # Record first occurrence of each unique illegal value
            if key not in seen_illegal:
                seen_illegal.add(key)
                cycle = row_to_cycle.get(row_idx, row_idx) if row_to_cycle else row_idx

                detections.append({
                    'signal': sig,
                    'value_raw': raw,
                    'value_int': int_val,
                    'is_xz': is_xz,
                    'row_idx': row_idx,
                    'cycle': cycle,
                    'prev_value': prev_raw,
                    'prev_row': prev_row,
                    'legal_set': legal_values,
                    'enc_name': enc_name,
                })

            prev_raw = raw
            prev_row = row_idx

    return detections


# ============================================================
# STEP 2: WINNING DRIVER (reuse evaluate_driver_overwrite_conditions)
# ============================================================

def step2_identify_winning_driver(sig, row_idx, wave, drivers,
                                   fsm_regs, fsm_enc, clock_sig,
                                   row_to_cycle):
    """
    Reuse evaluate_driver_overwrite_conditions from analyse_interactive.
    This is the SAME logic used in reason_stuck_signal -> Phase 2.
    Returns the full analysis dict with winner, execution_order, rows, etc.
    """
    # Filter to logical drivers (same filtering as reason_stuck_signal_multi_phase)
    logical_drivers = filter_drivers(drivers, mode=AnalysisMode.LOGICAL)
    if not logical_drivers:
        logical_drivers = drivers  # fallback: use all

    result = evaluate_driver_overwrite_conditions(
        sig, row_idx, wave, logical_drivers,
        fsm_regs, fsm_enc, clock_sig,
        row_to_cycle=row_to_cycle
    )
    return result, logical_drivers


# ============================================================
# STEP 3: CONDITION EVALUATION (extract from Step 2 result)
# ============================================================

def step3_extract_condition_info(driver_result, drivers_used, wave, row_idx):
    """
    Extract from Step 2 result:
      - winning driver's condition and which terms were TRUE
      - contributing signal values at the cycle
    
    NO new evaluation. Reuses what evaluate_driver_overwrite_conditions computed.
    """
    rows = driver_result.get('rows', [])
    empty = {
        'winner_idx': None, 'winner_cond': '', 'winner_rhs': '',
        'winner_block': None, 'winner_rhs_val': None,
        'true_terms': [], 'contributing_signals': {},
        'active_count': 0, 'all_active': [],
    }

    if not rows:
        return empty

    true_rows = [r for r in rows if r.get('cond_eval')]
    active_count = len(true_rows)

    # Winner is determined by execution order in Step 2
    winner = driver_result.get('winner')
    if not winner and true_rows:
        winner = true_rows[-1]  # NBA last-write-wins fallback

    if not winner:
        return empty

    wi = winner.get('driver_idx')
    cond = winner.get('cond', '')
    rhs = winner.get('rhs', '')
    block_id = winner.get('always_block_id')
    true_terms = winner.get('true_terms', [])

    # Extract contributing signals from the winning condition
    contributing = {}
    if cond:
        row = wave[row_idx] if row_idx < len(wave) else {}
        sig_names = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', cond)
        keywords = {'if', 'else', 'case', 'default', 'posedge', 'negedge',
                    'and', 'or', 'not', 'begin', 'end'}
        for sn in sig_names:
            if sn not in keywords and not sn.isdigit():
                val = row.get(sn, '')
                if val:
                    contributing[sn] = val

    return {
        'winner_idx': wi,
        'winner_cond': cond,
        'winner_rhs': rhs,
        'winner_block': block_id,
        'winner_rhs_val': winner.get('rhs_val'),
        'true_terms': true_terms,
        'contributing_signals': contributing,
        'active_count': active_count,
        'all_active': true_rows,
    }


# ============================================================
# STEP 4: EXPECTED DEPENDENCIES (reuse inter_fsm)
# ============================================================

def step4_get_expected_dependencies(sig, ifsm_drivers):
    """
    Reuse discover_fsms + get_all_interfsm_requirements + check_requirements.
    Same logic as analyze_single_design in inter_fsm.py.
    
    Returns: (requirements_list, satisfaction_results)
    """
    fsms = discover_fsms(ifsm_drivers)
    fsm_info = fsms.get(sig)

    # Try stripped variants (signal may be state_reg vs state)
    if not fsm_info:
        for sfx in ('_reg', '_next', '_ff'):
            stripped = sig[:-len(sfx)] if sig.endswith(sfx) else None
            if stripped and stripped in fsms:
                fsm_info = fsms[stripped]
                break

    if not fsm_info:
        return [], []

    # Try BOTH master and slave perspectives (same as analyze_single_design)
    all_reqs = []
    all_results = []

    for forced_module in ['MASTER', 'SLAVE']:
        info = dict(fsm_info)
        info['module'] = forced_module
        info['is_next_state'] = True  # force evaluation

        reqs = get_all_interfsm_requirements(info)
        if not reqs:
            continue

        analysis = check_requirements(sig, ifsm_drivers, reqs)
        if analysis.get('has_requirements'):
            all_reqs.extend(reqs)
            all_results.extend(analysis.get('results', []))

    return all_reqs, all_results


# ============================================================
# STEP 5: COMPARE ACTUAL vs REQUIRED -> CLASSIFICATION
# ============================================================

def step5_classify(detection, cond_info, dep_results, driver_result):
    """
    Compute: missing_dependencies = required_dependencies - conditions_checked_in_RTL
    Derive classification from evidence.
    
    Returns: (classification, missing_deps_str, exec_order_str)
    """
    is_xz = detection['is_xz']
    val_int = detection['value_int']
    legal = detection['legal_set']
    cycle = detection['cycle']
    active_count = cond_info['active_count']
    winner_cond = cond_info['winner_cond']

    # --- Compute: missing_dependencies = required - checked ---
    unmet = [r for r in dep_results if not r.get('met', True)]
    missing_deps_parts = []
    for u in unmet:
        msigs = u.get('missing_signals', [])
        mfsms = u.get('missing_fsms', [])
        parts = []
        if msigs:
            parts.append(f"signals: {', '.join(msigs)}")
        if mfsms:
            parts.append(f"FSMs: {', '.join(mfsms)}")
        missing_deps_parts.append(f"{u['rule_id']}({'; '.join(parts)})")
    missing_deps_str = '; '.join(missing_deps_parts) if missing_deps_parts else 'None'

    # --- Execution-order effect ---
    exec_order_str = 'None'
    if active_count > 1:
        all_active = cond_info['all_active']
        first_di = all_active[0].get('driver_idx', '?')
        last_di = all_active[-1].get('driver_idx', '?')
        exec_order_str = (f"{active_count} drivers active at cycle {cycle}; "
                          f"NBA last-write-wins: driver_idx {last_di} "
                          f"overwrites driver_idx {first_di}")

    # ---- CLASSIFICATION (derived from evidence, not labels) ----

    # Case 5: Reset-related
    if _is_reset_context(detection, cond_info):
        return 'RESET_VIOLATION', missing_deps_str, exec_order_str

    # NEW: Transition violation (from transition graph analysis)
    if detection.get('is_transition_violation'):
        from_st = detection.get('from_state')
        to_st = detection.get('to_state')
        
        # Sub-check: was this caused by execution-order overwrite? (Case 4)
        if active_count > 1:
            verdict = driver_result.get('verdict', '')
            if verdict in ('EXECUTION_ORDER_BUG', 'MIXED_BLOCKING_NONBLOCKING',
                            'BUG_CANDIDATE', 'OVERWRITTEN_UPDATE'):
                return 'EXECUTION_ORDER', missing_deps_str, exec_order_str
        
        # Sub-check: missing inter-FSM dependency? (Case 3)
        if unmet:
            return 'PROTOCOL_ILLEGAL', missing_deps_str, exec_order_str
        
        # Default: unreachable transition (Case 2)
        return 'UNREACHABLE_TRANSITION', missing_deps_str, exec_order_str

    # Case 1: Encoding illegal (X/Z or value not in legal set)
    if is_xz:
        return 'ENCODING_ILLEGAL_XZ', missing_deps_str, exec_order_str

    if val_int is not None and val_int not in legal:
        # Sub-check: was this caused by execution-order overwrite? (Case 4)
        if active_count > 1:
            verdict = driver_result.get('verdict', '')
            if verdict in ('EXECUTION_ORDER_BUG', 'MIXED_BLOCKING_NONBLOCKING',
                            'BUG_CANDIDATE', 'OVERWRITTEN_UPDATE'):
                return 'EXECUTION_ORDER', missing_deps_str, exec_order_str
        return 'ENCODING_ILLEGAL', missing_deps_str, exec_order_str

    # Case 4: Execution-order (legal encoding but wrong due to NBA)
    if active_count > 1:
        verdict = driver_result.get('verdict', '')
        if verdict in ('EXECUTION_ORDER_BUG', 'MIXED_BLOCKING_NONBLOCKING',
                        'BUG_CANDIDATE', 'OVERWRITTEN_UPDATE'):
            return 'EXECUTION_ORDER', missing_deps_str, exec_order_str

    # Case 3: Protocol/semantic illegal (legal encoding, missing inter-FSM dep)
    if unmet:
        return 'PROTOCOL_ILLEGAL', missing_deps_str, exec_order_str

    # Case 2: Unreachable transition (no specific evidence matched)
    return 'UNREACHABLE_TRANSITION', missing_deps_str, exec_order_str


def _is_reset_context(detection, cond_info):
    """Check if illegal state is during reset or caused by reset path."""
    if detection['cycle'] <= 5:
        return True
    cond = cond_info.get('winner_cond', '')
    if cond and has_reset_term(cond) and not has_non_reset_terms(cond):
        return True
    return False


# ============================================================
# FIX SUGGESTION
# ============================================================

def generate_fix(classification, detection, dep_results):
    """One-line actionable fix based on classification evidence."""
    sig = detection['signal']
    unmet = [r for r in dep_results if not r.get('met', True)]

    if classification == 'ENCODING_ILLEGAL_XZ':
        return f"Add explicit reset: if (rst) {sig} <= <init_state>; trace RHS X sources"

    if classification == 'RESET_VIOLATION':
        return f"Ensure reset dominates: if (!rst_n) {sig} <= <safe_state>; as first condition"

    if classification == 'ENCODING_ILLEGAL':
        return f"Add default case: default: {sig} <= <safe_state>; to prevent undefined transitions"

    if classification == 'EXECUTION_ORDER':
        return f"Restructure {sig} assignments as mutually-exclusive if-else-if chain"

    if classification == 'PROTOCOL_ILLEGAL':
        msigs = set()
        for u in unmet:
            msigs.update(u.get('missing_signals', []))
        if msigs:
            return f"Add guard: check {', '.join(sorted(msigs))} before {sig} transition"
        return f"Add inter-channel completion check before {sig} transition"

    return f"Add explicit transition guard or default for {sig}"


def generate_transition_fix(detection, val_to_name):
    """Generate fix suggestion specific to transition violations."""
    sig = detection['signal']
    from_st = detection.get('from_state')
    to_st = detection.get('to_state')
    
    from_name = val_to_name.get(from_st, str(from_st)) if from_st is not None else '?'
    to_name = val_to_name.get(to_st, str(to_st)) if to_st is not None else '?'
    
    return (f"Transition {from_name}->{to_name} not in RTL case logic for {sig}; "
            f"add intermediate state or guard condition")


# ============================================================
# 9-FIELD FINDING BUILDER
# ============================================================

def build_9field_finding(detection, cond_info, dep_results, driver_result,
                          classification, missing_deps_str, exec_order_str,
                          val_to_name):
    """
    Assemble the 9 mandatory output fields:
      1. FSM signal name
      2. Illegal state value
      3. Cycle number
      4. Winning RTL assignment (block + driver_idx)
      5. Condition that evaluated true
      6. Missing or violated dependency
      7. Execution-order effect (if any)
      8. Root-cause classification
      9. One-line actionable fix suggestion
    """
    sig = detection['signal']
    legal = detection['legal_set']

    # Field 2: value with symbolic name
    if detection['is_xz']:
        val_str = detection['value_raw']
    elif detection['value_int'] is not None:
        v = detection['value_int']
        name = val_to_name.get(v, '')
        val_str = f"{v}({name})" if name else str(v)
    else:
        val_str = detection['value_raw']

    # Field 4: winning driver
    wi = cond_info.get('winner_idx')
    blk = cond_info.get('winner_block')
    if wi is not None:
        winning_driver = f"always_block {blk}, driver_idx {wi}"
    else:
        winning_driver = '(no driver condition TRUE at this cycle)'

    # Field 5: condition
    cond = cond_info.get('winner_cond', '')
    condition_str = cond if cond else '(unconditional)'

    # Field 9: fix
    if detection.get('is_transition_violation'):
        fix = generate_transition_fix(detection, val_to_name)
    else:
        fix = generate_fix(classification, detection, dep_results)

    # Legal states formatted for display
    legal_fmt = _fmt_legal(legal, val_to_name)

    return {
        # === 9 MANDATORY FIELDS ===
        'fsm_signal': sig,                     # 1
        'illegal_value': val_str,              # 2
        'cycle': detection['cycle'],           # 3
        'winning_driver': winning_driver,      # 4
        'condition': condition_str,            # 5
        'missing_dep': missing_deps_str,       # 6
        'exec_order': exec_order_str,          # 7
        'classification': classification,      # 8
        'fix_suggestion': fix,                 # 9
        # === supplementary (display context) ===
        'contributing_signals': cond_info.get('contributing_signals', {}),
        'legal_states_fmt': legal_fmt,
        'prev_value': detection['prev_value'],
        'enc_name': detection['enc_name'],
        'active_count': cond_info['active_count'],
        'winner_rhs': cond_info.get('winner_rhs', ''),
        'winner_rhs_val': cond_info.get('winner_rhs_val'),
        'driver_verdict': driver_result.get('verdict', ''),
        # Transition-specific context
        'is_transition_violation': detection.get('is_transition_violation', False),
        'from_state': detection.get('from_state'),
        'to_state': detection.get('to_state'),
    }


def _fmt_legal(legal_set, val_to_name):
    parts = []
    for v in sorted(legal_set):
        n = val_to_name.get(v, '')
        parts.append(f"{v}({n})" if n else str(v))
    return '{' + ', '.join(parts) + '}'


# ============================================================
# OUTPUT FORMATTING
# ============================================================

def format_finding(f, idx=1):
    """Format one finding. Strict 9-field layout with supplementary context."""
    lines = []
    lines.append(f"{'='*80}")
    lines.append(f"  ILLEGAL FSM STATE #{idx}: {f['classification']}")
    lines.append(f"{'='*80}")
    lines.append('')
    lines.append(f"  1. FSM signal:      {f['fsm_signal']}")
    lines.append(f"  2. Illegal value:   {f['illegal_value']}")
    lines.append(f"     Legal states:    {f['legal_states_fmt']}")
    if f['prev_value']:
        lines.append(f"     Previous value:  {f['prev_value']}")
    if f.get('is_transition_violation'):
        from_st = f.get('from_state', '?')
        to_st = f.get('to_state', '?')
        lines.append(f"     Transition:      {from_st} → {to_st} (NOT in RTL graph)")
    lines.append(f"     Encoding set:    {f['enc_name']}")
    lines.append(f"  3. Cycle:           {f['cycle']}")
    lines.append(f"  4. Winning driver:  {f['winning_driver']}")
    lines.append(f"     RHS:             {f['winner_rhs']}")
    if f['winner_rhs_val'] is not None:
        lines.append(f"     RHS evaluated:   {f['winner_rhs_val']}")
    lines.append(f"  5. Condition TRUE:  {f['condition']}")

    if f.get('contributing_signals'):
        lines.append(f"     Signal values at cycle {f['cycle']}:")
        for sn, sv in sorted(f['contributing_signals'].items()):
            lines.append(f"       {sn} = {sv}")

    lines.append(f"  6. Missing dep:     {f['missing_dep']}")
    lines.append(f"  7. Exec-order:      {f['exec_order']}")
    lines.append(f"  8. Classification:  {f['classification']}")
    lines.append(f"  9. Fix:             {f['fix_suggestion']}")

    if f['driver_verdict'] and f['driver_verdict'] not in ('CONSISTENT_UPDATE',):
        lines.append(f"")
        lines.append(f"     analyse_interactive verdict: {f['driver_verdict']}")

    lines.append('')
    return '\n'.join(lines)


def format_summary(findings):
    """Summary across all findings."""
    lines = []
    lines.append(f"\n{'='*80}")
    lines.append(f"  ILLEGAL FSM STATE ANALYSIS SUMMARY")
    lines.append(f"{'='*80}\n")

    if not findings:
        lines.append("  [OK] No illegal FSM states detected.")
        lines.append("  All observed FSM values are within defined encodings.\n")
        return '\n'.join(lines)

    by_class = defaultdict(list)
    for f in findings:
        by_class[f['classification']].append(f)

    lines.append(f"  Total findings: {len(findings)}\n")

    for cls_name, cls_list in sorted(by_class.items()):
        lines.append(f"  [{cls_name}] {len(cls_list)} finding(s)")
        for f in cls_list:
            lines.append(f"    - {f['fsm_signal']} = {f['illegal_value']} at cycle {f['cycle']}")
            lines.append(f"      Fix: {f['fix_suggestion']}")
        lines.append('')

    return '\n'.join(lines)


# ============================================================
# MAIN: 5-STEP PIPELINE
# ============================================================

def analyze_illegal_fsm_states(waveform_csv, backtracking_csv,
                                fsm_encodings_json,
                                violations_csv=None):
    """
    Complete 5-step illegal FSM state analysis.
    
    Args:
        waveform_csv:       Mapped waveform CSV (class row + header + data)
        backtracking_csv:   true_drivers CSV
        fsm_encodings_json: from extract_fsm_encodings.py
        violations_csv:     Optional, for cross-reference
    
    Returns: list of 9-field finding dicts
    """
    print(f"\n{'='*80}")
    print("  ILLEGAL FSM STATE DETECTION & ROOT-CAUSE ANALYSIS")
    print(f"{'='*80}\n")

    # ---- Load data (reuse existing loaders) ----
    print("[LOAD] Data...")

    wave, hdr, cls = load_waveform_csv(waveform_csv)
    print(f"  Waveform: {len(wave)} rows, {len(hdr)} signals")

    logic = load_backtracking_csv(backtracking_csv)
    print(f"  Backtracking: {len(logic)} signals")

    clock_sig = detect_clock(waveform_csv)
    print(f"  Clock: {clock_sig or 'not detected'}")

    cycle_to_row, row_to_cycle = build_cycle_to_row_map(wave, clock_sig)

    # FSM encodings from extract_fsm_encodings.py output
    encodings = load_fsm_encodings_full(fsm_encodings_json)
    n_e = len(encodings.get('enums', {}))
    n_p = len(encodings.get('localparams', {}))
    print(f"  Encodings: {n_e} enum(s), {n_p} localparam(s)")

    legal_sets, name_to_val, val_to_name = build_legal_state_map(encodings)
    print(f"  Legal sets: {len(legal_sets)-1} group(s), "
          f"{len(legal_sets.get('_all', set()))} unique values")

    # analyse_interactive state (reuse its data structures)
    fsm_regs, fsm_states = detect_fsm_regs(cls, hdr)
    enum_map = load_enum_encodings(fsm_encodings_json)
    fsm_enc = build_fsm_encodings(cls, hdr, wave, enum_map=enum_map)

    # inter_fsm drivers dict (its own format)
    ifsm_drivers = ifsm_load_drivers(backtracking_csv)

    print()

    # ======================================
    # STEP 1A: ENCODING VIOLATIONS
    # ======================================
    print("[STEP 1A] Scanning waveform for illegal FSM states (encoding)...")
    detections = detect_illegal_states(wave, hdr, cls, legal_sets, name_to_val, row_to_cycle)

    if detections:
        print(f"  Found {len(detections)} encoding violation(s):")
        for d in detections:
            tag = 'X/Z' if d['is_xz'] else f"val={d['value_int']}"
            print(f"    {d['signal']}: {tag} at cycle {d['cycle']}")
    else:
        print("  [OK] No encoding violations detected.")
    print()

    # ======================================
    # STEP 1B: TRANSITION VIOLATIONS
    # ======================================
    print("[STEP 1B] Building transition graph from RTL & checking state changes...")
    transition_detections, dead_state_warnings = detect_transition_violations(
        wave, hdr, cls, legal_sets, name_to_val, row_to_cycle, logic
    )

    if transition_detections:
        print(f"  Found {len(transition_detections)} transition violation(s):")
        for d in transition_detections:
            print(f"    {d['signal']}: {d['from_state']}→{d['to_state']} at cycle {d['cycle']}")
    else:
        print("  [OK] All observed transitions match RTL case logic.")

    if dead_state_warnings:
        print(f"  Found {len(dead_state_warnings)} dead/unreachable state(s):")
        for w in dead_state_warnings:
            print(f"    {w['signal']}: state {w['state_value']} never visited "
                  f"(visited: {sorted(w['visited'])})")
    print()

    # Merge all detections
    all_detections = detections + transition_detections

    if not all_detections:
        print("  [OK] No illegal FSM states or transition violations detected.\n")
        # Still report dead states as warnings
        if dead_state_warnings:
            print("  [WARNING] Dead states detected (defined in RTL but never visited):")
            for w in dead_state_warnings:
                print(f"    {w['signal']}: state {w['state_value']}")
        print(format_summary([]))
        return []

    print(f"  Total detections for RCA: {len(all_detections)}")
    print()

    # ======================================
    # STEPS 2-5: RCA PER DETECTION
    # ======================================
    findings = []

    for idx, detection in enumerate(all_detections, 1):
        sig = detection['signal']
        cycle = detection['cycle']
        row_idx = detection['row_idx']

        trans_tag = ''
        if detection.get('is_transition_violation'):
            trans_tag = f" (transition {detection['from_state']}→{detection['to_state']})"
        print(f"[RCA #{idx}] {sig} = {detection['value_raw']} at cycle {cycle}{trans_tag}")

        # ---- STEP 2: Winning driver (reuse evaluate_driver_overwrite_conditions) ----
        if sig not in logic:
            print(f"  [SKIP] No RTL drivers for {sig}")
            continue

        drivers = logic[sig]
        driver_result, drivers_used = step2_identify_winning_driver(
            sig, row_idx, wave, drivers,
            fsm_regs, fsm_enc, clock_sig, row_to_cycle
        )
        verdict = driver_result.get('verdict', 'UNKNOWN')
        print(f"  Step 2 (winning driver): {verdict}")

        # ---- STEP 3: Condition info (extracted from Step 2) ----
        cond_info = step3_extract_condition_info(
            driver_result, drivers_used, wave, row_idx
        )
        print(f"  Step 3 (condition eval): active={cond_info['active_count']}, "
              f"winner_idx={cond_info['winner_idx']}, "
              f"cond='{cond_info['winner_cond'][:60]}'")

        # ---- STEP 4: Expected dependencies (reuse inter_fsm) ----
        requirements, dep_results = step4_get_expected_dependencies(sig, ifsm_drivers)
        unmet = [r for r in dep_results if not r.get('met', True)]
        print(f"  Step 4 (dependencies): {len(dep_results)} checked, "
              f"{len(unmet)} unmet")

        # ---- STEP 5: Classify ----
        classification, missing_deps_str, exec_order_str = step5_classify(
            detection, cond_info, dep_results, driver_result
        )
        print(f"  Step 5 (classify): {classification}")

        # ---- Build 9-field finding ----
        finding = build_9field_finding(
            detection, cond_info, dep_results, driver_result,
            classification, missing_deps_str, exec_order_str,
            val_to_name
        )
        findings.append(finding)
        print()

    # ======================================
    # OUTPUT
    # ======================================
    for idx, f in enumerate(findings, 1):
        print(format_finding(f, idx))

    # Append dead state warnings to findings as supplementary info
    if dead_state_warnings:
        print(f"\n{'='*80}")
        print(f"  DEAD STATE WARNINGS ({len(dead_state_warnings)} state(s) never visited)")
        print(f"{'='*80}\n")
        for w in dead_state_warnings:
            val_name = val_to_name.get(w['state_value'], '')
            label = f"{w['state_value']}({val_name})" if val_name else str(w['state_value'])
            print(f"  {w['signal']}: state {label} defined but never visited")
            print(f"    Visited: {sorted(w['visited'])}")
            print()
        
        # Add dead state findings to the output
        for w in dead_state_warnings:
            val_name = val_to_name.get(w['state_value'], '')
            label = f"{w['state_value']}({val_name})" if val_name else str(w['state_value'])
            findings.append({
                'fsm_signal': w['signal'],
                'illegal_value': f"NEVER_VISITED:{label}",
                'cycle': 'N/A',
                'winning_driver': '(state never reached)',
                'condition': '(no transition leads here)',
                'missing_dep': 'None',
                'exec_order': 'None',
                'classification': 'DEAD_STATE',
                'fix_suggestion': f"State {label} unreachable — remove or add transition to it",
                'contributing_signals': {},
                'legal_states_fmt': _fmt_legal(w['legal_values'], val_to_name),
                'prev_value': '',
                'enc_name': w['enc_name'],
                'active_count': 0,
                'winner_rhs': '',
                'winner_rhs_val': None,
                'driver_verdict': '',
                'is_transition_violation': False,
                'from_state': None,
                'to_state': None,
            })

    print(format_summary(findings))

    return findings


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Illegal FSM State Detection & Root-Cause Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fsm_illegal_state.py waveform.csv true_drivers.csv design.fsm_encodings.json
  python fsm_illegal_state.py waveform.csv true_drivers.csv design.fsm_encodings.json -v violations.csv
        """
    )

    parser.add_argument('waveform_csv',
                        help='Mapped waveform CSV (classification + header + data)')
    parser.add_argument('backtracking_csv',
                        help='true_drivers CSV or backtracking CSV')
    parser.add_argument('fsm_encodings_json',
                        help='FSM encodings JSON from extract_fsm_encodings.py')
    parser.add_argument('--violations', '-v',
                        help='Optional violations.csv for cross-reference',
                        default=None)

    args = parser.parse_args()

    for path, label in [
        (args.waveform_csv, 'Waveform CSV'),
        (args.backtracking_csv, 'Backtracking CSV'),
        (args.fsm_encodings_json, 'FSM encodings JSON'),
    ]:
        if not os.path.exists(path):
            print(f"[ERROR] {label} not found: {path}")
            sys.exit(1)

    findings = analyze_illegal_fsm_states(
        waveform_csv=args.waveform_csv,
        backtracking_csv=args.backtracking_csv,
        fsm_encodings_json=args.fsm_encodings_json,
        violations_csv=args.violations,
    )

    sys.exit(0 if not findings else 1)
