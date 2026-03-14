#!/usr/bin/env python3
"""
COMPLETE Inter-FSM Dependency Checker for ALL AXI4-Lite Rules
Dynamically discovers and validates ALL inter-FSM coordination requirements
"""

import csv
import re
from pathlib import Path
from collections import defaultdict

# ============================================================
# CSV PARSING
# ============================================================

def load_drivers_csv(filepath):
    """Load and parse the true_drivers CSV file."""
    drivers = defaultdict(list)
    
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            signal = row.get('signal', '').strip()
            if signal and signal != '':
                drivers[signal].append({
                    'condition': row.get('condition', '').strip(),
                    'rhs': row.get('rhs', '').strip(),
                    'construct': row.get('construct', '').strip(),
                    'driver_idx': row.get('driver_idx', '').strip()
                })
    
    return drivers
def analyze_single_design(drivers_file):
    """
    Analyze a single-module AXI design using ALL inter-FSM rules.
    """
    print(f"\n{'='*80}")
    print("SINGLE-MODULE - COMPLETE INTER-FSM ANALYSIS (ALL RULES)")
    print(f"{'='*80}\n")

    drivers = load_drivers_csv(drivers_file)
    print(f"[OK] Loaded {len(drivers)} signals\n")

    fsms = discover_fsms(drivers)

    all_issues = []
    rule_coverage = defaultdict(int)

    for fsm_signal, fsm_info in sorted(fsms.items()):
        if not fsm_info['is_next_state']:
            continue

        # IMPORTANT: try BOTH MASTER and SLAVE rule sets
        for forced_module in ['MASTER', 'SLAVE']:
            fsm_info_forced = dict(fsm_info)
            fsm_info_forced['module'] = forced_module

            requirements = get_all_interfsm_requirements(fsm_info_forced)
            if not requirements:
                continue

            analysis = check_requirements(fsm_signal, drivers, requirements)

            if not analysis.get('has_requirements'):
                continue

            for result in analysis['results']:
                rule_coverage[result['rule_id']] += 1

                if not result['met']:
                    all_issues.append({
                        'fsm': fsm_signal,
                        'module': forced_module,
                        'channel': fsm_info['channel'],
                        'result': result
                    })

    return all_issues, rule_coverage, drivers

# ============================================================
# FSM DISCOVERY
# ============================================================

def discover_fsms(drivers):
    """Automatically discover FSM AND control signals relevant to AXI rules."""
    fsm_signals = {}
    
    for signal in drivers.keys():

        signal_upper = signal.upper()

        # 1. FSM signals (existing behavior)
        if any(pat in signal_upper for pat in ['STATE']):
            module = 'MASTER'
            channel = None

            if 'AR' in signal_upper:
                channel = 'AR'
            elif signal_upper.startswith('R'):
                channel = 'R'
            elif 'AW' in signal_upper:
                channel = 'AW'
            elif signal_upper.startswith('W'):
                channel = 'W'
            elif signal_upper.startswith('B'):
                channel = 'B'

            if channel:
                fsm_signals[signal] = {
                    'module': module,
                    'channel': channel,
                    'is_next_state': 'next' in signal.lower()
                }

        # 2. CONTROL signals that enforce inter-FSM rules (NEW, REQUIRED)
        elif any(sig in signal_upper for sig in [
            'ARREADY', 'ARVALID',
            'RVALID', 'RREADY',
            'AWREADY', 'AWVALID',
            'WVALID', 'WREADY',
            'BVALID', 'BREADY'
        ]):
            channel = None
            if 'AR' in signal_upper:
                channel = 'AR'
            elif signal_upper.startswith('R'):
                channel = 'R'
            elif 'AW' in signal_upper:
                channel = 'AW'
            elif signal_upper.startswith('W'):
                channel = 'W'
            elif signal_upper.startswith('B'):
                channel = 'B'

            if channel:
                fsm_signals[signal] = {
                    'module': 'MASTER',
                    'channel': channel,
                    'is_next_state': True   # force evaluation
                }

    return fsm_signals


# ============================================================
# SIGNAL REFERENCE EXTRACTION
# ============================================================

def extract_signal_references(condition):
    """Extract all signal names referenced in a condition."""
    if not condition or condition == '':
        return set()
    
    pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
    matches = re.findall(pattern, condition)
    
    keywords = {
        'if', 'else', 'case', 'default', 'posedge', 'negedge',
        'and', 'or', 'not', 'begin', 'end'
    }
    
    signals = {m for m in matches if m not in keywords and not m.isdigit()}
    return signals

def get_all_conditions(drivers_list):
    """Get all conditions from drivers."""
    all_conditions = []
    for driver in drivers_list:
        cond = driver.get('condition', '')
        if cond:
            all_conditions.append(cond)
    return all_conditions

# ============================================================
# COMPLETE INTER-FSM REQUIREMENTS FOR ALL RULES
# ============================================================

def get_all_interfsm_requirements(fsm_info):
    """
    Complete inter-FSM dependency requirements for ALL AXI4-Lite rules.
    Returns list of requirement dicts for each rule.
    """
    module = fsm_info['module']
    channel = fsm_info['channel']
    is_next = fsm_info['is_next_state']
    
    if not is_next:
        return []
    
    requirements = []
    
    # ========================================================================
    # MASTER-SIDE REQUIREMENTS
    # ========================================================================
    
    if module == 'MASTER':
        
        # ====================================================================
        # AR (READ ADDRESS) CHANNEL
        # ====================================================================
        if channel == 'AR':
            
            # RULE_12: Only 1 outstanding read transaction
            requirements.append({
                'rule_id': 'RULE_12',
                'rule_name': 'Multiple Outstanding Read Transactions',
                'requirement': 'AR must wait for R completion before new read',
                'inter_fsm_deps': {
                    'fsms': ['RState_M', 'RNext_state_M'],
                    'signals': ['RVALID', 'RREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'AR FSM must check R channel completion (RVALID && RREADY) before issuing new ARVALID',
                'severity': 'CRITICAL'
            })
            
            # RULE_7: ARVALID must not drop until handshake
            requirements.append({
                'rule_id': 'RULE_7',
                'rule_name': 'ARVALID Stability',
                'requirement': 'ARVALID must remain high until ARREADY',
                'inter_fsm_deps': {
                    'fsms': ['ARState_M'],
                    'signals': ['ARREADY', 'ARVALID'],
                    'need_at_least_one': True
                },
                'explanation': 'AR FSM must hold ARVALID until handshake completes',
                'severity': 'HIGH'
            })
            
            # RULE_8: ARADDR/control must be stable while ARVALID high
            requirements.append({
                'rule_id': 'RULE_8',
                'rule_name': 'ARADDR Stability',
                'requirement': 'ARADDR must not change while ARVALID high',
                'inter_fsm_deps': {
                    'fsms': ['ARState_M'],
                    'signals': ['ARVALID', 'ARADDR'],
                    'need_at_least_one': True
                },
                'explanation': 'AR FSM must prevent ARADDR changes during active transaction',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # R (READ DATA) CHANNEL
        # ====================================================================
        elif channel == 'R':
            
            # RULE_9: Master must be ready to accept data
            requirements.append({
                'rule_id': 'RULE_9',
                'rule_name': 'Read Data Acceptance',
                'requirement': 'R must coordinate with AR handshake',
                'inter_fsm_deps': {
                    'fsms': ['ARState_M', 'ARNext_state_M'],
                    'signals': ['ARVALID', 'ARREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'R FSM should assert RREADY after AR handshake',
                'severity': 'MEDIUM'
            })
            
            # RULE_10: RREADY can wait for RVALID but must accept eventually
            requirements.append({
                'rule_id': 'RULE_10',
                'rule_name': 'RREADY Behavior',
                'requirement': 'R must handle RVALID properly',
                'inter_fsm_deps': {
                    'fsms': ['RState_M'],
                    'signals': ['RVALID', 'RREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'R FSM must respond to slave RVALID',
                'severity': 'MEDIUM'
            })
        
        # ====================================================================
        # AW (WRITE ADDRESS) CHANNEL
        # ====================================================================
        elif channel == 'AW':
            
            # RULE_11: Only 1 outstanding write transaction
            requirements.append({
                'rule_id': 'RULE_11',
                'rule_name': 'Multiple Outstanding Write Transactions',
                'requirement': 'AW must wait for B completion before new write',
                'inter_fsm_deps': {
                    'fsms': ['BState_M', 'BNext_state_M'],
                    'signals': ['BVALID', 'BREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'AW FSM must check B channel completion (BVALID && BREADY) before issuing new AWVALID',
                'severity': 'CRITICAL'
            })
            
            # RULE_1: AWVALID must not drop until handshake
            requirements.append({
                'rule_id': 'RULE_1',
                'rule_name': 'AWVALID Stability',
                'requirement': 'AWVALID must remain high until AWREADY',
                'inter_fsm_deps': {
                    'fsms': ['AWState_M'],
                    'signals': ['AWREADY', 'AWVALID'],
                    'need_at_least_one': True
                },
                'explanation': 'AW FSM must hold AWVALID until handshake completes',
                'severity': 'HIGH'
            })
            
            # RULE_2: AWADDR must be stable while AWVALID high
            requirements.append({
                'rule_id': 'RULE_2',
                'rule_name': 'AWADDR Stability',
                'requirement': 'AWADDR must not change while AWVALID high',
                'inter_fsm_deps': {
                    'fsms': ['AWState_M'],
                    'signals': ['AWVALID', 'AWADDR'],
                    'need_at_least_one': True
                },
                'explanation': 'AW FSM must prevent AWADDR changes during transaction',
                'severity': 'HIGH'
            })
            
            # RULE_13: AW and W must coordinate
            requirements.append({
                'rule_id': 'RULE_13',
                'rule_name': 'Write Channel Coordination',
                'requirement': 'AW must coordinate with W channel',
                'inter_fsm_deps': {
                    'fsms': ['WState_M', 'WNext_state_M'],
                    'signals': ['WVALID', 'WREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'AW FSM should coordinate with W FSM for proper write ordering',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # W (WRITE DATA) CHANNEL
        # ====================================================================
        elif channel == 'W':
            
            # RULE_13: W must coordinate with AW
            requirements.append({
                'rule_id': 'RULE_13',
                'rule_name': 'Write Channel Coordination',
                'requirement': 'W must coordinate with AW channel',
                'inter_fsm_deps': {
                    'fsms': ['AWState_M', 'AWNext_state_M'],
                    'signals': ['AWVALID', 'AWREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'W FSM should check AW FSM state for proper ordering',
                'severity': 'HIGH'
            })
            
            # RULE_3: WVALID must follow AWVALID
            requirements.append({
                'rule_id': 'RULE_3',
                'rule_name': 'Write Data Requirements',
                'requirement': 'W should follow AW handshake',
                'inter_fsm_deps': {
                    'fsms': ['AWState_M', 'AWNext_state_M'],
                    'signals': ['AWVALID', 'AWREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'W FSM should wait for AW handshake',
                'severity': 'MEDIUM'
            })
            
            # RULE_4: WDATA must be stable while WVALID high
            requirements.append({
                'rule_id': 'RULE_4',
                'rule_name': 'WDATA Stability',
                'requirement': 'WDATA must not change while WVALID high',
                'inter_fsm_deps': {
                    'fsms': ['WState_M'],
                    'signals': ['WVALID', 'WDATA'],
                    'need_at_least_one': True
                },
                'explanation': 'W FSM must prevent WDATA changes during transaction',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # B (WRITE RESPONSE) CHANNEL
        # ====================================================================
        elif channel == 'B':
            
            # RULE_5: Master must accept write response
            requirements.append({
                'rule_id': 'RULE_5',
                'rule_name': 'Write Response Acceptance',
                'requirement': 'B must coordinate with AW/W completion',
                'inter_fsm_deps': {
                    'fsms': ['AWState_M', 'WState_M'],
                    'signals': ['AWVALID', 'AWREADY', 'WVALID', 'WREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'B FSM should verify AW and W handshakes occurred',
                'severity': 'MEDIUM'
            })
            
            # RULE_6: BREADY behavior
            requirements.append({
                'rule_id': 'RULE_6',
                'rule_name': 'BREADY Behavior',
                'requirement': 'B must handle BVALID properly',
                'inter_fsm_deps': {
                    'fsms': ['BState_M'],
                    'signals': ['BVALID', 'BREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'B FSM must respond to slave BVALID',
                'severity': 'MEDIUM'
            })
    
    # ========================================================================
    # SLAVE-SIDE REQUIREMENTS
    # ========================================================================
    
    elif module == 'SLAVE':
        
        # ====================================================================
        # AR (READ ADDRESS) CHANNEL - SLAVE
        # ====================================================================
        if channel == 'AR':
            
            # RULE_7: Must accept ARVALID properly
            requirements.append({
                'rule_id': 'RULE_7',
                'rule_name': 'AR Handshake Slave',
                'requirement': 'AR must trigger R response',
                'inter_fsm_deps': {
                    'fsms': ['RState_S', 'RNext_state_S'],
                    'signals': ['RVALID', 'RREADY', 'ARVALID'],
                    'need_at_least_one': True
                },
                'explanation': 'Slave AR FSM must coordinate with R FSM to send response',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # R (READ DATA) CHANNEL - SLAVE
        # ====================================================================
        elif channel == 'R':
            
            # RULE_9/10: Must send read data after AR acceptance
            requirements.append({
                'rule_id': 'RULE_9',
                'rule_name': 'Read Data Response',
                'requirement': 'R must follow AR acceptance',
                'inter_fsm_deps': {
                    'fsms': ['ARState_S', 'ARNext_State_S'],
                    'signals': ['ARVALID', 'ARREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'Slave R FSM must wait for AR handshake',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # AW (WRITE ADDRESS) CHANNEL - SLAVE
        # ====================================================================
        elif channel == 'AW':
            
            # RULE_13: Must coordinate with W for write completion
            requirements.append({
                'rule_id': 'RULE_13',
                'rule_name': 'Write Coordination Slave',
                'requirement': 'AW must coordinate with W and trigger B',
                'inter_fsm_deps': {
                    'fsms': ['WState_S', 'WNext_state_S', 'BState_S', 'BNext_state_S'],
                    'signals': ['WVALID', 'WREADY', 'BVALID', 'BREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'Slave AW FSM must coordinate with W and B',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # W (WRITE DATA) CHANNEL - SLAVE
        # ====================================================================
        elif channel == 'W':
            
            # RULE_13: Must coordinate with AW
            requirements.append({
                'rule_id': 'RULE_13',
                'rule_name': 'Write Data Coordination Slave',
                'requirement': 'W must coordinate with AW and trigger B',
                'inter_fsm_deps': {
                    'fsms': ['AWState_S', 'WANext_state_S', 'BState_S', 'BNext_state_S'],
                    'signals': ['AWVALID', 'AWREADY', 'BVALID', 'BREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'Slave W FSM must coordinate with AW and B',
                'severity': 'HIGH'
            })
        
        # ====================================================================
        # B (WRITE RESPONSE) CHANNEL - SLAVE
        # ====================================================================
        elif channel == 'B':
            
            # RULE_5/6: Must send response after AW and W complete
            requirements.append({
                'rule_id': 'RULE_5',
                'rule_name': 'Write Response Slave',
                'requirement': 'B must follow AW+W acceptance',
                'inter_fsm_deps': {
                    'fsms': ['AWState_S', 'WANext_state_S', 'WState_S', 'WNext_state_S'],
                    'signals': ['AWVALID', 'AWREADY', 'WVALID', 'WREADY'],
                    'need_at_least_one': True
                },
                'explanation': 'Slave B FSM must wait for both AW and W handshakes',
                'severity': 'HIGH'
            })
    
    return requirements

# ============================================================
# DEPENDENCY CHECKER
# ============================================================

def check_requirements(fsm_signal, drivers, requirements):
    """Check if FSM satisfies ALL its inter-FSM requirements."""
    if not requirements:
        return {'has_requirements': False}
    
    if fsm_signal not in drivers:
        return {'has_requirements': True, 'error': 'FSM not in drivers'}
    
    # Get all conditions
    conditions = get_all_conditions(drivers[fsm_signal])
    all_text = ' '.join(conditions)
    all_refs = extract_signal_references(all_text)
    
    results = []
    
    for req in requirements:
        deps = req['inter_fsm_deps']
        
        # Check if required FSMs are referenced
        required_fsms = set(deps['fsms'])
        found_fsms = required_fsms & all_refs
        
        # Check if required signals are referenced
        required_sigs = set(deps['signals'])
        found_sigs = required_sigs & all_refs
        
        # Determine if requirement is met
        has_any = len(found_fsms) > 0 or len(found_sigs) > 0

        # FIX: Explicitly flag missing inter-FSM dependency
        if deps['need_at_least_one']:
            if not has_any:
                requirement_met = False
                missing_type = 'MISSING_INTER_FSM_DEPENDENCY'
            else:
                requirement_met = True
                missing_type = None
        else:
            requirement_met = (
                len(found_fsms) == len(required_fsms) and
                len(found_sigs) == len(required_sigs)
            )
            missing_type = None

        results.append({
            'rule_id': req['rule_id'],
            'rule_name': req['rule_name'],
            'requirement': req['requirement'],
            'met': requirement_met,
            'missing_type': missing_type,  # <- NEW
            'required_fsms': list(required_fsms),
            'found_fsms': list(found_fsms),
            'missing_fsms': list(required_fsms - found_fsms),
            'required_signals': list(required_sigs),
            'found_signals': list(found_sigs),
            'missing_signals': list(required_sigs - found_sigs),
            'explanation': req['explanation'],
            'severity': req['severity']
        })

    
    return {
        'has_requirements': True,
        'results': results,
        'all_met': all(r['met'] for r in results)
    }

# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_all_interfsm_rules(drivers_file, module_name):
    """Analyze ALL inter-FSM dependencies for ALL rules."""
    
    print(f"\n{'='*80}")
    print(f"{module_name} - COMPLETE INTER-FSM ANALYSIS (ALL RULES)")
    print(f"{'='*80}\n")
    
    drivers = load_drivers_csv(drivers_file)
    print(f"[OK] Loaded {len(drivers)} signals\n")
    
    fsms = discover_fsms(drivers)
    
    all_issues = []
    rule_coverage = defaultdict(int)
    
    for fsm_signal, fsm_info in sorted(fsms.items()):
        if not fsm_info['is_next_state']:
            continue
        
        requirements = get_all_interfsm_requirements(fsm_info)
        if not requirements:
            continue
        
        print(f"{'-'*80}")
        print(f"FSM: {fsm_signal}")
        print(f"Channel: {fsm_info['channel']}")
        print(f"Rules to check: {len(requirements)}")
        
        analysis = check_requirements(fsm_signal, drivers, requirements)
        
        if not analysis.get('has_requirements'):
            continue
        
        for result in analysis['results']:
            rule_coverage[result['rule_id']] += 1
            
            print(f"\n  [{result['severity']}] {result['rule_id']}: {result['rule_name']}")
            print(f"  Requirement: {result['requirement']}")
            
            if result['met']:
                print(f"  Status: [OK] SATISFIED")
                if result['found_fsms']:
                    print(f"    Checks FSMs: {', '.join(result['found_fsms'])}")
                if result['found_signals']:
                    print(f"    Checks signals: {', '.join(result['found_signals'])}")
            else:
                print(f"  Status: [FAIL] NOT SATISFIED")
                print(f"  Explanation: {result['explanation']}")
                if result['missing_fsms']:
                    print(f"    Missing FSMs: {', '.join(result['missing_fsms'])}")
                if result['missing_signals']:
                    print(f"    Missing signals: {', '.join(result['missing_signals'])}")
                
                all_issues.append({
                    'fsm': fsm_signal,
                    'module': module_name,
                    'channel': fsm_info['channel'],
                    'result': result
                })
        
        print()
    
    return all_issues, rule_coverage, drivers

# ============================================================
# VIOLATION CROSS-REFERENCE
# ============================================================

def load_violations(filepath):
    """Load violations CSV, capturing all columns for cycle-level context."""
    violations = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            v = {
                'rule_id': row.get('rule_id', ''),
                'rule_name': row.get('rule_name', ''),
                'channel': row.get('channel', ''),
                'cycle': row.get('cycle', ''),
                'signal': row.get('signal', ''),
                'expected': row.get('expected', ''),
                'actual': row.get('actual', ''),
                'description': row.get('description', ''),
            }
            violations.append(v)
    return violations

def _base_signal_name(name):
    """
    Collapse signal variants into a single base name.
    e.g. m_axil_arvalid, m_axil_arvalid_next, m_axil_arvalid_reg -> m_axil_arvalid
    """
    for suffix in ('_next', '_reg'):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name


def _format_violation_cycles(vlist, max_show=5):
    """Format violation cycle numbers with signal context."""
    lines = []
    shown = vlist[:max_show]
    for v in shown:
        parts = [f"cycle {v['cycle']}"]
        if v.get('signal'):
            parts.append(f"signal={v['signal']}")
        if v.get('expected') and v.get('actual'):
            parts.append(f"expected={v['expected']}, actual={v['actual']}")
        elif v.get('description'):
            parts.append(v['description'])
        lines.append('  - ' + ', '.join(parts))
    if len(vlist) > max_show:
        lines.append(f'  ... and {len(vlist) - max_show} more')
    return '\n'.join(lines)


# ============================================================
# CYCLE-LEVEL PREDICATE EXPLANATION
# ============================================================
# Bridge between structural detection (this file) and execution
# analysis (analyse_interactive).  For each matched violation
# cycle, identifies WHICH driver controls the signal and WHICH
# AXI dependencies are absent from its predicate.

def explain_violation_cycle(signal, cycle, drivers, required_deps):
    """
    Determine which driver controls *signal* and explain why it is
    protocol-incomplete at the given *cycle*.

    This is the STRUCTURAL version (no waveform evaluation).
    It inspects all driver conditions for the signal and checks
    whether required dependency signals appear in any of them.

    Parameters
    ----------
    signal        : str   – RTL signal name (e.g. "awready")
    cycle         : int   – violation cycle number
    drivers       : dict  – full driver table {signal: [driver_dicts]}
    required_deps : list  – protocol dependencies that MUST be in predicate
                            (e.g. ["WVALID", "WREADY"])

    Returns
    -------
    dict with keys:
        signal, cycle, winning_condition, rhs,
        missing_dependencies, present_dependencies,
        all_conditions, driver_count, status
    """
    result = {
        "signal": signal,
        "cycle": cycle,
        "winning_condition": None,
        "rhs": None,
        "missing_dependencies": list(required_deps),
        "present_dependencies": [],
        "all_conditions": [],
        "driver_count": 0,
        "status": "no_drivers",
    }

    # Find the signal in drivers (case-insensitive match)
    sig_drivers = None
    for sig_key in drivers:
        if sig_key.lower() == signal.lower():
            sig_drivers = drivers[sig_key]
            break

    # Also try common RTL prefixes
    if sig_drivers is None:
        for prefix in ["s_axi_", "m_axi_", "s_axil_", "m_axil_", "axil_", "axi_"]:
            test_name = prefix + signal.lower()
            for sig_key in drivers:
                if sig_key.lower() == test_name:
                    sig_drivers = drivers[sig_key]
                    break
            if sig_drivers is not None:
                break

    if not sig_drivers:
        return result

    result["driver_count"] = len(sig_drivers)

    # Collect all non-reset conditions
    non_reset_drivers = []
    for drv in sig_drivers:
        cond = drv.get("condition", drv.get("cond", "")).strip()
        cond_lower = cond.lower().replace(" ", "")
        is_reset = any(pat in cond_lower for pat in
                       ["!rst", "~rst", "!reset", "~reset",
                        "!aresetn", "~aresetn", "!s_axi_aresetn",
                        "~s_axi_aresetn"])
        if not is_reset and cond:
            non_reset_drivers.append(drv)
            result["all_conditions"].append(cond)

    if not non_reset_drivers:
        result["status"] = "only_reset_drivers"
        return result

    # If exactly one non-reset driver, it's the controlling condition
    if len(non_reset_drivers) == 1:
        drv = non_reset_drivers[0]
        cond = drv.get("condition", drv.get("cond", "")).strip()
        rhs = drv.get("rhs", "").strip()
        result["winning_condition"] = cond
        result["rhs"] = rhs
        result["status"] = "single_driver"
    else:
        # Multiple drivers: report all conditions
        # The LAST one in synthesis order typically wins (NBA semantics)
        drv = non_reset_drivers[-1]
        cond = drv.get("condition", drv.get("cond", "")).strip()
        rhs = drv.get("rhs", "").strip()
        result["winning_condition"] = cond
        result["rhs"] = rhs
        result["status"] = "multiple_drivers"

    # Check which required deps appear in ANY driver condition
    all_cond_text = " ".join(result["all_conditions"]).lower()
    # Also include RHS expressions (might reference signals)
    for drv in non_reset_drivers:
        rhs = drv.get("rhs", "").strip()
        if rhs:
            all_cond_text += " " + rhs.lower()

    present = []
    missing = []
    for dep in required_deps:
        dep_lower = dep.lower()
        found = False
        # Check bare name and common RTL prefixed variants
        # Use word-boundary regex to avoid false positives
        # (e.g. 'rvalid' matching inside 'arvalid')
        variants = [dep_lower]
        for prefix in ["s_axi_", "m_axi_", "s_axil_", "m_axil_", "axil_", "axi_"]:
            variants.append(prefix + dep_lower)
        for variant in variants:
            # \b ensures word boundary: 'rvalid' won't match 'arvalid'
            if re.search(r'\b' + re.escape(variant) + r'\b', all_cond_text):
                found = True
                break
        if found:
            present.append(dep)
        else:
            missing.append(dep)

    result["missing_dependencies"] = missing
    result["present_dependencies"] = present

    if not missing:
        result["status"] = "deps_satisfied"
    elif result["status"] not in ("only_reset_drivers",):
        result["status"] = "missing_deps"

    return result


def format_cycle_explanation(result):
    """
    Format a human-readable RCA explanation from explain_violation_cycle output.

    Output format:
        Cycle 486: AWREADY driven by:
          if (aw_state == IDLE && fifo_space)
        This condition does NOT reference: WVALID, WREADY handshake completion
        Therefore AWREADY is computed from local readiness instead of write
        transaction completion.
    """
    signal = result["signal"]
    cycle = result["cycle"]
    cond = result.get("winning_condition", "")
    rhs = result.get("rhs", "")
    missing = result.get("missing_dependencies", [])
    present = result.get("present_dependencies", [])
    status = result.get("status", "")

    lines = []

    if status == "no_drivers":
        lines.append(f"  Cycle {cycle}: {signal} — no drivers found in backtracking table")
        return "\n".join(lines)

    if status == "only_reset_drivers":
        lines.append(f"  Cycle {cycle}: {signal} — only reset drivers found (no functional logic)")
        return "\n".join(lines)

    # Header
    if cond:
        lines.append(f"  Cycle {cycle}: {signal} driven by:")
        lines.append(f"    if ({cond})")
        if rhs and rhs not in ("0", "1", "1'b0", "1'b1"):
            lines.append(f"    RHS = {rhs}")
    else:
        lines.append(f"  Cycle {cycle}: {signal} — condition not resolved")

    # Dependency analysis
    if missing:
        lines.append(f"    ✗ Does NOT reference: {', '.join(missing)}")
    if present:
        lines.append(f"    ✓ References: {', '.join(present)}")

    # Conclusion
    if missing and not present:
        lines.append(
            f"    → {signal} is computed from LOCAL logic only, "
            f"ignoring required AXI handshake dependencies"
        )
    elif missing:
        lines.append(
            f"    → {signal} checks {', '.join(present)} but MISSES "
            f"{', '.join(missing)} — incomplete protocol coordination"
        )

    if result.get("status") == "multiple_drivers":
        n = result.get("driver_count", 0)
        lines.append(f"    [NOTE] {n} drivers present — showing last-wins (NBA order)")

    return "\n".join(lines)


def match_all_issues_to_violations(issues, violations, drivers=None):
    """
    Match detected inter-FSM issues to actual violations.

    Fixes applied:
      1. Deduplicate signal variants (_next, _reg) into one finding
      2. Print violation cycle numbers and signal context
      3. Report violations that have NO matching inter-FSM root cause
    """
    violations_by_rule = defaultdict(list)
    for v in violations:
        violations_by_rule[v['rule_id']].append(v)

    print(f"\n{'='*80}")
    print("COMPLETE ROOT CAUSE ANALYSIS")
    print(f"{'='*80}\n")

    print("Violations found in waveform:")
    for rule_id, vlist in sorted(violations_by_rule.items()):
        print(f"  {rule_id}: {len(vlist)} violation(s)")
    print()

    # ------------------------------------------------------------------
    # FIX 1: Group issues by (rule_id, channel) to deduplicate
    #         All signals on the same channel with the same missing
    #         dependency are ONE root cause, not separate findings.
    # ------------------------------------------------------------------
    grouped = defaultdict(list)
    for issue in issues:
        rule = issue['result']['rule_id']
        ch = issue['channel']
        grouped[(rule, ch)].append(issue)

    matched_rules = set()
    matched = []

    for (rule, channel), group in sorted(grouped.items()):
        if rule not in violations_by_rule:
            continue

        matched_rules.add(rule)
        vlist = violations_by_rule[rule]

        # Pick the representative issue (first one)
        rep = group[0]
        # Collect all unique base signal names affected
        all_bases = sorted(set(_base_signal_name(iss['fsm']) for iss in group))

        print(f"{'!'*80}")
        print(f"CONFIRMED ROOT CAUSE: {rule}")
        print(f"{'!'*80}\n")
        print(f"Module:   {rep['module']}")
        print(f"Channel:  {channel}")
        print(f"Severity: {rep['result']['severity']}")
        print(f"\nViolation: {rule} - {rep['result']['rule_name']}")
        print(f"Occurrences: {len(vlist)}")

        # FIX 2: Show cycle-level detail
        print(f"\nViolation details:")
        print(_format_violation_cycles(vlist))

        print(f"\nRoot Cause: {rep['result']['explanation']}")
        print(f"\nMissing Inter-FSM Dependencies:")
        if rep['result']['missing_fsms']:
            print(f"  FSMs not checked: {', '.join(rep['result']['missing_fsms'])}")
        if rep['result']['missing_signals']:
            print(f"  Signals not checked: {', '.join(rep['result']['missing_signals'])}")
        print(f"\nAffected signals: {', '.join(all_bases)}")

        # ── Cycle-level predicate explanation ──────────────────────
        # Compute and ATTACH to issue dicts so downstream consumers
        # (rca.py Step 7) can use the structured data directly.
        representative_analysis = None
        if drivers is not None:
            # Pass ALL required signals (found + missing) so the cycle-level
            # analysis can report which are present vs absent in the winning condition
            all_required = rep['result'].get('required_signals', [])
            if not all_required:
                # Fallback: combine found + missing
                all_required = (rep['result'].get('found_signals', []) +
                                rep['result'].get('missing_signals', []))
            if all_required:
                print(f"\n  Predicate-level analysis:")
                cycles_shown = 0
                for v in vlist[:3]:
                    cyc = v.get('cycle', '')
                    if not cyc:
                        continue
                    try:
                        cyc_int = int(cyc)
                    except (ValueError, TypeError):
                        continue
                    for base_sig in all_bases:
                        explanation = explain_violation_cycle(
                            signal=base_sig,
                            cycle=cyc_int,
                            drivers=drivers,
                            required_deps=all_required,
                        )
                        if explanation.get("status") != "no_drivers":
                            print(format_cycle_explanation(explanation))
                            # Keep first valid one as representative
                            if representative_analysis is None:
                                representative_analysis = explanation
                            cycles_shown += 1
                            break
                    if cycles_shown >= 3:
                        break
                if representative_analysis is None:
                    print("    [No driver match for reported signal in backtracking table]")

        # Attach structured cycle_analysis to EVERY issue in this group
        if representative_analysis is not None:
            miss = representative_analysis.get("missing_dependencies", [])
            pres = representative_analysis.get("present_dependencies", [])
            sig = representative_analysis.get("signal", "?")
            if miss and not pres:
                expl_text = (f"{sig} is computed from local logic only, "
                             f"ignoring required AXI dependencies {', '.join(miss)}")
            elif miss:
                expl_text = (f"{sig} checks {', '.join(pres)} but misses "
                             f"{', '.join(miss)} — incomplete protocol coordination")
            else:
                expl_text = f"{sig} references all required dependencies"

            ca = {
                "cycle": representative_analysis.get("cycle"),
                "signal": sig,
                "winning_condition": representative_analysis.get("winning_condition", ""),
                "rhs": representative_analysis.get("rhs", ""),
                "missing_dependencies": miss,
                "present_dependencies": pres,
                "explanation": expl_text,
                "status": representative_analysis.get("status", ""),
            }
            for iss in group:
                iss["cycle_analysis"] = ca
        print()

        matched.append((rep, rule, len(vlist), all_bases))

    # ------------------------------------------------------------------
    # FIX 3: Report violations with NO inter-FSM root cause identified
    # ------------------------------------------------------------------
    unmatched_rules = set(violations_by_rule.keys()) - matched_rules
    if unmatched_rules:
        print(f"{'='*80}")
        print("UNRESOLVED VIOLATIONS (no inter-FSM root cause found)")
        print(f"{'='*80}\n")
        for rule_id in sorted(unmatched_rules):
            vlist = violations_by_rule[rule_id]
            rule_name = vlist[0].get('rule_name', '') if vlist else ''
            print(f"  {rule_id}: {rule_name}")
            print(f"  Occurrences: {len(vlist)}")
            print(f"  Violation details:")
            print(_format_violation_cycles(vlist))
            print(f"  Status: No missing inter-FSM dependency detected.")
            print(f"          Root cause may be intra-FSM logic or testbench stimulus.")
            print(f"          Use interactive analysis (commands: v, vp, vs) to investigate.\n")

    return matched

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    import sys
    import argparse

    print("\n")
    print("+" + "="*78 + "+")
    print("|" + " "*8 + "COMPLETE INTER-FSM CHECKER - SINGLE AXI MODULE" + " "*10 + "|")
    print("|" + " "*15 + "(All AXI4-Lite Rules Preserved)" + " "*23 + "|")
    print("+" + "="*78 + "+")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Inter-FSM Dependency Checker for AXI4-Lite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using specific files
  python inter_fsm.py <rtl_name>_true_drivers.csv violations.csv
  python inter_fsm.py axi_master_true_drivers.csv violations.csv
  
  # Using default violations.csv
  python inter_fsm.py axi_master_true_drivers.csv
  
  # Original default files
  python inter_fsm.py axil_adapter_rd_true_drivers.csv violations.csv
        """
    )
    
    parser.add_argument('drivers_file', 
                        type=str,
                        help='True drivers CSV file (e.g., <rtl_name>_true_drivers.csv)')
    parser.add_argument('violations_file', 
                        type=str, 
                        nargs='?',
                        default='violations.csv',
                        help='Violations CSV file (default: violations.csv)')
    
    args = parser.parse_args()
    
    drivers_file = Path(args.drivers_file)
    violations_file = Path(args.violations_file)
    
    # Validate files exist
    if not drivers_file.exists():
        print(f"\n[ERROR] True drivers file not found: {drivers_file}")
        print(f"\nExpected file format: <rtl_name>_true_drivers.csv")
        print(f"Example: axi_master_true_drivers.csv\n")
        sys.exit(1)
    
    if not violations_file.exists():
        print(f"\n[ERROR] Violations file not found: {violations_file}")
        print(f"\nPlease run axil4.py first to generate violations.csv\n")
        sys.exit(1)
    
    print(f"\n[INFO] Loading files:")
    print(f"  True drivers: {drivers_file}")
    print(f"  Violations:   {violations_file}\n")

    # Analyze single design
    all_issues, rule_coverage, loaded_drivers = analyze_single_design(drivers_file)

    # Load violations
    violations = load_violations(violations_file)

    # Match (pass drivers for cycle-level explanation)
    matched = match_all_issues_to_violations(all_issues, violations, drivers=loaded_drivers)

    # Summary
    print(f"{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}\n")

    print(f"Rule Coverage:")
    for rule_id in sorted(rule_coverage.keys()):
        print(f"  {rule_id}: checked")

    print()
    print(f"Total inter-FSM issues found: {len(all_issues)}")
    print(f"Issues matched to violations: {len(matched)}")
    print(f"Total violations in waveform: {len(violations)}")

    if matched:
        print(f"\nROOT CAUSES IDENTIFIED:\n")
        for issue, rule, count, affected_sigs in matched:
            print(f"  [OK] {rule} ({issue['channel']} channel)")
            print(f"       Module: {issue['module']}")
            print(f"       Violations: {count}")
            print(f"       Root cause: {issue['result']['explanation']}")
            print(f"       Affected signals: {', '.join(affected_sigs)}")
            print()
    else:
        print("\n[FAIL] Violations present but NO FSM-level gating detected")
        print("  -> Indicates protocol violation due to missing inter-channel dependency")
        print("  -> Use interactive analysis to investigate further")

    print()