#!/usr/bin/env python3
"""
Orchestrated CLI for AXI4-Lite Complete Analysis Pipeline
=========================================================
Complete analysis workflow:
1. IR Backtracking Analysis (existing pipeline) → true_drivers.csv
   1a. IR Building → IR JSON
   1b. IR Backtracking → backtracking CSV
   1c. True Drivers Extraction → true_drivers.csv
   1d. FSM Encoding Extraction → fsm_encodings.json
2. AXI4-Lite Protocol Checking (axil4.py) → violations.json/csv
3. Signal Grouping (grouping.py) → signals.csv
4. Interactive Analysis → user reviews signals
5. FSM Illegal State Detection (fsm_illegal_state.py) → transition + encoding checks
6. Inter-FSM Analysis (inter_fsm.py) → only if no root causes found

Usage:
    python cli_orchestrated.py --interactive <waveform.csv>
    OR
    waveeye.exe --interactive <waveform.csv>
"""

import sys
import os
import io
import contextlib
from pathlib import Path

# ============================================================
# EXE-SAFE IMPORT PATH SETUP
# Must be BEFORE any project imports!
# ============================================================

def setup_import_paths(debug=False):
    """Configure import paths to work in both development and production."""
    candidates = []

    # Prefer script directory whenever __file__ is available.
    # In frozen runpy execution this is typically _MEIPASS/IR_backtracking.
    try:
        candidates.append(Path(__file__).parent.resolve())
    except NameError:
        pass

    if getattr(sys, 'frozen', False):
        mei = Path(getattr(sys, '_MEIPASS', Path(sys.executable).parent))
        candidates.extend([
            mei / "IR_backtracking",
            mei,
            Path(sys.executable).parent / "IR_backtracking",
            Path(sys.executable).parent,
        ])

    # Dev fallback
    candidates.append(Path.cwd())

    # Resolve, dedupe, and enforce deterministic precedence:
    # script directory first, then frozen fallbacks, cwd last.
    ordered = []
    seen = set()
    for candidate in candidates:
        c = candidate.resolve()
        key = str(c).lower()
        if key in seen or not c.exists():
            continue
        seen.add(key)
        ordered.append(c)

    # Remove any existing occurrences and re-insert in priority order.
    for c in ordered:
        c_str = str(c)
        sys.path = [p for p in sys.path if p != c_str]

    for c in reversed(ordered):
        sys.path.insert(0, str(c))

    # Return first valid path; this is used to resolve sibling scripts.
    if ordered:
        return ordered[0]

    return Path.cwd()

_debug_imports = os.environ.get('WAVEEYE_DEBUG', '').lower() in ('1', 'true', 'yes')
_script_dir = setup_import_paths(debug=_debug_imports)

# ============================================================
# IMPORT PROJECT MODULES
# ============================================================

try:
    from ir_builder import build_ir_to_json
    from IR_backtracking import run_ir_backtracking
    from true_drivers import extract_true_drivers
    from rca_8 import run_waveeye_rca  # Hybrid RCA stack (protocol + datapath fusion)
except ImportError as e:
    print(f"\n[ERROR] Failed to import required modules: {e}")
    sys.exit(1)

import json
import csv
import time
import subprocess
import importlib.util
import re
from typing import List, Optional, Dict, Any
from contextlib import contextmanager, redirect_stdout, redirect_stderr

# ── Verbosity gate ────────────────────────────────────────────────────────────
# Production mode is silent except for errors and the final diagnostic block.
# Set WAVEEYE_VERBOSE=1 to restore all progress messages.
_VERBOSE: bool = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"


@contextmanager
def _suppress_intermediate_output(enabled: bool):
    """Optionally suppress stdout/stderr for noisy analysis substeps."""
    if not enabled:
        yield
        return
    with open(os.devnull, "w", encoding="utf-8", errors="ignore") as sink:
        with redirect_stdout(sink), redirect_stderr(sink):
            yield


def _run_with_quiet_output(func, *args, **kwargs):
    """
    Run noisy analyzers quietly in production mode.
    Set WAVEEYE_VERBOSE=1 to see full intermediate logs.
    """
    with _suppress_intermediate_output(enabled=not _VERBOSE):
        return func(*args, **kwargs)

try:
    from reports import generate_console_diagnosis as _gen_report_check
    _REPORTS_AVAILABLE = True
except ImportError:
    _REPORTS_AVAILABLE = False

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║     AXI4-LITE COMPLETE ANALYSIS PIPELINE - INTERACTIVE MODE      ║
║        IR Backtrack → Protocol → Grouping → FSM Analysis         ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_header(title):
    if not _VERBOSE:
        return
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_success(message):
    if _VERBOSE:
        print(f"✓ [OK] {message}")

def print_warning(message):
    print(f"⚠ [WARNING] {message}")

def print_error(message):
    print(f"✗ [ERROR] {message}")

def print_info(message):
    if _VERBOSE:
        print(f"ℹ [INFO] {message}")

def print_step(step_num, total, description):
    if _VERBOSE:
        print(f"\n[STEP {step_num}/{total}] {description}")
        print("-" * 70)


def _find_latest_user_run_dir(waveform_csv: Path) -> Optional[Path]:
    """
    Find latest run directory in an outputs root using userNNN naming.
    Example: .../outputs/user129
    """
    candidate_roots: List[Path] = []

    # Prefer outputs roots discoverable from waveform path.
    for p in [waveform_csv.parent, *waveform_csv.parents]:
        if p.name.lower() == "outputs":
            candidate_roots.append(p)

    # Common local fallback roots.
    candidate_roots.append(Path.cwd() / "outputs")
    candidate_roots.append(Path.home() / "WaveEye" / "outputs")

    # Optional explicit override for deployments.
    env_root = os.environ.get("WAVEEYE_OUTPUTS_ROOT", "").strip()
    if env_root:
        candidate_roots.append(Path(env_root))

    # Deduplicate while preserving order.
    seen = set()
    roots = []
    for root in candidate_roots:
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        roots.append(root)

    user_pattern = re.compile(r"^user(\d+)$", re.IGNORECASE)
    best = None
    best_key = (-1, -1.0)  # (user_number, mtime)

    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            for child in root.iterdir():
                if not child.is_dir():
                    continue
                m = user_pattern.match(child.name)
                if not m:
                    continue
                user_num = int(m.group(1))
                has_expected = (child / "preprocessing").exists() or (child / "analysis").exists()
                if not has_expected:
                    continue
                mtime = child.stat().st_mtime
                key = (user_num, mtime)
                if key > best_key:
                    best_key = key
                    best = child
        except Exception:
            continue

    return best


def _pick_waveform_csv_from_preprocessing(pre_dir: Path, fallback_waveform: Path) -> Path:
    """Pick a mapped waveform CSV from preprocessing folder, fallback to current waveform."""
    if not pre_dir.exists() or not pre_dir.is_dir():
        return fallback_waveform

    candidates: List[Path] = []
    for pattern in ("*mapped*.csv", "*waveform*.csv", "*.csv"):
        candidates.extend(sorted(pre_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True))
        if candidates:
            break

    return candidates[0] if candidates else fallback_waveform


def _analysis_has_violations_files(analysis_dir: Path) -> bool:
    """True if analysis dir already contains violations JSON/CSV artifacts."""
    if not analysis_dir.exists() or not analysis_dir.is_dir():
        return False
    if (analysis_dir / "violations.json").exists() or (analysis_dir / "violations.csv").exists():
        return True
    if any(analysis_dir.glob("*violations*.json")):
        return True
    if any(analysis_dir.glob("*violations*.csv")):
        return True
    return False


def _analysis_has_driver_files(analysis_dir: Path) -> bool:
    """True if analysis dir contains true_drivers CSV artifacts."""
    if not analysis_dir.exists() or not analysis_dir.is_dir():
        return False
    if any(analysis_dir.glob("*true_drivers*.csv")):
        return True
    return False

# ============================================================
# RTL FILE SELECTION
# ============================================================
# [UNTOUCHED] — both functions preserved exactly

def find_rtl_files(search_dir: Path) -> List[Path]:
    rtl_files = []
    rtl_files.extend(search_dir.glob("*.sv"))
    rtl_files.extend(search_dir.glob("*.v"))
    if not rtl_files:
        rtl_files.extend(search_dir.glob("*/*.sv"))
        rtl_files.extend(search_dir.glob("*/*.v"))
    return sorted(rtl_files)

def interactive_rtl_selection(waveform_csv: Path) -> List[Path]:
    rtl_dir = None
    test_path = Path.cwd() / "Preprocessing" / "user_input"
    if test_path.exists():
        rtl_dir = test_path

    if not rtl_dir:
        search_dir = Path.cwd()
        for _ in range(5):
            test_path = search_dir / "Preprocessing" / "user_input"
            if test_path.exists():
                rtl_dir = test_path
                break
            if search_dir.parent == search_dir:
                break
            search_dir = search_dir.parent

    if not rtl_dir and waveform_csv:
        outputs_dir = waveform_csv.parent.parent.parent
        test_path = outputs_dir / "Preprocessing" / "user_input"
        if test_path.exists():
            rtl_dir = test_path

    if not rtl_dir:
        rtl_dir = Path.cwd()

    rtl_files = find_rtl_files(rtl_dir)

    if not rtl_files:
        print_error(f"No RTL files found in: {rtl_dir}")
        print_error("Please ensure RTL files (.sv or .v) are in Preprocessing/user_input/")
        return []

    print_info(f"RTL directory: {rtl_dir}")
    print(f"\nProcessing all {len(rtl_files)} RTL file(s):")
    for rtl in rtl_files:
        print(f"  - {rtl.name}")

    return rtl_files

# ============================================================
# STEP 1: IR BACKTRACKING PIPELINE
# ============================================================
# [UNTOUCHED] — process_rtl_file preserved exactly

def process_rtl_file(rtl_file: Path, output_dir: Path) -> dict:
    base_name = rtl_file.stem
    
    ir_json = output_dir / f"{base_name}_ir.json"
    backtrack_csv = output_dir / f"{base_name}_backtracking.csv"
    backtrack_json = output_dir / f"{base_name}_backtracking.json"
    true_drivers_csv = output_dir / f"{base_name}_true_drivers.csv"
    fsm_encodings_json = output_dir / f"{base_name}.fsm_encodings.json"
    
    results = {
        'rtl_file': rtl_file.name,
        'rtl_path': rtl_file,
        'base_name': base_name,
        'success': False,
        'ir_json': None,
        'backtrack_csv': None,
        'backtrack_json': None,
        'true_drivers_csv': None,
        'fsm_encodings_json': None,
        'errors': []
    }
    
    print_header(f"PROCESSING: {rtl_file.name}")
    
    # Build IR
    if _VERBOSE: print(f"\n[1/4] Building IR...")
    try:
        build_ir_to_json([str(rtl_file)], ir_json)
        if ir_json.exists():
            print_success(f"IR generated: {ir_json.name}")
            results['ir_json'] = ir_json
        else:
            raise Exception("IR file not generated")
    except Exception as e:
        error_msg = f"IR building failed: {e}"
        print_error(error_msg)
        results['errors'].append(error_msg)
        return results
    
    # IR Backtracking
    if _VERBOSE: print(f"\n[2/4] Running IR backtracking...")
    try:
        run_ir_backtracking(ir_json, backtrack_csv, backtrack_json)
        
        if backtrack_csv.exists():
            print_success(f"Backtracking CSV: {backtrack_csv.name}")
            results['backtrack_csv'] = backtrack_csv
        
        if backtrack_json.exists():
            print_success(f"Backtracking JSON: {backtrack_json.name}")
            results['backtrack_json'] = backtrack_json
        
        if not (backtrack_csv.exists() or backtrack_json.exists()):
            raise Exception("Backtracking files not generated")
            
    except Exception as e:
        error_msg = f"Backtracking failed: {e}"
        print_error(error_msg)
        results['errors'].append(error_msg)
        return results
    
    # Extract True Drivers
    if _VERBOSE: print(f"\n[3/4] Extracting true drivers...")
    try:
        extract_true_drivers(backtrack_csv, true_drivers_csv)
        
        if true_drivers_csv.exists():
            print_success(f"True drivers: {true_drivers_csv.name}")
            results['true_drivers_csv'] = true_drivers_csv
            results['success'] = True
        else:
            raise Exception("True drivers file not generated")
            
    except Exception as e:
        error_msg = f"True drivers extraction failed: {e}"
        print_error(error_msg)
        results['errors'].append(error_msg)
        return results
    
    # Extract FSM Encodings
    if _VERBOSE: print(f"\n[4/4] Extracting FSM encodings from RTL...")
    enc_result = extract_fsm_encodings_for_rtl(rtl_file, fsm_encodings_json)
    if enc_result:
        results['fsm_encodings_json'] = enc_result
    
    print_success(f"Processing complete: {rtl_file.name}")
    return results


# ============================================================
# FSM ENCODING EXTRACTION
# ============================================================

def extract_fsm_encodings_for_rtl(rtl_file: Path, output_json: Path) -> Optional[Path]:
    """
    Extract FSM encodings (enum types + localparams) from a single RTL file.
    
    Returns:
        Path to generated JSON, or None on failure.
    """
    try:
        fsm_enc_path = _script_dir / "extract_fsm_encodings.py"
        
        if not fsm_enc_path.exists():
            raise FileNotFoundError(f"extract_fsm_encodings.py not found at {fsm_enc_path}")
        
        spec = importlib.util.spec_from_file_location("extract_fsm_encodings", fsm_enc_path)
        extract_fsm_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extract_fsm_mod)
        
        encodings = extract_fsm_mod.extract_fsm_encodings(str(rtl_file))
        
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(encodings, f, indent=2)
        
        total_enums = len(encodings.get('enums', {}))
        total_params = len(encodings.get('localparams', {}))
        total_members = sum(len(m) for m in encodings.get('enums', {}).values())
        
        print_success(f"FSM encodings: {output_json.name}")
        print_info(f"  {total_enums} enum(s) ({total_members} members), {total_params} localparam(s)")
        return output_json
        
    except Exception as e:
        print_warning(f"FSM encoding extraction failed: {e}")
        print_info("Illegal FSM state detection will be unavailable for this file")
        return None


# ============================================================
# STEP 2: AXI4-LITE PROTOCOL CHECKING
# ============================================================
# [UNTOUCHED] — run_axil4_checker preserved exactly

def run_axil4_checker(waveform_csv: Path, output_dir: Path) -> Optional[Dict]:
    print_step(2, 7, "AXI4-LITE PROTOCOL CHECKING")
    
    violations_json = output_dir / 'violations.json'
    violations_csv = output_dir / 'violations.csv'
    
    try:
        axil4_path = _script_dir / 'axil4.py'
        
        if not axil4_path.exists():
            raise FileNotFoundError(f"axil4.py not found at {axil4_path}")
        
        spec = importlib.util.spec_from_file_location("axil4", axil4_path)
        axil4 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(axil4)
        
        _verbose = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"
        waveform_data = axil4.load_csv_waveform(waveform_csv, verbose=_verbose)

        checker = axil4.CompleteAXI4LiteChecker()
        violations = checker.run(waveform_data, verbose=_verbose)

        # Write JSON
        with open(violations_json, 'w') as f:
            json.dump([v.to_dict() for v in violations], f, indent=2)
        
        # Write CSV
        with open(violations_csv, 'w', newline='') as f:
            if violations:
                all_fact_keys = set()
                for v in violations:
                    all_fact_keys.update(v.facts.keys())
                fact_keys = sorted(all_fact_keys)
                
                header = ['rule_id', 'rule_name', 'cycle', 'channel', 'severity', 
                          'explanation', 'symptoms', 'root_cause', 'recommendation']
                header.extend([f'fact_{k}' for k in fact_keys])
                
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                
                for v in violations:
                    row = {
                        'rule_id': v.rule_id,
                        'rule_name': v.rule_name,
                        'cycle': v.cycle,
                        'channel': v.channel,
                        'severity': v.severity,
                        'explanation': v.explanation,
                        'symptoms': v.symptoms,
                        'root_cause': v.root_cause,
                        'recommendation': v.recommendation
                    }
                    for fk in fact_keys:
                        row[f'fact_{fk}'] = v.facts.get(fk, '')
                    writer.writerow(row)
            else:
                f.write("rule_id,rule_name,cycle,channel,severity,explanation,symptoms,root_cause,recommendation\n")
        
        return {
            'violations_json': violations_json,
            'violations_csv': violations_csv,
            'violation_count': len(violations)
        }
        
    except Exception as e:
        print_error(f"AXI4-Lite checking failed: {e}")
        import traceback
        traceback.print_exc()
        return None

# ============================================================
# STEP 3: SIGNAL GROUPING
# ============================================================
# [UNTOUCHED] — run_signal_grouping preserved exactly

def run_signal_grouping(violations_json: Path, output_dir: Path) -> Optional[Path]:
    print_step(3, 7, "SIGNAL GROUPING & ANALYSIS")
    
    signals_csv = output_dir / 'signals.csv'
    
    try:
        grouping_path = _script_dir / 'grouping.py'
        
        if not grouping_path.exists():
            raise FileNotFoundError(f"grouping.py not found at {grouping_path}")
        
        spec = importlib.util.spec_from_file_location("grouping", grouping_path)
        grouping = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(grouping)
        
        print_info(f"Loading violations: {violations_json.name}")
        analyzer = grouping.AutomaticViolationAnalyzer()
        num_violations = analyzer.load_violations(violations_json)
        if num_violations == 0:
            print_info("No protocol violations found — generating structural signal groupings")

            analyzer.analysis_results = []
            analyzer.export_signals_csv(signals_csv)

            # ensure file actually exists
            if not signals_csv.exists():
                with open(signals_csv, "w") as f:
                    f.write("rule_id,cycle,primary_signals,secondary_signals\n")

            print_success(f"Generated structural grouping: {signals_csv.name}")
            return signals_csv


        
        print_info(f"Loaded {num_violations} violations")
        print_info("Analyzing violations and grouping signals...")
        
        analyzer.analyze_all()
        
        # Export signals CSV (max 3 violations per rule)
        analyzer.export_signals_csv(signals_csv)
        print_success(f"Generated: {signals_csv.name}")
        
        return signals_csv
        
    except Exception as e:
        print_error(f"Signal grouping failed: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================
# STEP 4: INTERACTIVE SIGNAL ANALYSIS (analyse_interactive.py)
# ============================================================
# [MODIFIED] — signals_csv is now Optional[Path] to support generic mode.
#              This is explicitly required by spec requirement B:
#              "analyse_interactive MUST be runnable even if there are ZERO
#               protocol violations ... using true_drivers.csv as its causal input"

def run_interactive_analysis(waveform_csv: Path, backtracking_csv: Path,
                             signals_csv: Optional[Path] = None,
                             fsm_encodings_json: Optional[Path] = None) -> bool:

    """
    Run analyse_interactive.py for deep signal exploration
    
    Args:
        waveform_csv: Path to waveform CSV
        backtracking_csv: Path to backtracking CSV (or true_drivers.csv)
        signals_csv: Path to signals CSV (for reference); None in generic mode
        
    Returns:
        True if root causes found, False otherwise
    """
    print_step(4, 7, "INTERACTIVE SIGNAL ANALYSIS (analyse_interactive.py)")

    try:
        # --------------------------------------------------
        # Show signal groups if available
        # --------------------------------------------------
        if signals_csv and signals_csv.exists():
            print_info("Signal Groups Preview (from grouping analysis):")
            print("="*70)

            with open(signals_csv, 'r') as f:
                reader = csv.DictReader(f)
                signals = list(reader)

            if signals:
                by_rule = {}
                for sig in signals:
                    by_rule.setdefault(sig['rule_id'], []).append(sig)

                for rule_id in sorted(by_rule.keys()):
                    rule_signals = by_rule[rule_id]
                    print(f"\n{rule_id} ({len(rule_signals)} violations):")
                    print("-"*70)

                    for sig in rule_signals:
                        print(f"  Cycle {sig['cycle']}:")
                        print(f"    PRIMARY:   {sig['primary_signals']}")
                        print(f"    SECONDARY: {sig['secondary_signals']}")
            else:
                print_warning("No signals found in CSV")

            print("\n" + "="*70)

        else:
            print_info("Running in generic RTL causality mode")
            print_info(f"Causal input: {backtracking_csv.name}")
            print("="*70)

        # --------------------------------------------------
        # Launch interactive tool
        # --------------------------------------------------
        import runpy
        import sys
        import os

        analyse_interactive_path = _script_dir / "analyse_interactive.py"

        if not analyse_interactive_path.exists():
            print_warning(f"analyse_interactive.py not found at {analyse_interactive_path}")
            response = input("\nDid you find clear root causes from the analysis above? (yes/no): ").strip().lower()
            return response in ("yes", "y")

        if not backtracking_csv.exists():
            print_error(f"Backtracking CSV not found: {backtracking_csv}")
            return False

        if not waveform_csv.exists():
            print_error(f"Waveform CSV not found: {waveform_csv}")
            return False

        print_info(f"Waveform: {waveform_csv.name}")
        print_info(f"Backtracking: {backtracking_csv.name}")
        if signals_csv:
            print_info(f"Signals: {signals_csv.name}")
        print()

        argv_backup = sys.argv[:]
        cwd_backup = os.getcwd()

        stdout_backup = sys.stdout
        stderr_backup = sys.stderr

        try:
            sys.argv = [
                str(analyse_interactive_path),
                str(waveform_csv.resolve()),
                str(backtracking_csv.resolve()),
            ]

            if signals_csv and signals_csv.exists():
                sys.argv.append(str(signals_csv.resolve()))

            if fsm_encodings_json and fsm_encodings_json.exists():
                sys.argv.append(str(fsm_encodings_json.resolve()))

            os.chdir(analyse_interactive_path.parent)

            # ---------------------------------------------
            # Run interactive safely (prevent sys.exit kill)
            # ---------------------------------------------
            try:
                runpy.run_path(str(analyse_interactive_path), run_name="__main__")
            except SystemExit:
                pass
            except EOFError:
                # stdin is not a TTY (e.g. piped input or non-interactive run) —
                # skip interactive analysis silently.
                return True

        finally:
            # restore interpreter state
            sys.argv = argv_backup
            os.chdir(cwd_backup)

            sys.stdout = stdout_backup
            sys.stderr = stderr_backup

            # PyInstaller protection if child closed them
            if sys.stdout is None or getattr(sys.stdout, "closed", False):
                sys.stdout = open(os.devnull, "w")

            if sys.stderr is None or getattr(sys.stderr, "closed", False):
                sys.stderr = open(os.devnull, "w")


        print("\n" + "="*70)
        print("Interactive analysis session ended")
        print("="*70)
        try:
            input("\nPress Enter to continue...")
            response = input("\nDid you find the root cause through interactive analysis? (yes/no): ").strip().lower()
            return response in ("yes", "y")
        except EOFError:
            return True

    # --------------------------------------------------
    # OUTER exception handlers (required)
    # --------------------------------------------------
    except KeyboardInterrupt:
        print("\n\nInteractive analysis interrupted by user")
        try:
            response = input("\nDid you find the root cause before interrupting? (yes/no): ").strip().lower()
            return response in ("yes", "y")
        except EOFError:
            return True

    except EOFError:
        # Non-interactive run (piped stdin / no TTY) — skip cleanly.
        return True

    except Exception as e:
        print_error(f"Interactive analysis failed: {e}")
        import traceback
        traceback.print_exc()

        try:
            response = input("\nProceed without inter-FSM analysis? (yes to skip, no to continue): ").strip().lower()
            return response in ("yes", "y")
        except EOFError:
            return True



# STEP 5: FSM ILLEGAL STATE DETECTION (fsm_illegal_state.py)
# ============================================================

def run_fsm_illegal_state_check(
    waveform_csv: Path,
    true_drivers_csv: Path,
    fsm_encodings_json: Path,
    violations_csv: Optional[Path],
    output_dir: Path
) -> Optional[Dict]:
    """
    Run fsm_illegal_state.py to detect:
      - Encoding violations (value ∉ legal set, X/Z)
      - Transition violations (prev→curr not in RTL graph)
      - Dead states (defined but never visited)
    Then perform 5-step RCA on each finding.
    
    Args:
        waveform_csv:       Mapped waveform CSV (from preprocessing)
        true_drivers_csv:   True drivers CSV (from IR backtracking)
        fsm_encodings_json: FSM encodings JSON (from extract_fsm_encodings)
        violations_csv:     Protocol violations CSV (optional, from axil4)
        output_dir:         Directory for output files
    
    Returns:
        Dict with 'findings' list and 'count', or None on failure.
    """
    print_step(5, 7, "FSM ILLEGAL STATE DETECTION")
    
    if not fsm_encodings_json or not fsm_encodings_json.exists():
        print_warning("FSM encodings JSON not available — skipping illegal state detection")
        print_info("Run extract_fsm_encodings.py first, or ensure RTL has enum/localparam FSM states")
        return None
    
    try:
        #
        fsm_illegal_path = _script_dir / 'fsm_illegal_state.py'
        
        if not fsm_illegal_path.exists():
            print_warning(f"fsm_illegal_state.py not found at {fsm_illegal_path}")
            print_info("Skipping illegal FSM state detection")
            return None
        
        spec = importlib.util.spec_from_file_location("fsm_illegal_state", fsm_illegal_path)
        fsm_illegal_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fsm_illegal_mod)
        
        print_info(f"Waveform:   {waveform_csv.name}")
        print_info(f"Drivers:    {true_drivers_csv.name}")
        print_info(f"Encodings:  {fsm_encodings_json.name}")
        if violations_csv and violations_csv.exists():
            print_info(f"Violations: {violations_csv.name}")
        
        # Call the main analysis entry point
        findings = fsm_illegal_mod.analyze_illegal_fsm_states(
            waveform_csv=str(waveform_csv),
            backtracking_csv=str(true_drivers_csv),
            fsm_encodings_json=str(fsm_encodings_json),
            violations_csv=str(violations_csv) if (violations_csv and violations_csv.exists()) else None
        )
        
        if not findings:
            print_success("All FSM states & transitions legal — no issues detected")
            return {'findings': [], 'count': 0}
        
        # Print findings summary
        print(f"\n{'='*70}")
        print(f"FSM ILLEGAL STATE FINDINGS: {len(findings)} issue(s)")
        print(f"{'='*70}")
        
        # Group by classification
        by_class = {}
        for finding in findings:
            cls = finding.get('classification', 'UNKNOWN')
            by_class.setdefault(cls, []).append(finding)
        
        for cls, items in sorted(by_class.items()):
            print(f"\n  {cls}: {len(items)} finding(s)")
            for item in items:
                sig = item.get('fsm_signal', '?')
                val = item.get('illegal_value', '?')
                cyc = item.get('cycle', '?')
                fix = item.get('fix_suggestion', '')
                print(f"    → {sig} = {val} @ cycle {cyc}")
                if fix:
                    print(f"      Fix: {fix}")
        
        # Save findings to JSON
        findings_json = output_dir / 'fsm_illegal_state_findings.json'
        with open(findings_json, 'w', encoding='utf-8') as fj:
            json.dump(findings, fj, indent=2)
        print_success(f"Findings saved: {findings_json.name}")
        
        return {'findings': findings, 'count': len(findings)}
        
    except Exception as e:
        print_error(f"FSM illegal state detection failed: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================
# VP/VS GROUPING FROM FSM FINDINGS (generic mode)
# ============================================================

def build_vpvs_from_fsm_findings(fsm_result: Optional[Dict],
                                  true_drivers_csv: Path) -> Optional[Dict]:
    """
    Derive VP (primary violation) / VS (secondary) signal groupings
    from FSM illegal state findings. Used in generic mode where no
    signals.csv exists from protocol checking.
    
    VP = FSM signals with findings
    VS = Signals referenced in their driver conditions (dependencies)
    
    Returns: dict with 'vp_signals', 'vs_signals', 'groups' or None
    """
    if not fsm_result or not fsm_result.get('findings'):
        return None
    
    findings = fsm_result['findings']
    vp_signals = set()
    vs_signals = set()
    groups = []
    
    for f in findings:
        fsm_sig = f.get('fsm_signal', '')
        classification = f.get('classification', 'UNKNOWN')
        
        if not fsm_sig:
            continue
        
        vp_signals.add(fsm_sig)
        
        # Extract dependency signals from condition and contributing signals
        contributing = f.get('contributing_signals', {})
        for dep_sig in contributing:
            if dep_sig != fsm_sig:
                vs_signals.add(dep_sig)
        
        groups.append({
            'vp': fsm_sig,
            'vs': sorted(contributing.keys() - {fsm_sig}) if contributing else [],
            'classification': classification,
            'cycle': f.get('cycle', '?'),
            'fix': f.get('fix_suggestion', ''),
        })
    
    # Remove any VP signals from VS (VP takes priority)
    vs_signals -= vp_signals
    
    return {
        'vp_signals': sorted(vp_signals),
        'vs_signals': sorted(vs_signals),
        'groups': groups,
    }


def display_vpvs_groups(vpvs: Dict):
    """Display VP/VS signal groups in the interactive analysis header."""
    if not vpvs:
        return
    
    print("\n" + "="*70)
    print("  FSM-DERIVED SIGNAL GROUPS (VP = Primary, VS = Secondary)")
    print("="*70)
    
    for g in vpvs['groups']:
        print(f"\n  [{g['classification']}] @ cycle {g['cycle']}:")
        print(f"    VP (primary):   {g['vp']}")
        if g['vs']:
            print(f"    VS (secondary): {', '.join(g['vs'])}")
        else:
            print(f"    VS (secondary): (none identified)")
        if g['fix']:
            print(f"    Fix: {g['fix']}")
    
    print("\n" + "="*70)


# ============================================================
# STEP 7: UNIFIED RCA SYNTHESIS
# ============================================================
# Correlates FSM illegal state findings with protocol violation cycles
# and inter-FSM dependency gaps to produce one actionable verdict.

# AXI rule → (direction, request_signal, ready_signal)
_SYNTH_RULE_MAP = {
    'RULE_2':  ('read',  'ARVALID', 'ARREADY'),
    'RULE_3':  ('write', 'AWVALID', 'AWREADY'),
    'RULE_4':  ('write', 'WVALID',  'WREADY'),
    'RULE_5':  ('read',  'RVALID',  'RREADY'),
    'RULE_6':  ('write', 'BVALID',  'BREADY'),
    'RULE_10': ('read',  'ARVALID', 'RVALID'),
    'RULE_11': ('write', 'AWVALID', 'BVALID'),
    'RULE_12': ('read',  'ARVALID', 'RVALID'),
    'RULE_13': ('write', 'AWVALID', 'BVALID'),
}

# FSM classification priority (how actionable/certain the finding is)
_SYNTH_FSM_PRIORITY = {
    'PROTOCOL_ILLEGAL':      5,
    'ENCODING_ILLEGAL':      4,
    'EXECUTION_ORDER':       3,
    'UNREACHABLE_TRANSITION':3,
    'RESET_VIOLATION':       1,   # too early in time to be causal
    'DEAD_STATE':            1,
}

# Max cycles between FSM event and downstream protocol violation
_SYNTH_CYCLE_WINDOW = 60


def _synth_rule_cycles(rca_result: dict) -> dict:
    """Extract {rule_id: [cycle, ...]} from rca_result findings."""
    out = {}
    for f in (rca_result or {}).get('findings') or []:
        rule = f.get('rule_id') or f.get('rule') or f.get('violation_type') or ''
        cycle = f.get('cycle') or f.get('analysis_cycle')
        if rule and cycle is not None:
            try:
                out.setdefault(rule, []).append(int(cycle))
            except (ValueError, TypeError):
                pass
    return out


def _synth_fsm_cycle(finding: dict):
    """Return integer cycle from FSM finding, or None."""
    raw = finding.get('cycle')
    if raw is None or str(raw).upper() in ('N/A', 'NONE', ''):
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _synth_correlate(fsm_findings: list, rule_cycles: dict) -> list:
    """
    Return list of (fsm_finding, rule_id, downstream_cycles, confidence)
    for FSM events that precede protocol violations within the cycle window.
    Excludes RESET_VIOLATION / DEAD_STATE (too early to be causal).
    """
    links = []
    for fsm_f in fsm_findings:
        fc = _synth_fsm_cycle(fsm_f)
        if fc is None:
            continue
        cls = fsm_f.get('classification', '')
        pri = _SYNTH_FSM_PRIORITY.get(cls, 0)
        if pri <= 1:
            continue   # RESET / DEAD — not causal in this window

        for rule, cycles in rule_cycles.items():
            nearby = sorted(c for c in cycles if fc <= c <= fc + _SYNTH_CYCLE_WINDOW)
            if nearby:
                conf = 'HIGH' if pri >= 4 else 'MEDIUM'
                links.append((fsm_f, rule, nearby, conf))

    # Deduplicate by (fsm_signal, rule), keep highest priority
    seen = {}
    for fsm_f, rule, nearby, conf in links:
        key = (fsm_f.get('fsm_signal', ''), rule)
        cur_pri = _SYNTH_FSM_PRIORITY.get(fsm_f.get('classification', ''), 0)
        if key not in seen or cur_pri > _SYNTH_FSM_PRIORITY.get(seen[key][0].get('classification', ''), 0):
            seen[key] = (fsm_f, rule, nearby, conf)

    return sorted(seen.values(),
                  key=lambda t: (-_SYNTH_FSM_PRIORITY.get(t[0].get('classification', ''), 0),
                                 _synth_fsm_cycle(t[0]) or 0))


def print_synthesis_verdict(
    rca_result:       Optional[dict],
    fsm_result:       Optional[dict],
    inter_fsm_result: Optional[dict],
) -> None:
    """
    Correlate RCA + FSM + inter-FSM results and print one unified verdict.

    Priority:
      1. FSM illegal state with cycle proximity to protocol violations  -> FSM root cause
      2. Inter-FSM matched dependency gap                               -> INTER_FSM root cause
      3. RCA engine DATAPATH / TRANSPORT                                -> RTL root cause
      4. RCA engine PROTOCOL                                            -> pure protocol
      5. Nothing found                                                  -> INCONCLUSIVE
    """
    SEP  = '=' * 72
    SEP2 = '-' * 72

    fsm_findings   = (fsm_result       or {}).get('findings') or []
    inter_matched  = (inter_fsm_result  or {}).get('matched')  or []
    rca_final      = (rca_result        or {}).get('final_rca') or {}
    rca_root_type  = rca_final.get('root_cause_type', 'INCONCLUSIVE')
    rca_summary    = rca_final.get('summary') or rca_final.get('explanation') or ''

    rule_cycles    = _synth_rule_cycles(rca_result or {})
    causal_links   = _synth_correlate(fsm_findings, rule_cycles)

    # Primary failing rule (most violations)
    if rule_cycles:
        primary_rule, primary_cycles = max(
            rule_cycles.items(), key=lambda kv: len(kv[1]))
        primary_signal = _SYNTH_RULE_MAP.get(primary_rule, ('?', primary_rule, '?'))[1]
    else:
        primary_rule, primary_cycles, primary_signal = 'UNKNOWN', [], 'UNKNOWN'

    # Collect fix recommendations
    fixes = []
    unresolved = [r for r in rule_cycles
                  if r not in {lnk[1] for lnk in causal_links}]

    # Determine root cause type and detail
    if causal_links:
        fsm_f, rule, dcycles, conf = causal_links[0]
        cls     = fsm_f.get('classification', '')
        sig     = fsm_f.get('fsm_signal', '?')
        val     = str(fsm_f.get('illegal_value', '?'))
        fc      = _synth_fsm_cycle(fsm_f)
        root_type   = 'FSM_ILLEGAL'
        root_detail = (f"{sig} escapes to illegal value {val} at cycle {fc} "
                       f"[{cls}], causing {rule} violations at cycles "
                       f"{', '.join(str(c) for c in dcycles[:6])}")
        for fsm_f2, _, _, _ in causal_links:
            fix = fsm_f2.get('fix_suggestion', '')
            sig2 = fsm_f2.get('fsm_signal', '')
            cls2 = fsm_f2.get('classification', '')
            if fix:
                entry = f"[{sig2} / {cls2}]  {fix}"
                if entry not in fixes:
                    fixes.append(entry)

    elif inter_matched:
        item   = inter_matched[0]
        issue  = item[0]
        irule  = item[1]
        icount = item[2]
        expl   = issue.get('result', {}).get('explanation', '')
        root_type   = 'INTER_FSM'
        root_detail = (f"Missing inter-FSM dependency on {issue.get('fsm','?')} "
                       f"({issue.get('channel','?')} channel) — "
                       f"{expl}  ({icount} occurrence(s) of {irule})")
        if expl:
            fixes.append(f"[Inter-FSM / {irule}]  {expl}")

    elif rca_root_type in ('DATAPATH', 'TRANSPORT'):
        root_type   = rca_root_type
        root_detail = rca_summary or f"RTL datapath defect detected ({rca_root_type})"
        conf        = rca_final.get('confidence', 'MEDIUM')
        for ev in (rca_final.get('primary_evidence') or [])[:2]:
            s = ev.get('fix') or ev.get('description') or ''
            if s and s not in fixes:
                fixes.append(f"[Datapath]  {s}")

    elif rca_root_type == 'PROTOCOL':
        root_type   = 'PROTOCOL'
        root_detail = rca_summary or 'Pure protocol handshake violation — no upstream RTL defect confirmed'
        if not fixes and primary_signal != 'UNKNOWN':
            ready = _SYNTH_RULE_MAP.get(primary_rule, ('?', '?', 'READY'))[2]
            fixes.append(
                f"[Protocol]  Review {primary_signal} driver logic — "
                f"signal must stay high until {ready} is asserted "
                f"(AXI4-Lite persistence rule)"
            )
    else:
        root_type   = 'INCONCLUSIVE'
        root_detail = 'No causal root cause identified across all analysis engines'

    # Always include RESET_VIOLATION fixes as secondary recommendations
    for fsm_f in fsm_findings:
        if fsm_f.get('classification') == 'RESET_VIOLATION':
            fix = fsm_f.get('fix_suggestion', '')
            sig = fsm_f.get('fsm_signal', '')
            if fix:
                entry = f"[{sig} / RESET]  {fix}"
                if entry not in fixes:
                    fixes.append(entry)

    # Confidence label
    conf_tag = {'HIGH': '[HIGH]', 'MEDIUM': '[MED] ', 'LOW': '[LOW] '}
    if causal_links:
        conf = causal_links[0][3]
    elif inter_matched:
        conf = 'MEDIUM'
    elif rca_root_type in ('DATAPATH', 'TRANSPORT', 'PROTOCOL'):
        conf = rca_final.get('confidence', 'MEDIUM')
    else:
        conf = 'LOW'
    ctag = conf_tag.get(conf, '[???] ')

    root_tag = {
        'FSM_ILLEGAL':  '[FSM]     ',
        'INTER_FSM':    '[FSM-DEP] ',
        'DATAPATH':     '[RTL]     ',
        'TRANSPORT':    '[RTL]     ',
        'PROTOCOL':     '[PROTO]   ',
        'INCONCLUSIVE': '[?]       ',
    }.get(root_type, '[?]       ')

    # ── Print ────────────────────────────────────────────────────────────────
    print()
    print(SEP)
    print('  UNIFIED ROOT CAUSE SYNTHESIS')
    print(SEP)

    # Primary failure
    print(f"\n  Primary Failure  :  {primary_rule}"
          + (f"  (signal: {primary_signal})" if primary_signal != primary_rule else ''))
    if primary_cycles:
        cyc_str = ', '.join(str(c) for c in sorted(primary_cycles)[:8])
        if len(primary_cycles) > 8:
            cyc_str += f'  (+{len(primary_cycles)-8} more)'
        print(f"  Violation cycles :  {cyc_str}")

    # Root cause
    print(f"\n  Root Cause {root_tag}")
    print(f"  {ctag}  {root_detail}")

    # Causal chain
    if causal_links:
        print(f"\n{SEP2}")
        print('  CAUSAL CHAIN')
        print(SEP2)
        for i, (fsm_f2, lrule, dcycles, lconf) in enumerate(causal_links, 1):
            sig2  = fsm_f2.get('fsm_signal', '?')
            val2  = str(fsm_f2.get('illegal_value', '?'))
            cls2  = fsm_f2.get('classification', '')
            fc2   = _synth_fsm_cycle(fsm_f2)
            dcstr = ', '.join(str(c) for c in dcycles[:6])
            asigs = list(_SYNTH_RULE_MAP.get(lrule, ('?', lrule, '?'))[1:])
            print(f"\n  [{i}] {sig2} at cycle {fc2}  [{cls2}]")
            print(f"       FSM escapes to illegal value {val2}")
            print(f"       Downstream violation: {lrule}  (cycles {dcstr})")
            if asigs:
                print(f"       Affected AXI signals: {', '.join(asigs)}")

    # Fix recommendations
    if fixes:
        print(f"\n{SEP2}")
        print('  FIX RECOMMENDATIONS')
        print(SEP2)
        for i, fix in enumerate(fixes, 1):
            # Word-wrap at 68 chars
            words, line, lines = fix.split(), '', []
            for w in words:
                if len(line) + len(w) + 1 > 68:
                    lines.append(line); line = w
                else:
                    line = f'{line} {w}' if line else w
            if line:
                lines.append(line)
            print(f"\n  {i}. {lines[0]}")
            for ln in lines[1:]:
                print(f"     {ln}")

    # Unresolved violations
    if unresolved:
        print(f"\n{SEP2}")
        print('  UNRESOLVED VIOLATIONS  (no FSM causal link found)')
        print(SEP2)
        for rule in sorted(unresolved):
            print(f"  - {rule}  -> likely intra-FSM logic or testbench stimulus")
        print('    Use interactive analysis (commands: v, vp, vs) to investigate.')

    # Summary
    print(f"\n{SEP2}")
    print(f"  Evidence summary:  "
          f"FSM findings={len(fsm_findings)}  "
          f"inter-FSM matched={len(inter_matched)}  "
          f"RCA engine={rca_root_type}  "
          f"confidence={conf}")
    print(SEP)
    print()


# ============================================================
# STRUCTURAL ANALYSIS: Generic mode detector on AXI signals
# ============================================================

def run_structural_analysis(
    rca_result: Optional[dict],
    waveform_csv: str,
    drivers_csv: str,
) -> None:
    """
    Run analyse_interactive.py as a subprocess on the primary signal and
    its dependency signals (missing + found from predicate analysis).
    Signal numbers are pre-computed from the drivers CSV so that
    communicate() can be used — avoiding readline() deadlocks on prompts
    that have no trailing newline.
    """
    if not rca_result:
        return
    ai_path = _script_dir / "analyse_interactive.py"
    if not ai_path.exists():
        return

    pred_a = (rca_result.get("final_rca") or {}).get("predicate_analysis") or {}

    # Build set of target signal names (uppercase for matching)
    targets: set = set()
    pa_sig = (pred_a.get("signal") or "").strip()
    if pa_sig:
        targets.add(pa_sig.upper())
    for s in (pred_a.get("missing_signals") or []) + (pred_a.get("found_signals") or []):
        if s:
            targets.add(s.strip().upper())

    if not targets:
        return

    import subprocess, csv as _csv

    # Read signal list from drivers CSV to determine menu numbers without
    # waiting for the interactive prompt (menu is alphabetically sorted).
    _sigs: list = []
    try:
        with open(drivers_csv, encoding="utf-8-sig", errors="replace") as _f:
            for _row in _csv.DictReader(_f):
                _s = (_row.get("signal") or "").strip()
                if _s and not _s.startswith("---") and _s != "NEXT DRIVER" and _s not in _sigs:
                    _sigs.append(_s)
        _sigs.sort()
    except Exception:
        return

    sig_nums = [str(i + 1) for i, s in enumerate(_sigs) if s.upper() in targets]
    if not sig_nums:
        return

    # Build full stdin up-front: select signals → Enter to continue → quit
    # The script interaction pattern is:
    #   "Enter command: "  → send "1,3\n"
    #   analysis output
    #   "Press Enter to continue..." → send "\n"
    #   "Enter command: "  → send "q\n"
    stdin_input = ",".join(sig_nums) + "\n\nq\n"

    try:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(ai_path), waveform_csv, drivers_csv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        stdout, _ = proc.communicate(input=stdin_input, timeout=60)
    except Exception:
        return

    # Extract only the analysis sections — everything from the first
    # "ANALYZING:" block to "Analysis complete" (strips menu/header noise).
    import re as _re
    sections = _re.findall(
        r'(={10,}.*?ANALYZING:.*?Analysis complete[^\n]*)',
        stdout, flags=_re.S
    )
    if sections:
        print("")
        print("\n\n".join(s.strip() for s in sections))
        print("")


def _detect_clock_from_csv(csv_path: str) -> Optional[str]:
    """Detect clock signal from a waveform CSV (thin wrapper)."""
    try:
        from rca_core.io import detect_clock
        return detect_clock(str(csv_path))
    except Exception:
        return None


# ============================================================
# STEP 6: INTER-FSM ANALYSIS
# ============================================================

def run_inter_fsm_analysis(true_drivers_csv: Path, violations_csv: Path, output_dir: Path) -> dict:
    print_step(6, 7, "INTER-FSM DEPENDENCY ANALYSIS")
    
    print_info("Running comprehensive inter-FSM analysis...")
    print_info("This checks for missing dependencies between FSMs")
    
    try:
        inter_fsm_path = _script_dir / 'inter_fsm.py'
        if not inter_fsm_path.exists():
            raise FileNotFoundError(f"inter_fsm.py not found at {inter_fsm_path}")
        
        spec = importlib.util.spec_from_file_location("inter_fsm", inter_fsm_path)
        inter_fsm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inter_fsm)
        
        print_info("Discovering FSMs...")
        # analyze_single_design returns (all_issues, rule_coverage, drivers) — 3-tuple
        all_issues, rule_coverage, _drv = inter_fsm.analyze_single_design(true_drivers_csv)

        print_info("Loading violations...")
        violations = inter_fsm.load_violations(violations_csv)

        print_info("Matching issues to violations...")
        matched = inter_fsm.match_all_issues_to_violations(all_issues, violations, _drv)
        
        # Print results
        print("\n" + "="*70)
        print("INTER-FSM ANALYSIS RESULTS")
        print("="*70)
        
        print(f"\nRule Coverage:")
        for rule_id in sorted(rule_coverage.keys()):
            print(f"  ✓ {rule_id}")
        
        print(f"\nTotal inter-FSM issues found: {len(all_issues)}")
        print(f"Issues matched to violations: {len(matched)}")
        print(f"Total violations in waveform: {len(violations)}")
        
        if matched:
            print(f"\n{'='*70}")
            print("ROOT CAUSES IDENTIFIED:")
            print(f"{'='*70}")
            for item in matched:
                issue = item[0]
                rule  = item[1]
                count = item[2]

                print(f"\n {rule} → {issue['fsm']}")
                print(f"  Module: {issue['module']}")
                print(f"  Channel: {issue['channel']}")
                print(f"  Violation count: {count}")
                print(f"  Root cause: {issue['result']['explanation']}")

        else:
            print("\n⚠ Violations present but NO FSM-level gating detected")
            print("  → Indicates protocol violation due to missing inter-channel dependency")
        
        return {
            'all_issues': all_issues,
            'matched':    matched,
            'rule_coverage': rule_coverage,
            'violations': violations,
            'success':    len(matched) > 0,
        }

    except Exception as e:
        print_error(f"Inter-FSM analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return {'all_issues': [], 'matched': [], 'rule_coverage': {}, 'violations': [], 'success': False}


# ============================================================
# FSM FALLBACK CHECKS (triggered when rca_8 returns INCONCLUSIVE)
# ============================================================

def _offer_fsm_fallback_checks(
    rca_result: Optional[Dict],
    waveform_path: Path,
    drivers_path: Optional[Path],
    all_results: List[Dict],
    violations_csv: Optional[Path],
    output_dir: Path,
) -> None:
    """
    Called after run_waveeye_rca() when the result is INCONCLUSIVE.

    Interactively offers two supplementary checks:
      1. FSM Illegal State Detection  — encoding/transition/dead-state violations
      2. Inter-FSM Dependency Analysis — missing cross-channel FSM dependencies

    Both checks use the same artifacts already produced by the pipeline
    (waveform CSV, true drivers CSV, FSM encodings JSON, violations CSV).

    The user can choose either, both, or skip entirely.
    """
    if not rca_result:
        return

    final_rca   = rca_result.get("final_rca") or {}
    rca_type    = final_rca.get("root_cause_type", "")
    confidence  = final_rca.get("confidence", "")
    explanation = final_rca.get("explanation", "")

    # Only activate when rca_8 explicitly returned INCONCLUSIVE
    if rca_type != "INCONCLUSIVE":
        return

    print("\n" + "=" * 70)
    print("  RCA-8 RESULT: INCONCLUSIVE")
    print("=" * 70)
    print(f"  Type      : {rca_type}")
    print(f"  Confidence: {confidence or 'LOW'}")
    if explanation:
        print(f"  Reason    : {str(explanation)[:120]}")
    print()
    print("  No conclusive root cause was found by the RCA-8 pipeline.")
    print("  Supplementary FSM checks may uncover additional evidence:")
    print()
    print("    1. FSM Illegal State Detection")
    print("       Detects illegal encodings (X/Z or out-of-range), unreachable")
    print("       transitions (prev->curr not in RTL graph), and dead states.")
    print("       Runs 5-step per-finding RCA:")
    print("         encoding -> transition -> protocol -> execution -> reset")
    print()
    print("    2. Inter-FSM Dependency Analysis")
    print("       Checks for missing cross-channel FSM dependencies (RULE_7,")
    print("       RULE_8, RULE_12, RULE_13 …) and correlates issues to")
    print("       waveform violation cycles.")
    print()
    print("    3. Both of the above")
    print("    4. Skip  (accept INCONCLUSIVE result)")
    print()

    while True:
        choice = input("  Choose check to run (1/2/3/4): ").strip()
        if choice in ("1", "2", "3", "4"):
            break
        print("  Invalid choice. Enter 1, 2, 3, or 4.")

    if choice == "4":
        print_info("Skipping supplementary FSM checks — INCONCLUSIVE accepted.")
        return

    run_fsm_check  = choice in ("1", "3")
    run_ifsm_check = choice in ("2", "3")

    # ── Resolve FSM encodings JSON from IR backtracking results ──────────────
    fsm_enc_json: Optional[Path] = None
    for res in all_results:
        enc = res.get("fsm_encodings_json")
        if enc:
            fsm_enc_json = Path(enc)
            break

    # ── 1. FSM Illegal State Detection ────────────────────────────────────────
    if run_fsm_check:
        if not drivers_path or not drivers_path.exists():
            print_warning("True drivers CSV not available — cannot run FSM illegal state check")
        elif not fsm_enc_json or not fsm_enc_json.exists():
            print_warning("FSM encodings JSON not found.")
            print_info("This file is produced by extract_fsm_encodings.py from RTL source.")
            print_info("Ensure your RTL defines FSM states via 'typedef enum' or 'localparam'.")
        else:
            fsm_result = _run_with_quiet_output(
                run_fsm_illegal_state_check,
                waveform_csv=waveform_path,
                true_drivers_csv=drivers_path,
                fsm_encodings_json=fsm_enc_json,
                violations_csv=violations_csv,
                output_dir=output_dir,
            )
            vpvs = build_vpvs_from_fsm_findings(fsm_result, drivers_path)
            if vpvs:
                display_vpvs_groups(vpvs)

    # ── 2. Inter-FSM Dependency Analysis ──────────────────────────────────────
    if run_ifsm_check:
        if not drivers_path or not drivers_path.exists():
            print_warning("True drivers CSV not available — cannot run inter-FSM analysis")
        elif not violations_csv or not violations_csv.exists():
            print_warning("Protocol violations CSV not available for inter-FSM analysis.")
            print_info("Inter-FSM correlation requires violations from the AXI4-Lite checker.")
            print_info("Re-run with analysis mode 2 (AXI4-Lite RCA) to generate violations.")
        else:
            _run_with_quiet_output(run_inter_fsm_analysis, drivers_path, violations_csv, output_dir)


# ============================================================
# ANALYSIS MODE SELECTION
# ============================================================
# [NEW] — Required by spec item A: explicit mode selection after IR backtracking.
# Inserted as a decision point between Step 1 and Steps 2-5.

def select_analysis_mode() -> str:
    """
    Prompt user to choose analysis mode after IR backtracking completes.
    
    Returns one of: 'generic', 'axil_direct', 'both'
    """
    print_header("SELECT ANALYSIS MODE")
    print()
    print("  1. Generic RTL causality analysis only")
    print("     → Run interactive analysis using true_drivers.csv")
    print("     → Skip AXI4-Lite protocol checking entirely")
    print()
    print("  2. AXI4-Lite protocol RCA")
    print("     → Run AXI4-Lite checker + signal grouping")
    print("     → Interactive analysis available regardless of violation count")
    print()
    print("  3. Both (generic first, then optional AXI4-Lite)")
    print("     → Run interactive analysis first (true_drivers.csv)")
    print("     → Then optionally run AXI4-Lite protocol checking")
    print()
    
    while True:
        choice = input("Select mode (1/2/3): ").strip()
        if choice == '1':
            print_info("Mode: Generic RTL causality analysis")
            return 'generic'
        elif choice == '2':
            print_info("Mode: AXI4-Lite protocol RCA")
            print_info("Input files will be auto-resolved from current run paths")
            return 'axil_direct'
        elif choice == '3':
            print_info("Mode: Both (generic + AXI4-Lite)")
            return 'both'
        else:
            print_warning("Invalid choice. Enter 1, 2, or 3.")


# ============================================================
# MAIN ENTRY POINT
# ============================================================
def main():
    start_time = time.time()
    
    print_banner()
    
    print_info(f"Arguments: {sys.argv}")
    
    # ================================================================
    # ENTRY POINT: waveform-first (no --interactive required)
    # ================================================================
    # [UNTOUCHED] — arg parsing preserved exactly
    from pathlib import Path
    
    # Strip optional flags (backward compatible)
    args = [
        arg for arg in sys.argv[1:]
        if arg.lower() not in ('--interactive', '-i')
    ]
    
    # Extract waveform CSV
    csv_args = [arg for arg in args if arg.lower().endswith('.csv')]
    
    if not csv_args:
        print_error("Waveform CSV required")
        print("\nUsage:")
        print("  python cli_orchestrated.py <waveform.csv>")
        sys.exit(1)
    
    waveform_csv = Path(csv_args[0]).resolve()
    
    if not waveform_csv.exists():
        print_error(f"Waveform CSV not found: {waveform_csv}")
        sys.exit(1)
    
    print_info(f"Waveform CSV: {waveform_csv}")
    
    # ================================================================
    # SETUP OUTPUT DIRECTORY
    # ================================================================
    # [UNTOUCHED]
    
    if waveform_csv.parent.name == "preprocessing":
        output_dir = waveform_csv.parent.parent / "analysis"
    else:
        output_dir = Path.cwd() / "outputs" / "analysis"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    print_info(f"Output directory: {output_dir}")
    
    # ================================================================
    # PIPELINE STEP 1: IR BACKTRACKING
    # ================================================================
    # [UNTOUCHED] — IR backtracking logic preserved exactly
    
    print_header("PIPELINE PHASE 1: IR BACKTRACKING")
    
    # Auto-select all RTL files
    rtl_files = interactive_rtl_selection(waveform_csv)

    if not rtl_files:
        print_error("No RTL files found — cannot run IR backtracking")
        sys.exit(1)
    
    all_results = []
    true_drivers_csv = None
    
    for idx, rtl_file in enumerate(rtl_files, 1):
        print(f"\n{'='*70}")
        print(f"  RTL FILE {idx}/{len(rtl_files)}")
        print(f"{'='*70}")
        
        result = process_rtl_file(rtl_file, output_dir)
        all_results.append(result)
        
        if result['success'] and result['true_drivers_csv']:
            true_drivers_csv = result['true_drivers_csv']
    
    success_count = sum(1 for r in all_results if r['success'])
    if success_count == 0:
        print_error("IR backtracking failed for all RTL files")
        sys.exit(1)

    print_success(f"IR backtracking completed: {success_count}/{len(rtl_files)} files")

    # ── Merge true_drivers CSVs from all processed RTL files ─────────────────
    _all_driver_csvs = [
        r['true_drivers_csv'] for r in all_results
        if r['success'] and r.get('true_drivers_csv') and Path(r['true_drivers_csv']).exists()
    ]
    if len(_all_driver_csvs) > 1:
        import csv as _csv
        _merged_path = output_dir / "merged_true_drivers.csv"
        with open(_merged_path, "w", newline="", encoding="utf-8") as _mf:
            _writer = _csv.writer(_mf)
            _header_written = False
            for _p in _all_driver_csvs:
                with open(_p, newline="", encoding="utf-8") as _sf:
                    _reader = _csv.reader(_sf)
                    _hdr = next(_reader, None)
                    if _hdr and not _header_written:
                        _writer.writerow(_hdr)
                        _header_written = True
                    for _row in _reader:
                        _writer.writerow(_row)
        true_drivers_csv = _merged_path
        print_success(f"Merged true_drivers: merged_true_drivers.csv ({len(_all_driver_csvs)} modules)")
    
    # ================================================================
    # [NEW] DECISION POINT: ANALYSIS MODE SELECTION
    # ================================================================
    # Required by spec item A: user must explicitly choose analysis mode
    # after IR backtracking completes, before any protocol-specific steps.
    
    analysis_mode = select_analysis_mode()
    if analysis_mode == 'axil_direct':
        if _VERBOSE: print("\n[AXI-LITE RCA MODE]\n")
        current_drivers_file = None
        if true_drivers_csv:
            try:
                tdc = Path(true_drivers_csv)
                if tdc.exists():
                    current_drivers_file = tdc
            except Exception:
                current_drivers_file = None

        use_current_run = bool(current_drivers_file) or _analysis_has_driver_files(output_dir)

        if use_current_run:
            print_info("Using current run artifacts for AXI-Lite RCA")
            mapped_waveform = waveform_csv
            analysis_dir = output_dir
            analysis_dir.mkdir(parents=True, exist_ok=True)

            print_info(f"AXI-Lite checker waveform: {mapped_waveform}")
            axil4_result = run_axil4_checker(mapped_waveform, analysis_dir)
            if not axil4_result and not _analysis_has_violations_files(analysis_dir):
                print_error("AXI4-Lite checker did not produce violations artifacts for current run.")
                print_error(f"Expected in: {analysis_dir}")
                sys.exit(1)

            mapped_csv = str(mapped_waveform)
            drivers_csv = str(current_drivers_file) if current_drivers_file else str(analysis_dir)
            violations_json = str(analysis_dir)
        else:
            latest_user_dir = _find_latest_user_run_dir(waveform_csv)
            if latest_user_dir:
                print_info(f"Using latest user run folder: {latest_user_dir}")
                preprocessing_dir = latest_user_dir / "preprocessing"
                analysis_dir = latest_user_dir / "analysis"
                analysis_dir.mkdir(parents=True, exist_ok=True)

                mapped_waveform = _pick_waveform_csv_from_preprocessing(preprocessing_dir, waveform_csv)
                print_info(f"AXI-Lite checker waveform: {mapped_waveform}")
                axil4_result = run_axil4_checker(mapped_waveform, analysis_dir)

                if not axil4_result and not _analysis_has_violations_files(analysis_dir):
                    print_error("AXI4-Lite checker did not produce violations artifacts for latest user run.")
                    print_error(f"Expected in: {analysis_dir}")
                    sys.exit(1)
                if not _analysis_has_driver_files(analysis_dir):
                    print_error("Latest user run has no true_drivers CSV for RCA.")
                    print_error(f"Expected in: {analysis_dir}")
                    sys.exit(1)

                mapped_csv = str(mapped_waveform)
                drivers_csv = str(analysis_dir)
                violations_json = str(analysis_dir)
            else:
                print_warning("No userNNN run folder found; falling back to current run paths")
                # Ensure protocol artifacts exist before RCA.
                if not _analysis_has_violations_files(output_dir):
                    print_info("No violations artifacts in fallback analysis folder; running AXI4-Lite checker now.")
                    axil4_result = run_axil4_checker(waveform_csv, output_dir)
                    if not axil4_result and not _analysis_has_violations_files(output_dir):
                        print_error("AXI4-Lite checker did not produce violations artifacts in fallback analysis folder.")
                        print_error(f"Expected in: {output_dir}")
                        sys.exit(1)

                mapped_csv = str(waveform_csv)
                drivers_csv = str(true_drivers_csv) if true_drivers_csv else str(output_dir)
                violations_json = str(output_dir)
        rca_result = run_waveeye_rca(
            waveform_csv=mapped_csv,
            drivers_csv=drivers_csv,
            violations_path=violations_json,
            context_dir=str(output_dir),
            debug=False,
        )

        # ── Structural analysis on primary + dependency signals ───────────────
        _struct_bugs = run_structural_analysis(rca_result, mapped_csv, drivers_csv) or []

        # ── FSM fallback: offered interactively when rca_8 is INCONCLUSIVE ───
        _vcsv = output_dir / "violations.csv"
        _offer_fsm_fallback_checks(
            rca_result    = rca_result,
            waveform_path = Path(mapped_csv),
            drivers_path  = Path(drivers_csv) if drivers_csv else None,
            all_results   = all_results,
            violations_csv= _vcsv if _vcsv.exists() else None,
            output_dir    = output_dir,
        )

        # ── FSM Illegal State Detection ───────────────────────────────────────
        _drivers_path = Path(drivers_csv) if drivers_csv else None
        _fsm_enc_json = None
        for _r in all_results:
            if _r.get('fsm_encodings_json'):
                _fsm_enc_json = _r['fsm_encodings_json']
                break

        _fsm_result = None
        if _fsm_enc_json and _drivers_path:
            _fsm_result = _run_with_quiet_output(
                run_fsm_illegal_state_check,
                waveform_csv=Path(mapped_csv),
                true_drivers_csv=_drivers_path,
                fsm_encodings_json=Path(_fsm_enc_json),
                violations_csv=_vcsv if _vcsv.exists() else None,
                output_dir=output_dir,
            )

        # ── Inter-FSM Dependency Analysis ─────────────────────────────────────
        _inter_result = None
        _violations_csv = _vcsv if _vcsv.exists() else None
        if _drivers_path and _violations_csv:
            _inter_result = _run_with_quiet_output(
                run_inter_fsm_analysis,
                _drivers_path,
                _violations_csv,
                output_dir,
            )
        # (inter-FSM result included in report via print_synthesis_verdict fallback)

        # ── Unified Root Cause Report ─────────────────────────────────────────
        if rca_result and _REPORTS_AVAILABLE:
            try:
                from reports import generate_console_diagnosis as _gen_report
                _fsm_finds   = (_fsm_result or {}).get("findings") or []
                # Extract design name from mapped CSV filename
                _dn = Path(mapped_csv).stem.replace("_mapped", "").replace("_signals", "")
                print("")
                try:
                    print(_gen_report(rca_result, fsm_findings=_fsm_finds,
                                      design_name=_dn, structural_bugs=_struct_bugs))
                except UnicodeEncodeError:
                    _r = _gen_report(rca_result, fsm_findings=_fsm_finds,
                                     design_name=_dn, structural_bugs=_struct_bugs)
                    print(_r.encode("ascii", errors="replace").decode("ascii"))
            except Exception as _e:
                print_warning(f"Report generation failed: {_e}")
                print_synthesis_verdict(rca_result, _fsm_result, _inter_result)
        else:
            print_synthesis_verdict(rca_result, _fsm_result, _inter_result)

        elapsed = time.time() - start_time
        print_header("ANALYSIS COMPLETE")
        print(f"\nTotal execution time: {elapsed:.2f}s\n")
        return
    
    # Resolve backtracking CSV for interactive analysis (used in all modes)
    backtracking_csv = None
    for result in all_results:
        if result['success'] and result['backtrack_csv']:
            backtracking_csv = result['backtrack_csv']
            break
    
    # ================================================================
    # MODE: GENERIC RTL CAUSALITY ANALYSIS
    # ================================================================
    # Spec item A.1: Run analyse_interactive with true_drivers.csv only.
    # Spec item B: analyse_interactive MUST be runnable with zero violations.
    # No protocol checking, no signal grouping, no inter-FSM.
    
    if analysis_mode == 'generic':
        print_header("PIPELINE PHASE 2: GENERIC RTL CAUSALITY ANALYSIS")
        
        print_info("Skipping AXI4-Lite protocol checking (not selected)")
        print_info("Skipping signal grouping (no protocol violations to group)")
        
        if not true_drivers_csv:
            print_error("True drivers CSV not available for interactive analysis")
            sys.exit(1)
        
        # Run interactive analysis with true_drivers only, no signals.csv
        run_interactive_analysis(
            waveform_csv,
            true_drivers_csv,
            signals_csv=None  # Spec B: works without protocol data
        )
        
        # Step 5: FSM Illegal State Detection (runs in all modes)
        fsm_enc_json = None
        for result in all_results:
            if result.get('fsm_encodings_json'):
                fsm_enc_json = result['fsm_encodings_json']
                break
        
        fsm_result = None
        if fsm_enc_json:
            fsm_result = _run_with_quiet_output(
                run_fsm_illegal_state_check,
                waveform_csv, true_drivers_csv, fsm_enc_json,
                violations_csv=None,  # no protocol violations in generic mode
                output_dir=output_dir
            )
        else:
            print_info("Skipping FSM illegal state detection (no encodings available)")
        
        # VP/VS grouping from FSM findings (generic mode substitute for signals.csv)
        vpvs = build_vpvs_from_fsm_findings(fsm_result, true_drivers_csv)
        if vpvs:
            display_vpvs_groups(vpvs)
        
        # Skip inter-FSM: spec item D — only runs when protocol violations exist
        print_info("Skipping inter-FSM analysis (no protocol violations to correlate)")
    
    # ================================================================
    # MODE: AXI4-LITE PROTOCOL RCA
    # ================================================================
    # Spec item A.2: Run AXI4-Lite checker. If violations → full pipeline.
    # If no violations → still allow analyse_interactive (spec item B).
    # Spec item C: zero violations is informational, not an exit condition.
    
    elif analysis_mode == 'axil':
        print_header("PIPELINE PHASE 2: PROTOCOL & SIGNAL ANALYSIS")
        
        # --- Step 2: AXI4-Lite protocol checking ---
        axil4_result = run_axil4_checker(waveform_csv, output_dir)
        
        if not axil4_result:
            # Spec item C: checker failure ≠ silent exit. Inform and continue.
            print_warning("AXI4-Lite protocol checking failed or no AXI signals detected")
            print_info("This may indicate the design is not AXI4-Lite")
            print_info("Continuing with interactive analysis using true_drivers.csv")
            
            if true_drivers_csv:
                run_interactive_analysis(
                    waveform_csv,
                    true_drivers_csv,
                    signals_csv=None
                )
            else:
                print_error("True drivers CSV not available")
        
        elif axil4_result is not None:
            # --- Step 3: Signal grouping (always executed) ---
            signals_csv = None

            if axil4_result['violation_count'] > 0:
                print_info("Protocol violations detected → running protocol signal grouping")
                signals_csv = run_signal_grouping(
                    axil4_result['violations_json'],
                    output_dir
                )
            else:
                print_success("No protocol violations detected")
                print_info("Running structural signal grouping (no-rule mode)")

                try:
                    grouping_path = _script_dir / 'grouping.py'
                    spec = importlib.util.spec_from_file_location("grouping", grouping_path)
                    grouping = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(grouping)

                    analyzer = grouping.AutomaticViolationAnalyzer()
                    analyzer.violations = []   # empty violation list
                    analyzer.analyze_all()

                    signals_csv = output_dir / "signals.csv"
                    analyzer.export_signals_csv(signals_csv)

                    print_success(f"Generated: {signals_csv.name}")

                except Exception as e:
                    print_warning(f"Structural grouping failed: {e}")



            
            if not signals_csv:
                print_warning("Signal grouping produced no output")
                print_info("Continuing with interactive analysis using true_drivers.csv")
            
            # --- Step 4: Interactive analysis (with protocol signals) ---
            if not true_drivers_csv:
                print_error("True drivers CSV not available for interactive analysis")
                print_warning("Skipping interactive analysis")
                root_causes_found = False
            else:
                root_causes_found = run_interactive_analysis(
                    waveform_csv,
                    true_drivers_csv,
                    signals_csv  # May be None if grouping failed
                )
            
            # --- Step 5: FSM Illegal State Detection ---
            fsm_enc_json = None
            for result in all_results:
                if result.get('fsm_encodings_json'):
                    fsm_enc_json = result['fsm_encodings_json']
                    break
            
            if fsm_enc_json:
                _run_with_quiet_output(
                    run_fsm_illegal_state_check,
                    waveform_csv, true_drivers_csv, fsm_enc_json,
                    violations_csv=axil4_result['violations_csv'],
                    output_dir=output_dir
                )
            
            # --- Step 6: Inter-FSM (conditional) ---
            # Spec item D: ONLY runs when protocol violations exist (they do here)
            if not root_causes_found:
                print("\n" + "="*70)
                print_info("No clear root causes found in interactive analysis")
                print_info("Proceeding to inter-FSM dependency analysis...")

                if not true_drivers_csv:
                    print_error("True drivers CSV not available for inter-FSM analysis")
                else:
                    inter_fsm_r = _run_with_quiet_output(
                        run_inter_fsm_analysis,
                        true_drivers_csv,
                        axil4_result['violations_csv'],
                        output_dir
                    )

                    if not inter_fsm_r.get('success'):
                        print_warning("Inter-FSM analysis did not identify additional root causes")
            else:
                print("\n" + "="*70)
                print_success("Root causes identified in interactive analysis!")
                print_info("Skipping inter-FSM analysis (not needed)")
    
    # ================================================================
    # MODE: BOTH (GENERIC FIRST, THEN OPTIONAL AXI4-LITE)
    # ================================================================
    # Spec item A.3: Always run interactive first, then optionally protocol.
    
    elif analysis_mode == 'both':
        # --- Phase 2a: Generic interactive analysis first ---
        print_header("PIPELINE PHASE 2a: GENERIC RTL CAUSALITY ANALYSIS")
        
        if not true_drivers_csv:
            print_error("True drivers CSV not available for interactive analysis")
            root_causes_found = False
        else:
            root_causes_found = run_interactive_analysis(
                waveform_csv,
                true_drivers_csv,
                signals_csv=None
            )
        
        # --- Phase 2b: Optional AXI4-Lite protocol checking ---
        print_header("PIPELINE PHASE 2b: OPTIONAL AXI4-LITE PROTOCOL CHECK")
        
        if root_causes_found:
            print_success("Root causes already identified in generic analysis")
            run_protocol = input("Still run AXI4-Lite protocol checking? (yes/no): ").strip().lower()
        else:
            print_info("No root causes found yet. AXI4-Lite checking recommended.")
            run_protocol = input("Run AXI4-Lite protocol checking? (yes/no): ").strip().lower()
        
        if run_protocol in ('yes', 'y'):
            axil4_result = run_axil4_checker(waveform_csv, output_dir)
            
            if axil4_result and axil4_result['violation_count'] > 0:
                # Signal grouping
                signals_csv = run_signal_grouping(
                    axil4_result['violations_json'],
                    output_dir
                )
                
                # Re-run interactive with protocol signals if available
                if signals_csv and true_drivers_csv:
                    print_info("Protocol violations found. Re-launching interactive with signal groups...")
                    root_causes_found = run_interactive_analysis(
                        waveform_csv,
                        true_drivers_csv,
                        signals_csv
                    )
                
                # FSM Illegal State Detection
                fsm_enc_json = None
                for result in all_results:
                    if result.get('fsm_encodings_json'):
                        fsm_enc_json = result['fsm_encodings_json']
                        break
                
                if fsm_enc_json:
                    _run_with_quiet_output(
                        run_fsm_illegal_state_check,
                        waveform_csv, true_drivers_csv, fsm_enc_json,
                        violations_csv=axil4_result['violations_csv'],
                        output_dir=output_dir
                    )
                
                # Inter-FSM: spec item D — only when violations exist
                if not root_causes_found:
                    print_info("Proceeding to inter-FSM dependency analysis...")
                    if true_drivers_csv:
                        _run_with_quiet_output(
                            run_inter_fsm_analysis,
                            true_drivers_csv,
                            axil4_result['violations_csv'],
                            output_dir
                        )
                else:
                    print_success("Root causes identified!")
                    print_info("Skipping inter-FSM analysis (not needed)")
            
            elif axil4_result and axil4_result['violation_count'] == 0:
                # Spec item C: informational, not failure
                print_success("No protocol violations detected")
                print_info("Design appears AXI4-Lite compliant")
                print_info("Skipping inter-FSM (no violations to correlate)")
            
            elif not axil4_result:
                # Spec item C: failure is informational
                print_warning("AXI4-Lite checking failed or no AXI signals detected")
                print_info("This may indicate the design is not AXI4-Lite")
        else:
            print_info("Skipping AXI4-Lite protocol checking (user declined)")
            print_info("Skipping inter-FSM analysis (no protocol violations to correlate)")
    
    # ================================================================
    # FINAL SUMMARY
    # ================================================================
    # [UNTOUCHED] — summary logic preserved, adapted for all modes
    
    elapsed = time.time() - start_time
    
    print_header("ANALYSIS COMPLETE")
    
    print(f"\nTotal execution time: {elapsed:.2f}s\n")
    
    print("Generated files:")
    if true_drivers_csv:
        print(f"   {true_drivers_csv.name}")
    
    for result in all_results:
        if result['success']:
            if result['ir_json']:
                print(f"   {result['ir_json'].name}")
            if result['backtrack_csv']:
                print(f"   {result['backtrack_csv'].name}")
    
    # Only list protocol files if they were generated
    violations_json = output_dir / 'violations.json'
    violations_csv = output_dir / 'violations.csv'
    signals_csv_path = output_dir / 'signals.csv'
    
    if violations_json.exists():
        print(f"   {violations_json.name}")
    if violations_csv.exists():
        print(f"   {violations_csv.name}")
    if signals_csv_path.exists():
        print(f"   {signals_csv_path.name}")
    
    fsm_findings_json = output_dir / 'fsm_illegal_state_findings.json'
    if fsm_findings_json.exists():
        print(f"   {fsm_findings_json.name}")
    
    for result in all_results:
        if result.get('fsm_encodings_json') and result['fsm_encodings_json'].exists():
            print(f"   {result['fsm_encodings_json'].name}")
    
    print(f"\nAll files saved to: {output_dir}")
    print_info("Analysis pipeline complete")
    
    return




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Interrupted by user (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
