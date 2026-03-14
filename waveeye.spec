# -*- mode: python ; coding: utf-8 -*-
"""
WaveEye PyInstaller spec — explicit file collection, no __init__.py needed.
Run from the project root:
  Windows : pyinstaller waveeye.spec
  Linux   : pyinstaller waveeye.spec
"""
import os
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(SPECPATH)

def src(rel):
    """Absolute path to a source file."""
    return os.path.join(ROOT, *rel.split('/'))

def data(rel):
    """(abs_src, dest_dir) tuple for a single .py file."""
    parts = rel.split('/')
    dest  = '/'.join(parts[:-1]) if len(parts) > 1 else '.'
    return (src(rel), dest)

# ── All source files shipped as data (runpy needs the .py text) ───────────
SOURCE_FILES = [
    'main.py',
    # Preprocessing
    'Preprocessing/cli.py',
    'Preprocessing/mapping/mapping.py',
    'Preprocessing/mapping/mapping_values.py',
    'Preprocessing/mapping/merge_map_signals.py',
    'Preprocessing/rtl/check_system.py',
    'Preprocessing/rtl/classify_signals.py',
    'Preprocessing/rtl/classify_system.py',
    'Preprocessing/vcd/clock_estimation.py',
    'Preprocessing/vcd/detect_clocks.py',
    'Preprocessing/vcd/file_manager.py',
    'Preprocessing/vcd/inspect_vcd_structure.py',
    'Preprocessing/vcd/list_vcd_signals.py',
    'Preprocessing/vcd/run_script.py',
    'Preprocessing/vcd/upload_run_convert_rtl_tb.py',
    'Preprocessing/vcd/vcd_converter.py',
    # IR_backtracking root
    'IR_backtracking/IR_backtracking.py',
    'IR_backtracking/alias_engine.py',
    'IR_backtracking/amba_axi_lite_rules.py',
    'IR_backtracking/analyse_interactive.py',
    'IR_backtracking/axil4.py',
    'IR_backtracking/capability_loader.py',
    'IR_backtracking/cli.py',
    'IR_backtracking/cyclic_dependency_analyzer.py',
    'IR_backtracking/deep_backtrack.py',
    'IR_backtracking/design_causal_graph.py',
    'IR_backtracking/design_causal_graph_viz.py',
    'IR_backtracking/extract_fsm_encodings.py',
    'IR_backtracking/fsm_illegal_state.py',
    'IR_backtracking/grouping.py',
    'IR_backtracking/handshake_cycles.py',
    'IR_backtracking/inter_fsm.py',
    'IR_backtracking/ir_builder.py',
    'IR_backtracking/merge_true_drivers.py',
    'IR_backtracking/rca_8.py',
    'IR_backtracking/rca_resolver.py',
    'IR_backtracking/rca_synthesis.py',
    'IR_backtracking/rising_falling_edges.py',
    'IR_backtracking/rtl_causal_graph_pipeline.py',
    'IR_backtracking/runtime_paths.py',
    'IR_backtracking/stuck_signals.py',
    'IR_backtracking/temporal_predicate_analysis.py',
    'IR_backtracking/true_drivers.py',
    'IR_backtracking/utils.py',
    # IR_backtracking/protocols
    'IR_backtracking/protocols/__init__.py',
    'IR_backtracking/protocols/base.py',
    'IR_backtracking/protocols/loader.py',
    'IR_backtracking/protocols/axi_lite/__init__.py',
    'IR_backtracking/protocols/axi_lite/adapter.py',
    'IR_backtracking/protocols/axi_lite/rules.py',
    'IR_backtracking/protocols/axi_lite/signal_map.py',
    'IR_backtracking/protocols/dummy/__init__.py',
    'IR_backtracking/protocols/dummy/adapter.py',
    # IR_backtracking/rca_core
    'IR_backtracking/rca_core/__init__.py',
    'IR_backtracking/rca_core/causal_graph.py',
    'IR_backtracking/rca_core/contracts.py',
    'IR_backtracking/rca_core/cyclic_dependency_analyzer.py',
    'IR_backtracking/rca_core/deep_backtrack.py',
    'IR_backtracking/rca_core/engine.py',
    'IR_backtracking/rca_core/io.py',
    'IR_backtracking/rca_core/mechanism.py',
    'IR_backtracking/rca_core/predicate_backtrack.py',
    'IR_backtracking/rca_core/scheduling.py',
    'IR_backtracking/rca_core/semantic_datapath_analysis.py',
    'IR_backtracking/rca_core/temporal_predicate_analysis.py',
    'IR_backtracking/rca_core/transaction_binding.py',
    # IR_backtracking/reports
    'IR_backtracking/reports/__init__.py',
    'IR_backtracking/reports/backtrack_trace.py',
    'IR_backtracking/reports/causal_pruner.py',
    'IR_backtracking/reports/console_diagnosis.py',
    'IR_backtracking/reports/deep_appendix.py',
    'IR_backtracking/reports/determinism_scorer.py',
    'IR_backtracking/reports/evidence_filter.py',
    'IR_backtracking/reports/executive_summary.py',
    'IR_backtracking/reports/failure_timeline.py',
    'IR_backtracking/reports/llm_rca_prompt.py',
    'IR_backtracking/reports/peer_review_defense.py',
    'IR_backtracking/reports/rca_explanation.py',
    'IR_backtracking/reports/rtl_fix_advisor.py',
    'IR_backtracking/reports/signal_set.py',
    'IR_backtracking/reports/structural_root_cause.py',
    'IR_backtracking/reports/tool_differentiator.py',
    'IR_backtracking/reports/violation_reducer.py',
    # IR_backtracking/semantic_checks
    'IR_backtracking/semantic_checks/__init__.py',
    'IR_backtracking/semantic_checks/invertibility.py',
    'IR_backtracking/semantic_checks/memory_write_analysis.py',
    'IR_backtracking/semantic_checks/transport_semantic_analysis.py',
    # Preprocessing/rtl data files
    'Preprocessing/rtl/classy.csv_signals.csv',
    'Preprocessing/rtl/classy.csv_signals.json',
    'Preprocessing/rtl/axil_reg_if_rd.v',
    'Preprocessing/rtl/axil_reg_if_wr.v',
]

datas = [data(f) for f in SOURCE_FILES]

# ── JS/CSS lib assets ─────────────────────────────────────────────────────
datas += [
    (src('IR_backtracking/lib'), 'IR_backtracking/lib'),
]

binaries = []

hiddenimports = [
    'IR_backtracking.extract_fsm_encodings',
    'IR_backtracking.axil4',
    'IR_backtracking.grouping',
    'IR_backtracking.fsm_illegal_state',
    'IR_backtracking.inter_fsm',
    'IR_backtracking.protocols.axi_lite.adapter',
    'IR_backtracking.protocols.dummy.adapter',
    'IR_backtracking.rca_core.engine',
    'IR_backtracking.rca_core.io',
    'IR_backtracking.rca_core.mechanism',
    'IR_backtracking.rca_core.contracts',
    'IR_backtracking.rca_core.scheduling',
    'IR_backtracking.rca_core.causal_graph',
    'IR_backtracking.rca_core.transaction_binding',
    'IR_backtracking.rca_core.predicate_backtrack',
    'IR_backtracking.rca_core.semantic_datapath_analysis',
    'IR_backtracking.reports.console_diagnosis',
    'IR_backtracking.reports.rtl_fix_advisor',
    'IR_backtracking.reports.executive_summary',
    'glob', 'csv', 'pathlib', 'shutil', 'tempfile', 'hashlib',
    'contextlib', 'datetime', 'fnmatch', 'subprocess', 'logging',
    'copy', 'textwrap', 'inspect', 'ast', 'traceback', 'struct',
    'base64', 'threading', 'queue', 'io', 'runpy',
]

# ── Third-party packages (these ARE proper packages with __init__.py) ─────
for pkg in ('vcdvcd', 'pandas', 'pyslang'):
    d, b, h = collect_all(pkg)
    datas          += d
    binaries       += b
    hiddenimports  += h

a = Analysis(
    [src('main.py')],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='waveeye',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='waveeye',
)
