# -*- mode: python ; coding: utf-8 -*-
"""
WaveEye PyInstaller spec — platform-agnostic (Windows & Linux).
Run from the project root:
  Windows : pyinstaller waveeye.spec
  Linux   : pyinstaller waveeye.spec
Output:  dist/waveeye/waveeye[.exe]  (directory bundle)
"""
import os, sys
from PyInstaller.utils.hooks import collect_all

ROOT = os.path.abspath(SPECPATH)   # project root (where this .spec lives)

# ── Data files (Python source shipped as data so runpy can execute them) ──
datas = [
    (os.path.join(ROOT, 'main.py'),                                                             '.'),
    (os.path.join(ROOT, 'Preprocessing', 'cli.py'),                                            'Preprocessing'),
    (os.path.join(ROOT, 'Preprocessing', 'vcd', 'upload_run_convert_rtl_tb.py'),               'Preprocessing/vcd'),
    (os.path.join(ROOT, 'Preprocessing', 'vcd', 'run_script.py'),                              'Preprocessing/vcd'),
    (os.path.join(ROOT, 'Preprocessing', 'vcd', 'inspect_vcd_structure.py'),                   'Preprocessing/vcd'),
    (os.path.join(ROOT, 'Preprocessing', 'vcd', 'list_vcd_signals.py'),                        'Preprocessing/vcd'),
    (os.path.join(ROOT, 'Preprocessing', 'vcd', 'detect_clocks.py'),                           'Preprocessing/vcd'),
    (os.path.join(ROOT, 'Preprocessing', 'vcd', 'clock_estimation.py'),                        'Preprocessing/vcd'),
    (os.path.join(ROOT, 'Preprocessing', 'rtl', 'classify_signals.py'),                        'Preprocessing/rtl'),
    (os.path.join(ROOT, 'Preprocessing', 'rtl', 'classify_system.py'),                         'Preprocessing/rtl'),
    (os.path.join(ROOT, 'Preprocessing', 'mapping', 'mapping.py'),                             'Preprocessing/mapping'),
    (os.path.join(ROOT, 'Preprocessing', 'mapping', 'mapping_values.py'),                      'Preprocessing/mapping'),
    (os.path.join(ROOT, 'Preprocessing', 'mapping', 'merge_map_signals.py'),                   'Preprocessing/mapping'),
    (os.path.join(ROOT, 'IR_backtracking', 'cli.py'),                                          'IR_backtracking'),
    (os.path.join(ROOT, 'IR_backtracking', 'analyse_interactive.py'),                          'IR_backtracking'),
    (os.path.join(ROOT, 'IR_backtracking', 'protocols', '__init__.py'),                        'IR_backtracking/protocols'),
    (os.path.join(ROOT, 'IR_backtracking', 'protocols', 'axi_lite', '__init__.py'),            'IR_backtracking/protocols/axi_lite'),
    (os.path.join(ROOT, 'IR_backtracking', 'protocols', 'dummy', '__init__.py'),               'IR_backtracking/protocols/dummy'),
    (os.path.join(ROOT, 'IR_backtracking', 'rca_core', '__init__.py'),                        'IR_backtracking/rca_core'),
    (os.path.join(ROOT, 'IR_backtracking', 'reports', '__init__.py'),                         'IR_backtracking/reports'),
    (os.path.join(ROOT, 'IR_backtracking', 'semantic_checks', '__init__.py'),                 'IR_backtracking/semantic_checks'),
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

for pkg in ('IR_backtracking', 'Preprocessing', 'vcdvcd', 'pandas', 'pyslang'):
    d, b, h = collect_all(pkg)
    datas     += d
    binaries  += b
    hiddenimports += h

a = Analysis(
    [os.path.join(ROOT, 'main.py')],
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
