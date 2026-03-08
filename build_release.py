"""
build_release.py — WaveEye AXI-Lite Protocol Analyzer
======================================================

Orchestrates the full Cython release pipeline and produces distributable
output in one or more formats:

  MODE A — Wheel (--wheel, default)
  ─────────────────────────────────
  Compiles all .py → .pyd/.so, packages into a platform wheel.
      pip install dist/waveeye_axi_lite-1.0.0-cp312-cp312-win_amd64.whl
  Requires: Python (same major version) on the target PC.

  MODE B — Standalone executable (--standalone)
  ──────────────────────────────────────────────
  PyInstaller bundles Python + all compiled extensions into a folder.
  No Python installation required on the target PC.
  Output: standalone/waveeye/waveeye.exe  (Windows)
          standalone/waveeye/waveeye      (Linux/macOS)
  Add --onefile to produce a single .exe (slower startup, same result).

  BOTH MODES (--both)
  ───────────────────
  Compiles once, then builds wheel AND standalone in sequence.
      python build_release.py --both

  MODE C — Raw dist folder (--raw)
  ─────────────────────────────────
  Copies compiled extensions + runpy stubs to dist/waveeye/ for manual
  deployment.

Usage
-----
    python build_release.py              # compile + wheel
    python build_release.py --both       # compile + wheel + standalone exe
    python build_release.py --standalone # compile + standalone only
    python build_release.py --raw        # compile + raw folder
    python build_release.py --no-build   # skip compile, re-package existing

How the standalone exe works
-----------------------------
main.py::get_base_path() already returns sys._MEIPASS when frozen
(PyInstaller sets sys.frozen=True and sys._MEIPASS to the extraction dir).
runpy.run_path() calls in run_stage() therefore resolve to the bundled
.py stubs inside the exe — no code changes required.

runpy stubs
-----------
Files executed via runpy.run_path() need the .py present at runtime.
RUNPY_STUBS are bundled as data files in the exe AND copied to the wheel.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# runpy-called files — must be kept as plain .py in every distribution mode
# (see MAIN_TOOL_CALL_GRAPH.md for the full call graph)
# ---------------------------------------------------------------------------
RUNPY_STUBS: list[str] = [
    # Entry point
    "main.py",

    # Stage 1 — called by main.py via runpy
    "Preprocessing/cli.py",

    # Stage 1 sub-scripts — called by Preprocessing/cli.py via runpy
    "Preprocessing/vcd/upload_run_convert_rtl_tb.py",
    "Preprocessing/rtl/classify_signals.py",
    "Preprocessing/rtl/classify_system.py",
    "Preprocessing/mapping/mapping.py",
    "Preprocessing/mapping/mapping_values.py",
    "Preprocessing/mapping/merge_map_signals.py",

    # VCD tool scripts — called by run_script.py via runpy
    "Preprocessing/vcd/run_script.py",
    "Preprocessing/vcd/inspect_vcd_structure.py",
    "Preprocessing/vcd/list_vcd_signals.py",
    "Preprocessing/vcd/detect_clocks.py",
    "Preprocessing/vcd/clock_estimation.py",

    # Stage 2 — called by main.py via runpy
    "IR_backtracking/cli.py",

    # IR interactive analysis — called by cli.py via runpy
    "IR_backtracking/analyse_interactive.py",
]

# Non-Python asset patterns copied into every distribution
ASSET_PATTERNS: list[str] = ["*.json", "*.yaml", "*.yml", "*.cfg"]

# Directories whose compiled output is included
INCLUDE_DIRS: list[str] = ["IR_backtracking", "Preprocessing"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path | None = None) -> None:
    print("  $", " ".join(cmd))
    result = subprocess.run(cmd, cwd=cwd or ROOT)
    if result.returncode != 0:
        print(f"\n[build_release] FAILED (exit {result.returncode})", file=sys.stderr)
        sys.exit(result.returncode)


def _is_build_dir(path: Path) -> bool:
    return "build" + os.sep in str(path) or "/build/" in str(path)


def collect_compiled(root: Path) -> list[Path]:
    """Return all in-place .pyd / .so files (excludes build/ temp dir)."""
    found: list[Path] = []
    for pat in ("**/*.pyd", "**/*.so"):
        for p in root.glob(pat):
            if not _is_build_dir(p):
                found.append(p)
    return sorted(found)


# ---------------------------------------------------------------------------
# Step 1 — Cython compilation
# ---------------------------------------------------------------------------

def step_compile() -> None:
    print()
    _banner("Step 1 — Cython compilation")
    cmd = [sys.executable, "setup_cython.py", "build_ext", "--inplace"]
    # On Windows, MSVC is not always available; use MinGW (MSYS2) if present.
    if sys.platform == "win32":
        import shutil
        if not shutil.which("cl"):          # no MSVC on PATH
            cmd.append("--compiler=mingw32")
    _run(cmd)
    print("[build_release] Compilation complete.")


# ---------------------------------------------------------------------------
# Step 2A — Wheel
# ---------------------------------------------------------------------------

def step_wheel() -> None:
    """Build a platform wheel (.whl) that can be installed via pip."""
    print()
    _banner("Step 2A — Wheel packaging")

    # Chain: build_ext (recompiles if needed) then bdist_wheel.
    # On Windows without MSVC, use MinGW32.
    import shutil as _sh
    compiler_flag = []
    if sys.platform == "win32" and not _sh.which("cl"):
        compiler_flag = ["--compiler=mingw32"]

    # Delete stale egg-info to avoid absolute-path errors in SOURCES.txt
    import shutil as _shutil
    egg_info = ROOT / "waveeye_axi_lite.egg-info"
    if egg_info.exists():
        _shutil.rmtree(egg_info)

    _run([sys.executable, "setup_cython.py", "build_ext"]
         + compiler_flag + ["bdist_wheel"])

    wheels = list((ROOT / "dist").glob("*.whl"))
    if not wheels:
        print("[build_release] WARNING: No .whl found in dist/", file=sys.stderr)
        return

    for w in sorted(wheels):
        size_mb = w.stat().st_size / 1_048_576
        print(f"\n  Wheel: {w.name}  ({size_mb:.1f} MB)")

    print("\n  Install on any PC with matching Python:")
    print(f"      pip install dist/{wheels[-1].name}")


# ---------------------------------------------------------------------------
# Step 2B — Standalone executable via PyInstaller
# ---------------------------------------------------------------------------

# Modules loaded dynamically via importlib inside IR_backtracking/cli.py.
# PyInstaller cannot auto-detect these; they must be listed explicitly.
_HIDDEN_IMPORTS: list[str] = [
    "IR_backtracking.extract_fsm_encodings",
    "IR_backtracking.axil4",
    "IR_backtracking.grouping",
    "IR_backtracking.fsm_illegal_state",
    "IR_backtracking.inter_fsm",
    "IR_backtracking.protocols.axi_lite.adapter",
    "IR_backtracking.protocols.dummy.adapter",
    # rca_core submodules (imported dynamically via rca_8.py)
    "IR_backtracking.rca_core.engine",
    "IR_backtracking.rca_core.io",
    "IR_backtracking.rca_core.mechanism",
    "IR_backtracking.rca_core.contracts",
    "IR_backtracking.rca_core.scheduling",
    "IR_backtracking.rca_core.causal_graph",
    "IR_backtracking.rca_core.transaction_binding",
    "IR_backtracking.rca_core.predicate_backtrack",
    "IR_backtracking.rca_core.semantic_datapath_analysis",
    # report modules
    "IR_backtracking.reports.console_diagnosis",
    "IR_backtracking.reports.rtl_fix_advisor",
    "IR_backtracking.reports.executive_summary",
]


def step_standalone(onefile: bool = False) -> None:
    """Build a self-contained executable — no Python required on target PC."""
    print()
    _banner("Step 2B — Standalone executable (PyInstaller)")

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[build_release] PyInstaller not installed.  Run:", file=sys.stderr)
        print("    pip install pyinstaller", file=sys.stderr)
        sys.exit(1)

    out_dir = ROOT / "standalone"
    out_dir.mkdir(exist_ok=True)

    # PyInstaller uses os.pathsep as src;dest separator (';' Win, ':' Unix)
    sep = os.pathsep

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name",      "waveeye",
        "--distpath",  str(out_dir),
        "--workpath",  str(ROOT / "build" / "pyinstaller_work"),
        "--specpath",  str(ROOT / "build"),
        "--noconfirm",
        "--clean",
        # Add project root to analysis path so packages are importable
        "--paths", str(ROOT),
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    # --- Hidden imports (dynamic importlib/runpy targets) ---
    for h in _HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", h])

    # --- Bundle compiled .pyd/.so extensions as binaries ---
    # (PyInstaller treats them as native binaries, not data)
    compiled = collect_compiled(ROOT)
    if not compiled:
        print("[build_release] WARNING: No compiled extensions found — "
              "did you run Cython compilation first?", file=sys.stderr)
    for pyd in compiled:
        dest_dir = str(pyd.relative_to(ROOT).parent)
        cmd.extend(["--add-binary", f"{pyd}{sep}{dest_dir}"])

    # --- Bundle runpy stub .py files as data ---
    # get_base_path() returns sys._MEIPASS when frozen, so
    # runpy.run_path(base / "IR_backtracking/cli.py") resolves correctly.
    for stub_rel in RUNPY_STUBS:
        stub_src = ROOT / stub_rel
        if not stub_src.exists():
            continue
        dest_dir = str(Path(stub_rel).parent)
        if dest_dir == ".":
            dest_dir = "."
        cmd.extend(["--add-data", f"{stub_src}{sep}{dest_dir}"])

    # --- Bundle __init__.py package markers ---
    for d in INCLUDE_DIRS:
        for init_src in (ROOT / d).rglob("__init__.py"):
            dest_dir = str(init_src.relative_to(ROOT).parent)
            cmd.extend(["--add-data", f"{init_src}{sep}{dest_dir}"])

    # --- Entry point ---
    cmd.append(str(ROOT / "main.py"))

    _run(cmd)

    # Report result
    if onefile:
        exe_name = "waveeye.exe" if sys.platform == "win32" else "waveeye"
        exe_path = out_dir / exe_name
    else:
        exe_name = "waveeye.exe" if sys.platform == "win32" else "waveeye"
        exe_path = out_dir / "waveeye" / exe_name

    print(f"\n  Standalone output : {out_dir}")
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / 1_048_576
        print(f"  Executable        : {exe_path.name}  ({size_mb:.1f} MB)")
    else:
        print(f"  Executable        : {exe_name}  (check {out_dir})")
    print("\n  Runs on any PC — no Python installation needed:")
    print(f"      {exe_path}")


# ---------------------------------------------------------------------------
# Step 2C — Raw dist folder
# ---------------------------------------------------------------------------

def step_raw(dist_dir: Path) -> None:
    """Assemble a raw dist/ folder with compiled extensions + stubs."""
    print()
    _banner(f"Step 2C — Raw dist folder → {dist_dir.relative_to(ROOT)}")

    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir(parents=True)

    # Compiled extensions
    compiled = collect_compiled(ROOT)
    if not compiled:
        print("[build_release] WARNING: No compiled extensions found.", file=sys.stderr)
    for src in compiled:
        rel = src.relative_to(ROOT)
        dst = dist_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    # runpy stubs
    stub_count = 0
    for rel_str in RUNPY_STUBS:
        src = ROOT / rel_str
        if src.exists():
            dst = dist_dir / rel_str
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            stub_count += 1

    # __init__.py package markers
    init_count = 0
    for d in INCLUDE_DIRS:
        for init_src in (ROOT / d).rglob("__init__.py"):
            rel = init_src.relative_to(ROOT)
            dst = dist_dir / rel
            if not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(init_src, dst)
                init_count += 1

    # Non-Python assets
    asset_count = 0
    for d in INCLUDE_DIRS:
        for pattern in ASSET_PATTERNS:
            for asset in (ROOT / d).rglob(pattern):
                rel = asset.relative_to(ROOT)
                dst = dist_dir / rel
                if not dst.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(asset, dst)
                    asset_count += 1

    pyd = list(dist_dir.rglob("*.pyd"))
    so  = list(dist_dir.rglob("*.so"))
    py  = list(dist_dir.rglob("*.py"))
    print(f"  Compiled  : {len(pyd) + len(so):>4}  (.pyd/.so)")
    print(f"  Stubs     : {len(py):>4}  (.py — runpy + __init__)")
    print(f"  Assets    : {asset_count:>4}")
    print(f"  Total     : {len(list(dist_dir.rglob('*'))):>4}  files")


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _banner(msg: str) -> None:
    print("=" * 64)
    print(f" {msg}")
    print("=" * 64)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="WaveEye Cython release builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--wheel",
        action="store_true",
        default=False,
        help="Build a pip-installable wheel (default if no mode flag given)",
    )
    mode.add_argument(
        "--standalone",
        action="store_true",
        help="Build a standalone executable via PyInstaller (no Python on target)",
    )
    mode.add_argument(
        "--both",
        action="store_true",
        help="Build BOTH wheel AND standalone executable (compile once)",
    )
    mode.add_argument(
        "--raw",
        action="store_true",
        help="Copy compiled extensions + stubs to a raw dist/ folder",
    )

    parser.add_argument(
        "--onefile",
        action="store_true",
        help="(standalone / both) Single .exe instead of a folder — slower startup",
    )
    parser.add_argument(
        "--dist-dir",
        default="dist/waveeye",
        metavar="PATH",
        help="Output directory for --raw mode (default: dist/waveeye)",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip Cython compilation; re-package whatever .pyd/.so already exist",
    )
    args = parser.parse_args()

    # Compile once regardless of how many packaging modes are requested
    if not args.no_build:
        step_compile()

    # Dispatch
    if args.both:
        step_wheel()
        step_standalone(onefile=args.onefile)
    elif args.standalone:
        step_standalone(onefile=args.onefile)
    elif args.raw:
        step_raw(ROOT / args.dist_dir)
    else:
        # Default (--wheel or no flag)
        step_wheel()

    print("\n[build_release] Done.\n")


if __name__ == "__main__":
    main()
