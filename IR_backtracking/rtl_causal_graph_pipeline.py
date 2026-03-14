"""
rtl_causal_graph_pipeline.py
=============================
Self-contained RTL-only causal backtracking graph pipeline.

Stage 1 — IR Builder  (ir_builder.py)
    Parses RTL source → IR records + structural violation detectors.

Stage 2 — True Drivers  (true_drivers.py)
    Filters IR records to keep only the signals that are *actually* true
    (condition satisfied) at the failing cycle, producing a compact
    true_drivers.csv for each RTL module.

Stage 3 — Causal Graph  (design_causal_graph.py)
    Loads all true_drivers CSVs, merges into a unified NetworkX DiGraph,
    performs reverse-BFS from each target signal, and ranks root causes.

Stage 4 — Visualisation  (design_causal_graph_viz.py)
    Generates interactive Pyvis HTML graphs (full design + per-signal
    subgraphs) written alongside the analysis output files.

Usage
-----
    # Analyse a single RTL file (static, no waveform needed):
    python rtl_causal_graph_pipeline.py --rtl path/to/design.sv \\
                                        --out  path/to/output_dir

    # Analyse multiple RTL files:
    python rtl_causal_graph_pipeline.py --rtl foo.sv bar.sv top.sv \\
                                        --out  ./my_analysis \\
                                        --signals RDATA BVALID wr_en

    # Use an existing true_drivers directory (skip IR + extraction stages):
    python rtl_causal_graph_pipeline.py --drivers_dir path/to/analysis_dir \\
                                        --signals RDATA

    # Default demo (user314):
    python rtl_causal_graph_pipeline.py

Dependencies
------------
    pip install networkx pyvis
    (slang must be on PATH for IR building — already part of WaveEye install)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import networkx as nx

# ---------------------------------------------------------------------------
# Resolve paths relative to this file
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))


# ---------------------------------------------------------------------------
# Module loaders
# ---------------------------------------------------------------------------

def _load_module(name: str, path: Path):
    """Dynamically load a Python module by file path."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # register before exec so @dataclass works
    spec.loader.exec_module(mod)
    return mod


def _load_ir_builder():
    return _load_module("ir_builder", _HERE / "ir_builder.py")

def _load_true_drivers():
    return _load_module("true_drivers", _HERE / "true_drivers.py")

def _load_causal_graph():
    return _load_module("design_causal_graph", _HERE / "design_causal_graph.py")

def _load_viz():
    return _load_module("design_causal_graph_viz", _HERE / "design_causal_graph_viz.py")


# ---------------------------------------------------------------------------
# Stage 1: IR Building
# ---------------------------------------------------------------------------

def stage_ir_build(rtl_files: List[Path], out_dir: Path) -> Optional[Path]:
    """
    Run ir_builder on the provided RTL files and write IR JSON to out_dir.
    Returns path to the written IR JSON, or None on failure.
    """
    print("\n" + "="*65)
    print("  STAGE 1 — IR Builder")
    print("="*65)

    ir_builder = _load_ir_builder()

    # Collect all RTL files (expand .sv/.v/.vhd)
    rtl_paths = []
    for p in rtl_files:
        p = Path(p)
        if p.is_dir():
            rtl_paths.extend(p.glob("**/*.sv"))
            rtl_paths.extend(p.glob("**/*.v"))
        elif p.exists():
            rtl_paths.append(p)
        else:
            print(f"  [WARN] RTL file not found: {p}")

    if not rtl_paths:
        print("  [ERROR] No RTL files found.")
        return None

    print(f"  RTL files  : {len(rtl_paths)}")
    for f in rtl_paths:
        print(f"    {f.name}")

    # Derive base name from first RTL file
    base      = rtl_paths[0].stem
    ir_json   = out_dir / f"{base}_ir.json"

    try:
        build_ir_to_json = ir_builder.build_ir_to_json
        build_ir_to_json([str(p) for p in rtl_paths], str(ir_json))
        print(f"  [OK] IR JSON -> {ir_json.name}")
        return ir_json
    except Exception as e:
        print(f"  [ERROR] IR build failed: {e}")
        import traceback; traceback.print_exc()
        return None


# ---------------------------------------------------------------------------
# Stage 2: True Drivers Extraction
# ---------------------------------------------------------------------------

def stage_extract_true_drivers(
    ir_json: Optional[Path],
    out_dir: Path,
    existing_backtrack_csvs: Optional[List[Path]] = None,
) -> List[Path]:
    """
    Convert IR JSON (or existing backtracking CSV files) into true_drivers CSVs.
    Returns a list of produced true_drivers CSV paths.
    """
    print("\n" + "="*65)
    print("  STAGE 2 — True Drivers Extraction")
    print("="*65)

    true_drivers_mod = _load_true_drivers()

    produced: List[Path] = []

    # Path A: existing backtracking CSVs from a previous analysis run
    if existing_backtrack_csvs:
        for bt_csv in existing_backtrack_csvs:
            base  = bt_csv.stem.replace("_backtracking", "")
            td_csv = out_dir / f"{base}_true_drivers.csv"
            if td_csv.exists():
                print(f"  [SKIP] Already exists: {td_csv.name}")
            else:
                try:
                    true_drivers_mod.extract_true_drivers(str(bt_csv), str(td_csv))
                    print(f"  [OK]   {td_csv.name}")
                except Exception as e:
                    print(f"  [WARN] extract_true_drivers failed for {bt_csv.name}: {e}")
            if td_csv.exists():
                produced.append(td_csv)
        return produced

    # Path B: build true_drivers directly from IR JSON
    if ir_json and ir_json.exists():
        base   = ir_json.stem.replace("_ir", "")
        td_csv = out_dir / f"{base}_true_drivers.csv"
        try:
            # Load IR records and emit a flat backtracking-style CSV
            with open(ir_json) as fh:
                ir_records = json.load(fh)
            _emit_true_drivers_from_ir(ir_records, td_csv)
            print(f"  [OK]   {td_csv.name}")
            produced.append(td_csv)
        except Exception as e:
            print(f"  [WARN] Could not emit true_drivers from IR: {e}")
            import traceback; traceback.print_exc()
        return produced

    print("  [SKIP] No IR JSON or backtracking CSVs available.")
    return produced


def _emit_true_drivers_from_ir(ir_records: list, out_csv: Path) -> None:
    """
    Convert IR records directly into a true_drivers CSV without a waveform.
    Every IR assignment is treated as a candidate driver (static analysis mode).
    This matches the column schema expected by design_causal_graph.build_graph().
    """
    import csv

    fieldnames = [
        "signal", "alias_chain", "depth", "driver_idx",
        "rhs", "condition", "construct", "file",
        "sensitivity", "assign_type", "always_block_id", "parent",
    ]

    rows_by_signal: dict = {}
    for rec in ir_records:
        sig = (rec.get("signal") or "").strip()
        if not sig:
            continue
        entry = {
            "signal":        sig,
            "alias_chain":   sig,
            "depth":         1,
            "driver_idx":    rec.get("if_chain_id") or 1,
            "rhs":           rec.get("rhs") or "",
            "condition":     rec.get("guard") or "true",
            "construct":     rec.get("process") or "always",
            "file":          f"{rec.get('source','')}" ,
            "sensitivity":   rec.get("clock") or "",
            "assign_type":   "nonblocking" if rec.get("clock") else "blocking",
            "always_block_id": rec.get("always_block_id") or "",
            "parent":        "",
        }
        rows_by_signal.setdefault(sig, []).append(entry)

    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for sig, rows in rows_by_signal.items():
            for row in rows:
                writer.writerow(row)
            writer.writerow({k: "" for k in fieldnames})   # blank separator


# ---------------------------------------------------------------------------
# Stage 3: Causal Graph Build
# ---------------------------------------------------------------------------

def stage_build_graph(true_driver_csvs: List[Path]) -> Optional[nx.DiGraph]:
    """
    Load all true_drivers CSVs and build the unified DesignCausalGraph.
    Returns the DiGraph, or None if no CSVs were provided.
    """
    print("\n" + "="*65)
    print("  STAGE 3 — Causal Graph Construction")
    print("="*65)

    if not true_driver_csvs:
        print("  [ERROR] No true_drivers CSV files available.")
        return None

    cg_mod = _load_causal_graph()
    G = cg_mod.build_graph(true_driver_csvs)

    print(f"  CSVs loaded : {len(true_driver_csvs)}")
    for f in true_driver_csvs:
        print(f"    {f.name}")
    print(f"  Graph nodes : {G.number_of_nodes()}")
    print(f"  Graph edges : {G.number_of_edges()}")

    # Print all source-less nodes (true primary inputs / roots)
    roots = [n for n in G.nodes if G.in_degree(n) == 0]
    print(f"  Primary inputs (no upstream driver): {len(roots)}")
    for r in sorted(roots)[:15]:
        print(f"    {r}")
    if len(roots) > 15:
        print(f"    ... and {len(roots)-15} more")

    return G


# ---------------------------------------------------------------------------
# Stage 4: Trace + Rank + Visualise
# ---------------------------------------------------------------------------

def stage_trace_and_visualise(
    G: nx.DiGraph,
    target_signals: List[str],
    out_dir: Path,
    render_html: bool = True,
) -> None:
    """
    For each target signal: run reverse-BFS, print ranked root causes,
    and optionally render interactive HTML graphs.
    """
    print("\n" + "="*65)
    print("  STAGE 4 — Trace & Visualise")
    print("="*65)

    cg_mod  = _load_causal_graph()
    viz_mod = _load_viz() if render_html else None

    if not target_signals:
        # Auto-detect: AXI output signals present in graph
        auto_candidates = [
            "RDATA", "BVALID", "BRESP", "AWREADY", "WREADY", "ARREADY",
            "RVALID", "wr_en", "rd_en", "fifo_level", "dout", "full", "empty",
        ]
        target_signals = [s for s in auto_candidates if s in G]
        if not target_signals:
            # Fall back to top-10 highest out-degree nodes
            target_signals = sorted(
                G.nodes, key=lambda n: G.out_degree(n), reverse=True
            )[:10]
        print(f"  Auto-detected {len(target_signals)} target signal(s)")

    for sig in target_signals:
        if sig not in G:
            print(f"\n  [SKIP] '{sig}' not in graph")
            continue

        # --- text trace ---
        steps     = cg_mod.trace_back(sig, G)
        candidates = cg_mod.rank_root_causes(steps, G)
        cg_mod.print_trace(sig, steps)
        cg_mod.print_root_causes(sig, candidates, G)

        # --- HTML subgraph ---
        if viz_mod:
            safe  = sig.replace("/", "_").replace(":", "_")
            opath = out_dir / f"causal_graph_{safe}.html"
            try:
                viz_mod.render_signal_subgraph(G, sig, opath)
            except Exception as e:
                print(f"  [WARN] Visualisation failed for {sig}: {e}")

    # --- full design graph ---
    if viz_mod:
        try:
            viz_mod.render_full_graph(G, out_dir / "causal_graph.html")
        except Exception as e:
            print(f"  [WARN] Full graph render failed: {e}")


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------

def run_rtl_causal_pipeline(
    rtl_files:      Optional[List[Path]] = None,
    drivers_dir:    Optional[Path]       = None,
    out_dir:        Optional[Path]       = None,
    target_signals: Optional[List[str]]  = None,
    render_html:    bool                  = True,
) -> Optional[nx.DiGraph]:
    """
    Run the full RTL causal graph pipeline end-to-end.

    Parameters
    ----------
    rtl_files       : list of RTL (.sv/.v) source files to analyse
    drivers_dir     : directory already containing *_true_drivers.csv files
                      (skips stages 1 & 2 if provided)
    out_dir         : where to write all output files
    target_signals  : signals to backtrack from (None = auto-detect)
    render_html     : produce interactive Pyvis HTML graphs

    Returns
    -------
    The built NetworkX DiGraph, or None on failure.
    """
    print("\n" + "#"*65)
    print("  WaveEye RTL Causal Graph Pipeline")
    print("#"*65)

    # --- resolve output directory ---
    if out_dir is None:
        out_dir = Path(tempfile.mkdtemp(prefix="waveeye_causal_"))
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"  Output dir  : {out_dir}")

    # ---------------------------------------------------------------
    # Fast path: pre-existing true_drivers CSVs
    # ---------------------------------------------------------------
    if drivers_dir is not None:
        drivers_dir = Path(drivers_dir)
        td_csvs = sorted(drivers_dir.glob("*_true_drivers.csv"))
        if td_csvs:
            print(f"\n  Using {len(td_csvs)} existing true_drivers CSV(s) from:")
            print(f"    {drivers_dir}")
            G = stage_build_graph(td_csvs)
            if G is None:
                return None
            stage_trace_and_visualise(G, target_signals or [], out_dir, render_html)
            return G
        else:
            print(f"  [WARN] No *_true_drivers.csv in {drivers_dir} — "
                  f"falling through to IR build")

    # ---------------------------------------------------------------
    # Full pipeline: IR → true_drivers → graph
    # ---------------------------------------------------------------
    if not rtl_files:
        print("  [ERROR] No RTL files or drivers_dir provided.")
        return None

    # Stage 1: IR build
    ir_json = stage_ir_build([Path(f) for f in rtl_files], out_dir)

    # Stage 2: True drivers extraction
    bt_csvs = sorted(out_dir.glob("*_backtracking.csv"))
    td_csvs = stage_extract_true_drivers(ir_json, out_dir, bt_csvs or None)

    if not td_csvs:
        print("\n  [ERROR] No true_drivers CSVs produced. Cannot build graph.")
        return None

    # Stage 3: Causal graph
    G = stage_build_graph(td_csvs)
    if G is None:
        return None

    # Stage 4: Trace + visualise
    stage_trace_and_visualise(G, target_signals or [], out_dir, render_html)

    print(f"\n{'#'*65}")
    print(f"  Pipeline complete. Outputs in: {out_dir}")
    print(f"{'#'*65}\n")
    return G


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="RTL-only causal backtracking graph pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--rtl", nargs="+", metavar="FILE",
        help="RTL source file(s) to analyse (.sv / .v)",
    )
    p.add_argument(
        "--drivers_dir", metavar="DIR",
        help="Directory with existing *_true_drivers.csv files (skip IR stage)",
    )
    p.add_argument(
        "--out", metavar="DIR", default=None,
        help="Output directory for graphs and HTML (default: alongside drivers_dir or temp)",
    )
    p.add_argument(
        "--signals", nargs="+", metavar="SIG",
        help="Signals to backtrack from (default: auto-detect AXI outputs)",
    )
    p.add_argument(
        "--no_html", action="store_true",
        help="Skip Pyvis HTML generation",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    # Default demo: user314 analysis directory
    if not args.rtl and not args.drivers_dir:
        _demo_dir = Path(r"C:\Users\gadap\WaveEye\outputs\user314\analysis")
        print(f"No inputs given — running demo on: {_demo_dir}")
        run_rtl_causal_pipeline(
            drivers_dir    = _demo_dir,
            out_dir        = _demo_dir,
            target_signals = args.signals,
            render_html    = not args.no_html,
        )
    else:
        out_dir = Path(args.out) if args.out else (
            Path(args.drivers_dir) if args.drivers_dir
            else Path(args.rtl[0]).parent / "causal_analysis"
        )
        run_rtl_causal_pipeline(
            rtl_files      = args.rtl,
            drivers_dir    = args.drivers_dir,
            out_dir        = out_dir,
            target_signals = args.signals,
            render_html    = not args.no_html,
        )
