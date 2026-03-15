#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import glob as _glob
import importlib.util
import io
import json
import os
import re
import sys

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Production-silent flag: set WAVEEYE_VERBOSE=1 to restore verbose output.
_PROD_VERBOSE: bool = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"


class _Tee(io.TextIOBase):
    """
    Write simultaneously to the real stdout and an internal StringIO buffer.
    Used to capture the full analysis trace while still showing it on screen.
    """

    def __init__(self, real_stdout: io.TextIOBase) -> None:
        super().__init__()
        self._real = real_stdout
        self._buf  = io.StringIO()

    def write(self, s: str) -> int:
        try:
            self._real.write(s)
        except (UnicodeEncodeError, UnicodeDecodeError):
            # Windows console may not support Unicode (e.g. ✓/✗) — replace safely
            self._real.write(s.encode("ascii", errors="replace").decode("ascii"))
        self._buf.write(s)
        return len(s)

    def flush(self) -> None:
        self._real.flush()

    def getvalue(self) -> str:
        return self._buf.getvalue()

from protocols.loader import load_protocol
from rca_core import (
    RCACoreEngine,
    WaveformView,
    load_driver_table,
    load_violations_file,
    load_waveform_file,
)
from rca_core.deep_backtrack import build_dependency_graph, format_dependency_graph
from rca_core.mechanism import synthesize_mechanisms
from semantic_checks.memory_write_analysis import detect_memory_write_semantic_mismatch
from rca_core.semantic_datapath_analysis import detect_semantic_datapath_violations
from rca_core.transaction_binding import run_transaction_binding
from rca_resolver import (
    resolve_root_cause,
    print_final_rca,
    derive_authority,
    derive_responsibility,
    _CONFIDENCE_MAP,
)
from utils import parse_literal_token, split_conditions, expand_row_with_aliases, eval_expr as _eval_expr_fsm

def _load_predicate_backtrack_py():
    """Load the Python source module explicitly to avoid stale compiled extensions."""
    _pb_path = Path(__file__).resolve().parent / "rca_core" / "predicate_backtrack.py"
    spec = importlib.util.spec_from_file_location("waveeye_predicate_backtrack_py", _pb_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_predicate_backtrack_py = _load_predicate_backtrack_py()
_predicate_full_trace = _predicate_backtrack_py.format_full_trace
_eval_all_drivers = _predicate_backtrack_py.evaluate_all_drivers
_detect_overwrite = _predicate_backtrack_py.detect_overwrite
from protocols.axi_lite.signal_map import (
    RULE_STABILITY_SIGNAL_MAP as _STABILITY_SIGNAL_MAP,
    STABILITY_RULES as _STABILITY_RULES,
    resolve_signal as _resolve_axi_signal,
)

# Post-analysis report generators (optional — gracefully absent if package missing)
try:
    from reports import (
        # primary outputs (always written + printed to console)
        generate_console_diagnosis,
        generate_llm_rca_prompt,
        # debug-internal extras (written only when debug=True)
        generate_structural_root_cause,
        generate_executive_summary,
        reduce_violations,
        generate_failure_timeline,
        generate_peer_review_defense,
        score_determinism_risk,
        filter_evidence,
        generate_deep_appendix,
        generate_tool_differentiator,
        generate_causal_path,
        generate_rca_explanation,
        extract_signal_set,
    )
    _REPORTS_AVAILABLE = True
except ImportError:
    _REPORTS_AVAILABLE = False


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "value"):
        return obj.value
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return str(obj)


def _sanitize_for_output(obj: Any) -> Any:
    """Recursively replace None/empty-string values with 'not_available' in dicts.

    Applied only to human-facing summary and violation entries so the demo
    output never shows bare null or empty strings for expected fields.
    Preserves None in numeric fields (e.g. analysis_cycle) and lists.
    """
    if isinstance(obj, dict):
        return {
            k: ("not_available"
                if (v is None or v == "") and isinstance(k, str)
                   and k not in {"analysis_cycle", "rtl_line",
                                 "always_block_id", "inferred_src_width",
                                 "inferred_dst_width", "rep_factor",
                                 "const_padding_bits"}
                else _sanitize_for_output(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize_for_output(i) for i in obj]
    return obj


def _ascii_safe(text: str) -> str:
    if not isinstance(text, str):
        return str(text)
    out = text.replace("├──", "|--").replace("└──", "`--").replace("│", "|")
    return out.encode("ascii", errors="replace").decode("ascii")


def _resolve_path(raw: Optional[str]) -> Optional[Path]:
    if not raw:
        return None
    p = Path(str(raw))
    if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
    return p


def _pick_default_analysis_dir(args: argparse.Namespace) -> Path:
    candidates: List[Path] = []
    for raw in [args.true_drivers_csv, args.violations, args.waveform_csv]:
        p = _resolve_path(raw)
        if p is None:
            continue
        d = p if p.is_dir() else p.parent
        candidates.append(d)
        if d.name.lower() == "preprocessing":
            candidates.append(d.parent / "analysis")

    for d in candidates:
        if d.name.lower() == "analysis":
            return d
        for anc in [d, *list(d.parents)]:
            if anc.name.lower() == "analysis":
                return anc

    # Fallback to latest outputs/user*/analysis under current workspace.
    out_root = Path.cwd() / "outputs"
    if out_root.exists() and out_root.is_dir():
        user_dirs = [p for p in out_root.iterdir() if p.is_dir() and p.name.lower().startswith("user")]
        if user_dirs:
            def _rank(p: Path) -> tuple:
                m = re.search(r"(\d+)$", p.name.lower())
                idx = int(m.group(1)) if m else -1
                try:
                    mt = p.stat().st_mtime
                except Exception:
                    mt = 0.0
                return (idx, mt)
            user_dirs.sort(key=_rank, reverse=True)
            for u in user_dirs:
                ad = u / "analysis"
                if ad.exists() and ad.is_dir():
                    return ad

    return Path.cwd() / "outputs" / "analysis"


def _default_proof_json_path(args: argparse.Namespace) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    proto = str(args.protocol or "none").strip().lower()
    analysis_dir = _pick_default_analysis_dir(args)
    return analysis_dir / f"rca8_{proto}_{stamp}.proof.json"


_SEP  = "=" * 79
_THIN = "-" * 79


def _fmt_section(title: str) -> str:
    return f"\n{_SEP}\n  {title}\n{_SEP}\n"


def _fmt_dependency_graph(
    dg: Dict[str, Any],
    rule_id: str = "?",
    analysis_cycle: Any = "?",
    indent: str = "    ",
) -> str:
    """
    Render a dependency_graph dict in rca-7 TRUE-PATH BACKTRACKING format.

    Output mirrors rca-7's SYSTEM-2+3 block:
      [RULE_X @ analysis_cycle Y] TRUE-PATH RCA - PRIMARY: SIGNAL
        SYSTEM-2+3: TRUE-path backtracking from SIGNAL:
          SIGNAL drivers:
            D0: if (cond) -> rhs  [assign_type, block=N]
            ...
          child_signal drivers:
            ...
        BACKTRACK MAP (COND vs RHS, by depth):
          L0 NODE SIGNAL [root]
          L0 D0: if (cond) -> rhs
          ...
            L1 NODE child_signal [intermediate]
            L1 D0: if (cond) -> rhs
            L1 CYCLIC: child_signal in own driver conditions [ENABLE_CYCLE]
        LEAF SIGNALS: a, b, c
        ROOT LEAF: child_signal [CYCLIC_ENABLE]
    """
    import re as _re

    root = (dg.get("root") or "?").strip()
    nodes: List[Dict[str, Any]] = dg.get("nodes") or []
    raw_adjacency: Dict[str, Any] = dg.get("adjacency") or {}
    leaf_signals_list: List[str] = dg.get("leaf_signals") or []
    inter_signals_list: List[str] = dg.get("intermediate_signals") or []

    # Pre-computed waveform annotations (added by _annotate_dg_with_waveform)
    wf_vals: Dict[str, Any] = dg.get("waveform_values") or {}

    # Normalise adjacency to lowercase keys
    adjacency: Dict[str, List[Dict[str, Any]]] = {
        k.lower(): v for k, v in raw_adjacency.items()
    }

    leaf_set  = {s.lower() for s in leaf_signals_list}
    inter_set = {s.lower() for s in inter_signals_list}
    # Cyclic = appears as BOTH intermediate (has drivers) AND leaf (re-encountered)
    cyclic_set = leaf_set & inter_set

    # ── Build sig_to_drivers: lowercase_sig → [driver_node, ...] ─────────────
    _idx_re = _re.compile(r'\[(\d+)\]$')
    sig_to_drivers: Dict[str, List[Dict[str, Any]]] = {}
    orig_case: Dict[str, str] = {}   # lowercase → original-case name

    for n in nodes:
        ntype = n.get("type") or ""
        # Collect original-case names from both signal and driver nodes
        name = (n.get("signal") or n.get("label") or "").strip()
        # driver label is "SIGNAL[N]" — strip the index suffix
        base_name = _idx_re.sub("", name).strip()
        if base_name:
            orig_case[base_name.lower()] = base_name

        if ntype == "driver":
            sig = (n.get("signal") or "").lower().strip()
            if sig:
                sig_to_drivers.setdefault(sig, []).append(n)

    # Sort each signal's drivers by their in-label index
    def _drv_sort_key(n: Dict[str, Any]) -> int:
        m = _idx_re.search(n.get("label", ""))
        return int(m.group(1)) if m else 999

    for sig in sig_to_drivers:
        sig_to_drivers[sig].sort(key=_drv_sort_key)

    # Ensure root has an original-case entry
    orig_case.setdefault(root.lower(), root)

    # ── Helper: get child signals (with drivers) referenced by a signal ───────
    _KW_LOW = frozenset({
        "and", "or", "not", "if", "else", "true", "false",
        "posedge", "negedge", "reg", "wire", "input", "output",
        "inout", "assign", "begin", "end",
    })
    _IDENT = _re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')

    def _child_sigs(sig_lower: str) -> List[str]:
        """Return sorted lowercase names of signals (with drivers) that sig uses."""
        children: set = set()
        for dep in adjacency.get(sig_lower, []):
            if dep.get("kind") == "signal":
                dep_name = (dep.get("name") or "").lower()
                if dep_name and dep_name in sig_to_drivers and dep_name != sig_lower:
                    children.add(dep_name)
        # Fallback: scan driver text directly (catches cases adjacency missed)
        for drv in sig_to_drivers.get(sig_lower, []):
            for text in (drv.get("condition") or "", drv.get("rhs") or ""):
                for m in _IDENT.finditer(text):
                    n2 = m.group(1).lower()
                    if n2 in sig_to_drivers and n2 != sig_lower and n2 not in _KW_LOW:
                        children.add(n2)
        return sorted(children)

    # ── BFS order of all signals with drivers reachable from root ─────────────
    bfs_order: List[str] = []
    bfs_visited: set = set()
    bfs_queue: List[str] = [root.lower()]
    while bfs_queue:
        sig = bfs_queue.pop(0)
        if sig in bfs_visited:
            continue
        bfs_visited.add(sig)
        if sig in sig_to_drivers:
            bfs_order.append(sig)
        for child in _child_sigs(sig):
            if child not in bfs_visited:
                bfs_queue.append(child)

    # ── Format a single driver line ───────────────────────────────────────────
    def _fmt_drv(d_idx: int, drv: Dict[str, Any], depth_tag: str, extra_indent: str) -> str:
        cond  = (drv.get("condition") or "").strip()
        rhs   = (drv.get("rhs") or "").strip()
        atype = (drv.get("assign_type") or "").strip()
        blk   = drv.get("always_block_id")
        src   = (drv.get("file") or drv.get("source_location") or "").strip()
        cond_str = f"if {cond}" if cond else "if true"
        line = f"{extra_indent}{depth_tag} D{d_idx}: {cond_str} -> {rhs}"
        meta: List[str] = []
        if atype:
            meta.append(atype)
        if blk is not None:
            meta.append(f"block={blk}")
        if src:
            meta.append(src)
            _src_m = _re.search(r":(\d+)(?::\d+)?$", src)
            if _src_m:
                meta.append(f"rtl_line={_src_m.group(1)}")
        if meta:
            line += f"  [{', '.join(meta)}]"
        # Highlight the driver that sets the signal to 1
        if rhs.strip() in ("1", "1'b1", "1'h1"):
            line += "  [*** SETS TO 1 ***]"
        # Waveform activation annotation (rca-7 style per-term evaluation)
        active = drv.get("condition_active")
        if active is True:
            line += "  *** ACTIVE @ waveform ***"
            # Show each true term and the signal values that made it true
            true_terms = drv.get("true_terms") or []
            if true_terms:
                term_vals = drv.get("term_values") or {}
                for tt in true_terms:
                    # Extract signal names from the term and show their values
                    sig_refs = [m for m in _IDENT.findall(tt)
                                if m.lower() not in _KW_LOW]
                    sv_parts = []
                    for sr in sig_refs:
                        v = wf_vals.get(sr)
                        if v is None:
                            v = wf_vals.get(sr.lower())
                        if v is not None:
                            sv_parts.append(f"{sr}={v}")
                    val_str = "  [" + ", ".join(sv_parts) + "]" if sv_parts else ""
                    line += f"\n{extra_indent}       TRUE: {tt}{val_str}"
        elif active is False:
            line += "  [inactive]"
            # Show the blocking term
            first_false = drv.get("first_false_term")
            if first_false:
                sig_refs = [m for m in _IDENT.findall(first_false)
                            if m.lower() not in _KW_LOW]
                sv_parts = []
                for sr in sig_refs:
                    v = wf_vals.get(sr)
                    if v is None:
                        v = wf_vals.get(sr.lower())
                    if v is not None:
                        sv_parts.append(f"{sr}={v}")
                val_str = "  [" + ", ".join(sv_parts) + "]" if sv_parts else ""
                line += f"\n{extra_indent}       BLOCKED by: {first_false}{val_str}"
        return line

    # ── Build output ──────────────────────────────────────────────────────────
    i = indent   # base indent for all lines
    out: List[str] = []

    # Header — show root signal's waveform value if available
    _root_val = wf_vals.get(root)
    if _root_val is None:
        _root_val = wf_vals.get(root.lower())
    _root_str = f"  [{root}={_root_val} @ cycle={analysis_cycle}]" if _root_val is not None else ""
    out.append(
        f"{i}[{rule_id} @ analysis_cycle {analysis_cycle}]"
        f" TRUE-PATH RCA - PRIMARY: {root}{_root_str}"
    )
    out.append(f"{i}  SYSTEM-2+3: TRUE-path backtracking from {root}:")

    # Per-signal driver listing (root first, then reachable intermediates)
    for sig_lower in bfs_order:
        sig_orig = orig_case.get(sig_lower, sig_lower)
        drvs = sig_to_drivers.get(sig_lower, [])
        if not drvs:
            continue
        out.append(f"{i}    {sig_orig} drivers:")
        for d_idx, drv in enumerate(drvs):
            out.append(f"{i}  " + _fmt_drv(d_idx, drv, "", "    "))

    # BACKTRACK MAP
    out.append(f"{i}  BACKTRACK MAP (COND vs RHS, by depth):")

    bt_visited: set = set()

    def _render_bt(sig_lower: str, depth: int) -> None:
        if sig_lower in bt_visited:
            return
        bt_visited.add(sig_lower)

        sig_orig   = orig_case.get(sig_lower, sig_lower)
        depth_tag  = f"L{depth}"
        extra      = "  " * depth        # 2 spaces per depth level

        if depth == 0:
            node_tag = "[root]"
        else:
            node_tag = "[intermediate]"

        out.append(f"{i}    {extra}{depth_tag} NODE {sig_orig} {node_tag}")

        drvs = sig_to_drivers.get(sig_lower, [])
        for d_idx, drv in enumerate(drvs):
            out.append(f"{i}    {extra}" + _fmt_drv(d_idx, drv, depth_tag, ""))

        if sig_lower in cyclic_set:
            # Show self-reference annotation and stop recursing
            out.append(
                f"{i}    {extra}{depth_tag} CYCLIC:"
                f" {sig_orig} in own driver conditions [ENABLE_CYCLE]"
            )
            return

        for child in _child_sigs(sig_lower):
            _render_bt(child, depth + 1)

    _render_bt(root.lower(), 0)

    # Leaf signals summary with waveform values
    if leaf_signals_list:
        _leaf_parts = []
        for _ls in leaf_signals_list:
            _lv = wf_vals.get(_ls)
            if _lv is None:
                _lv = wf_vals.get(_ls.lower())
            _leaf_parts.append(f"{_ls}={_lv}" if _lv is not None else _ls)
        out.append(f"{i}  LEAF SIGNALS: {', '.join(_leaf_parts)}")

    # Root leaf: prefer cyclic signal encountered first in BFS, else deepest leaf
    root_leaf_name = ""
    root_leaf_tag  = ""
    for sig in bfs_order:
        if sig in cyclic_set:
            root_leaf_name = orig_case.get(sig, sig)
            root_leaf_tag  = "CYCLIC_ENABLE"
            break
    if not root_leaf_name and leaf_signals_list:
        root_leaf_name = leaf_signals_list[-1]   # last = deepest in BFS order
        root_leaf_tag  = "registered_latch_unknown"
    if root_leaf_name:
        _rl_val = wf_vals.get(root_leaf_name)
        if _rl_val is None:
            _rl_val = wf_vals.get(root_leaf_name.lower())
        _rl_str = f"  val={_rl_val}" if _rl_val is not None else ""
        out.append(f"{i}  ROOT LEAF: {root_leaf_name} [{root_leaf_tag}]{_rl_str}")

    return "\n".join(out)


def _annotate_dg_with_waveform(
    dg: Dict[str, Any],
    view: Any,
    cycle: int,
) -> None:
    """
    Mutate a dependency_graph dict in-place by adding waveform values at `cycle`.

    Mirrors rca-7's per-term condition evaluation:
      - Splits each driver guard into individual AND-terms via split_conditions()
      - Evaluates each term independently via view.condition_true()
      - Stores true_terms / false_terms / first_false_term on each driver node
      - Resolves a waveform value for every signal referenced anywhere in the DG

    Adds to each driver node:
        condition_active   (bool | None) — whole guard True/False at `cycle`
        true_terms         (list[str])   — terms that evaluated True
        false_terms        (list[str])   — terms that evaluated False
        first_false_term   (str | None)  — blocking term for inactive drivers
        term_values        (dict)        — {term: bool} for each split term

    Adds to dg top-level:
        waveform_values    {signal_name: int | None} — all referenced signals
        eval_cycle         (int) — the cycle used for evaluation
    """
    import re as _re

    if not dg or view is None or cycle is None:
        return

    nodes: List[Dict[str, Any]] = dg.get("nodes") or []
    _IDENT = _re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')
    _KW_LOW = frozenset({
        "and", "or", "not", "if", "else", "true", "false",
        "posedge", "negedge", "reg", "wire", "input", "output",
        "inout", "assign", "begin", "end",
    })

    sig_names: set = set()

    # Seed with root and all known leaf/intermediate signals
    root = (dg.get("root") or "").strip()
    if root:
        sig_names.add(root)
    for s in (dg.get("leaf_signals") or []) + (dg.get("intermediate_signals") or []):
        sig_names.add(s)

    # Walk driver nodes — per-term evaluation + harvest all idents
    for node in nodes:
        ntype = node.get("type") or ""
        sig = (node.get("signal") or "").strip()
        if sig:
            sig_names.add(sig.split("[")[0])

        if ntype != "driver":
            continue

        cond = (node.get("condition") or "").strip()

        # Whole-condition evaluation
        try:
            node["condition_active"] = view.condition_true(cond, cycle) if cond else True
        except Exception:
            node["condition_active"] = None

        # Per-term evaluation (rca-7 style)
        terms = split_conditions(cond) if cond else []
        true_terms: List[str] = []
        false_terms: List[str] = []
        term_values: Dict[str, Any] = {}
        first_false: Any = None

        for term in terms:
            try:
                result = view.condition_true(term, cycle)
                term_values[term] = result
                if result is True:
                    true_terms.append(term)
                elif result is False:
                    false_terms.append(term)
                    if first_false is None:
                        first_false = term
            except Exception:
                term_values[term] = None

        node["true_terms"]      = true_terms
        node["false_terms"]     = false_terms
        node["first_false_term"] = first_false
        node["term_values"]     = term_values

        # Harvest all identifiers from cond and rhs for wf_values lookup
        for text in (cond, node.get("rhs") or ""):
            for m in _IDENT.finditer(text):
                tok = m.group(1)
                if tok.lower() not in _KW_LOW:
                    sig_names.add(tok)

    # Resolve waveform value for every collected name
    wf_values: Dict[str, Any] = {}
    for sn in sig_names:
        if not sn:
            continue
        try:
            val = view.signal_value(sn, cycle)
            if val is None:
                val = view.signal_value(sn.lower(), cycle)
            wf_values[sn] = val
        except Exception:
            wf_values[sn] = None

    dg["waveform_values"] = wf_values
    dg["eval_cycle"] = cycle


def _fmt_finding(idx: int, f: Dict[str, Any]) -> str:
    """Format one protocol finding as readable text (mirrors rca_7 per-finding block)."""
    import re as _re
    lines: List[str] = []
    rule    = f.get("rule_id", "?")
    cls     = f.get("classification", f.get("verdict", "?"))
    cycle   = f.get("analysis_cycle", f.get("cycle", "?"))
    verdict = f.get("verdict", "")
    signal  = f.get("signal", f.get("rtl_sig", "")) or ""
    # If signal not directly available, infer from required_observation
    ev = f.get("evidence") or {}
    if not signal:
        req = ev.get("required_observation", "")
        if req:
            m = _re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)', req)
            if m:
                signal = m.group(1)
    lines.append(f"  [{idx}] {rule}  |  {cls}  |  cycle={cycle}  |  {verdict}")
    if signal:
        lines.append(f"       Signal: {signal}")
    detail = f.get("detail", "")
    if detail:
        for dl in str(detail).splitlines():
            lines.append(f"       {dl}")
    # Scheduling cancellation detail
    ic = ev.get("intra_cycle_cancellation") or {}
    if ic.get("detected"):
        exp = ic.get("expected_driver_conditions") or []
        ovw = ic.get("final_overwrite_conditions") or []
        cnt = (f.get("occurrence_count") or ev.get("mechanism_occurrence_count")
               or ic.get("occurrence_count") or "")
        if exp:
            lines.append(f"       Sets   {signal}=1 when: {'; '.join(str(e) for e in exp)}")
        if ovw:
            lines.append(f"       Overwrites {signal}=0 when: {'; '.join(str(o) for o in ovw)}")
        if cnt:
            lines.append(f"       Occurrences: {cnt}")
    # Enable-cycle detail
    cycle_report = f.get("cycle_report") or {}
    if cycle_report.get("cycle_detected"):
        lines.append(f"       Enable cycle on: {cycle_report.get('blocking_signal', signal)}")
    # Dependency-graph backtracking (rca-7 TRUE-PATH format)
    dg = ev.get("dependency_graph")
    if dg and isinstance(dg, dict) and dg.get("nodes"):
        dg_text = _fmt_dependency_graph(
            dg=dg,
            rule_id=rule,
            analysis_cycle=cycle,
            indent="    ",
        )
        lines.append(dg_text)
    return "\n".join(lines)


def _fmt_violation(idx: int, v: Dict[str, Any]) -> str:
    """Format one datapath/transport violation as readable text."""
    cls     = v.get("class", "?")
    subtype = v.get("subtype", "")
    src     = v.get("source_signal", v.get("lhs", ""))
    dst     = v.get("destination_signal", v.get("signal", ""))
    loc     = v.get("source", "") or (f"line {v['rtl_line']}" if v.get("rtl_line") else "")
    tag     = f"{cls}" + (f"/{subtype}" if subtype else "")
    sig_part = f"  {dst} <- {src}" if (src and dst) else (f"  signal={dst or src}" if (src or dst) else "")
    header  = f"  [{idx}] {tag}  |  {loc}"
    impact  = v.get("impact", "")
    parts   = [header]
    if sig_part:
        parts.append(sig_part)
    if impact:
        for il in str(impact).splitlines()[:3]:   # first 3 lines of impact text
            parts.append(f"       {il.strip()}")
    return "\n".join(parts)


def _write_proof_artifacts(
    payload: Dict[str, Any],
    json_path: Path,
    raw_trace: str = "",
    debug: bool = False,
) -> Dict[str, str]:
    """
    Write structured RCA-8 proof artifacts (mirrors rca_7 appendix format):
      <name>.proof.json    — machine-readable full payload
      <name>.appendix.txt  — human-readable structured report

    Sections (in order):
      [SUMMARY]              — key facts at a glance + stats
      [FINAL_RCA]            — formatted FINAL ROOT CAUSE ANALYSIS block + raw JSON
      [TRANSPORT_VIOLATIONS] — human-readable + raw JSON
      [DATAPATH_VIOLATIONS]  — human-readable + raw JSON
      [PROTOCOL_FINDINGS]    — per-finding readable summary + raw JSON
      [CAUSAL_BINDING]       — binding pass results
      [FULL_TRACE]           — captured stdout (when available)
      [FULL_PAYLOAD]         — complete machine-readable JSON dump
    """
    json_path.parent.mkdir(parents=True, exist_ok=True)

    # ── 1. Machine-readable proof JSON ──────────────────────────────────────
    with open(str(json_path), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=_json_default)

    # ── 2. Human-readable structured appendix ───────────────────────────────
    appendix_path = json_path.with_suffix(".appendix.txt")

    final_rca      = payload.get("final_rca") or {}
    findings       = payload.get("findings") or []
    dp_viols       = payload.get("datapath_violations") or []
    tp_viols       = payload.get("transport_violations") or []
    binding_result = payload.get("binding_result") or {}
    b_summary      = binding_result.get("summary") or {}

    lines: List[str] = []
    lines.append("# RCA-8 APPENDIX PROOF")
    lines.append(f"# generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"# protocol:  {payload.get('protocol', 'unknown')}")
    lines.append("")

    # ── [SUMMARY] ── key facts as readable table ─────────────────────────────
    lines.append("[SUMMARY]")
    lines.append(_SEP)
    lines.append(f"  ROOT_CAUSE_TYPE  : {final_rca.get('root_cause_type', 'UNKNOWN')}")
    lines.append(f"  CLASSIFICATION   : {final_rca.get('classification', 'UNKNOWN')}")
    lines.append(f"  CONFIDENCE       : {final_rca.get('confidence', 'UNKNOWN')}")
    lines.append(_THIN)
    lines.append(f"  Waveform cycles  : {payload.get('waveform_max_cycle', '?')}")
    lines.append(f"  Transactions     : {len(payload.get('transactions') or [])}")
    lines.append(f"  Protocol findings: {len(findings)}")
    lines.append(f"  Datapath viols   : {len(dp_viols)}")
    lines.append(f"  Transport viols  : {len(tp_viols)}")
    lines.append(f"  Binding causal   : {b_summary.get('causal', 0)}")
    lines.append(f"  Binding latent   : {b_summary.get('latent', 0)}")
    lines.append(_SEP)
    explanation = final_rca.get("explanation", "")
    if explanation:
        lines.append("")
        lines.append("EXPLANATION:")
        for el in str(explanation).splitlines():
            lines.append(f"  {el}")
    lines.append("")

    # ── [FINAL_RCA] ── rca-7 style root cause block then raw JSON ────────────
    lines.append("[FINAL_RCA]")
    lines.append(_fmt_section("FINAL ROOT CAUSE ANALYSIS"))
    _authority      = derive_authority(final_rca)
    _responsibility = derive_responsibility(final_rca)
    _conf_raw       = str(final_rca.get("confidence", "UNKNOWN"))
    _confidence     = _CONFIDENCE_MAP.get(_conf_raw, _conf_raw)
    lines.append(f"CLASSIFICATION : {final_rca.get('classification', 'UNKNOWN')}")
    lines.append(f"AUTHORITY      : {_authority}")
    lines.append(f"CONFIDENCE     : {_confidence}")
    lines.append(f"RESPONSIBILITY : {_responsibility}")
    lines.append("")

    explanation = final_rca.get("explanation", "")
    if explanation:
        lines.append("ROOT_CAUSE:")
        for el in str(explanation).splitlines():
            lines.append(f"  {el}")
        lines.append("")

    # VERDICT / SIGNAL / RULE / ANALYSIS_CYCLE from the primary finding
    pev = final_rca.get("primary_evidence") or []
    if pev and isinstance(pev[0], dict):
        pev0    = pev[0]
        verdict = pev0.get("verdict") or "VIOLATED"
        signal  = (pev0.get("signal") or pev0.get("failure_signal")
                   or pev0.get("destination_signal") or "not_available")
        rule_id = (pev0.get("rule_id") or final_rca.get("rule_id") or "not_available")
        cycle   = pev0.get("analysis_cycle") or final_rca.get("analysis_cycle")
        lines.append(f"VERDICT        : {verdict}")
        lines.append(f"SIGNAL         : {signal}")
        lines.append(f"RULE           : {rule_id}")
        if cycle is not None:
            lines.append(f"ANALYSIS_CYCLE : {cycle}")
        lines.append("")

    # STRUCTURAL PROOF (causal chain)
    causal_chain = final_rca.get("causal_chain")
    if causal_chain:
        lines.append("STRUCTURAL PROOF:")
        for cl in str(causal_chain).splitlines():
            lines.append(f"  {cl}")
        lines.append("")

    # OVERWRITE PROOF (render-only; source is engine-produced predicate_analysis)
    _pred = final_rca.get("predicate_analysis")
    if isinstance(_pred, dict):
        _mode = _pred.get("mode_analysis")
        if isinstance(_mode, dict) and _mode:
            lines.append("OVERWRITE PROOF:")
            _m = str(_mode.get("mode") or "")
            _st = str(_mode.get("subtype") or "")
            if _m and _st:
                lines.append(f"  Mode            : {_m} ({_st})")
            elif _m:
                lines.append(f"  Mode            : {_m}")

            _ad_idx = _mode.get("asserting_driver_idx")
            _ad_cond = _mode.get("asserting_driver_cond")
            if _ad_idx is not None or _ad_cond:
                lines.append(
                    f"  Asserting driver: D{_ad_idx}  if ({_ad_cond or 'not_available'}) -> 1"
                )

            _wd_idx = _mode.get("winning_driver_idx")
            _wd_cond = _mode.get("winning_driver_cond")
            _wd_rhs = _mode.get("winning_driver_rhs")
            if _wd_idx is not None or _wd_cond or _wd_rhs is not None:
                lines.append(
                    f"  Winning driver  : D{_wd_idx}  if ({_wd_cond or 'not_available'}) "
                    f"-> {_wd_rhs if _wd_rhs is not None else 'not_available'}"
                )

            _ac_idx = _mode.get("active_driver_idx")
            _ac_cond = _mode.get("active_driver_cond")
            _ac_rhs = _mode.get("active_driver_rhs")
            if _ac_idx is not None or _ac_cond or _ac_rhs is not None:
                lines.append(
                    f"  Active driver   : D{_ac_idx}  if ({_ac_cond or 'not_available'}) "
                    f"-> {_ac_rhs if _ac_rhs is not None else 'not_available'}"
                )

            _bterm = _mode.get("blocking_term")
            if _bterm:
                lines.append(f"  Blocking term   : {_bterm}")
            lines.append("")

    # Transform nodes (NON_BIJECTIVE_TRANSFORM graph traversal)
    tnodes = final_rca.get("transform_nodes") or []
    if tnodes:
        lines.append(f"NON_BIJECTIVE_TRANSFORM_NODES ({len(tnodes)}):")
        for tn in tnodes:
            lines.append(f"  {tn.get('lhs', '?')} <- [{tn.get('property', '?')}] {tn.get('rhs', '?')[:60]}")
            lines.append(f"    bijective={tn.get('bijective')} | entropy_preserved={tn.get('entropy_preserved')} | reversible={tn.get('reversible')}")
            if tn.get("source_location"):
                lines.append(f"    source: {tn['source_location']}")
        lines.append("")

    # ADDITIONAL_PROVEN_FINDINGS (secondary effects)
    seff = final_rca.get("secondary_effects") or []
    if seff:
        lines.append(f"ADDITIONAL_PROVEN_FINDINGS ({len(seff)} item(s)):")
        seen_cls: set = set()
        for se in seff:
            cls   = se.get("classification") or se.get("verdict") or se.get("class") or "?"
            rule  = se.get("rule_id", "")
            cycle = se.get("analysis_cycle", se.get("cycle", ""))
            key   = (cls, rule)
            if key in seen_cls:
                continue
            seen_cls.add(key)
            parts = [f"  {rule}" if rule else ""]
            if cls:
                parts.append(cls)
            if cycle:
                parts.append(f"cycle={cycle}")
            lines.append("  " + " | ".join(p for p in parts if p))
        lines.append("")

    lines.append(_fmt_section("ANALYSIS METADATA"))
    lines.append(f"  Protocol         : {payload.get('protocol', 'unknown')}")
    lines.append(f"  Waveform cycles  : {payload.get('waveform_max_cycle', '?')}")
    lines.append(f"  Transactions     : {len(payload.get('transactions') or [])}")
    if final_rca.get("rule_id"):
        lines.append(f"  Rule             : {final_rca['rule_id']}")
    if final_rca.get("analysis_cycle") is not None:
        lines.append(f"  Analysis Cycle   : {final_rca['analysis_cycle']}")
    lines.append(_SEP)
    lines.append("")
    lines.append("# Raw resolver JSON:")
    lines.append(json.dumps(_sanitize_for_output(final_rca), indent=2, default=_json_default))
    lines.append("")

    # ── [TRANSPORT_VIOLATIONS] ────────────────────────────────────────────────
    lines.append("[TRANSPORT_VIOLATIONS]")
    if tp_viols:
        lines.append(f"  {len(tp_viols)} transport violation(s):")
        for i, v in enumerate(tp_viols, 1):
            lines.append(_fmt_violation(i, v))
        lines.append("")
        lines.append("# Raw JSON:")
    lines.append(json.dumps(tp_viols, indent=2, default=_json_default))
    lines.append("")

    # ── [DATAPATH_VIOLATIONS] ─────────────────────────────────────────────────
    lines.append("[DATAPATH_VIOLATIONS]")
    if dp_viols:
        lines.append(f"  {len(dp_viols)} datapath violation(s):")
        for i, v in enumerate(dp_viols, 1):
            lines.append(_fmt_violation(i, v))
        lines.append("")
        lines.append("# Raw JSON:")
    lines.append(json.dumps(dp_viols, indent=2, default=_json_default))
    lines.append("")

    # ── [PROTOCOL_FINDINGS] ───────────────────────────────────────────────────
    lines.append("[PROTOCOL_FINDINGS]")
    if findings:
        lines.append(f"  {len(findings)} finding(s):")
        for i, f_ in enumerate(findings, 1):
            lines.append(_fmt_finding(i, f_))
        lines.append("")
        lines.append("# Raw JSON:")
    lines.append(json.dumps(findings, indent=2, default=_json_default))
    lines.append("")

    # ── [CAUSAL_BINDING] ──────────────────────────────────────────────────────
    lines.append("[CAUSAL_BINDING]")
    cbs = binding_result.get("causal_bindings") or []
    lbs = binding_result.get("latent_violations") or []
    if cbs or lbs:
        lines.append(f"  Causal bindings : {len(cbs)}")
        lines.append(f"  Latent viols    : {len(lbs)}")
        for cb in cbs:
            txn  = cb.get("transaction_id", "?")
            sig  = cb.get("assignment_signal", "?")
            cyc  = cb.get("cycle", "?")
            addr = cb.get("address")
            addr_str = f"  addr=0x{addr:X}" if isinstance(addr, int) else ""
            lines.append(f"  CAUSAL  txn={txn} sig={sig} cycle={cyc}{addr_str}")
        lines.append("")
        lines.append("# Raw JSON:")
    lines.append(json.dumps(binding_result, indent=2, default=_json_default))
    lines.append("")

    # ── [FULL_TRACE] ── predicate backtracking + captured stdout ─────────────
    _pred_trace = final_rca.get("full_predicate_trace", "")
    if _pred_trace or raw_trace:
        lines.append("[FULL_TRACE]")
        if _pred_trace:
            lines.append(_fmt_section("PREDICATE BACKTRACKING TRACE"))
            lines.append(_pred_trace)
            lines.append("")
        if raw_trace:
            lines.append(_fmt_section("CAPTURED STDOUT"))
            lines.append(raw_trace)
            lines.append("")

    # ── [FULL_PAYLOAD] ── complete machine-readable dump ─────────────────────
    lines.append("[FULL_PAYLOAD]")
    lines.append(json.dumps(payload, indent=2, default=_json_default))

    with open(str(appendix_path), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # ── 3. Post-analysis report suite ───────────────────────────────────────
    report_paths: Dict[str, str] = {}
    if _REPORTS_AVAILABLE:
        # Derive base name: strip ".proof.json" → "rca8_axi_lite_<stamp>"
        base_stem = json_path.stem  # e.g. "rca8_axi_lite_20240101_120000.proof"
        if base_stem.endswith(".proof"):
            base_stem = base_stem[:-6]
        out_dir = json_path.parent

        # ── 4 primary output files (always written) ─────────────────────────
        _report_funcs = [
            ("diagnosis",         generate_console_diagnosis),
            ("rca_analysis",        generate_llm_rca_prompt),
        ]

        # ── Debug-internal extras (written only when debug=True) ─────────────
        if debug:
            _report_funcs += [
                ("structural_root_cause", generate_structural_root_cause),
                ("exec_summary",          generate_executive_summary),
                ("violation_summary",     reduce_violations),
                ("failure_timeline",      generate_failure_timeline),
                ("peer_review",           generate_peer_review_defense),
                ("determinism_score",     score_determinism_risk),
                ("evidence_filtered",     filter_evidence),
                ("deep_appendix",         generate_deep_appendix),
                ("tool_diff",             generate_tool_differentiator),
                ("causal_path",           generate_causal_path),
                ("rca_explanation",       generate_rca_explanation),
                ("signal_set",            extract_signal_set),
            ]

        for suffix, fn in _report_funcs:
            rpt_path = out_dir / f"{base_stem}.{suffix}.txt"
            try:
                text = fn(payload)
                with open(str(rpt_path), "w", encoding="utf-8") as rf:
                    rf.write(text)
                report_paths[suffix] = str(rpt_path)
                if _PROD_VERBOSE:
                    print(f"[REPORT] {suffix}: {rpt_path.name}", flush=True)
            except Exception as _rpt_err:
                if _PROD_VERBOSE:
                    print(f"[REPORT] {suffix}: skipped ({_rpt_err})", flush=True)

    return {
        "json":     str(json_path),
        "appendix": str(appendix_path),
        **report_paths,
    }


def _load_transport_violations_from_dir(context_dir: str) -> List[Dict[str, Any]]:
    """Load all *_transport_violations.json artifacts from the analysis directory."""
    violations: List[Dict[str, Any]] = []
    for fpath in _glob.glob(os.path.join(context_dir, "*_transport_violations.json")):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                violations.extend(data)
        except Exception:
            pass
    return violations


_ID_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_KW = {"and", "or", "not", "if", "else", "true", "false", "posedge", "negedge"}


def _rhs_bucket(rhs: str) -> str:
    rv = parse_literal_token(str(rhs or "").strip())
    if rv == 1:
        return "assigns_1"
    if rv == 0:
        return "assigns_0"
    return "assigns_other"


def _condition_signals(expr: str) -> List[str]:
    out: List[str] = []
    for tok in _ID_RE.findall(str(expr or "")):
        tl = tok.lower()
        if tl in _KW:
            continue
        if tok not in out:
            out.append(tok)
    return out


def _build_split_backtrack_view(
    signal: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
    max_depth: int = 3,
) -> str:
    lines: List[str] = [f"{signal}"]

    def walk(sig: str, depth: int, path: List[str]) -> None:
        indent = "  " * depth
        drivers = list(logic_table.get(sig, []) or [])
        if not drivers:
            lines.append(f"{indent}- {sig}: primary/leaf (no RTL drivers)")
            return

        groups: Dict[str, List[Dict[str, Any]]] = {
            "assigns_1": [],
            "assigns_0": [],
            "assigns_other": [],
        }
        for d in drivers:
            groups[_rhs_bucket(str(d.get("rhs", "")))].append(d)

        for gkey, gtitle in (
            ("assigns_1", "ASSIGNS 1"),
            ("assigns_0", "ASSIGNS 0"),
            ("assigns_other", "ASSIGNS OTHER"),
        ):
            gdrivers = groups[gkey]
            if not gdrivers:
                continue
            lines.append(f"{indent}- {sig} {gtitle}:")
            for idx, drv in enumerate(gdrivers, 1):
                cond = str(drv.get("cond", "") or "").strip()
                rhs = str(drv.get("rhs", "") or "").strip()
                if cond:
                    lines.append(f"{indent}  D{idx}: if ({cond}) -> {rhs}")
                else:
                    lines.append(f"{indent}  D{idx}: default -> {rhs}")

                cond_sigs = _condition_signals(cond)
                if not cond_sigs:
                    continue
                lines.append(f"{indent}    condition deps:")
                for dep in cond_sigs:
                    if dep in path:
                        lines.append(f"{indent}      - {dep} (cycle)")
                        continue
                    lines.append(f"{indent}      - {dep}")
                    if depth < max_depth and dep in logic_table:
                        walk(dep, depth + 3, path + [dep])

    walk(signal, 0, [signal])
    return "\n".join(lines)


def _print_header(title: str) -> None:
    print("")
    print("=" * 79)
    print(f"  {title}")
    print("=" * 79)



def _load_datapath_violations_from_dir(context_dir: str) -> List[Dict[str, Any]]:
    """
    Load all *_datapath_violations.json artifacts written by ir_builder.
    Uses glob so filenames are never hard-coded in cli.py.
    """
    violations: List[Dict[str, Any]] = []
    for fpath in _glob.glob(os.path.join(context_dir, "*_datapath_violations.json")):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                violations.extend(data)
        except Exception:
            pass
    return violations


def _load_semantic_violations_from_dir(context_dir: str) -> List[Dict[str, Any]]:
    """
    Load all *_semantic_violations.json artifacts written by ir_builder.
    Falls back to running detect_semantic_datapath_violations on the IR JSON
    if no pre-computed file exists and an IR file is found.
    """
    violations: List[Dict[str, Any]] = []
    for fpath in _glob.glob(os.path.join(context_dir, "*_semantic_violations.json")):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                violations.extend(data)
        except Exception:
            pass
    if violations:
        return violations

    # Fallback: run analysis live on the IR if semantic file not pre-computed
    for ir_path in _glob.glob(os.path.join(context_dir, "*_ir.json")):
        try:
            with open(ir_path, encoding="utf-8") as f:
                ir = json.load(f)
            live = detect_semantic_datapath_violations(ir)
            violations.extend(live)
        except Exception:
            pass

    return violations


def _load_ir_from_dir(context_dir: str) -> List[Dict[str, Any]]:
    """Load IR assignment records from *_ir.json in the analysis directory."""
    for ir_path in _glob.glob(os.path.join(context_dir, "*_ir.json")):
        try:
            with open(ir_path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


# Maps axil4.py rule_id -> the AXI signal to backtrack from (for dependency graph)
# Signal = the signal that fired/failed the rule (what to backtrack in RTL)
_AXIL4_RULE_SIGNALS: Dict[str, str] = {
    "RULE_1":  "AWVALID",   # AWVALID persistence failure
    "RULE_2":  "AWREADY",
    "RULE_3":  "WVALID",
    "RULE_4":  "BVALID",
    "RULE_5":  "RVALID",    # RVALID persistence: deasserted before R handshake
    "RULE_6":  "BVALID",    # BVALID persistence: deasserted before B handshake
    "RULE_7":  "RVALID",
    "RULE_8":  "RREADY",
    "RULE_9":  "BRESP",     # Write response stability: BRESP changed while BVALID held
    "RULE_10": "RVALID",    # RVALID asserted without AR handshake (unprompted)
    "RULE_11": "BVALID",    # BVALID asserted before AW+W handshakes complete
    "RULE_12": "RVALID",    # Read response missing  / RVALID never asserted (AR → R channel)
    "RULE_13": "BVALID",    # Write response missing / BVALID never asserted (AW+W → B channel)
    "RULE_14": "WSTRB",
    "RULE_15": "BRESP",
}


def _promote_raw_violations(
    raw_violations: List[Dict[str, Any]],
    logic_table: Dict[str, Any],
    view: Any,
) -> List[Dict[str, Any]]:
    """
    Convert axil4.py raw violations to protocol finding dicts with
    dependency_graph backtracking when the contract engine found no failures.

    Each promoted finding contains:
      - rule_id, classification, analysis_cycle, verdict, signal, detail
      - evidence.dependency_graph  <- TRUE-PATH backtracking tree
    """
    findings: List[Dict[str, Any]] = []
    for rv in raw_violations:
        rule_id = str(rv.get("rule_id", "")).upper()
        cycle   = rv.get("cycle")

        # Determine which AXI signal to backtrack from
        sig_name = _AXIL4_RULE_SIGNALS.get(rule_id, "")

        # Match against actual waveform column names via AXI alias resolution,
        # with suffix fallback for prefixed signals (s_axil_*, s_axil_a_*, etc.)
        actual = sig_name
        if sig_name and view is not None:
            wf_hit = _resolve_axi_signal(sig_name, view.signals)
            if not wf_hit:
                # Suffix match: "BVALID" matches "s_axil_bvalid", "s_axil_a_bvalid", etc.
                suffix = "_" + sig_name.lower()
                wf_hit = next(
                    (s for s in view.signals if s.lower() == sig_name.lower()
                     or s.lower().endswith(suffix)),
                    None,
                )
            if wf_hit:
                actual = wf_hit

        # Generate dependency graph via deep_backtrack, then annotate with
        # waveform values so the diagnosis report can show per-term evaluation.
        dg: Dict[str, Any] = {}
        if actual and isinstance(logic_table, dict) and logic_table:
            try:
                dg = build_dependency_graph(actual, logic_table, max_depth=6)
                if dg and view is not None and cycle is not None:
                    _annotate_dg_with_waveform(dg, view, int(cycle))
            except Exception:
                dg = {}

        detail = (
            rv.get("explanation")
            or rv.get("symptoms")
            or rv.get("root_cause")
            or f"{rule_id} protocol violation at cycle {cycle}"
        )

        findings.append({
            "rule_id":        rule_id,
            "classification": "TEMPORAL_VIOLATION",
            "analysis_cycle": cycle,
            "verdict":        "VIOLATED",
            "signal":         actual,
            "detail":         detail,
            "evidence": {
                "expected_signal":   actual,
                "trigger_condition": rv.get("symptoms", ""),
                "dependency_graph":  dg,
            },
        })
    return findings


# ── Structured console summaries ──────────────────────────────────────────────

import re as _re

_STRUCT_BAR = "─" * 79


def _classify_transform_semantics(sv: dict) -> str:
    """
    Map a violation dict to a canonical semantic transform name.
    Derived from violation class + subtype — NOT from line numbers or text.

    Canonical names:
      WIDTH_TRUNCATION     — source bits silently dropped (dst narrower than src)
      NON_BIJECTIVE_CAST   — reduction/collapse operator (^, &, |) or replication
      PARTIAL_ASSIGNMENT   — lane bijection failure (loop writes to constant slice)
      LANE_COLLAPSE        — write aliasing — N logical addresses → same physical entry
      TRANSPORT_MISMATCH   — WSTRB/WDATA byte-lane steering divergence
    """
    sub = (sv.get("subtype") or "").upper()
    cls = (sv.get("class") or sv.get("violation_class") or "").upper()
    combined = sub + " " + cls

    if "TRUNCATION" in combined or ("WIDTH" in combined and "CONSERVATION" in combined):
        return "WIDTH_TRUNCATION"
    if ("COLLAPSE" in combined or "NON_INVERTIBLE" in combined
            or "INVERTIBILITY" in combined or "SYNTHETIC" in combined
            or "DUPLICATION" in combined):
        return "NON_BIJECTIVE_CAST"
    if "BIJECTION" in combined or ("LANE" in combined and "BIJECTION" in combined):
        return "PARTIAL_ASSIGNMENT"
    if "ALIASING" in combined:
        return "LANE_COLLAPSE"
    if "TRANSPORT" in combined or "STROBE" in combined or "WSTRB" in combined:
        return "TRANSPORT_MISMATCH"
    return sub.replace(" ", "_") or cls.replace(" ", "_") or "UNKNOWN_TRANSFORM"


def _defect_signature(sv: dict) -> tuple:
    """
    Return a 4-field semantic signature that folds replicated RTL mistakes.

    Identity: (destination_object, source_signal_base, transform_semantics, bit_loss)

    Line numbers are intentionally EXCLUDED from the key — two assignments at
    different lines that perform the same lossy transform on the same signals
    are manifestations of ONE design-intent mistake, not separate defects.
    RTL locations are tracked as evidence (instances list) on the merged defect.
    """
    dst      = sv.get("memory") or sv.get("destination_signal") or ""
    dst_base = dst.split("[")[0].strip() if dst else ""
    src      = sv.get("source_signal") or ""
    src_base = src.split("[")[0].strip() if src else ""   # strip bit-slice e.g. WDATA[7:0]→WDATA
    xform    = _classify_transform_semantics(sv)
    sw, dw   = sv.get("inferred_src_width"), sv.get("inferred_dst_width")
    bit_loss = f"{sw} → {dw}" if (sw and dw) else ""
    return (dst_base, src_base, xform, bit_loss)


def _rtl_location_of(sv: dict) -> str:
    """Extract the most specific RTL location string from a violation dict."""
    return (sv.get("source_location") or sv.get("source")
            or (f"line {sv['rtl_line']}" if sv.get("rtl_line") else "")
            or (f"always_block {sv['always_block_id']}" if sv.get("always_block_id") else "")
            or "")


# ── Address index normalization (PROMPT 2) ─────────────────────────────────

_INDEX_RE = re.compile(
    r"^(?P<base>[^\[]+)"              # base object, e.g. slave_mem
    r"\["
    r"(?P<reg>[A-Za-z_][A-Za-z0-9_]*)"  # index register, e.g. AWADDR_reg
    r"(?:\s*\+\s*(?P<off>\d+))?"     # optional + integer offset
    r"\]$"
)


def _parse_indexed_dst(dst: str) -> tuple:
    """
    Parse a destination like 'slave_mem[AWADDR_reg+1]' into
    (base_object, index_register, offset_int).

    Returns (dst, None, None) when no recognised index expression is present.
    """
    dst = dst.strip()
    m = _INDEX_RE.match(dst)
    if not m:
        return (dst, None, None)
    return (m.group("base").strip(), m.group("reg"), int(m.group("off") or 0))


def _compress_offsets(offsets: list) -> str:
    """
    Compress a sorted list of integer offsets into a human-readable range string.

    [0, 1, 2]    → '{0..2}'
    [0, 2, 4]    → '{0, 2, 4}'
    [0]          → '0'
    """
    if not offsets:
        return ""
    offsets = sorted(set(offsets))
    if len(offsets) == 1:
        return str(offsets[0])
    # Check contiguous
    contiguous = all(offsets[i] + 1 == offsets[i + 1] for i in range(len(offsets) - 1))
    if contiguous:
        return f"{{{offsets[0]}..{offsets[-1]}}}"
    return "{" + ", ".join(str(o) for o in offsets) + "}"


# ── Predicate dependency analysis (PROTOCOL root cause) ───────────────────────

_WORD_BOUNDARY = re.compile(r"[A-Za-z0-9_]+")

# _STABILITY_RULES and _STABILITY_SIGNAL_MAP are imported from
# protocols.axi_lite.signal_map (single source of truth).

# SV language keywords and numeric literals to skip during signal extraction
_BT_SV_KW = frozenset({
    "and", "or", "not", "if", "else", "begin", "end", "assign",
    "posedge", "negedge", "reg", "wire", "input", "output",
    "true", "false", "1", "0", "1b1", "1b0",
})


def _backtrack_signal_set(
    sig_names: list,
    logic: dict,
    view: Any,
    cycle: int,
) -> dict:
    """
    For each name in sig_names that resolves to a waveform signal:
      - read its value at `cycle`
      - if it has an RTL driver in the logic table, find the active driver
    Returns:
        {sig_name: {
            "value":               Any,
            "is_leaf":             bool,   # True = master/primary input, no slave RTL driver
            "active_driver_cond":  str,
            "active_driver_rhs":   str,
            "active_driver_idx":   int | None,
        }}
    """
    result: dict = {}
    for sig in sig_names:
        if not sig or sig.lower() in _BT_SV_KW or sig in result:
            continue
        actual = next((s for s in view.signals if s.upper() == sig.upper()), None)
        if not actual:
            continue

        # Skip constant-valued signals (localparams / VCD-exported parameters).
        # Probe two cycles: if the signal has only one unique value it's not a
        # real dynamic signal — treat as not found (avoids "master input" spam).
        try:
            _v0 = view.signal_value(actual, max(0, cycle - 2))
            _v1 = view.signal_value(actual, cycle)
            _v2 = view.signal_value(actual, min(view.max_cycle, cycle + 2))
            if _v0 == _v1 == _v2 and _v0 is not None:
                # Constant across ±2 cycles — also check at a wider range
                _v_early = view.signal_value(actual, 0)
                if _v_early == _v0:
                    # Looks like a parameter/localparam — skip
                    continue
        except Exception:
            pass

        entry: dict = {
            "is_leaf":            True,
            "value":              None,
            "active_driver_cond": "",
            "active_driver_rhs":  "",
            "active_driver_idx":  None,
            "source_location":    None,
            "rtl_line":           None,
        }
        try:
            entry["value"] = view.signal_value(actual, cycle)
        except Exception:
            pass
        # Slave-driven?  Check logic table
        key = next((k for k in logic if k.upper() == actual.upper()), None)
        if key:
            entry["is_leaf"] = False
            try:
                evals = _eval_all_drivers(actual, logic, view, cycle)
                active = next(
                    (d for d in evals if d.get("condition_active") is True), None
                )
                if active:
                    entry["active_driver_cond"] = (
                        active.get("condition") or active.get("cond") or ""
                    )
                    entry["active_driver_rhs"]  = str(active.get("rhs") or "")
                    entry["active_driver_idx"]  = active.get("driver_idx")
                    entry["source_location"]    = (
                        active.get("file") or active.get("source_location") or None
                    )
                    entry["rtl_line"]           = active.get("rtl_line")
                else:
                    # No combinational driver active — this is a registered FF
                    # (e.g. FSM state register).  Look one cycle back for the
                    # transition that put the signal into its current value.
                    if cycle > 0:
                        _prev_evals = _eval_all_drivers(actual, logic, view, cycle - 1)
                        _prev_active = next(
                            (d for d in _prev_evals if d.get("condition_active") is True),
                            None,
                        )
                        if _prev_active:
                            entry["active_driver_cond"] = (
                                _prev_active.get("condition") or _prev_active.get("cond") or ""
                            )
                            entry["active_driver_rhs"]  = str(_prev_active.get("rhs") or "")
                            entry["active_driver_idx"]  = _prev_active.get("driver_idx")
                            entry["source_location"]    = (
                                _prev_active.get("file") or _prev_active.get("source_location") or None
                            )
                            entry["rtl_line"]           = _prev_active.get("rtl_line")
                            entry["registered"] = True   # mark so formatter adds note
            except Exception:
                pass
        result[sig] = entry
    return result


def _find_first_incomplete_aw_cycle(
    view: Any,
    t_violation: int,
    adapter: Any,
) -> Optional[int]:
    """
    Find the first AW handshake burst (AWVALID && AWREADY) before t_violation
    where BVALID was never asserted before the next burst.

    AXI4-Lite allows multiple outstanding-but-pipelined transactions; for
    RULE_13 (write response missing) the relevant abort is the FIRST
    incomplete handshake, not the last one before the violation cycle.

    Returns the cycle number of the first cycle of the first incomplete burst,
    or None if no incomplete burst is found.
    """
    try:
        sig_map = adapter._resolve_axi_signals(view)
    except Exception:
        sig_map = {}

    aw_valid_col = sig_map.get("AWVALID") or _resolve_axi_signal("AWVALID", view.signals)
    aw_ready_col = sig_map.get("AWREADY") or _resolve_axi_signal("AWREADY", view.signals)
    bvalid_col   = sig_map.get("BVALID")  or _resolve_axi_signal("BVALID",  view.signals)

    if not aw_valid_col or not aw_ready_col or not bvalid_col:
        return None

    # ── 1. Collect the start cycle of each AW handshake burst ──────────────
    # Consecutive cycles where AWVALID=1 && AWREADY=1 count as a single burst.
    burst_starts: List[int] = []
    in_burst = False
    for cyc in range(0, int(t_violation)):
        try:
            av = view.signal_value(aw_valid_col, cyc)
            ar = view.signal_value(aw_ready_col, cyc)
            active = (av == 1 and ar == 1)
        except Exception:
            active = False
        if active and not in_burst:
            burst_starts.append(cyc)
            in_burst = True
        elif not active:
            in_burst = False

    if not burst_starts:
        return None

    # ── 2. For each burst, check whether BVALID fired before the next burst ─
    for i, burst_cyc in enumerate(burst_starts):
        next_start = burst_starts[i + 1] if i + 1 < len(burst_starts) else int(t_violation)
        bvalid_seen = False
        for check_cyc in range(burst_cyc + 1, next_start):
            try:
                bv = view.signal_value(bvalid_col, check_cyc)
                if bv == 1:
                    bvalid_seen = True
                    break
            except Exception:
                continue
        if not bvalid_seen:
            return burst_cyc  # first incomplete handshake burst

    return None


def _find_fsm_abort_cycle(
    view: Any,
    fsm_signal: str,
    t_start: int,
    max_scan: int = 2000,
    idle_val: int = 0,
    done_vals: Optional[set] = None,
) -> Optional[int]:
    """
    Scan forward from t_start for the cycle where the FSM was aborted —
    i.e., it was in an active (non-idle, non-done) state and jumped back
    to the idle/reset state without completing the normal exit sequence.

    Returns the cycle index where the transition to idle first appears
    (the cycle AFTER the last active-state cycle), or None if not found.
    """
    done_vals = done_vals or set()
    prev_val: Optional[int] = None
    max_cyc = view.max_cycle if hasattr(view, "max_cycle") else t_start + max_scan
    for cyc in range(t_start, min(t_start + max_scan, max_cyc + 1)):
        try:
            val = view.signal_value(fsm_signal, cyc)
        except Exception:
            break
        if val is None:
            continue
        # Transition: was in active state, now back at idle
        if (prev_val is not None
                and prev_val != idle_val
                and prev_val not in done_vals
                and val == idle_val):
            return cyc
        prev_val = val
    return None


def _backtrack_condition_chain(
    start_term: str,
    logic: dict,
    view: Any,
    cycle: int,
    max_depth: int = 5,
    *,
    fsm_enc: Optional[Dict[str, int]] = None,
    fsm_regs: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """
    Recursively trace WHY a condition term holds its value, following the
    active driver chain through the logic table.

    Starting from a term like 'w_state == W_IDLE', this function:
      1. Extracts the signal reference (e.g. 'w_state')
      2. Reads its value at `cycle` from the waveform
      3. Finds its active RTL driver
      4. Picks the most informative TRUE term from that driver's condition
      5. Recurses into that term's signal up to max_depth

    Returns a list of dicts, one per depth level:
      {signal, value, driver_cond, driver_rhs, driver_idx,
       term, is_leaf, registered, next_term}

    Example chain produced for user319 (awready incorrectly asserted):
      depth=0: signal=w_state, value=0(W_IDLE), driver='if (flush) -> W_IDLE'
      depth=1: signal=flush,   value=1,         is_leaf=True (master input)
    """
    chain: List[Dict[str, Any]] = []
    visited: set = set()
    current_term = start_term
    # Per-step evaluation cycle — normally == cycle, but drops to cycle-1 when
    # following the RHS of a registered FF (e.g. state<=next_state) so that we
    # evaluate the combinational next-state signal at the clock edge that
    # produced the current registered value, not after it has already advanced.
    current_cycle = cycle

    for depth in range(max_depth):
        if not current_term:
            break

        # Extract candidate signal names from the current term
        tokens = [m for m in _WORD_BOUNDARY.findall(current_term)
                  if m.lower() not in _BT_SV_KW and not m.isdigit()]
        # Prefer FSM state registers ('state' in name)
        target_sig: str | None = None
        for tok in tokens:
            if tok.lower() in visited:
                continue
            if target_sig is None:
                target_sig = tok
            if "state" in tok.lower():
                target_sig = tok
                break

        if not target_sig or target_sig.lower() in visited:
            break
        visited.add(target_sig.lower())

        actual = next((s for s in view.signals if s.upper() == target_sig.upper()), None)

        step: Dict[str, Any] = {
            "depth":            depth,
            "term":             current_term,
            "signal":           target_sig,
            "value":            None,
            "is_leaf":          True,
            "registered":       False,
            "active_driver_cond": "",
            "active_driver_rhs":  "",
            "active_driver_idx":  None,
            "source_location":    None,
            "rtl_line":           None,
            "next_term":        None,
        }

        if actual:
            try:
                step["value"] = view.signal_value(actual, current_cycle)
            except Exception:
                pass

            key = next((k for k in logic if k.upper() == actual.upper()), None)
            if not key:
                # Prefix-stripped fallback (S_BVALID → BVALID, etc.)
                for _k in logic:
                    for _pfx in ("S_", "M_", "u_", "s_", "m_"):
                        if _k.upper().startswith(_pfx.upper()) and _k[len(_pfx):].upper() == actual.upper():
                            key = _k
                            break
                    if key:
                        break
            if key:
                step["is_leaf"] = False
                try:
                    evals = _eval_all_drivers(actual, logic, view, current_cycle)
                    # For nonblocking always blocks the LAST active assignment wins.
                    # Iterate all evals and keep overwriting so we end up with the
                    # final active driver (not the first).
                    active = None
                    for _d in evals:
                        if _d.get("condition_active") is True:
                            active = _d  # keep overwriting → last active wins

                    # FSM fallback: re-evaluate with enum encoding when conditions
                    # contain state-name comparisons (e.g. state == WRITE_CHANNEL).
                    if not active and fsm_enc:
                        _, _bt_row = view.row_at_cycle(current_cycle)
                        _bt_row_ext = expand_row_with_aliases(_bt_row)
                        _bt_fsmr = list(fsm_regs or _bt_row.keys())
                        for _d in evals:
                            _cond = _d.get("condition") or _d.get("cond") or ""
                            if not _cond:
                                active = _d
                                # don't break — last wins
                                continue
                            try:
                                if _eval_expr_fsm(
                                    _cond, _bt_row_ext,
                                    fsm_regs=_bt_fsmr, fsm_enc=fsm_enc,
                                ) in (True, 1):
                                    active = _d  # keep overwriting → last wins
                            except Exception:
                                pass

                    if not active:
                        # Scan back up to 500 cycles to find the last value-change cycle.
                        # For registered FSMs the active driver fired at the transition
                        # edge, not at the query cycle.
                        cur_val = step["value"]
                        transition_cycle: int | None = None
                        search_start = min(current_cycle - 1, current_cycle)
                        for _sc in range(search_start, max(0, current_cycle - 500), -1):
                            try:
                                prev_val = view.signal_value(actual, _sc)
                            except Exception:
                                break
                            if prev_val != cur_val:
                                transition_cycle = _sc + 1  # cycle where value changed to cur_val
                                break
                        if transition_cycle is not None and transition_cycle > 0:
                            step["transition_cycle"] = transition_cycle
                            # Try the transition cycle first (captures same-edge input changes),
                            # then one cycle before (captures setup-time NBA inputs).
                            for _tc in (transition_cycle, transition_cycle - 1):
                                t_evals = _eval_all_drivers(actual, logic, view, _tc)
                                # Last active driver wins (nonblocking semantics)
                                active = None
                                for _d in t_evals:
                                    if _d.get("condition_active") is True:
                                        active = _d
                                # FSM fallback for scan-back path
                                if not active and fsm_enc:
                                    _, _sb_row = view.row_at_cycle(_tc)
                                    _sb_row_ext = expand_row_with_aliases(_sb_row)
                                    _sb_fsmr = list(fsm_regs or _sb_row.keys())
                                    for _d2 in t_evals:
                                        _cond2 = _d2.get("condition") or _d2.get("cond") or ""
                                        if not _cond2:
                                            active = _d2
                                            continue
                                        try:
                                            if _eval_expr_fsm(
                                                _cond2, _sb_row_ext,
                                                fsm_regs=_sb_fsmr, fsm_enc=fsm_enc,
                                            ) in (True, 1):
                                                active = _d2  # last wins
                                        except Exception:
                                            pass
                                if active:
                                    step["registered"] = True
                                    break

                    if active:
                        step["active_driver_cond"] = (
                            active.get("condition") or active.get("cond") or ""
                        )
                        step["active_driver_rhs"]  = str(active.get("rhs") or "")
                        step["active_driver_idx"]  = active.get("driver_idx")
                        step["source_location"]    = (
                            active.get("file") or active.get("source_location") or None
                        )
                        step["rtl_line"]           = active.get("rtl_line")

                        # Pick next term to follow: the most informative TRUE term.
                        # Priority: FSM state refs > other signals > skip reset/clock.
                        _RESET_KW = frozenset({
                            "rst", "rst_n", "reset", "reset_n", "resetn",
                            "aresetn", "areset_n", "nreset",
                        })
                        true_terms = active.get("true_terms") or []
                        next_term: str | None = None
                        for tt in true_terms:
                            tt_toks = [m for m in _WORD_BOUNDARY.findall(tt)
                                       if m.lower() not in _BT_SV_KW and not m.isdigit()]
                            candidates = [t for t in tt_toks
                                          if t.lower() not in visited
                                          and t.lower() not in _RESET_KW]
                            if not candidates:
                                continue
                            if next_term is None:
                                next_term = tt
                            # Prefer FSM state terms
                            if any("state" in t.lower() for t in candidates):
                                next_term = tt
                                break

                        # RHS fallback: for registered FFs driven as
                        #   if (ARESETN) state <= next_state
                        # the only true_term is the reset enable (ARESETN),
                        # which is a dead-end primary input.  When no useful
                        # next_term was found from the condition, follow the
                        # RHS signal instead — it carries the actual FSM value.
                        _rhs_fallback_used = False
                        if next_term is None:
                            _rhs_str = str(active.get("rhs") or "")
                            _rhs_toks = [m for m in _WORD_BOUNDARY.findall(_rhs_str)
                                         if m.lower() not in _BT_SV_KW
                                         and not m.isdigit()
                                         and m.lower() not in visited
                                         and m.lower() not in _RESET_KW]
                            for _rt in _rhs_toks:
                                # Only follow if the RHS signal has logic table entries
                                _rk = next((k for k in logic
                                            if k.upper() == _rt.upper()
                                            or k.upper().endswith("_" + _rt.upper())
                                            or k.upper() == ("S_" + _rt).upper()
                                            or k.upper() == ("M_" + _rt).upper()),
                                           None)
                                if _rk:
                                    next_term = _rt
                                    _rhs_fallback_used = True
                                    break

                        step["next_term"] = next_term
                        # When following a combinational RHS (next_state) from a
                        # registered FF (state <= next_state, assign_type=nonblocking),
                        # the evaluation cycle for the next depth must be the cycle
                        # BEFORE the FF last transitioned to its current value — i.e.,
                        # the exact clock edge that loaded this registered value.
                        # A plain -1 fails when the register has held its value for
                        # multiple cycles (e.g. state=WRESP at cycles 13..14 means
                        # next_state produced WRESP at cycle 12, not at cycle 13).
                        _is_nb = (active.get("assign_type") or "") == "nonblocking"
                        if _rhs_fallback_used and _is_nb and actual and step["value"] is not None:
                            # Scan back to find the cycle when `actual` last changed
                            # to its current value (transition_cycle).
                            _rhs_cur_val = step["value"]
                            _rhs_trans: int | None = None
                            for _rs in range(current_cycle - 1,
                                             max(0, current_cycle - 500), -1):
                                try:
                                    _rpv = view.signal_value(actual, _rs)
                                except Exception:
                                    break
                                if _rpv != _rhs_cur_val:
                                    _rhs_trans = _rs + 1  # first cycle with cur_val
                                    break
                            if _rhs_trans is not None and _rhs_trans > 0:
                                step["_rhs_eval_cycle"] = _rhs_trans - 1
                            else:
                                step["_rhs_eval_cycle"] = current_cycle - 1
                        else:
                            step["_rhs_eval_cycle"] = None
                        step["_rhs_fallback"] = _rhs_fallback_used and _is_nb
                except Exception:
                    pass

        chain.append(step)
        # Advance to the next term; if we just crossed a registered FF boundary
        # via RHS fallback, use the pre-computed transition-based eval cycle.
        if step.get("_rhs_fallback") and step.get("_rhs_eval_cycle") is not None:
            current_cycle = step["_rhs_eval_cycle"]
        current_term = step["next_term"]

    return chain


def _detect_stability_mutation(
    rule_id: str,
    logic: dict,
    view: Any,
    t_violation: int,
    second_list: list,
) -> Tuple[dict, dict]:
    """
    MODE-C algorithm — stability mutation root cause.

    Steps:
      1. Look up the stability signal and its VALID/READY pair.
      2. Find t_start: scan back from t_violation to the cycle when VALID
         was first asserted (defines the start of the stability window).
      3. Confirm mutation: value(t_violation) != value(t_violation - 1).
      4. Evaluate all RTL drivers at t_violation (the mutation cycle).
      5. Identify the ACTIVE driver — the one whose condition was TRUE.
      6. Backtrack the TRUE terms of that driver (same as MODE-A/D).

    Returns (pred_a, mode_info):
      pred_a    — predicate_analysis dict for the stability signal
      mode_info — mode_analysis dict with mode="MODE-C"
    Returns ({}, {}) on failure (signal not in waveform / no RTL drivers).
    """
    stab_cfg = _STABILITY_SIGNAL_MAP.get(rule_id.upper())
    if not stab_cfg:
        return {}, {}

    stab_sig, valid_sig, ready_sig = stab_cfg
    t_mut = t_violation  # axil4.py already found the mutation cycle

    # ── Step 1: Resolve waveform signal names ────────────────────────────
    # Use _resolve_axi_signal so that prefixed names like "s_axi_rdata"
    # are found via AXI_LITE_SIGNAL_ALIASES when looking for canonical "RDATA".
    stab_actual  = _resolve_axi_signal(stab_sig,  view.signals)
    valid_actual = _resolve_axi_signal(valid_sig, view.signals)

    if not stab_actual:
        return {}, {}

    # ── Step 2: Find t_start — walk back while VALID is continuously high ─
    t_start = t_mut
    if valid_actual and t_mut > 0:
        for _c in range(t_mut - 1, max(0, t_mut - 1024) - 1, -1):
            try:
                v_val = view.signal_value(valid_actual, _c)
                if v_val not in (1, "1", "1'b1"):
                    t_start = _c + 1
                    break
            except Exception:
                pass

    # ── Step 3: Confirm mutation (value diff) ─────────────────────────────
    # axil4 reports change_cycle N but the VCD may have the value change at
    # N-1 (off-by-one between simulation timestep and cycle counter).
    # Scan up to 3 cycles backward to find where the value actually changed.
    val_before: Any = None
    val_after:  Any = None
    actual_t_mut: int = t_mut
    try:
        v_at_mut = view.signal_value(stab_actual, t_mut)
        val_after = v_at_mut
        for _back in range(min(3, t_mut)):
            _t_prev = t_mut - _back - 1
            _v_prev = view.signal_value(stab_actual, _t_prev)
            if _v_prev != v_at_mut:
                val_before    = _v_prev
                actual_t_mut  = t_mut - _back
                val_after     = v_at_mut
                break
        if val_before is None:
            val_before = view.signal_value(stab_actual, max(0, t_mut - 1))
    except Exception:
        pass

    # ── Step 4 & 5: Evaluate all drivers at t_mut, find the active one ───
    try:
        drv_evals = _eval_all_drivers(stab_actual, logic, view, t_mut)
    except Exception:
        return {}, {}

    active_drv = next((d for d in drv_evals if d.get("condition_active") is True), None)

    if not active_drv:
        # Fallback: registered FF — look one cycle back
        if t_mut > 0:
            try:
                prev_evals = _eval_all_drivers(stab_actual, logic, view, t_mut - 1)
                active_drv = next(
                    (d for d in prev_evals if d.get("condition_active") is True), None
                )
            except Exception:
                pass
        # If still no active driver, the signal is either not in the logic table
        # (e.g. a combinational wire whose assign is not tracked) or has no
        # evaluable condition.  For stability rules the mutation itself is
        # sufficient evidence — continue with degenerate driver info rather than
        # returning early, so that ready_gate_absent=True is still reported.

    if active_drv:
        a_cond  = (active_drv.get("condition") or active_drv.get("cond") or "").strip()
        a_rhs   = str(active_drv.get("rhs") or "")
        a_idx   = active_drv.get("driver_idx")
        a_terms = active_drv.get("true_terms") or []
        a_tvals = active_drv.get("term_values") or {}
    else:
        # Signal not in driver table (e.g. combinational wire from assign).
        # Mutation is confirmed from waveform; absence of driver entry implies
        # no READY gate exists in RTL — structural root cause confirmed.
        a_cond  = ""
        a_rhs   = "(driver not in table)"
        a_idx   = None
        a_terms = []
        a_tvals = {}

    # ── Predicate analysis: are VALID/READY absent from the driver predicate?
    # If the stability signal's driver does not reference the required handshake
    # signals, it can mutate freely during the stability window.
    cond_tokens: set = set()
    stab_key = next((k for k in logic if k.upper() == stab_actual.upper()), None)
    if stab_key:
        for drv in (logic.get(stab_key) or []):
            c = (drv.get("condition") or drv.get("cond") or "").strip()
            if c:
                cond_tokens.update(t.lower() for t in _WORD_BOUNDARY.findall(c))

    stability_deps = [valid_sig, ready_sig]
    found_signals   = [s for s in stability_deps if s.lower() in cond_tokens]
    missing_signals = [s for s in stability_deps if s.lower() not in cond_tokens]

    # ── Architectural check: is READY absent from ALL driver conditions? ──────
    # If ready_sig never appears in any condition of the stability signal's
    # RTL driver tree, the design has no backpressure gate on that signal.
    # This is the structural root cause of the stability violation:
    # "RDATA can advance because fifo_read_enable is never gated by RREADY."
    ready_gate_absent = ready_sig.lower() not in cond_tokens

    # Collect secondary waveform values at t_mut
    sec_wave: dict = {}
    for wsig in stability_deps + second_list:
        wa = next((s for s in view.signals if s.upper() == wsig.upper()), None)
        if wa:
            try:
                sec_wave[wsig] = view.signal_value(wa, t_mut)
            except Exception:
                pass

    pred_a = {
        "signal":                stab_actual,
        "driver_predicate":      a_cond,
        "found_signals":         found_signals,
        "missing_signals":       missing_signals,
        "t_eval":                t_mut,
        "primary_waveform_value": val_after,
        "secondary_waveform":    sec_wave,
    }

    # ── Step 6: Backtrack TRUE terms of the active driver ─────────────────
    bt_raw: List[str] = []
    for term in a_terms:
        bt_raw.extend(_WORD_BOUNDARY.findall(term))
    bt_sigs = list(dict.fromkeys(
        tok for tok in bt_raw
        if tok and tok.lower() not in _BT_SV_KW
    ))

    # Resolve RTL source location from the active driver's logic table entry.
    stab_key = next((k for k in logic if k.upper() == stab_actual.upper()), None)
    active_source: Optional[str] = None
    if stab_key and a_idx is not None:
        for drv in (logic.get(stab_key) or []):
            if drv.get("driver_idx") == a_idx:
                active_source = drv.get("file") or drv.get("source_location")
                break
        if active_source is None and logic.get(stab_key):
            active_source = (logic[stab_key][0].get("file")
                             or logic[stab_key][0].get("source_location"))

    mode_info: dict = {
        "mode":             "MODE-C",
        "subtype":          "STABILITY_MUTATION",
        "t_start":          t_start,
        "t_mutation":       actual_t_mut,
        "stability_signal": stab_sig,
        "value_before":     val_before,
        "value_after":      val_after,
        "valid_signal":        valid_sig,
        "ready_signal":        ready_sig,
        "ready_gate_absent":   ready_gate_absent,
        "active_driver_cond":  a_cond,
        "active_driver_idx":   a_idx,
        "active_driver_rhs":   a_rhs,
        "active_true_terms":   a_terms,
        "active_term_values":  a_tvals,
        "source_location":     active_source,
        "term_backtrack": _backtrack_signal_set(bt_sigs, logic, view, t_mut),
        "secondary_backtrack": _backtrack_signal_set(second_list, logic, view, t_mut),
    }

    return pred_a, mode_info


def _compute_predicate_analysis(
    rule_id: str,
    primary_sigs: list,
    secondary_sigs: list,
    logic: dict,
) -> dict | None:
    """
    For the primary signal of a PROTOCOL violation, find its RTL ASSERTING
    driver condition in the logic table and determine which of the required
    secondary signals (per AXI4-Lite spec) are absent.

    Mirrors rca_7 default-driver filtering: DEFAULT (unconditional) and pure
    RESET drivers are excluded from predicate selection.  The asserting driver
    (rhs == 1) is preferred as the representative predicate — it shows the
    condition that SHOULD have been satisfied, not the deassert/else path.

    Returns a dict:
        {
          "signal":           "RVALID",
          "driver_predicate": "(ARESETn) && (read_state == RESP)",
          "found_signals":    ["ARESETn", "read_state"],   # present
          "missing_signals":  ["ARVALID", "ARREADY"],      # absent (BUG)
        }
    Returns None when no logic table entry is found for any primary signal.
    """
    if not logic or not primary_sigs:
        return None

    _ASSERT_RHS = frozenset({"1", "1'b1", "1'h1"})

    def _get_cond(drv: dict) -> str:
        # logic table may use either "condition" or "cond" as key
        return (drv.get("condition") or drv.get("cond") or "").strip()

    def _get_rhs(drv: dict) -> str:
        return (drv.get("rhs") or "").strip()

    def _is_default(drv: dict) -> bool:
        c = _get_cond(drv).lower()
        return not c or c in ("1", "true", "1'b1")

    def _is_asserting(drv: dict) -> bool:
        return _get_rhs(drv) in _ASSERT_RHS

    # Locate the primary signal in the logic table (case-insensitive).
    # AXI RTL often uses module-level port prefixes (S_, M_, u_) that differ
    # from the canonical signal names in RULE_SIGNAL_MAP.  After the exact
    # match fails, retry with each common AXI prefix so that e.g. "BVALID"
    # finds "S_BVALID" in the logic table.
    _AXI_PREFIXES = ("S_", "M_", "u_", "s_", "m_")
    primary_sig = None
    primary_drivers: list = []
    for sig in primary_sigs:
        # 1. Exact case-insensitive match
        for k, drivers in logic.items():
            if k.upper() == sig.upper():
                primary_sig = k
                primary_drivers = list(drivers or [])
                break
        # 2. Prefix-stripped fallback: logic table key may have AXI prefix
        if not primary_sig:
            for k, drivers in logic.items():
                k_stripped = k
                for pfx in _AXI_PREFIXES:
                    if k.upper().startswith(pfx.upper()):
                        k_stripped = k[len(pfx):]
                        break
                if k_stripped.upper() == sig.upper():
                    primary_sig = k
                    primary_drivers = list(drivers or [])
                    break
        if primary_sig:
            break

    if not primary_drivers:
        return None

    # Ternary-assign expansion: continuous assigns of the form
    #   assign S_BVALID = (cond) ? 1 : 0;
    # are stored as condition="true", rhs="(cond) ? 1 : 0".
    # Expand them into synthetic drivers so the condition is visible
    # to the asserting-driver selector and the missing-signal checker.
    import re as _re_tern
    _TERNARY_ASSERT_RE = _re_tern.compile(
        r'^\s*\(?(.*?)\)?\s*\?\s*1\s*:\s*0\s*$'
    )
    _expanded: list = []
    for _d in primary_drivers:
        _c = _get_cond(_d)
        _r = _get_rhs(_d)
        if _c.lower() in ("true", "1", "1'b1") and _r:
            _tm = _TERNARY_ASSERT_RE.match(_r)
            if _tm:
                _inner = _tm.group(1).strip()
                if _inner:
                    _expanded.append({**_d, "cond": _inner, "rhs": "1"})
                    _expanded.append({**_d, "cond": f"!({_inner})", "rhs": "0"})
                    continue
        _expanded.append(_d)
    primary_drivers = _expanded

    # Build token-frequency table: how many distinct conditions each token appears in.
    # Tokens that appear across multiple driver conditions (e.g. "write_state" present
    # in every branch) are the TRUE controlling signals — they score highest.
    nd = [d for d in primary_drivers if not _is_default(d)]
    scored_pool = nd or primary_drivers          # skip unconditional "always 0/1" defaults

    def _repeat_count(cond_str: str) -> int:
        """Count tokens that appear MORE THAN ONCE inside this single condition.
        A token repeated in the same condition (e.g. read_state in
        '!((read_state==IDLE)||(read_state==RESP))') marks a negated compound
        else-path — not the direct asserting condition we want."""
        toks = [t.lower() for t in _WORD_BOUNDARY.findall(cond_str)]
        seen: set = set()
        repeats: set = set()
        for t in toks:
            if t in seen:
                repeats.add(t)
            seen.add(t)
        return len(repeats)

    # Candidate drivers: prefer asserting (rhs==1) non-default; fall back to all non-default
    asserting_nd = [d for d in scored_pool if _is_asserting(d)]
    candidate_pool = asserting_nd or scored_pool

    cand_conds = [_get_cond(d) for d in candidate_pool if _get_cond(d)]
    if not cand_conds:
        return None

    # Representative predicate: fewest intra-condition token repeats (0 = direct
    # asserting condition; >0 = negated compound else-path).
    # Tie-break: shorter string (more concise = less negation).
    driver_predicate = min(
        cand_conds,
        key=lambda c: (_repeat_count(c), len(c)),
    )

    # Capture RTL source location from the driver whose condition was selected.
    pred_source: Optional[str] = None
    for d in candidate_pool:
        if _get_cond(d) == driver_predicate:
            pred_source = d.get("file") or d.get("source_location") or None
            break

    # Token presence check uses ALL non-default conditions so we detect any
    # secondary signal referenced anywhere in the driver logic.
    check_pool = nd or primary_drivers
    combined_tokens: set = set()
    for d in check_pool:
        c = _get_cond(d)
        if c:
            combined_tokens.update(t.lower() for t in _WORD_BOUNDARY.findall(c))

    found_signals   = [req for req in secondary_sigs if req.lower() in combined_tokens]
    missing_signals = [req for req in secondary_sigs if req.lower() not in combined_tokens]

    return {
        "signal":           primary_sig or primary_sigs[0],
        "driver_predicate": driver_predicate,
        "found_signals":    found_signals,
        "missing_signals":  missing_signals,
        "source_location":  pred_source,
    }


def _print_structural_summary(violations: list) -> tuple:
    """
    Semantic pattern folding: merge all violations with the same
    (destination, source, transform, bit-loss) into ONE defect entry.

    RTL line numbers are demoted to supporting evidence (instances list).

    Returns (n_semantic_defects, n_total_instances).
    """
    sig_map = {}
    for sv in violations:
        sig = _defect_signature(sv)
        if sig not in sig_map:
            sig_map[sig] = []
        sig_map[sig].append(sv)

    n_semantic = len(sig_map)
    n_total    = len(violations)

    print(f"\nSTRUCTURAL DEFECT SUMMARY")
    print(_STRUCT_BAR)
    for sig, entries in sig_map.items():
        dst_base, src_base, xform, bit_loss = sig
        rep = entries[0]

        # Display label — "Systemic" if multiple RTL locations share the same semantic
        tag = " (Systemic)" if len(entries) > 1 else ""
        print(f"  {xform}{tag}")

        # ── Address index normalization (PROMPT 2) ────────────────────────
        # Collect all raw destination strings from entries, parse index exprs.
        addr_groups: dict = {}   # index_reg → list[int offset]
        plain_dsts:  list = []   # destinations without a recognised index
        for sv in entries:
            raw_dst = sv.get("memory") or sv.get("destination_signal") or dst_base
            obj, idx_reg, offset = _parse_indexed_dst(raw_dst)
            if idx_reg is not None:
                addr_groups.setdefault(idx_reg, []).append(offset)
            else:
                if obj and obj not in plain_dsts:
                    plain_dsts.append(obj)

        if addr_groups:
            for idx_reg, offsets in addr_groups.items():
                compressed = _compress_offsets(offsets)
                print(f"  Destination      : {dst_base}[{idx_reg} + {compressed}]")
                print(f"  Address Pattern  : Base = {idx_reg}, Offsets = {compressed}")
        else:
            print(f"  Destination      : {dst_base or '-'}")

        if src_base:
            print(f"  Source           : {src_base}")
        if bit_loss:
            print(f"  Bit loss         : {bit_loss}")

        # Collect distinct RTL locations as evidence
        locs_seen: set = set()
        locs: list = []
        for sv in entries:
            loc = _rtl_location_of(sv)
            if loc and loc not in locs_seen:
                locs_seen.add(loc)
                locs.append(loc)

        if locs:
            first = locs[0]
            print(f"  First seen       : {first}")
            if len(locs) > 1:
                print(f"  Also at          :", end="")
                for i, loc in enumerate(locs[1:6]):
                    print(f" {loc}", end=("," if i < min(len(locs)-2, 4) else ""))
                if len(locs) > 6:
                    print(f" ... (+{len(locs)-6} more)", end="")
                print()

        print(f"  Instance count   : {len(entries)} replicated assignment"
              + ("s" if len(entries) != 1 else ""))
        print()

    print(_STRUCT_BAR)
    return n_semantic, n_total


def _print_causal_summary(
    n_protocol: int,
    n_unique_defects: int,
    n_total_occurrences: int,
    n_causal: int,
    n_latent: int,
) -> None:
    """PART 3: Print causal analysis summary block."""
    n_independent = max(0, n_protocol - n_causal - n_latent)
    W = 44  # label column width
    print(f"\nCAUSAL ANALYSIS SUMMARY")
    print(_STRUCT_BAR)
    print(f"  {'Protocol violations detected':<{W}}: {n_protocol:>3}   "
          f"(AXI handshake rule failures)")
    print(f"  {'Structural defects (semantic patterns)':<{W}}: {n_unique_defects:>3}   "
          f"(distinct destination / transform / bit-loss)")
    print(f"  {'Replicated instances':<{W}}: {n_total_occurrences:>3}   "
          f"(RTL locations exhibiting the same defect pattern)")
    print(f"  {'Violations caused by structural defects':<{W}}: {n_causal:>3}   "
          f"(protocol failures traceable to RTL)")
    print(f"  {'Downstream secondary effects':<{W}}: {n_latent:>3}   "
          f"(cascading from primary cause)")
    print(f"  {'Independent protocol issues':<{W}}: {n_independent:>3}   "
          f"(pure FSM / handshake, no RTL link)")
    print(_STRUCT_BAR)


def run_waveeye_rca(
    waveform_csv: str,
    drivers_csv: str,
    violations_path: Optional[str],
    context_dir: str,
    protocol: str = "axi_lite",
    debug: bool = False,
    output_mode: str = "production",  # "production" | "debug" | "research"
) -> Dict[str, Any]:
    """
    Single entry point for the hybrid RCA pipeline.

    Called by cli.py; rca_core internals are never exposed to the caller.

    Pipeline:
      1. Load pre-waveform structural violations (transport + datapath) from context_dir.
      2. Load waveform and driver table.
      3. Run protocol RCA via rca_core (stdout captured for appendix).
      4. Causation-binding root cause resolution (resolver).
      5. Emit exactly one causal conclusion.
      6. Write structured appendix proof (mirrors rca_7 format).
    """
    # ── 1. Pre-waveform structural violations ───────────────────────────────
    # Transport violations (WSTRB/WDATA misalignment) have highest priority.
    transport_violations = _load_transport_violations_from_dir(context_dir)
    datapath_violations  = _load_datapath_violations_from_dir(context_dir)
    semantic_violations  = _load_semantic_violations_from_dir(context_dir)
    ir_records           = _load_ir_from_dir(context_dir)
    # Combined list passed to resolver (transport first = higher priority).
    all_structural       = transport_violations + datapath_violations

    # Pre-define output paths so they are available inside the tee block.
    stamp      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir    = Path(context_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    proof_path = out_dir / f"rca8_{protocol}_{stamp}.proof.json"

    # ── 2. Load waveform and driver table ───────────────────────────────────
    wave, header, cls, _ = load_waveform_file(waveform_csv)

    # drivers_csv may be a directory — resolve to merged or all *_true_drivers.csv.
    # When multiple driver CSVs exist (multi-module analysis), merge them all so
    # every RTL signal is available for causal backtracking.
    if os.path.isdir(drivers_csv):
        _merged = _glob.glob(os.path.join(drivers_csv, "merged_true_drivers.csv"))
        if _merged:
            drivers_csv = _merged[0]
            logic = load_driver_table(drivers_csv)
        else:
            _drv_candidates = sorted(
                _glob.glob(os.path.join(drivers_csv, "*_true_drivers.csv"))
            )
            if len(_drv_candidates) == 1:
                drivers_csv = _drv_candidates[0]
                logic = load_driver_table(drivers_csv)
            elif len(_drv_candidates) > 1:
                # Merge all driver tables: for each signal, combine all driver lists
                logic = {}
                for _dc in _drv_candidates:
                    for _sig, _drvs in load_driver_table(_dc).items():
                        if _sig in logic:
                            # Extend, avoiding exact-duplicate rows
                            _existing = logic[_sig]
                            for _d in (_drvs or []):
                                if _d not in _existing:
                                    _existing.append(_d)
                        else:
                            logic[_sig] = list(_drvs or [])
                drivers_csv = _drv_candidates[0]  # keep path for logging
            else:
                logic = {}
    else:
        logic = load_driver_table(drivers_csv)

    # ── 2a. Load FSM state encodings from context_dir ───────────────────────
    # Needed to evaluate conditions like `state == WRITE_CHANNEL` during
    # causal backtracking.  Merge all *.fsm_encodings.json files found.
    _fsm_enc: Dict[str, int] = {}
    for _enc_f in _glob.glob(os.path.join(context_dir, "*.fsm_encodings.json")):
        try:
            with open(_enc_f, encoding="utf-8") as _ef:
                _enc_data = json.load(_ef)
            for _etype, _members in _enc_data.get("enums", {}).items():
                if isinstance(_members, dict):
                    _fsm_enc.update(_members)
            _lp = _enc_data.get("localparams", {})
            if isinstance(_lp, dict):
                _fsm_enc.update(_lp)
        except Exception:
            pass
    _fsm_regs: set = set(header) if header else set()

    # violations_path may be a file or a directory; normalise to file.
    if violations_path and os.path.isdir(violations_path):
        v_candidates = (
            _glob.glob(os.path.join(violations_path, "violations.json"))
            + _glob.glob(os.path.join(violations_path, "*violations*.json"))
        )
        violations_path = v_candidates[0] if v_candidates else None

    raw_violations = load_violations_file(violations_path) if violations_path else []

    # ── 3. Protocol RCA — stdout captured for appendix (mirrors rca_7 trace) ─
    tee = _Tee(sys.stdout)
    with contextlib.redirect_stdout(tee):

        _n_unique_defects   = 0
        _n_total_structural = len(all_structural)
        if all_structural:
            _n_unique_defects, _n_total_structural = _print_structural_summary(all_structural)

        view   = WaveformView(wave, header, cls)
        _prod  = (output_mode == "production")
        if not _prod:
            print(f"\n[RCA] Waveform loaded: {view.max_cycle} cycles, "
                  f"{len(view.rows)} rows", flush=True)
        engine = RCACoreEngine(
            waveform=view,
            logic_table=logic,
            max_graph_depth=8,
            temporal_window_cycles=20,
        )

        adapter = load_protocol(protocol, violations=raw_violations, max_window_cycles=None)
        if hasattr(adapter, "attach_logic_table"):
            try:
                adapter.attach_logic_table(logic)
            except Exception:
                pass

        if not _prod:
            print(f"[RCA] Detecting protocol transactions across {view.max_cycle} cycles...", flush=True)
        transactions = adapter.detect_transactions(view)
        if not _prod:
            print(f"[RCA] {len(transactions)} transaction(s) selected for obligation analysis", flush=True)

        # ── Transaction → datapath binding pass ──────────────────────────────
        binding_result = run_transaction_binding(
            transactions, ir_records, semantic_violations, view,
            output_path=out_dir / "causal_binding.json",
        )
        _b = binding_result["summary"]
        _print_causal_summary(
            n_protocol=len(raw_violations),
            n_unique_defects=_n_unique_defects,
            n_total_occurrences=_n_total_structural,
            n_causal=_b.get("causal", 0),
            n_latent=_b.get("latent", 0),
        )

        obligations  = adapter.define_obligations(transactions)
        if not _prod:
            print(f"[RCA] Evaluating {len(obligations)} causal obligation(s)...", flush=True)
        results      = engine.evaluate_contracts(obligations)
        mechanisms   = synthesize_mechanisms(results)
        if not _prod:
            print(f"[RCA] Synthesized {len(mechanisms)} failure mechanism(s)", flush=True)

        findings: List[Dict[str, Any]] = []
        for mech in mechanisms:
            record = adapter.classify_violation(mech)
            record["mechanism_id"]         = mech.mechanism_id
            record["contract_id"]          = mech.related_contract_ids[0] if mech.related_contract_ids else ""
            record["related_contract_ids"] = list(mech.related_contract_ids)
            record["occurrence_count"]     = int(mech.occurrence_count)
            record["status"]               = mech.status.value if hasattr(mech.status, "value") else str(mech.status)
            findings.append(record)
        if hasattr(adapter, "annotate_findings"):
            try:
                adapter.annotate_findings(findings)
            except Exception:
                pass

        # ── Fallback: promote axil4.py violations when contract engine finds 0 failures ─
        # The contract engine evaluates obligations from detect_transactions().
        # When all transactions satisfy their windows, findings stays empty even
        # if axil4.py caught a temporal violation (e.g. RVALID without AR handshake).
        # Promote raw_violations so the appendix shows them with backtracking.
        if not findings and raw_violations:
            if not _prod:
                print(
                    f"[RCA] Contract engine found 0 failures but {len(raw_violations)} "
                    f"raw violation(s) from axil4 — promoting to findings with backtracking",
                    flush=True,
                )
            findings = _promote_raw_violations(raw_violations, logic, view)

        # ── 4. Causation-binding root cause resolution ───────────────────────
        final_rca = resolve_root_cause(
            findings, all_structural, logic,
            transport_violations=transport_violations,
            semantic_violations=semantic_violations,
            causal_bindings=binding_result["causal_bindings"],
        )

        # ── 4.5. Enrich final_rca for terminal + appendix output ─────────────
        # a) When RULE 3 fires with a promoted axil4 finding, the dependency
        #    graph lives in the finding's evidence dict but causal_chain is None.
        #    Annotate with waveform values (rca-7 per-term style), then format.
        #    Use adapter.compute_t_eval() to anchor to t_accept+1 not violation cycle.
        if not final_rca.get("causal_chain"):
            _pev = final_rca.get("primary_evidence") or []
            if _pev and isinstance(_pev[0], dict):
                _dg = (_pev[0].get("evidence") or {}).get("dependency_graph") or {}
                if _dg and _dg.get("nodes"):
                    _pev0_rule_a  = str(_pev[0].get("rule_id") or "?")
                    _raw_cycle_a  = _pev[0].get("analysis_cycle")
                    _eval_cycle   = adapter.compute_t_eval(_pev0_rule_a, _raw_cycle_a, view)
                    _annotate_dg_with_waveform(_dg, view, _eval_cycle)
                    final_rca["causal_chain"] = _fmt_dependency_graph(
                        dg=_dg,
                        rule_id=_pev0_rule_a,
                        analysis_cycle=_eval_cycle or "?",
                    )
        # b) When root cause is PROTOCOL but latent datapath violations exist,
        #    surface them in secondary_effects → ADDITIONAL_PROVEN_FINDINGS.
        if final_rca.get("root_cause_type") == "PROTOCOL" and all_structural:
            _sec = list(final_rca.get("secondary_effects") or [])
            _sec.extend(all_structural)
            final_rca["secondary_effects"] = _sec

        # c) Secondary signal DG backtrack + d) full predicate traces
        #
        #    Uses adapter.get_rule_signal_groups() (RULE_SIGNAL_MAP) to get ALL
        #    primary and secondary signals for the violated rule — mirroring
        #    rca_7's step1_grouping primary/secondary classification.
        #
        #    Uses adapter.compute_t_eval() (RULE_ACCEPT_CHANNEL) to anchor the
        #    evaluation cycle to t_accept+1 (cycle after the protocol handshake)
        #    rather than the raw violation cycle — mirroring rca_7's step2_75.
        _full_traces: List[str] = []
        if final_rca.get("root_cause_type") == "PROTOCOL":
            _pev0_list = final_rca.get("primary_evidence") or []
            if _pev0_list and isinstance(_pev0_list[0], dict):
                _pev0        = _pev0_list[0]
                _pt_rule     = str(_pev0.get("rule_id") or "?")
                _t_violation = _pev0.get("analysis_cycle")

                # Proper t_eval anchored to t_accept+1 (rca_7 step2_75 behaviour)
                _t_eval = adapter.compute_t_eval(_pt_rule, _t_violation, view)
                if _t_eval is not None and _t_eval != _t_violation:
                    if not _prod:
                        print(
                            f"[RCA] {_pt_rule}: t_eval corrected "
                            f"{_t_violation} → {_t_eval} (anchored to t_accept+1)",
                            flush=True,
                        )

                # Signal grouping: primary (violated signal) + secondary (deps)
                _sig_groups   = adapter.get_rule_signal_groups(_pt_rule)
                _primary_list = list(_sig_groups.get("primary", []))
                _second_list  = [s for s in _sig_groups.get("secondary", [])
                                 if s not in _primary_list]
                _all_proto    = _primary_list + _second_list

                # ── c) Dependency graph backtrack for ALL secondary signals ──
                _chain_so_far = final_rca.get("causal_chain") or ""
                for _proto in _second_list:
                    _actual = next(
                        (s for s in view.signals if s.upper() == _proto.upper()), None
                    )
                    if not _actual or not isinstance(logic, dict) or not logic:
                        continue
                    # Only backtrack signals that have RTL drivers in the logic table
                    if not any(
                        k.lower() == _actual.lower() or _actual.lower() in k.lower()
                        for k in logic
                    ):
                        continue
                    try:
                        _sec_dg = build_dependency_graph(_actual, logic, max_depth=6)
                        if _sec_dg and _sec_dg.get("nodes"):
                            _annotate_dg_with_waveform(_sec_dg, view, _t_eval)
                            _sec_chain = _fmt_dependency_graph(
                                dg=_sec_dg,
                                rule_id=f"{_pt_rule} / {_proto} [secondary]",
                                analysis_cycle=_t_eval or "?",
                            )
                            _chain_so_far += (
                                f"\n\n-- SECONDARY SIGNAL: {_proto} --\n" + _sec_chain
                            )
                    except Exception:
                        pass
                if _chain_so_far != (final_rca.get("causal_chain") or ""):
                    final_rca["causal_chain"] = _chain_so_far

                # ── d) Full predicate trace for ALL primary + secondary signals ──
                #    Runs evaluate_all_drivers / detect_overwrite / causal_chain
                #    from predicate_backtrack.py — mirroring rca_7's STEP 3 output.
                for _proto in _all_proto:
                    _actual = next(
                        (s for s in view.signals if s.upper() == _proto.upper()), None
                    )
                    if not _actual or _t_eval is None or not isinstance(logic, dict) or not logic:
                        continue
                    _role = "primary" if _proto in _primary_list else "secondary"
                    try:
                        _ft = _predicate_full_trace(
                            _actual, _t_eval, logic, view,
                            rule_id=f"{_pt_rule} / {_proto} [{_role}]",
                        )
                        _full_traces.append(_ft)
                    except Exception:
                        pass

                # ── d2) MODE-C: stability mutation (run FIRST, independent of predicate) ─
                # For stability rules (RULE_8 / RULE_5 / RULE_6 …) the primary signal
                # (e.g. RREADY) is master-controlled and absent from the logic table, so
                # _compute_predicate_analysis returns None.  Run MODE-C unconditionally.
                _pred_a = None
                if _pt_rule in _STABILITY_RULES and _t_violation is not None:
                    try:
                        _mc_pred_a, _mc_mode = _detect_stability_mutation(
                            _pt_rule, logic, view, _t_violation, _second_list
                        )
                        if _mc_pred_a and _mc_mode:
                            _pred_a = _mc_pred_a
                            _pred_a["mode_analysis"] = _mc_mode
                            if _t_eval is not None:
                                _pred_a["t_eval"] = _t_eval
                    except Exception:
                        pass

                if _pred_a is None:
                    # Predicate dependency analysis: which required signals absent?
                    _pred_a = _compute_predicate_analysis(
                        _pt_rule, _primary_list, _second_list, logic
                    )
                if _pred_a:
                    # Enrich with actual waveform values for every required signal
                    # at t_eval — confirms whether each dep was hi/lo when the
                    # violation occurred (primary + all secondary signals).
                    if _t_eval is not None:
                        _sec_wave: dict = {}
                        _all_req = (
                            (_pred_a.get("missing_signals") or [])
                            + (_pred_a.get("found_signals") or [])
                        )
                        for _wsig in _all_req:
                            _wa = next(
                                (s for s in view.signals if s.upper() == _wsig.upper()),
                                None,
                            )
                            if _wa:
                                try:
                                    _sec_wave[_wsig] = view.signal_value(_wa, _t_eval)
                                except Exception:
                                    pass
                        # Also capture primary signal value at t_eval.
                        # The pred_a signal may carry a prefixed name (S_BVALID)
                        # from the logic table; fall back to prefix-stripped lookup
                        # so we can find it in the waveform (which uses BVALID).
                        _pa_sig_name = _pred_a.get("signal") or ""
                        _pa_actual = next(
                            (s for s in view.signals if s.upper() == _pa_sig_name.upper()),
                            None,
                        )
                        if not _pa_actual:
                            # Try stripping AXI module prefixes (S_, M_, u_, …)
                            for _pfx in ("S_", "M_", "u_", "s_", "m_"):
                                if _pa_sig_name.upper().startswith(_pfx.upper()):
                                    _stripped = _pa_sig_name[len(_pfx):]
                                    _pa_actual = next(
                                        (s for s in view.signals
                                         if s.upper() == _stripped.upper()),
                                        None,
                                    )
                                    if _pa_actual:
                                        break
                        if _pa_actual:
                            try:
                                _pred_a["primary_waveform_value"] = view.signal_value(
                                    _pa_actual, _t_eval
                                )
                            except Exception:
                                pass
                        _pred_a["secondary_waveform"] = _sec_wave
                        if "t_eval" not in _pred_a:
                            _pred_a["t_eval"] = _t_eval
                        # Capture values of signals that appear directly in the
                        # driver predicate string (e.g. rst_n, w_state) so the
                        # report can show "rst_n = 1, w_state = W_IDLE" at t_eval.
                        _dp_str = _pred_a.get("driver_predicate") or ""
                        _dp_terms: dict = {}
                        if _dp_str:
                            import re as _re2
                            # Tokens that appear as the RHS of a comparison (e.g. RESP in
                            # read_state == RESP) are FSM state constants — exclude them.
                            _cmp_consts = set(
                                _re2.findall(r'[!=]=\s*(\w+)', _dp_str)
                            )
                            for _tok in dict.fromkeys(
                                t for t in _WORD_BOUNDARY.findall(_dp_str)
                                if t.lower() not in _BT_SV_KW
                                and not t.isdigit()
                                and t not in _cmp_consts
                            ):
                                _wa2 = next(
                                    (s for s in view.signals if s.upper() == _tok.upper()),
                                    None,
                                )
                                if _wa2:
                                    try:
                                        _dp_terms[_tok] = view.signal_value(_wa2, _t_eval)
                                    except Exception:
                                        pass
                        _pred_a["predicate_term_values"] = _dp_terms

                        # ── d3) MODE-A / MODE-B / MODE-D on non-stability rules ──
                        # (stability rules already handled above via _detect_stability_mutation)
                        if _pa_actual and _pt_rule not in _STABILITY_RULES:
                            try:
                                # ── MODE-A / MODE-B / MODE-D ─────────────────────────
                                _drv_evals = _eval_all_drivers(
                                    _pa_actual, logic, view, _t_eval
                                )
                                _pa_val    = _pred_a.get("primary_waveform_value")
                                _ow        = _detect_overwrite(_pa_val, _drv_evals)
                                _mode_info: dict = {}
                                if _ow:
                                    if _ow["mode"] == "MODE-A_BLOCKED_ASSERTER":
                                        _ad = _ow["asserting_driver"]
                                        _wd = _ow["winning_driver"]
                                        _mode_info = {
                                            "mode":    "MODE-B",
                                            "subtype": "BLOCKED_ASSERTER",
                                            "asserting_driver_cond": (_ad.get("condition") or _ad.get("cond") or ""),
                                            "asserting_driver_idx":  _ad.get("driver_idx"),
                                            "winning_driver_cond":   (_wd.get("condition") or _wd.get("cond") or ""),
                                            "winning_driver_idx":    _wd.get("driver_idx"),
                                            "winning_driver_rhs":    (_wd.get("rhs") or "0"),
                                            "winning_true_terms":    (_wd.get("true_terms") or []),
                                            "winning_term_values":   (_wd.get("term_values") or {}),
                                        }
                                    elif _ow["mode"] == "MODE-A_UNEXPECTED_ASSERTION":
                                        _wd = _ow["winning_driver"]
                                        _mode_info = {
                                            "mode":    "MODE-A",
                                            "subtype": "UNEXPECTED_ASSERTION",
                                            "active_driver_cond": (_wd.get("condition") or _wd.get("cond") or ""),
                                            "active_driver_idx":  _wd.get("driver_idx"),
                                            "active_driver_rhs":  (_wd.get("rhs") or "1"),
                                            "active_true_terms":  (_wd.get("true_terms") or []),
                                            "active_term_values": (_wd.get("term_values") or {}),
                                        }
                                else:
                                    _blocked = [
                                        d for d in _drv_evals
                                        if d.get("is_asserting")
                                        and d.get("condition_active") is False
                                    ]
                                    if _blocked:
                                        _ab = _blocked[0]
                                        _mode_info = {
                                            "mode":    "MODE-D",
                                            "subtype": "UNSATISFIED_ENABLE",
                                            "asserting_driver_cond": (_ab.get("condition") or _ab.get("cond") or ""),
                                            "asserting_driver_idx":  _ab.get("driver_idx"),
                                            "blocking_term":         (_ab.get("first_false_term") or ""),
                                            "true_terms":            (_ab.get("true_terms") or []),
                                            "false_terms":           (_ab.get("false_terms") or []),
                                            "all_term_values":       (_ab.get("term_values") or {}),
                                        }
                                if _mode_info:
                                    _bt_raw: list = []
                                    _sub = _mode_info.get("subtype", "")
                                    if _sub == "BLOCKED_ASSERTER":
                                        for _t in (_mode_info.get("winning_true_terms") or []):
                                            _bt_raw.extend(_WORD_BOUNDARY.findall(_t))
                                    elif _sub == "UNEXPECTED_ASSERTION":
                                        for _t in (_mode_info.get("active_true_terms") or []):
                                            _bt_raw.extend(_WORD_BOUNDARY.findall(_t))
                                    elif _sub == "UNSATISFIED_ENABLE":
                                        for _t in ((_mode_info.get("false_terms") or [])
                                                   + [_mode_info.get("blocking_term") or ""]):
                                            _bt_raw.extend(_WORD_BOUNDARY.findall(_t))
                                    _bt_sigs = list(dict.fromkeys(_bt_raw))
                                    _mode_info["term_backtrack"] = _backtrack_signal_set(
                                        _bt_sigs, logic, view, _t_eval
                                    )
                                    _mode_info["secondary_backtrack"] = _backtrack_signal_set(
                                        _second_list, logic, view, _t_eval
                                    )

                                    # ── Deep condition chain backtracking ──────────────
                                    # Recursively follow WHY the key term holds its value,
                                    # mirroring rca_7's _backtrack_condition_chain logic.
                                    try:
                                        _chain_start: str = ""
                                        if _sub == "UNSATISFIED_ENABLE":
                                            # MODE-D: follow the blocking/false term to find
                                            # what's keeping the asserting driver from firing.
                                            _chain_start = (_mode_info.get("blocking_term") or "")
                                            if not _chain_start:
                                                _fterms = _mode_info.get("false_terms") or []
                                                _chain_start = _fterms[0] if _fterms else ""
                                        elif _sub == "UNEXPECTED_ASSERTION":
                                            # MODE-A: follow the most informative true term
                                            # to find why the signal is unexpectedly asserted.
                                            _aterms = _mode_info.get("active_true_terms") or []
                                            # Prefer terms referencing FSM state signals
                                            for _at in _aterms:
                                                _at_toks = _WORD_BOUNDARY.findall(_at)
                                                if any("state" in t.lower() for t in _at_toks):
                                                    _chain_start = _at
                                                    break
                                            if not _chain_start and _aterms:
                                                _chain_start = _aterms[0]
                                        elif _sub == "BLOCKED_ASSERTER":
                                            # MODE-B: follow the winning driver's true terms
                                            _wterms = _mode_info.get("winning_true_terms") or []
                                            for _wt in _wterms:
                                                _wt_toks = _WORD_BOUNDARY.findall(_wt)
                                                if any("state" in t.lower() for t in _wt_toks):
                                                    _chain_start = _wt
                                                    break
                                            if not _chain_start and _wterms:
                                                _chain_start = _wterms[0]

                                        if _chain_start and _t_eval is not None:
                                            _mode_info["condition_chain"] = (
                                                _backtrack_condition_chain(
                                                    _chain_start, logic, view, _t_eval,
                                                    fsm_enc=_fsm_enc, fsm_regs=_fsm_regs,
                                                )
                                            )
                                    except Exception:
                                        pass

                                    _pred_a["mode_analysis"] = _mode_info
                            except Exception:
                                pass
                    # ── Fallback condition chain when mode detection couldn't resolve ──
                    # MODE-A/D detection fails when enum comparisons can't be evaluated
                    # (e.g. w_state == W_IDLE where W_IDLE is a localparam).
                    # In this case, directly backtrack the most informative term
                    # from the driver_predicate string itself.
                    #
                    # For write-response-missing rules (RULE_13/RULE_6): find the
                    # FIRST incomplete AW handshake (BVALID never issued after that
                    # handshake), scan forward from it for the FSM abort cycle
                    # (e.g. flush→W_IDLE), then backtrack at that abort cycle so
                    # the chain reveals the actual root-cause driver.
                    _bt_eval = _t_eval  # default: use predicate evaluation cycle
                    _WRITE_RESP_MISSING_RULES = frozenset({"RULE_13", "RULE_6"})
                    if _pt_rule in _WRITE_RESP_MISSING_RULES and _t_eval is not None:
                        try:
                            # ── Step 1: anchor to first incomplete AW handshake ──
                            _first_incomplete_cyc = _find_first_incomplete_aw_cycle(
                                view, int(_t_violation or _t_eval), adapter,
                            )
                            _scan_start = (
                                _first_incomplete_cyc
                                if _first_incomplete_cyc is not None
                                else _t_eval
                            )
                            if not _prod and _first_incomplete_cyc is not None:
                                print(
                                    f"[RCA] {_pt_rule}: first incomplete AW handshake "
                                    f"at cycle {_first_incomplete_cyc} "
                                    f"(was t_eval={_t_eval})",
                                    flush=True,
                                )
                            # ── Step 2: find the FSM signal from the predicate ──
                            _dp_str2 = _pred_a.get("driver_predicate") or "" if _pred_a else ""
                            _fsm_cand = None
                            for _tok2 in _WORD_BOUNDARY.findall(_dp_str2):
                                if "state" in _tok2.lower():
                                    _fsm_cand = next(
                                        (s for s in view.signals if s.upper() == _tok2.upper()),
                                        None,
                                    )
                                    if _fsm_cand:
                                        break
                            if _fsm_cand:
                                # DONE states: the two highest encoded states (W_DONE, W_RESP)
                                # are "completion" states — we don't treat them as abort.
                                _done_enc = set()
                                if _fsm_enc:
                                    _enc_vals = sorted(set(_fsm_enc.values()))
                                    if len(_enc_vals) >= 2:
                                        _done_enc = {_enc_vals[-1], _enc_vals[-2]}
                                # ── Step 3: scan forward from first incomplete ──
                                # handshake to find the FSM abort (active→idle).
                                _abort_cyc = _find_fsm_abort_cycle(
                                    view, _fsm_cand, _scan_start,
                                    done_vals=_done_enc,
                                )
                                if _abort_cyc is not None:
                                    _bt_eval = _abort_cyc
                        except Exception:
                            pass

                    if not (_pred_a.get("mode_analysis") or {}).get("condition_chain"):
                        try:
                            _dp = _pred_a.get("driver_predicate") or ""
                            if _dp and _t_eval is not None:
                                # Split predicate into terms and pick FSM state ref
                                _dp_terms = [t.strip() for t in _dp.replace("&&", "\n")
                                             .replace("||", "\n").split("\n") if t.strip()]
                                _fallback_term: str = ""
                                for _dt in _dp_terms:
                                    _dt_toks = _WORD_BOUNDARY.findall(_dt)
                                    if any("state" in t.lower() for t in _dt_toks):
                                        _fallback_term = _dt
                                        break
                                if not _fallback_term and _dp_terms:
                                    # Pick first non-trivial term (not just rst_n)
                                    for _dt in _dp_terms:
                                        _dt_toks = _WORD_BOUNDARY.findall(_dt)
                                        non_reset = [t for t in _dt_toks
                                                     if t.lower() not in ("rst", "rst_n", "reset", "reset_n")]
                                        if non_reset:
                                            _fallback_term = _dt
                                            break
                                if _fallback_term:
                                    _fb_chain = _backtrack_condition_chain(
                                        _fallback_term, logic, view, _bt_eval,
                                        fsm_enc=_fsm_enc, fsm_regs=_fsm_regs,
                                    )
                                    if _fb_chain:
                                        if not _pred_a.get("mode_analysis"):
                                            _pred_a["mode_analysis"] = {}
                                        _pred_a["mode_analysis"]["condition_chain"] = _fb_chain
                                        _pred_a["mode_analysis"]["chain_source"] = "predicate_fallback"
                                        _pred_a["mode_analysis"]["chain_start_term"] = _fallback_term
                        except Exception:
                            pass
                    final_rca["predicate_analysis"] = _pred_a

        if _full_traces:
            final_rca["full_predicate_trace"] = "\n\n".join(_full_traces)

        # ── 5. Emit exactly one causal conclusion ────────────────────────────
        if debug:
            print_final_rca(final_rca)

    raw_trace = tee.getvalue()

    # ── 6. Write structured appendix proof ──────────────────────────────────
    # (stamp / out_dir / proof_path were defined before the tee block)

    payload = {
        "protocol":             protocol,
        "waveform_max_cycle":   view.max_cycle,
        "transactions":         transactions,
        "findings":             findings,
        "datapath_violations":  datapath_violations,
        "transport_violations": transport_violations,
        "binding_result":       binding_result,
        "final_rca":            final_rca,
    }

    artifacts = _write_proof_artifacts(payload, proof_path, raw_trace, debug=debug)

    # Console diagnosis is printed by cli.py after all engines run (with FSM data).
    # Standalone callers get it via the main() function below.

    if _PROD_VERBOSE:
        print(f"\n[APPENDIX] {artifacts['appendix']}")

    return {**payload, "artifacts": artifacts}


def _load_datapath_violations(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Load or compute datapath violations from IR/pre-computed JSON."""
    # 1. Pre-computed violations file takes precedence.
    if args.datapath_violations:
        p = _resolve_path(args.datapath_violations)
        if p and p.exists():
            with open(str(p), encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []

    # 2. If an IR JSON is supplied, run the analysis live.
    if args.ir_json:
        p = _resolve_path(args.ir_json)
        if p and p.exists():
            with open(str(p), encoding="utf-8") as f:
                ir_records = json.load(f)
            if isinstance(ir_records, list):
                return detect_memory_write_semantic_mismatch(ir_records)
    return []


# =============================================================================
# TRANSACTION PROVENANCE LAYER
# Connects structural datapath violations to the specific failing protocol
# event, replacing the old binary "global override" approach.
# =============================================================================

# ── Step 1: Transaction context snapshot ──────────────────────────────────────

class TransactionContext:
    """Snapshot of AXI channel state at the cycle a protocol rule fires."""

    __slots__ = ("cycle", "channel", "addr", "data_signal", "interface")

    def __init__(
        self,
        cycle: int,
        channel: str,
        addr: Optional[int],
        data_signal: Optional[str],
        interface: str,
    ) -> None:
        self.cycle       = cycle
        self.channel     = channel
        self.addr        = addr
        self.data_signal = data_signal
        self.interface   = interface

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle":       self.cycle,
            "channel":     self.channel,
            "addr":        self.addr,
            "data_signal": self.data_signal,
            "interface":   self.interface,
        }


# ── Step 2a: Waveform signal resolution helpers ───────────────────────────────

def _find_signal(view: WaveformView, *suffixes: str) -> Optional[str]:
    """Return first waveform column whose lowercased name ends with any suffix."""
    for sig in view.signals:
        sl = sig.lower()
        for sfx in suffixes:
            if sl.endswith(sfx.lower()):
                return sig
    return None


def _infer_interface(signal: Optional[str]) -> str:
    """Heuristically extract AXI interface prefix (e.g. 's_axil', 'm_axi')."""
    if not signal:
        return "unknown"
    s = signal.lower()
    for prefix in ("s_axil_", "m_axil_", "s_axi_", "m_axi_", "axil_", "axi_"):
        if prefix in s:
            return prefix.rstrip("_")
    return s.rsplit("_", 1)[0] if "_" in s else s


# ── Step 2b: Handshake cache — O(N_cycles), constant memory per interface ─────

class HandshakeCache:
    """
    Tracks AW/AR handshakes in a single O(N_cycles) pass over the waveform.

    State maintained:
        last_write[interface] = {addr, cycle}
        last_read[interface]  = {addr, cycle}
        write_log             = [{addr, cycle, interface}]   (ordered)
    """

    def __init__(self) -> None:
        self.last_write: Dict[str, Dict[str, Any]] = {}
        self.last_read:  Dict[str, Dict[str, Any]] = {}
        self.write_log:  List[Dict[str, Any]]      = []

    def build_from_view(self, view: WaveformView) -> None:
        """Single forward pass — piggybacks on the already-loaded WaveformView."""
        aw_valid = _find_signal(view, "_awvalid", "awvalid")
        aw_ready = _find_signal(view, "_awready", "awready")
        aw_addr  = _find_signal(view, "_awaddr",  "awaddr")
        ar_valid = _find_signal(view, "_arvalid", "arvalid")
        ar_ready = _find_signal(view, "_arready", "arready")
        ar_addr  = _find_signal(view, "_araddr",  "araddr")
        iface    = _infer_interface(aw_addr or ar_addr)

        for cycle in range(view.max_cycle + 1):
            # AW handshake: AWVALID & AWREADY high simultaneously
            if aw_valid and aw_ready:
                av = view.signal_value(aw_valid, cycle)
                ar = view.signal_value(aw_ready, cycle)
                if av == 1 and ar == 1:
                    addr = view.signal_value(aw_addr, cycle) if aw_addr else None
                    self.last_write[iface] = {"addr": addr, "cycle": cycle}
                    self.write_log.append({"addr": addr, "cycle": cycle, "interface": iface})

            # AR handshake: ARVALID & ARREADY high simultaneously
            if ar_valid and ar_ready:
                av  = view.signal_value(ar_valid, cycle)
                arr = view.signal_value(ar_ready, cycle)
                if av == 1 and arr == 1:
                    addr = view.signal_value(ar_addr, cycle) if ar_addr else None
                    self.last_read[iface] = {"addr": addr, "cycle": cycle}

    def last_write_before(
        self,
        addr: Optional[int],
        cycle: int,
        interface: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Find the most recent write to addr that occurred before cycle."""
        candidates = [
            w for w in self.write_log
            if w["cycle"] < cycle
            and (addr is None or w["addr"] == addr)
            and (interface is None or w["interface"] == interface)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda w: w["cycle"])


# ── Step 2c: Memory map from IR (heuristic) ───────────────────────────────────

_WDATA_PATS   = ("wdata", "_wdata", "writedata")
_ADDR_PATS    = ("awaddr", "_awaddr", "araddr", "_araddr", "addr")
_WEN_PATS     = ("wr_en", "we", "write_en", "mem_wr_en", "wen")
_IDENT_RE_MEM = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _first_token_matching(text: str, patterns: Tuple[str, ...]) -> Optional[str]:
    for tok in _IDENT_RE_MEM.findall(text):
        if any(p in tok.lower() for p in patterns):
            return tok
    return None


def build_memory_map_from_ir(
    ir_records: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Heuristically infer {memory_name -> {addr_signal, write_data, read_data,
    write_enable}} from IR records.

    Rules:
      - LHS is an array write (contains '[') -> memory name is the prefix
      - RHS contains an AXI WDATA token      -> associate write channel
      - Guard contains a write-enable token  -> associate enable signal
    """
    memory_map: Dict[str, Dict[str, Any]] = {}

    for rec in ir_records:
        sig = (rec.get("signal") or "").strip()
        if not sig or "[" not in sig:
            continue
        mem_name = sig[:sig.index("[")].strip()
        if not mem_name:
            continue

        rhs_text   = rec.get("rhs",   "") or ""
        guard_text = rec.get("guard", "") or ""
        rhs_l      = rhs_text.lower()
        guard_l    = guard_text.lower()

        entry = memory_map.setdefault(mem_name, {
            "addr_signal":  None,
            "write_data":   None,
            "read_data":    None,
            "write_enable": None,
        })

        if entry["write_data"] is None and any(p in rhs_l for p in _WDATA_PATS):
            entry["write_data"] = _first_token_matching(rhs_text, _WDATA_PATS)

        if entry["write_enable"] is None and any(p in guard_l for p in _WEN_PATS):
            entry["write_enable"] = _first_token_matching(guard_text, _WEN_PATS)

        if entry["addr_signal"] is None and any(p in guard_l for p in _ADDR_PATS):
            entry["addr_signal"] = _first_token_matching(guard_text, _ADDR_PATS)

    return memory_map


# ── Step 3: Resolve memory by address ────────────────────────────────────────

def resolve_memory_by_address(
    addr: Optional[int],
    memory_map: Dict[str, Dict[str, Any]],
) -> Optional[str]:
    """
    Return which memory was accessed at addr.
    Without a full address-range table, prefer the single memory with a write
    data association (most likely the AXI-mapped SRAM).
    """
    if addr is None or not memory_map:
        return None
    if len(memory_map) == 1:
        return next(iter(memory_map))
    for mem, info in memory_map.items():
        if info.get("write_data") is not None:
            return mem
    return next(iter(memory_map))


# ── Steps 1+4: Build transaction context from violation finding ───────────────

def _read_addr_at_cycle(
    view: WaveformView, cycle: int
) -> Tuple[Optional[int], str]:
    """Snapshot AWADDR or ARADDR at cycle. Returns (value, channel_hint)."""
    aw_sig = _find_signal(view, "_awaddr", "awaddr")
    ar_sig = _find_signal(view, "_araddr", "araddr")
    aw_val = view.signal_value(aw_sig, cycle) if aw_sig else None
    ar_val = view.signal_value(ar_sig, cycle) if ar_sig else None
    if aw_val is not None:
        return aw_val, "AW"
    if ar_val is not None:
        return ar_val, "AR"
    return None, "unknown"


def build_transaction_context(
    finding: Dict[str, Any],
    view: WaveformView,
) -> Optional[TransactionContext]:
    """
    Snapshot AXI channel state at the protocol violation cycle.
    Returns None if no cycle information is available.
    """
    raw_cycle = finding.get("analysis_cycle")
    if raw_cycle is None:
        return None
    cycle = int(raw_cycle)

    addr, channel = _read_addr_at_cycle(view, cycle)

    rule_id   = str(finding.get("rule_id", ""))
    detail    = str(finding.get("detail", ""))
    if "RDATA" in detail or rule_id in ("RULE_10", "RULE_12"):
        data_sig = _find_signal(view, "_rdata", "rdata")
    else:
        data_sig = _find_signal(view, "_wdata", "wdata")

    iface = _infer_interface(_find_signal(view, "_awaddr", "awaddr"))

    return TransactionContext(
        cycle=cycle,
        channel=channel,
        addr=addr,
        data_signal=data_sig,
        interface=iface,
    )


# ── Steps 4–6: Causal vs structural classification ───────────────────────────

def _classify_provenance(
    datapath_violations: List[Dict[str, Any]],
    txn_ctx: Optional[TransactionContext],
    hcache: HandshakeCache,
    memory_map: Dict[str, Dict[str, Any]],
) -> str:
    """
    Classify into one of four levels:
      DATAPATH_CAUSAL      -- proven root cause
      DATAPATH_STRUCTURAL  -- exists but not exercised on this failure path
      PROTOCOL_PRIMARY     -- no datapath involvement
      PROTOCOL_SECONDARY   -- protocol symptom of a globally detected datapath bug
    """
    if not datapath_violations:
        return "PROTOCOL_PRIMARY"

    # Step 3: resolve memory via transaction address
    affected_memory: Optional[str] = None
    if txn_ctx is not None:
        affected_memory = resolve_memory_by_address(txn_ctx.addr, memory_map)

    # Step 4: find datapath violations for this specific memory
    if affected_memory is not None:
        mem_dvs = [dv for dv in datapath_violations if dv.get("memory") == affected_memory]
    else:
        mem_dvs = []

    if not mem_dvs:
        # Datapath bugs exist but are not linked to this transaction's memory
        return "PROTOCOL_SECONDARY"

    # Step 5: locate last write to this address before the failure cycle
    if txn_ctx is not None:
        last_write = hcache.last_write_before(txn_ctx.addr, txn_ctx.cycle)
    else:
        last_write = None

    if last_write is None:
        # Memory has violations but no write was observed before this failure
        return "DATAPATH_STRUCTURAL"

    # Step 6: at least one always_block in the relevant violations was active
    # at last_write_cycle (conservative: any write through that path counts)
    for dv in mem_dvs:
        if dv.get("always_block_id") is not None:
            return "DATAPATH_CAUSAL"

    return "DATAPATH_STRUCTURAL"


def apply_provenance_classification(
    findings: List[Dict[str, Any]],
    datapath_violations: List[Dict[str, Any]],
    view: WaveformView,
    hcache: HandshakeCache,
    memory_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Step 7: Replace binary datapath override with four-level causal classification.

    Enriches each finding in-place with:
      datapath_classification  -- one of the four levels
      transaction_context      -- dict snapshot (or None)
      affected_memory          -- memory name (or None)
      last_write_event         -- {addr, cycle, interface} (or None)
    """
    for f in findings:
        txn_ctx        = build_transaction_context(f, view)
        classification = _classify_provenance(
            datapath_violations, txn_ctx, hcache, memory_map
        )
        f["datapath_classification"] = classification
        f["transaction_context"]     = txn_ctx.to_dict() if txn_ctx else None

        mem     = resolve_memory_by_address(txn_ctx.addr if txn_ctx else None, memory_map)
        last_wr = hcache.last_write_before(
            txn_ctx.addr if txn_ctx else None,
            txn_ctx.cycle if txn_ctx else 0,
        ) if mem else None
        f["affected_memory"]  = mem
        f["last_write_event"] = last_wr

        # Adjust 'classification' field consumed by downstream serialiser
        orig = f.get("classification", "")
        if classification in ("DATAPATH_CAUSAL", "DATAPATH_STRUCTURAL"):
            f["original_classification"] = orig
            f["classification"] = classification
        elif classification == "PROTOCOL_SECONDARY":
            f["original_classification"] = orig
            f["classification"] = "PROTOCOL_SECONDARY"
            f["secondary_reason"] = (
                "Datapath violation detected globally but not causally linked "
                "to this transaction's memory access."
            )
        # PROTOCOL_PRIMARY: leave classification unchanged

    return findings


# =============================================================================
# Protocol mode (uses rca_resolver for final diagnosis)
# =============================================================================

def _run_protocol_mode(args: argparse.Namespace) -> Dict[str, Any]:
    # ── STEP 0: Structural datapath analysis (runs BEFORE waveform/protocol) ──
    datapath_violations = _load_datapath_violations(args)
    semantic_violations = _load_semantic_violations_from_dir(
        getattr(args, "context_dir", None) or os.path.dirname(args.waveform_csv) or "."
    )
    if datapath_violations:
        _print_header("PRE-WAVEFORM STRUCTURAL ANALYSIS")
        print(f"Datapath violations found: {len(datapath_violations)}")
        for dv in datapath_violations:
            print(f"  [{dv.get('class', 'UNKNOWN')}] memory={dv.get('memory')}  "
                  f"block={dv.get('always_block_id')}")
            print(f"    expected: {dv.get('expected')}")
            print(f"    actual:   {dv.get('actual')}")

    wave, header, cls, clock = load_waveform_file(args.waveform_csv)
    logic = load_driver_table(args.true_drivers_csv)
    violations = load_violations_file(args.violations) if args.violations else []
    view = WaveformView(wave, header, cls, clock_signal=args.clock or clock)
    engine = RCACoreEngine(
        waveform=view,
        logic_table=logic,
        max_graph_depth=args.max_graph_depth,
        temporal_window_cycles=args.temporal_window,
    )

    adapter = load_protocol(
        args.protocol,
        violations=violations,
        max_window_cycles=args.max_window_cycles,
    )
    if hasattr(adapter, "attach_logic_table"):
        try:
            adapter.attach_logic_table(logic)
        except Exception:
            pass
    transactions = adapter.detect_transactions(view)
    obligations = adapter.define_obligations(transactions)
    results = engine.evaluate_contracts(obligations)
    mechanisms = synthesize_mechanisms(results)

    findings: List[Dict[str, Any]] = []
    for mech in mechanisms:
        record = adapter.classify_violation(mech)
        record["mechanism_id"] = mech.mechanism_id
        record["contract_id"] = mech.related_contract_ids[0] if mech.related_contract_ids else ""
        record["related_contract_ids"] = list(mech.related_contract_ids)
        record["occurrence_count"] = int(mech.occurrence_count)
        record["status"] = mech.status.value if hasattr(mech.status, "value") else str(mech.status)
        findings.append(record)
    if hasattr(adapter, "annotate_findings"):
        try:
            adapter.annotate_findings(findings)
        except Exception:
            pass

    # ── STEP 8+: Causation-binding root cause resolution ─────────────────────
    final_rca = resolve_root_cause(
        findings, datapath_violations, logic,
        semantic_violations=semantic_violations,
    )

    # Enrich final_rca — same logic as run_waveeye_rca() step 4.5
    # a) Primary signal DG → causal_chain (t_eval anchored to t_accept+1)
    if not final_rca.get("causal_chain"):
        _pev = final_rca.get("primary_evidence") or []
        if _pev and isinstance(_pev[0], dict):
            _dg = (_pev[0].get("evidence") or {}).get("dependency_graph") or {}
            if _dg and _dg.get("nodes"):
                _pev0_rule_cli = str(_pev[0].get("rule_id") or "?")
                _raw_cycle_cli = _pev[0].get("analysis_cycle")
                _eval_cycle    = adapter.compute_t_eval(_pev0_rule_cli, _raw_cycle_cli, view)
                _annotate_dg_with_waveform(_dg, view, _eval_cycle)
                final_rca["causal_chain"] = _fmt_dependency_graph(
                    dg=_dg,
                    rule_id=_pev0_rule_cli,
                    analysis_cycle=_eval_cycle or "?",
                )
    if final_rca.get("root_cause_type") == "PROTOCOL" and datapath_violations:
        _sec = list(final_rca.get("secondary_effects") or [])
        _sec.extend(datapath_violations)
        final_rca["secondary_effects"] = _sec

    # b) Secondary signal DG backtrack + predicate traces for all grouped signals
    _cli_full_traces: List[str] = []
    if final_rca.get("root_cause_type") == "PROTOCOL":
        _cli_pev_list = final_rca.get("primary_evidence") or []
        if _cli_pev_list and isinstance(_cli_pev_list[0], dict):
            _cli_pev0     = _cli_pev_list[0]
            _cli_rule     = str(_cli_pev0.get("rule_id") or "?")
            _cli_t_viol   = _cli_pev0.get("analysis_cycle")
            _cli_t_eval   = adapter.compute_t_eval(_cli_rule, _cli_t_viol, view)
            _cli_groups   = adapter.get_rule_signal_groups(_cli_rule)
            _cli_primary  = list(_cli_groups.get("primary", []))
            _cli_secondary = [s for s in _cli_groups.get("secondary", [])
                              if s not in _cli_primary]
            _cli_all      = _cli_primary + _cli_secondary
            _cli_chain    = final_rca.get("causal_chain") or ""
            for _proto in _cli_secondary:
                _actual = next(
                    (s for s in view.signals if s.upper() == _proto.upper()), None
                )
                if not _actual or not isinstance(logic, dict) or not logic:
                    continue
                if not any(
                    k.lower() == _actual.lower() or _actual.lower() in k.lower()
                    for k in logic
                ):
                    continue
                try:
                    _sec_dg = build_dependency_graph(_actual, logic, max_depth=6)
                    if _sec_dg and _sec_dg.get("nodes"):
                        _annotate_dg_with_waveform(_sec_dg, view, _cli_t_eval)
                        _cli_chain += (
                            f"\n\n-- SECONDARY SIGNAL: {_proto} --\n"
                            + _fmt_dependency_graph(
                                dg=_sec_dg,
                                rule_id=f"{_cli_rule} / {_proto} [secondary]",
                                analysis_cycle=_cli_t_eval or "?",
                            )
                        )
                except Exception:
                    pass
            if _cli_chain != (final_rca.get("causal_chain") or ""):
                final_rca["causal_chain"] = _cli_chain
            for _proto in _cli_all:
                _actual = next(
                    (s for s in view.signals if s.upper() == _proto.upper()), None
                )
                if not _actual or _cli_t_eval is None or not isinstance(logic, dict) or not logic:
                    continue
                _role = "primary" if _proto in _cli_primary else "secondary"
                try:
                    _ft = _predicate_full_trace(
                        _actual, _cli_t_eval, logic, view,
                        rule_id=f"{_cli_rule} / {_proto} [{_role}]",
                    )
                    _cli_full_traces.append(_ft)
                except Exception:
                    pass

            # For stability rules (RULE_8 / RULE_5 / RULE_6 …) the primary signal
            # (e.g. RREADY) is controlled by the master and is never in the logic
            # table.  Run MODE-C detection FIRST, independently of predicate analysis.
            _cli_pred_a = None
            if _cli_rule in _STABILITY_RULES and _cli_t_viol is not None:
                try:
                    _mc_pred_a, _mc_mode = _detect_stability_mutation(
                        _cli_rule, logic, view, _cli_t_viol, _cli_secondary
                    )
                    if _mc_pred_a and _mc_mode:
                        _cli_pred_a = _mc_pred_a
                        _cli_pred_a["mode_analysis"] = _mc_mode
                        if _cli_t_eval is not None:
                            _cli_pred_a["t_eval"] = _cli_t_eval
                except Exception:
                    pass

            if _cli_pred_a is None:
                # Predicate dependency analysis: which required signals absent?
                _cli_pred_a = _compute_predicate_analysis(
                    _cli_rule, _cli_primary, _cli_secondary, logic
                )
            if _cli_pred_a:
                if _cli_t_eval is not None:
                    _cli_sec_wave: dict = {}
                    _cli_all_req = (
                        (_cli_pred_a.get("missing_signals") or [])
                        + (_cli_pred_a.get("found_signals") or [])
                    )
                    for _wsig in _cli_all_req:
                        _wa = next(
                            (s for s in view.signals if s.upper() == _wsig.upper()),
                            None,
                        )
                        if _wa:
                            try:
                                _cli_sec_wave[_wsig] = view.signal_value(_wa, _cli_t_eval)
                            except Exception:
                                pass
                    _cli_pa_name = _cli_pred_a.get("signal") or ""
                    _cli_pa_actual = next(
                        (s for s in view.signals if s.upper() == _cli_pa_name.upper()),
                        None,
                    )
                    if _cli_pa_actual:
                        try:
                            _cli_pred_a["primary_waveform_value"] = view.signal_value(
                                _cli_pa_actual, _cli_t_eval
                            )
                        except Exception:
                            pass
                    _cli_pred_a["secondary_waveform"] = _cli_sec_wave
                    if "t_eval" not in _cli_pred_a:
                        _cli_pred_a["t_eval"] = _cli_t_eval

                    # MODE-A/B/D detection (CLI path) — only for non-stability rules
                    # (stability rules already handled above via _detect_stability_mutation)
                    if _cli_pa_actual and _cli_rule not in _STABILITY_RULES:
                        try:
                            # ── MODE-A / MODE-B / MODE-D (CLI path) ──────────────
                            _cli_drv_evals = _eval_all_drivers(
                                _cli_pa_actual, logic, view, _cli_t_eval
                            )
                            _cli_pa_val = _cli_pred_a.get("primary_waveform_value")
                            _cli_ow     = _detect_overwrite(_cli_pa_val, _cli_drv_evals)
                            _cli_mode:  dict = {}
                            if _cli_ow:
                                if _cli_ow["mode"] == "MODE-A_BLOCKED_ASSERTER":
                                    # Signal asserted but overwrite driver won → MODE-B
                                    _ad = _cli_ow["asserting_driver"]
                                    _wd = _cli_ow["winning_driver"]
                                    _cli_mode = {
                                        "mode":    "MODE-B",
                                        "subtype": "BLOCKED_ASSERTER",
                                        "asserting_driver_cond": (_ad.get("condition") or _ad.get("cond") or ""),
                                        "asserting_driver_idx":  _ad.get("driver_idx"),
                                        "winning_driver_cond":   (_wd.get("condition") or _wd.get("cond") or ""),
                                        "winning_driver_idx":    _wd.get("driver_idx"),
                                        "winning_driver_rhs":    (_wd.get("rhs") or "0"),
                                        "winning_true_terms":    (_wd.get("true_terms") or []),
                                        "winning_term_values":   (_wd.get("term_values") or {}),
                                    }
                                elif _cli_ow["mode"] == "MODE-A_UNEXPECTED_ASSERTION":
                                    # Signal is 1 when it should not be → MODE-A
                                    _wd = _cli_ow["winning_driver"]
                                    _cli_mode = {
                                        "mode":    "MODE-A",
                                        "subtype": "UNEXPECTED_ASSERTION",
                                        "active_driver_cond": (_wd.get("condition") or _wd.get("cond") or ""),
                                        "active_driver_idx":  _wd.get("driver_idx"),
                                        "active_driver_rhs":  (_wd.get("rhs") or "1"),
                                        "active_true_terms":  (_wd.get("true_terms") or []),
                                        "active_term_values": (_wd.get("term_values") or {}),
                                    }
                            else:
                                # MODE-D: signal never asserted, blocking term found
                                _cli_blocked = [
                                    d for d in _cli_drv_evals
                                    if d.get("is_asserting")
                                    and d.get("condition_active") is False
                                ]
                                if _cli_blocked:
                                    _ab = _cli_blocked[0]
                                    _cli_mode = {
                                        "mode":    "MODE-D",
                                        "subtype": "UNSATISFIED_ENABLE",
                                        "asserting_driver_cond": (_ab.get("condition") or _ab.get("cond") or ""),
                                        "asserting_driver_idx":  _ab.get("driver_idx"),
                                        "blocking_term":         (_ab.get("first_false_term") or ""),
                                        "true_terms":            (_ab.get("true_terms") or []),
                                        "false_terms":           (_ab.get("false_terms") or []),
                                        "all_term_values":       (_ab.get("term_values") or {}),
                                    }
                            if _cli_mode:
                                _cli_bt_raw: list = []
                                _cli_sub = _cli_mode.get("subtype", "")
                                if _cli_sub == "BLOCKED_ASSERTER":
                                    for _t in (_cli_mode.get("winning_true_terms") or []):
                                        _cli_bt_raw.extend(_WORD_BOUNDARY.findall(_t))
                                elif _cli_sub == "UNEXPECTED_ASSERTION":
                                    for _t in (_cli_mode.get("active_true_terms") or []):
                                        _cli_bt_raw.extend(_WORD_BOUNDARY.findall(_t))
                                elif _cli_sub == "UNSATISFIED_ENABLE":
                                    for _t in ((_cli_mode.get("false_terms") or [])
                                               + [_cli_mode.get("blocking_term") or ""]):
                                        _cli_bt_raw.extend(_WORD_BOUNDARY.findall(_t))
                                _cli_mode["term_backtrack"] = _backtrack_signal_set(
                                    list(dict.fromkeys(_cli_bt_raw)),
                                    logic, view, _cli_t_eval,
                                )
                                _cli_mode["secondary_backtrack"] = _backtrack_signal_set(
                                    _cli_secondary, logic, view, _cli_t_eval
                                )
                                _cli_pred_a["mode_analysis"] = _cli_mode
                        except Exception:
                            pass
                final_rca["predicate_analysis"] = _cli_pred_a

    if _cli_full_traces:
        final_rca["full_predicate_trace"] = "\n\n".join(_cli_full_traces)

    payload = {
        "protocol":            args.protocol,
        "waveform_max_cycle":  view.max_cycle,
        "transactions":        transactions,
        "obligations":         [o.__dict__ for o in obligations],
        "causal_results_count": len(results),
        "mechanisms":          [m.__dict__ for m in mechanisms],
        "findings":            findings,
        "datapath_violations": datapath_violations,
        "final_rca":           final_rca,
    }
    _cli_verbose = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"

    if _cli_verbose:
        # Verbose mode: render old-style per-rule ROOT CAUSE SUMMARY.
        rendered = False
        try:
            rendered = bool(adapter.render_report(payload))
        except Exception:
            rendered = False
        if not rendered:
            _print_header("RCA-8 Protocol Adapter Run")
            print(f"Waveform cycles          : 0..{view.max_cycle}")
            print(f"Transactions detected    : {len(transactions)}")
            if getattr(args, "debug_internal", False):
                print_final_rca(final_rca)
    else:
        # Production mode: emit the compact console diagnosis block only.
        # Note: the full block is ALSO printed from main() after _write_proof_artifacts.
        # Do not double-print here.
        pass

    return payload


def _run_core_only_mode(args: argparse.Namespace) -> Dict[str, Any]:
    wave, header, cls, clock = load_waveform_file(args.waveform_csv)
    logic = load_driver_table(args.true_drivers_csv)
    view = WaveformView(wave, header, cls, clock_signal=args.clock or clock)
    engine = RCACoreEngine(
        waveform=view,
        logic_table=logic,
        max_graph_depth=args.max_graph_depth,
        temporal_window_cycles=args.temporal_window,
    )

    targets = args.signal if args.signal else sorted(logic.keys())[:8]
    findings: List[Dict[str, Any]] = []
    _print_header("RCA-8 Core-Only Run (No Protocol Adapter)")
    print(f"Waveform cycles          : 0..{view.max_cycle}")
    print(f"Signals analyzed         : {len(targets)}")

    for sig in targets:
        graph = engine.build_causal_graph(sig)
        tree_text = format_dependency_graph(graph)
        split_text = _build_split_backtrack_view(
            signal=sig,
            logic_table=logic,
            max_depth=max(1, int(args.split_depth)),
        )
        cycle_report = engine.detect_enable_cycle(sig, graph)
        cancel = engine.find_first_scheduling_cancellation(
            signal=sig,
            expected_value=args.expected_value,
            start_cycle=args.analysis_cycle if args.analysis_cycle is not None else 0,
            end_cycle=args.end_cycle,
            lookahead_cycles=args.lookahead_cycles,
        )
        finding = {
            "signal": sig,
            "graph_depth": graph.get("depth_reached"),
            "dependency_tree": tree_text,
            "driver_split_tree": split_text,
            "dependency_graph": graph if args.include_graph_json else None,
            "cyclic_enable": bool(cycle_report),
            "cycle_report": cycle_report,
            "scheduling_cancellation": cancel,
        }
        findings.append(finding)
        print(f"- {sig}: cycle={bool(cycle_report)} cancel={bool(cancel.get('detected'))}")
        if args.show_tree:
            print("")
            print(f"[TREE] {sig}")
            print(_ascii_safe(tree_text))
            print("")
            print(f"[DRIVER SPLIT] {sig} (1-vs-0 paths)")
            print(_ascii_safe(split_text))
            print("")

    return {"protocol": None, "findings": findings}


def main() -> None:
    # Ensure the terminal can render Unicode box-drawing characters on Windows.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="RCA-8: protocol-agnostic causal core with pluggable protocol adapters."
    )
    parser.add_argument("waveform_csv", help="Mapped waveform CSV.")
    parser.add_argument("true_drivers_csv", help="True drivers/backtracking CSV.")
    parser.add_argument(
        "violations",
        nargs="?",
        default=None,
        help="Optional violations CSV/JSON (used by protocol adapters).",
    )
    parser.add_argument("--protocol", default="axi_lite", help="Protocol adapter name or 'none'.")
    parser.add_argument("--clock", default=None, help="Override clock signal name.")
    parser.add_argument("--max-graph-depth", type=int, default=8)
    parser.add_argument("--temporal-window", type=int, default=20)
    parser.add_argument("--max-window-cycles", type=int, default=None)
    parser.add_argument("--signal", action="append", default=[], help="Core-only signal target (repeatable).")
    parser.add_argument("--analysis-cycle", type=int, default=None)
    parser.add_argument("--end-cycle", type=int, default=None)
    parser.add_argument("--lookahead-cycles", type=int, default=1)
    parser.add_argument("--expected-value", type=int, default=1)
    parser.add_argument("--show-tree", action="store_true",
                        help="Core-only: print full dependency/backtracking tree per analyzed signal.")
    parser.add_argument("--split-depth", type=int, default=3,
                        help="Core-only: recursion depth for 1-vs-0 split backtracking tree.")
    parser.add_argument("--include-graph-json", action="store_true",
                        help="Core-only: include full dependency graph payload in --json-out.")
    parser.add_argument("--json-out", default=None, help="Override proof JSON output path (auto-saved by default).")
    parser.add_argument("--ir-json", default=None,
                        help="Path to IR JSON from ir_builder (enables structural memory write analysis).")
    parser.add_argument("--datapath-violations", default=None,
                        help="Path to pre-computed datapath violations JSON from ir_builder.")
    parser.add_argument("--debug-internal", action="store_true", dest="debug_internal",
                        help="Write all verbose debug reports in addition to the 3 primary outputs.")
    args = parser.parse_args()

    if str(args.protocol).lower() == "none":
        payload = _run_core_only_mode(args)
    else:
        payload = _run_protocol_mode(args)

    # Always persist proof artifacts (JSON + appendix text).
    json_path = _resolve_path(args.json_out) if args.json_out else _default_proof_json_path(args)
    written = _write_proof_artifacts(payload, json_path, debug=getattr(args, "debug_internal", False))
    payload["proof_files"] = dict(written)

    # ── Console diagnosis (replaces verbose log summary) ────────────────────
    if _REPORTS_AVAILABLE:
        try:
            _dx = generate_console_diagnosis(payload)
            print("")
            try:
                print(_dx)
            except UnicodeEncodeError:
                print(_dx.encode("ascii", errors="replace").decode("ascii"))
        except Exception:
            pass

    if _PROD_VERBOSE:
        print("")
        print(f"[INFO] Wrote proof JSON     : {written['json']}")
        print(f"[INFO] Wrote proof appendix : {written['appendix']}")


if __name__ == "__main__":
    main()
