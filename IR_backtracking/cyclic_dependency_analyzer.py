#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect temporal enable-dependency cycles in RTL predicate gating.

This is not a combinational loop check; it finds forward-progress cycles:
A enable depends on B, B depends on C, ..., and some node depends back on A.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set


_CONST_TRUE = {"1", "1'b1", "1'd1", "true"}
_CONST_FALSE = {"0", "1'b0", "1'd0", "false"}
_VERILOG_LIT = re.compile(r"^\d+\s*'\s*[sS]?[bBdDhHoO]\s*[0-9a-fA-F_xXzZ?]+$")


def _is_const_literal(s: str) -> bool:
    t = (s or "").strip().lower()
    return t in _CONST_TRUE or t in _CONST_FALSE or bool(_VERILOG_LIT.fullmatch(t))


def _build_enable_edges(dependency_graph: Dict[str, Any]) -> Dict[str, Set[str]]:
    """
    Build A -> B edges only for enable predicates (condition dependencies).
    Ignores pure RHS/dataflow references by design.
    """
    edges: Dict[str, Set[str]] = {}
    if not dependency_graph:
        return edges

    adjacency = dependency_graph.get("adjacency", {}) or {}
    signal_nodes = {
        n.get("signal")
        for n in dependency_graph.get("nodes", []) or []
        if n.get("type") == "signal" and n.get("signal")
    }

    for parent, children in adjacency.items():
        if signal_nodes and parent not in signal_nodes:
            continue
        for ch in children or []:
            if ch.get("kind") != "signal":
                continue
            if ch.get("source") not in ("condition", "fsm_condition"):
                continue
            dep = ch.get("name")
            if not dep:
                continue
            edges.setdefault(parent, set()).add(dep)
    return edges


def _infer_terminal_signals(
    dependency_graph: Dict[str, Any],
    eval_trace: Dict[str, Any],
    enable_edges: Dict[str, Set[str]],
) -> Set[str]:
    """
    Terminal signals stop cycle validity per requirements:
      - primary input (no RTL drivers)
      - unconditional assignment (if true / empty predicate)
      - constant driver (literal RHS under unconditional predicate)
    """
    terminals: Set[str] = set()
    if not dependency_graph:
        return terminals

    nodes = dependency_graph.get("nodes", []) or []
    edges = dependency_graph.get("edges", []) or []
    by_id = {n.get("id"): n for n in nodes if n.get("id")}

    drivers_by_signal: Dict[str, List[Dict[str, Any]]] = {}
    has_driver_edges = False
    for e in edges:
        if e.get("type") != "driven_by":
            continue
        has_driver_edges = True
        src = by_id.get(e.get("source"), {})
        dst = by_id.get(e.get("target"), {})
        if src.get("type") == "signal" and dst.get("type") == "driver":
            sig = src.get("signal")
            if sig:
                drivers_by_signal.setdefault(sig, []).append(dst)

    signals = {
        n.get("signal")
        for n in nodes
        if n.get("type") == "signal" and n.get("signal")
    }
    if has_driver_edges:
        for sig in signals:
            drivers = drivers_by_signal.get(sig, [])
            if not drivers:
                terminals.add(sig)  # primary input
                continue
            for drv in drivers:
                cond = (drv.get("condition") or "").strip().lower()
                rhs = (drv.get("rhs") or "").strip().lower()
                is_uncond = (not cond) or cond in _CONST_TRUE
                if is_uncond:
                    terminals.add(sig)
                    if _is_const_literal(rhs):
                        terminals.add(sig)
                    break

    # If no outgoing enable edge, it behaves as terminal for cycle walk.
    for sig in signals:
        if not enable_edges.get(sig):
            terminals.add(sig)
    return terminals


def detect_cyclic_enable(
    root_signal: str,
    dependency_graph: Dict[str, Any],
    eval_trace: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Detect a bounded temporal enable cycle starting from root_signal.

    Returns CycleReport dict on detection, else None.
    """
    if not root_signal or not dependency_graph:
        return None

    max_depth = 12
    enable_edges = _build_enable_edges(dependency_graph)
    if not enable_edges:
        return None

    root = root_signal
    if root not in enable_edges:
        # case-insensitive remap
        root_l = root.lower()
        for k in enable_edges.keys():
            if k.lower() == root_l:
                root = k
                break

    terminals = _infer_terminal_signals(dependency_graph, eval_trace, enable_edges)

    def _dfs(node: str, path: List[str], seen: Set[str], depth: int) -> Optional[List[str]]:
        if depth >= max_depth:
            return None
        if node != root and node in terminals:
            return None
        for nxt in sorted(enable_edges.get(node, set()), key=str.lower):
            if nxt in seen:
                idx = path.index(nxt)
                cyc = path[idx:] + [nxt]
                if any((p in terminals) for p in cyc[:-1]):
                    continue
                return cyc
            rep = _dfs(nxt, path + [nxt], seen | {nxt}, depth + 1)
            if rep:
                return rep
        return None

    cycle_path = _dfs(root, [root], {root}, 0)
    if not cycle_path:
        return None

    return {
        "type": "CYCLIC_ENABLE_DEPENDENCY",
        "cycle_path": cycle_path,
        "explanation": (
            "Response generation is gated by completion logic that itself "
            "requires the response to occur. This creates a forward-progress deadlock."
        ),
        "confidence": "HIGH",
    }
