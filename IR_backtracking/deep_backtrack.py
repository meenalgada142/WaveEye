#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deterministic recursive dependency backtracking for AXI-Lite RCA.

This module is additive: it only builds structural dependency graphs and does
not evaluate expressions or alter existing RCA verdict logic.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_VERILOG_LITERAL_RE = re.compile(r"^\d+\s*'\s*[sS]?[bBdDhHoO]\s*[0-9a-fA-F_xXzZ?]+$")
_KEYWORDS = {"and", "or", "not", "if", "else", "true", "false", "True", "False"}


def _is_constant_token(tok: str) -> bool:
    t = (tok or "").strip()
    if not t:
        return False
    if re.fullmatch(r"[+-]?\d+", t):
        return True
    return bool(_VERILOG_LITERAL_RE.fullmatch(t))


class _ExprParser:
    """Small deterministic parser for Verilog-like expressions."""

    _token_re = re.compile(
        r"""
        \s*(
            \?\:|  # not used, keep longest-operator discipline
            <<|>>|<=|>=|==|!=|\|\||&&|
            [\?\:\|\&\^\~\+\-\(\)\{\}\,\[\]<>!]|
            \d+\s*'\s*[sS]?[bBdDhHoO]\s*[0-9a-fA-F_xXzZ?]+|
            \d+|
            [A-Za-z_][A-Za-z0-9_]*
        )
        """,
        re.VERBOSE,
    )

    def __init__(self, text: str) -> None:
        self.text = text or ""
        self.tokens = self._tokenize(self.text)
        self.pos = 0

    @classmethod
    def _tokenize(cls, text: str) -> List[str]:
        out: List[str] = []
        pos = 0
        while pos < len(text):
            m = cls._token_re.match(text, pos)
            if not m:
                pos += 1
                continue
            tok = m.group(1)
            if tok:
                out.append(tok.strip())
            pos = m.end()
        return out

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _pop(self) -> Optional[str]:
        tok = self._peek()
        if tok is not None:
            self.pos += 1
        return tok

    def _eat(self, token: str) -> bool:
        if self._peek() == token:
            self.pos += 1
            return True
        return False

    def parse(self) -> Dict[str, Any]:
        if not self.tokens:
            return {"type": "empty"}
        node = self._parse_ternary()
        return node

    def _parse_ternary(self) -> Dict[str, Any]:
        cond = self._parse_logical_or()
        if self._eat("?"):
            if_true = self._parse_ternary()
            if self._eat(":"):
                if_false = self._parse_ternary()
            else:
                if_false = {"type": "unknown", "value": "missing_colon"}
            return {"type": "ternary", "cond": cond, "if_true": if_true, "if_false": if_false}
        return cond

    def _parse_logical_or(self) -> Dict[str, Any]:
        node = self._parse_logical_and()
        while self._eat("||"):
            rhs = self._parse_logical_and()
            node = {"type": "binary", "op": "||", "left": node, "right": rhs}
        return node

    def _parse_logical_and(self) -> Dict[str, Any]:
        node = self._parse_bit_or()
        while self._eat("&&"):
            rhs = self._parse_bit_or()
            node = {"type": "binary", "op": "&&", "left": node, "right": rhs}
        return node

    def _parse_bit_or(self) -> Dict[str, Any]:
        node = self._parse_bit_xor()
        while self._eat("|"):
            rhs = self._parse_bit_xor()
            node = {"type": "binary", "op": "|", "left": node, "right": rhs}
        return node

    def _parse_bit_xor(self) -> Dict[str, Any]:
        node = self._parse_bit_and()
        while self._eat("^"):
            rhs = self._parse_bit_and()
            node = {"type": "binary", "op": "^", "left": node, "right": rhs}
        return node

    def _parse_bit_and(self) -> Dict[str, Any]:
        node = self._parse_equality()
        while self._eat("&"):
            rhs = self._parse_equality()
            node = {"type": "binary", "op": "&", "left": node, "right": rhs}
        return node

    def _parse_equality(self) -> Dict[str, Any]:
        node = self._parse_relational()
        while True:
            if self._eat("=="):
                rhs = self._parse_relational()
                node = {"type": "compare", "op": "==", "left": node, "right": rhs}
            elif self._eat("!="):
                rhs = self._parse_relational()
                node = {"type": "compare", "op": "!=", "left": node, "right": rhs}
            else:
                return node

    def _parse_relational(self) -> Dict[str, Any]:
        node = self._parse_shift()
        while True:
            if self._eat("<="):
                rhs = self._parse_shift()
                node = {"type": "compare", "op": "<=", "left": node, "right": rhs}
            elif self._eat(">="):
                rhs = self._parse_shift()
                node = {"type": "compare", "op": ">=", "left": node, "right": rhs}
            elif self._eat("<"):
                rhs = self._parse_shift()
                node = {"type": "compare", "op": "<", "left": node, "right": rhs}
            elif self._eat(">"):
                rhs = self._parse_shift()
                node = {"type": "compare", "op": ">", "left": node, "right": rhs}
            else:
                return node

    def _parse_shift(self) -> Dict[str, Any]:
        node = self._parse_add_sub()
        while True:
            if self._eat("<<"):
                rhs = self._parse_add_sub()
                node = {"type": "binary", "op": "<<", "left": node, "right": rhs}
            elif self._eat(">>"):
                rhs = self._parse_add_sub()
                node = {"type": "binary", "op": ">>", "left": node, "right": rhs}
            else:
                return node

    def _parse_add_sub(self) -> Dict[str, Any]:
        node = self._parse_unary()
        while True:
            if self._eat("+"):
                rhs = self._parse_unary()
                node = {"type": "binary", "op": "+", "left": node, "right": rhs}
            elif self._eat("-"):
                rhs = self._parse_unary()
                node = {"type": "binary", "op": "-", "left": node, "right": rhs}
            else:
                return node

    def _parse_unary(self) -> Dict[str, Any]:
        tok = self._peek()
        if tok in ("~", "!", "+", "-"):
            op = self._pop()
            return {"type": "unary", "op": op, "operand": self._parse_unary()}
        return self._parse_primary()

    def _parse_primary(self) -> Dict[str, Any]:
        tok = self._peek()
        if tok is None:
            return {"type": "empty"}
        if self._eat("("):
            node = self._parse_ternary()
            self._eat(")")
            return node
        if self._eat("{"):
            parts: List[Dict[str, Any]] = []
            if self._peek() != "}":
                parts.append(self._parse_ternary())
                while self._eat(","):
                    parts.append(self._parse_ternary())
            self._eat("}")
            return {"type": "concat", "parts": parts}
        self._pop()
        if _is_constant_token(tok):
            return {"type": "literal", "value": tok}
        if _ID_RE.match(tok):
            base: Dict[str, Any] = {"type": "signal", "name": tok}
            while self._eat("["):
                idx = self._parse_ternary()
                if self._eat(":"):
                    lsb = self._parse_ternary()
                    self._eat("]")
                    base = {"type": "slice", "base": base, "msb": idx, "lsb": lsb}
                else:
                    self._eat("]")
                    base = {"type": "index", "base": base, "index": idx}
            return base
        return {"type": "unknown", "value": tok}


def _ast_to_text(node: Dict[str, Any]) -> str:
    typ = node.get("type")
    if typ == "signal":
        return str(node.get("name", ""))
    if typ == "literal":
        return str(node.get("value", ""))
    if typ == "unary":
        return f"{node.get('op', '')}{_ast_to_text(node.get('operand', {}))}"
    if typ == "binary" or typ == "compare":
        return f"{_ast_to_text(node.get('left', {}))} {node.get('op', '')} {_ast_to_text(node.get('right', {}))}"
    if typ == "ternary":
        return (
            f"{_ast_to_text(node.get('cond', {}))} ? "
            f"{_ast_to_text(node.get('if_true', {}))} : {_ast_to_text(node.get('if_false', {}))}"
        )
    if typ == "concat":
        return "{" + ", ".join(_ast_to_text(p) for p in node.get("parts", [])) + "}"
    if typ == "index":
        return f"{_ast_to_text(node.get('base', {}))}[{_ast_to_text(node.get('index', {}))}]"
    if typ == "slice":
        return (
            f"{_ast_to_text(node.get('base', {}))}"
            f"[{_ast_to_text(node.get('msb', {}))}:{_ast_to_text(node.get('lsb', {}))}]"
        )
    return str(node.get("value", ""))


def _collect_signals(node: Dict[str, Any], out: Set[str]) -> None:
    typ = node.get("type")
    if typ == "signal":
        name = str(node.get("name", "")).strip()
        if name and name not in _KEYWORDS and not _is_constant_token(name):
            out.add(name)
        return
    if typ in ("binary", "compare"):
        _collect_signals(node.get("left", {}), out)
        _collect_signals(node.get("right", {}), out)
        return
    if typ == "unary":
        _collect_signals(node.get("operand", {}), out)
        return
    if typ == "ternary":
        _collect_signals(node.get("cond", {}), out)
        _collect_signals(node.get("if_true", {}), out)
        _collect_signals(node.get("if_false", {}), out)
        return
    if typ == "concat":
        for p in node.get("parts", []):
            _collect_signals(p, out)
        return
    if typ == "index":
        _collect_signals(node.get("base", {}), out)
        _collect_signals(node.get("index", {}), out)
        return
    if typ == "slice":
        _collect_signals(node.get("base", {}), out)
        _collect_signals(node.get("msb", {}), out)
        _collect_signals(node.get("lsb", {}), out)


def _collect_fsm_refs(node: Dict[str, Any], out: List[Dict[str, str]]) -> None:
    typ = node.get("type")
    if typ == "compare":
        left = node.get("left", {})
        right = node.get("right", {})
        left_txt = _ast_to_text(left)
        right_txt = _ast_to_text(right)
        if re.search(r"(state|fsm|_next)", left_txt, re.IGNORECASE) or re.search(
            r"(state|fsm|_next)", right_txt, re.IGNORECASE
        ):
            out.append(
                {
                    "expr": f"{left_txt} {node.get('op', '')} {right_txt}",
                    "left": left_txt,
                    "right": right_txt,
                }
            )
    for key in ("left", "right", "operand", "cond", "if_true", "if_false", "base", "index", "msb", "lsb"):
        child = node.get(key)
        if isinstance(child, dict):
            _collect_fsm_refs(child, out)
    for part in node.get("parts", []) or []:
        if isinstance(part, dict):
            _collect_fsm_refs(part, out)


def _resolve_signal_key(sig: str, logic_table: Dict[str, List[Dict[str, Any]]]) -> Optional[str]:
    if sig in logic_table:
        return sig
    s_l = sig.lower()
    for k in logic_table.keys():
        if k.lower() == s_l:
            return k
    return None


def _driver_sort_key(driver: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    return (
        str(driver.get("cond", driver.get("condition", ""))),
        str(driver.get("rhs", "")),
        str(driver.get("assign_type", "")),
        str(driver.get("sensitivity", "")),
        str(driver.get("always_block_id", "")),
    )


def build_dependency_graph(
    target_signal: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
    max_depth: int = 8,
) -> Dict[str, Any]:
    """
    Build a bounded dependency graph rooted at *target_signal*.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    leaf_signals: Set[str] = set()
    intermediate_signals: Set[str] = set()
    fsm_references: List[Dict[str, str]] = []
    adjacency: Dict[str, List[Dict[str, Any]]] = {}
    depth_reached = 0

    node_counter = {"n": 0}
    signal_nodes: Dict[str, str] = {}
    visiting: Set[str] = set()
    expanded: Set[str] = set()

    def add_node(kind: str, label: str, **extra: Any) -> str:
        node_counter["n"] += 1
        node_id = f"n{node_counter['n']}"
        nodes.append({"id": node_id, "type": kind, "label": label, **extra})
        return node_id

    def get_signal_node(sig_name: str) -> str:
        key = sig_name.lower()
        if key in signal_nodes:
            return signal_nodes[key]
        node_id = add_node("signal", sig_name, signal=sig_name)
        signal_nodes[key] = node_id
        return node_id

    def add_edge(src: str, dst: str, kind: str, **extra: Any) -> None:
        edges.append({"source": src, "target": dst, "type": kind, **extra})

    def add_adjacency(parent_sig: str, child: Dict[str, Any]) -> None:
        adjacency.setdefault(parent_sig, [])
        existing = adjacency[parent_sig]
        key = (child.get("kind"), child.get("name"), child.get("expr"))
        if any((c.get("kind"), c.get("name"), c.get("expr")) == key for c in existing):
            return
        existing.append(child)

    def walk_signal(sig: str, depth: int, parent_expr_node: Optional[str], edge_kind: str) -> None:
        nonlocal depth_reached
        depth_reached = max(depth_reached, depth)

        signal_node = get_signal_node(sig)
        if parent_expr_node:
            add_edge(parent_expr_node, signal_node, edge_kind)
        intermediate_signals.add(sig)

        if depth >= max_depth:
            leaf_signals.add(sig)
            return

        logic_key = _resolve_signal_key(sig, logic_table)
        if logic_key is None:
            leaf_signals.add(sig)
            return

        lkey = logic_key.lower()
        if lkey in visiting:
            leaf_signals.add(logic_key)
            return
        if lkey in expanded:
            return

        drivers = logic_table.get(logic_key, [])
        if not drivers:
            leaf_signals.add(logic_key)
            return

        visiting.add(lkey)
        sorted_drivers = sorted(drivers, key=_driver_sort_key)

        for d_idx, drv in enumerate(sorted_drivers):
            cond = (drv.get("cond", drv.get("condition", "")) or "").strip()
            rhs = (drv.get("rhs", "") or "").strip()
            drv_label = f"{logic_key}[{d_idx}]"
            drv_node = add_node(
                "driver",
                drv_label,
                signal=logic_key,
                condition=cond,
                rhs=rhs,
                assign_type=str(drv.get("assign_type", "")),
                always_block_id=drv.get("always_block_id"),
                source_location=drv.get("file") or drv.get("source_location"),
            )
            add_edge(signal_node, drv_node, "driven_by")

            if cond:
                cond_ast = _ExprParser(cond).parse()
                cond_node = add_node("expression", cond, role="condition", ast=cond_ast)
                add_edge(drv_node, cond_node, "condition")
                cond_refs: Set[str] = set()
                _collect_signals(cond_ast, cond_refs)
                for dep in sorted(cond_refs):
                    add_adjacency(logic_key, {"kind": "signal", "name": dep, "source": "condition"})
                    walk_signal(dep, depth + 1, cond_node, "depends_on_condition")

                cond_fsm: List[Dict[str, str]] = []
                _collect_fsm_refs(cond_ast, cond_fsm)
                for ref in cond_fsm:
                    fsm_node = add_node("fsm_reference", ref["expr"], left=ref["left"], right=ref["right"])
                    add_edge(cond_node, fsm_node, "fsm_reference")
                    fsm_references.append(ref)
                    add_adjacency(logic_key, {"kind": "condition", "expr": ref["expr"]})
                    # Link state-like side to the condition node for tree output.
                    state_sig = ref["left"] if _ID_RE.match(ref["left"]) else ref["right"]
                    if _ID_RE.match(state_sig):
                        add_adjacency(ref["expr"], {"kind": "signal", "name": state_sig, "source": "fsm_condition"})

            if rhs:
                rhs_ast = _ExprParser(rhs).parse()
                rhs_node = add_node("expression", rhs, role="rhs", ast=rhs_ast)
                add_edge(drv_node, rhs_node, "assignment")
                rhs_refs: Set[str] = set()
                _collect_signals(rhs_ast, rhs_refs)
                for dep in sorted(rhs_refs):
                    add_adjacency(logic_key, {"kind": "signal", "name": dep, "source": "rhs"})
                    walk_signal(dep, depth + 1, rhs_node, "depends_on_rhs")

        visiting.remove(lkey)
        expanded.add(lkey)

    root_key = _resolve_signal_key(target_signal, logic_table) or target_signal
    walk_signal(root_key, 0, None, "root")

    for key in list(adjacency.keys()):
        adjacency[key] = sorted(
            adjacency[key],
            key=lambda item: (
                str(item.get("kind", "")),
                str(item.get("name", "")),
                str(item.get("expr", "")),
                str(item.get("source", "")),
            ),
        )

    return {
        "root": root_key,
        "nodes": nodes,
        "edges": edges,
        "leaf_signals": sorted(leaf_signals),
        "intermediate_signals": sorted(intermediate_signals),
        "fsm_references": fsm_references,
        "adjacency": adjacency,
        "depth_reached": depth_reached,
    }


def format_dependency_graph(graph: Dict[str, Any]) -> str:
    """Render a deterministic text tree for --explain-graph."""
    root = graph.get("root", "?")
    adjacency = graph.get("adjacency", {}) or {}
    lines: List[str] = [str(root)]
    visited: Set[str] = {str(root)}

    def walk(label: str, prefix: str) -> None:
        children = adjacency.get(label, [])
        if not children:
            return
        for idx, ch in enumerate(children):
            last = idx == len(children) - 1
            arm = "└── " if last else "├── "
            child_label = ch.get("expr") if ch.get("kind") == "condition" else ch.get("name")
            if not child_label:
                continue
            lines.append(f"{prefix}{arm}{child_label}")
            next_prefix = prefix + ("    " if last else "│   ")
            if child_label not in visited:
                visited.add(child_label)
                walk(str(child_label), next_prefix)

    walk(str(root), "")
    return "\n".join(lines)

