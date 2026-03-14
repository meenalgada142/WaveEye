"""
design_causal_graph.py
======================
Builds a design-wide causal dependency graph from WaveEye true_drivers CSV files.

Each CSV row encodes one driver assignment:
    signal ← rhs   (under condition, at file:line)

Graph edges:
    rhs_signal  →  signal   (data_driver edge)
    cond_signal →  signal   (control_dep edge)

Usage
-----
    python design_causal_graph.py
    # or from Python:
    from design_causal_graph import DesignCausalGraph, build_graph, trace_back
"""

from __future__ import annotations

import csv
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx


# ---------------------------------------------------------------------------
# Constants / heuristics
# ---------------------------------------------------------------------------

# Transform-type priority scores (higher = more likely to be a true root cause)
_TRANSFORM_SCORE: Dict[str, int] = {
    "register":   2,   # nonblocking always block → clocked FF
    "mux":        3,   # structural selection logic
    "structural": 3,   # generic structural assign
    "assign":     1,   # continuous assign
    "always":     1,   # combinational always
    "control":    0,   # condition dependency (secondary arc)
}
_DISTANCE_PENALTY = -1   # per hop away from the failing signal
_TOP_N = 5               # how many root-cause candidates to return

# Verilog keywords and constant patterns to skip when tokenising expressions
_VERILOG_KW = frozenset({
    "if", "else", "case", "endcase", "begin", "end", "module", "endmodule",
    "always", "assign", "input", "output", "wire", "reg", "logic",
    "posedge", "negedge", "and", "or", "not", "true", "false",
})
_CONST_RE = re.compile(
    r"^\d+$"                        # plain integer
    r"|^\d+'[bBoOdDhH][\w_]+$"     # 4'b0011, 8'hFF, …
    r"|^[01xXzZ]$"                  # single-bit literal
)

# AXI4-Lite protocol signal names (treated as node_type = "protocol")
_AXI_PROTOCOL_SIGNALS = frozenset({
    "AWVALID", "AWREADY", "AWADDR", "AWPROT",
    "WVALID",  "WREADY",  "WDATA",  "WSTRB",
    "BVALID",  "BREADY",  "BRESP",
    "ARVALID", "ARREADY", "ARADDR", "ARPROT",
    "RVALID",  "RREADY",  "RDATA",  "RRESP",
    # lowercase variants
    "awvalid", "awready", "awaddr", "awprot",
    "wvalid",  "wready",  "wdata",  "wstrb",
    "bvalid",  "bready",  "bresp",
    "arvalid", "arready", "araddr", "arprot",
    "rvalid",  "rready",  "rdata",  "rresp",
})

# Regex: hex literal tokenized as identifier  e.g. h0  h10  hDEAD_BEEF  hFF
_HEX_IDENT_RE  = re.compile(r"^h([0-9A-Fa-f][0-9A-Fa-f_]*)$")
# Regex: binary literal tokenized as identifier  e.g. b0  b1  b00  b10  b11
_BIN_IDENT_RE  = re.compile(r"^b([01][01_]*)$")
# Regex: FSM comparison in condition string  e.g.  write_state == IDLE
_FSM_COMP_RE   = re.compile(
    r"\b([a-zA-Z_]\w*)\s*==\s*([A-Z_][A-Z0-9_]*)\b"
)
# Regex: SIGNAL[optional_slice] == <N>'h<HEX>  (finds signal compared to hex const)
_CMP_SIG_HEX_RE = re.compile(
    r"\b([A-Za-z_]\w*)(?:\[[^\]]*\])?"   # signal name (optional bit-select)
    r"\s*==\s*"                           # ==
    r"(?:\d+')?[hH]([0-9A-Fa-f]+)",      # optional width, h/H, hex digits
)
# Regex: SIGNAL[optional_slice] == <N>'b<BIN>  (finds signal compared to bin const)
_CMP_SIG_BIN_RE = re.compile(
    r"\b([A-Za-z_]\w*)(?:\[[^\]]*\])?"
    r"\s*==\s*"
    r"(?:\d+')?[bB]([01]+)",
)
# Regex: detect reset conditions  e.g. !(ARESETn)  !rst_n  !reset
_RESET_COND_RE = re.compile(
    r"!\s*\(?\s*\w*(?:reset|rst|aresetn)\w*\s*\)?",
    re.IGNORECASE,
)
# Known BRESP / RRESP encoding names (binary)
_RESP_NAMES = {
    "00": "OKAY",   "01": "EXOKAY",
    "10": "SLVERR", "11": "DECERR",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_signals(expr: str) -> List[str]:
    """
    Tokenise a Verilog RHS expression or condition string and return the
    signal names referenced (excluding constants and keywords).

    Handles: plain identifiers, array indexing mem[ptr], bit-selects a[3:0].
    """
    if not expr or not isinstance(expr, str):
        return []
    # Pull identifiers (word chars including $)
    tokens = re.findall(r"[A-Za-z_\$][A-Za-z0-9_\$]*", expr)
    result = []
    for tok in tokens:
        if tok in _VERILOG_KW:
            continue
        if _CONST_RE.match(tok):
            continue
        result.append(tok)
    return result


def _infer_transform(row: dict) -> str:
    """
    Decide a human-readable transform label from a CSV row.
    """
    assign_type = (row.get("assign_type") or "").strip().lower()
    construct   = (row.get("construct")   or "").strip().lower()
    rhs         = (row.get("rhs")         or "").strip()

    if assign_type == "nonblocking":
        return "register"
    if construct == "assign":
        # Detect mux: ternary operator in rhs
        if "?" in rhs:
            return "mux"
        return "structural"
    if construct == "always":
        if "?" in rhs:
            return "mux"
        return "always"
    return construct or "unknown"


def _module_from_filename(csv_path: Path) -> str:
    """Derive a short module name from the CSV filename."""
    name = csv_path.stem  # e.g. axi_lite_fifo_wrapper_true_drivers
    return name.replace("_true_drivers", "")


def _parse_file_line(file_field: str) -> Tuple[str, Optional[int]]:
    """
    Split 'foo.sv:42' → ('foo.sv', 42).
    Returns (file_field, None) if no line number present.
    """
    if ":" in (file_field or ""):
        parts = file_field.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return file_field, None


# ---------------------------------------------------------------------------
# Core graph builder
# ---------------------------------------------------------------------------

@dataclass
class EdgeMeta:
    """Metadata attached to every graph edge."""
    transform:  str
    file:       str
    line:       Optional[int]
    module:     str
    condition:  str
    edge_type:  str   # "data_driver" | "control_dep"
    driver_idx: int   = 0


def load_csv(path: Path) -> List[dict]:
    """Load a true_drivers CSV, skipping blank rows."""
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if not (row.get("signal") or "").strip():
                continue   # blank separator row
            rows.append(row)
    return rows


def build_graph(csv_paths: List[Path]) -> nx.DiGraph:
    """
    Build a unified DesignCausalGraph from one or more true_drivers CSV files.

    Edge direction:  driver_signal  →  lhs_signal
    Node attributes: file, line, transform, module, drivers (list of EdgeMeta)
    """
    G = nx.DiGraph(name="DesignCausalGraph")

    for csv_path in csv_paths:
        csv_path = Path(csv_path)
        module = _module_from_filename(csv_path)
        rows   = load_csv(csv_path)

        for row in rows:
            lhs       = (row.get("signal") or "").strip()
            rhs_expr  = (row.get("rhs")    or "").strip()
            cond_expr = (row.get("condition") or "").strip()
            file_raw  = (row.get("file")   or "").strip()
            transform = _infer_transform(row)
            try:
                driver_idx = int(row.get("driver_idx") or 0)
            except ValueError:
                driver_idx = 0

            src_file, src_line = _parse_file_line(file_raw)

            meta_base = dict(
                transform=transform,
                file=src_file,
                line=src_line,
                module=module,
                condition=cond_expr,
                driver_idx=driver_idx,
            )

            # --- ensure LHS node exists ---
            if lhs not in G:
                G.add_node(lhs, module=module, file=src_file, line=src_line,
                           transform=transform, drivers=[])

            # --- data-driver edges: rhs tokens → lhs ---
            for sig in _extract_signals(rhs_expr):
                if sig == lhs:
                    continue   # self-loop (state register hold)
                if sig not in G:
                    G.add_node(sig, module=module, file=src_file, line=src_line,
                               transform="unknown", drivers=[])
                key = (sig, lhs, "data_driver")
                if G.has_edge(sig, lhs):
                    G[sig][lhs].setdefault("metas", []).append(
                        EdgeMeta(edge_type="data_driver", **meta_base)
                    )
                else:
                    G.add_edge(sig, lhs,
                               edge_type="data_driver",
                               transform=transform,
                               file=src_file, line=src_line,
                               module=module,
                               metas=[EdgeMeta(edge_type="data_driver", **meta_base)])

            # --- control-dep edges: condition tokens → lhs ---
            for sig in _extract_signals(cond_expr):
                if sig == lhs:
                    continue
                if sig not in G:
                    G.add_node(sig, module=module, file=src_file, line=src_line,
                               transform="unknown", drivers=[])
                if not G.has_edge(sig, lhs):
                    G.add_edge(sig, lhs,
                               edge_type="control_dep",
                               transform="control",
                               file=src_file, line=src_line,
                               module=module,
                               metas=[EdgeMeta(edge_type="control_dep",
                                               **{**meta_base, "transform": "control"})])

    return normalize_graph(G)


# ---------------------------------------------------------------------------
# Graph normalisation  (Step 1-3 from the spec)
# ---------------------------------------------------------------------------

def _const_display_label(token: str) -> str:
    """
    Convert a hex/binary identifier token to a CONST_… display label.

    h10       -> CONST_0x10
    hDEAD_BEEF -> CONST_0xDEAD_BEEF
    b0        -> CONST_0b0
    b10       -> CONST_0b10
    """
    m = _HEX_IDENT_RE.match(token)
    if m:
        return f"CONST_0x{m.group(1).upper()}"
    m = _BIN_IDENT_RE.match(token)
    if m:
        return f"CONST_0b{m.group(1)}"
    # plain decimal that slipped through
    return f"CONST_{token}"


def _is_const_token(token: str) -> bool:
    """Return True if token looks like a hex/binary literal identifier."""
    return bool(_HEX_IDENT_RE.match(token) or _BIN_IDENT_RE.match(token))


def _collect_fsm_registry(G: nx.DiGraph) -> Dict[str, Set[str]]:
    """
    Scan every edge's condition strings to build a registry of known FSM states.

    Returns: { fsm_signal_name -> set_of_state_names }
    e.g.     { "write_state": {"IDLE", "RESP"}, "read_state": {"IDLE", "RESP"} }
    """
    registry: Dict[str, Set[str]] = {}
    for u, v, data in G.edges(data=True):
        for meta in data.get("metas", []):
            cond = getattr(meta, "condition", "") or ""
            for fsm_sig, state_name in _FSM_COMP_RE.findall(cond):
                registry.setdefault(fsm_sig, set()).add(state_name)
    return registry


def _correct_truncated_fsm(token: str, all_known_states: Set[str]) -> Optional[str]:
    """
    Try to match a short/truncated token to a known FSM state name.

    Strategy (in order):
      1. Exact match — return token
      2. Suffix match — known state ends with token  (e.g. ILE matches IDLE)
      3. Prefix match — known state starts with token
      4. Substring     — token appears anywhere in known state
    Returns the corrected name or None.
    """
    if token in all_known_states:
        return token
    # suffix match: state ends with the token (min 2 chars overlap)
    if len(token) >= 2:
        for s in sorted(all_known_states):
            if s.endswith(token) and len(s) > len(token):
                return s
    # prefix match
    if len(token) >= 2:
        for s in sorted(all_known_states):
            if s.startswith(token) and len(s) > len(token):
                return s
    # substring
    for s in sorted(all_known_states):
        if token in s:
            return s
    return None


def normalize_graph(G: nx.DiGraph) -> nx.DiGraph:
    """
    Post-process the DesignCausalGraph to:

    1. Detect hex/binary literal nodes → rename to CONST_0x... and tag
       node_type = "constant"
    2. Detect FSM state nodes (via condition pattern matching) → tag
       node_type = "fsm_state", fsm_parent = <fsm_signal>
       Correct truncated names (e.g. ILE → IDLE)
    3. Tag AXI protocol signals → node_type = "protocol"
    4. Tag all remaining nodes → node_type = "signal"

    Returns the same graph (mutated in-place) after relabelling.
    """
    # --- Step 1: build FSM registry from edge conditions ---
    fsm_registry = _collect_fsm_registry(G)              # {fsm_sig: {states}}
    all_known_states: Set[str] = set()
    for states in fsm_registry.values():
        all_known_states.update(states)
    # build reverse map: state_name -> list of fsm_signals that own it
    state_to_fsm: Dict[str, List[str]] = {}
    for fsm_sig, states in fsm_registry.items():
        for s in states:
            state_to_fsm.setdefault(s, []).append(fsm_sig)

    # --- Step 2: build rename map for constants and truncated FSM states ---
    rename_map: Dict[str, str] = {}

    for node in list(G.nodes):
        if _is_const_token(node):
            new_label = _const_display_label(node)
            if new_label != node:
                rename_map[node] = new_label
        elif node not in all_known_states:
            # Check if it looks like a truncated FSM state
            corrected = _correct_truncated_fsm(node, all_known_states)
            if corrected and corrected != node:
                rename_map[node] = corrected

    # Apply renames (nx.relabel_nodes merges duplicate targets automatically)
    if rename_map:
        G = nx.relabel_nodes(G, rename_map)

    # Rebuild reverse state map after renaming
    all_known_states_final: Set[str] = set(all_known_states)

    # --- Step 3: tag every node with node_type ---
    for node in G.nodes:
        ndata = G.nodes[node]

        # Already tagged (e.g. from a previous call)?
        if "node_type" in ndata:
            continue

        upper = node.upper()

        if node.startswith("CONST_"):
            ndata["node_type"] = "constant"

        elif node in all_known_states_final or upper in all_known_states_final:
            # Determine which FSM(s) own this state
            parents = state_to_fsm.get(node) or state_to_fsm.get(upper) or []
            ndata["node_type"]   = "fsm_state"
            ndata["fsm_parents"] = parents
            ndata["display_label"] = (
                f"{node}\n({parents[0]})" if parents else node
            )

        elif node in _AXI_PROTOCOL_SIGNALS or upper in _AXI_PROTOCOL_SIGNALS:
            ndata["node_type"] = "protocol"

        else:
            ndata["node_type"] = "signal"

    return semanticize_constants(G)


# ---------------------------------------------------------------------------
# Constant semanticisation  (Steps 1-5 from the spec)
# ---------------------------------------------------------------------------

def _hex_str_from_const(node: str) -> Optional[str]:
    """'CONST_0x10' -> '10',  'CONST_0xDEAD_BEEF' -> 'DEADBEEF'."""
    if node.startswith("CONST_0x"):
        return node[8:].replace("_", "").upper()
    return None

def _bin_str_from_const(node: str) -> Optional[str]:
    """'CONST_0b10' -> '10'."""
    if node.startswith("CONST_0b"):
        return node[8:].replace("_", "")
    return None

def _find_comparison_signal(cond: str, hex_val: Optional[str],
                             bin_val: Optional[str]) -> Optional[str]:
    """
    Search a Verilog condition string for a signal-vs-constant comparison.

    Returns the signal name (base name, no bit-select) if found, else None.
    """
    for pat, val in [(_CMP_SIG_HEX_RE, hex_val), (_CMP_SIG_BIN_RE, bin_val)]:
        if val is None:
            continue
        for m in pat.finditer(cond):
            if m.group(2).lstrip("0") == val.lstrip("0") or m.group(2) == val:
                sig = m.group(1)
                if sig not in _VERILOG_KW and not _CONST_RE.match(sig):
                    return sig
    return None

def _is_reset_cond(cond: str) -> bool:
    """Return True if the condition represents a synchronous/async reset."""
    return bool(_RESET_COND_RE.search(cond))

def _edge_conditions(edge_data: dict) -> List[str]:
    """Collect all condition strings from edge metadata."""
    conds = []
    for meta in edge_data.get("metas", []):
        c = getattr(meta, "condition", "") or ""
        if c:
            conds.append(c)
    return conds


def semanticize_constants(G: nx.DiGraph) -> nx.DiGraph:
    """
    Replace raw CONST_ nodes with semantic comparison / reset nodes.

    Transformations applied:

    control_dep edge  CONST_0x10 → target
        condition contains  ARADDR[3:0] == 4'h10
        → create node  "ARADDR == 0x10"  (node_type = "comparison")
        → rewire: ARADDR → [ARADDR == 0x10] → target
        → remove original const edge

    data_driver edge  CONST_0x0 → target
        condition contains  !(ARESETn)
        → create/reuse node  "RESET_VALUE"  (node_type = "reset_constant")
        → rewire: RESET_VALUE → target
        → remove original const edge

    data_driver edge  CONST_0b10 → BRESP
        → create node  "BRESP_SLVERR"  (named response code)

    All other unresolved const edges are kept; their node_type stays "constant".
    """
    const_nodes = [n for n in list(G.nodes)
                   if G.nodes[n].get("node_type") == "constant"]

    edges_to_remove: List[Tuple[str, str]] = []
    new_nodes:  Dict[str, dict] = {}          # node_id -> attrs
    new_edges:  List[Tuple[str, str, dict]] = []

    for cnode in const_nodes:
        hex_val = _hex_str_from_const(cnode)
        bin_val = _bin_str_from_const(cnode)
        is_zero = (hex_val == "0") or (bin_val == "0")

        for target in list(G.successors(cnode)):
            edata   = G.get_edge_data(cnode, target) or {}
            etype   = edata.get("edge_type", "")
            conds   = _edge_conditions(edata)
            mod     = edata.get("module", "")
            file_   = edata.get("file", "")
            line_   = edata.get("line")

            # ----------------------------------------------------------
            # Case 1: control_dep edge — constant appears in a comparison
            # ----------------------------------------------------------
            if etype == "control_dep":
                comp_sig = None
                for c in conds:
                    comp_sig = _find_comparison_signal(c, hex_val, bin_val)
                    if comp_sig:
                        break

                if comp_sig:
                    # Build comparison node ID + human label
                    if hex_val:
                        comp_id  = f"COMP_{comp_sig}_EQ_0x{hex_val}"
                        comp_lbl = f"{comp_sig} == 0x{hex_val}"
                    else:
                        comp_id  = f"COMP_{comp_sig}_EQ_0b{bin_val}"
                        comp_lbl = f"{comp_sig} == 0b{bin_val}"

                    new_nodes[comp_id] = dict(
                        node_type     = "comparison",
                        display_label = comp_lbl,
                        operator      = "==",
                        constant      = hex_val or bin_val,
                        source_signal = comp_sig,
                        module=mod, file=file_, line=line_,
                    )
                    # source_signal → comparison_node  (data feed)
                    if comp_sig in G:
                        new_edges.append((comp_sig, comp_id, dict(
                            edge_type="data_driver", transform="comparison",
                            module=mod, file=file_, line=line_, metas=[])))
                    # comparison_node → target  (replaces const → target)
                    ed = dict(edata); ed["edge_type"] = "control_dep"; ed["transform"] = "comparison"
                    new_edges.append((comp_id, target, ed))
                    edges_to_remove.append((cnode, target))
                    continue

            # ----------------------------------------------------------
            # Case 2: data_driver edge, zero constant, reset condition
            # ----------------------------------------------------------
            if etype == "data_driver" and is_zero:
                if any(_is_reset_cond(c) for c in conds):
                    reset_id = "RESET_VALUE"
                    new_nodes.setdefault(reset_id, dict(
                        node_type     = "reset_constant",
                        display_label = "RESET\n(0x0)",
                        value         = "0x0",
                        module=mod, file=file_, line=line_,
                    ))
                    ed2 = dict(edata); ed2["edge_type"] = "control_dep"; ed2["transform"] = "reset"
                    new_edges.append((reset_id, target, ed2))
                    edges_to_remove.append((cnode, target))
                    continue

            # ----------------------------------------------------------
            # Case 3: data_driver on binary 2-bit value → named RESP code
            # ----------------------------------------------------------
            tgt_upper = target.upper()
            if (etype == "data_driver" and bin_val is not None
                    and bin_val in _RESP_NAMES
                    and ("resp" in tgt_upper or "bresp" in tgt_upper
                         or "rresp" in tgt_upper)):
                resp_name = _RESP_NAMES[bin_val]
                resp_id   = f"RESP_{resp_name}"
                new_nodes[resp_id] = dict(
                    node_type     = "comparison",
                    display_label = f"AXI_RESP\n{resp_name} (0b{bin_val})",
                    operator      = "literal",
                    constant      = bin_val,
                    source_signal = target,
                    module=mod, file=file_, line=line_,
                )
                ed3 = dict(edata); ed3["edge_type"] = "data_driver"; ed3["transform"] = "resp_literal"
                new_edges.append((resp_id, target, ed3))
                edges_to_remove.append((cnode, target))

    # --- Apply all mutations ---
    for nid, attrs in new_nodes.items():
        if nid not in G:
            G.add_node(nid, **attrs)

    for u, v, attrs in new_edges:
        if u in G and v in G and not G.has_edge(u, v):
            G.add_edge(u, v, **attrs)

    for u, v in edges_to_remove:
        if G.has_edge(u, v):
            G.remove_edge(u, v)

    # Remove orphaned constant nodes (all edges replaced)
    for cnode in const_nodes:
        if cnode in G and G.degree(cnode) == 0:
            G.remove_node(cnode)

    return G


# ---------------------------------------------------------------------------
# Backtracking / root-cause ranking
# ---------------------------------------------------------------------------

@dataclass
class CausalStep:
    signal:    str
    parent:    Optional[str]
    transform: str
    file:      str
    line:      Optional[int]
    module:    str
    depth:     int
    edge_type: str = "data_driver"


def trace_back(
    signal: str,
    G: nx.DiGraph,
    *,
    max_depth: int = 20,
    data_only: bool = False,
) -> List[CausalStep]:
    """
    Reverse-BFS from *signal* through predecessor edges.

    Parameters
    ----------
    signal    : failing signal to start from
    G         : the DesignCausalGraph
    max_depth : maximum hop depth before stopping
    data_only : if True, only follow data_driver edges (skip control_dep)

    Returns
    -------
    List of CausalStep objects in BFS order (breadth-first, closest first).
    """
    if signal not in G:
        print(f"  [WARN] '{signal}' not found in graph "
              f"({G.number_of_nodes()} nodes)")
        return []

    visited: Set[str]    = set()
    steps:   List[CausalStep] = []
    queue    = deque()   # (node, parent, depth)
    queue.append((signal, None, 0))
    visited.add(signal)

    while queue:
        node, parent, depth = queue.popleft()

        if depth > 0:   # don't emit the start signal itself
            edge_data  = G.get_edge_data(node, parent) or {}
            transform  = edge_data.get("transform", "unknown")
            file_      = edge_data.get("file", "")
            line_      = edge_data.get("line")
            module_    = edge_data.get("module", "")
            edge_type  = edge_data.get("edge_type", "data_driver")
            steps.append(CausalStep(
                signal=node, parent=parent,
                transform=transform, file=file_, line=line_,
                module=module_, depth=depth, edge_type=edge_type,
            ))

        if depth >= max_depth:
            continue

        for pred in G.predecessors(node):
            if pred in visited:
                continue
            edge_data = G.get_edge_data(pred, node) or {}
            if data_only and edge_data.get("edge_type") == "control_dep":
                continue
            visited.add(pred)
            queue.append((pred, node, depth + 1))

    return steps


def rank_root_causes(
    steps: List[CausalStep],
    G: nx.DiGraph,
    top_n: int = _TOP_N,
) -> List[Tuple[str, float, CausalStep]]:
    """
    Score each node in the causal chain and return the top N candidates.

    Scoring:
        +3  structural / mux transform
        +2  register (nonblocking FF driver)
        +1  assign / always
        +0  control dependency arc
        -1  per hop from failing signal (distance penalty)
        +1  if the node has no further predecessors (true root / primary input)
    """
    candidates: List[Tuple[str, float, CausalStep]] = []

    for step in steps:
        base = _TRANSFORM_SCORE.get(step.transform, 0)
        dist = _DISTANCE_PENALTY * step.depth
        # Bonus: node is a source (no further predecessors in graph)
        is_root = G.in_degree(step.signal) == 0
        root_bonus = 1 if is_root else 0
        # Penalty: constants and FSM states are rarely the true RTL root cause
        node_type = G.nodes[step.signal].get("node_type", "signal")
        type_penalty = -3 if node_type == "constant" else (
                       -1 if node_type == "fsm_state" else 0)
        score = base + dist + root_bonus + type_penalty
        candidates.append((step.signal, score, step))

    # Sort: highest score first; ties broken by depth (closer preferred)
    candidates.sort(key=lambda x: (-x[1], x[2].depth))
    # Deduplicate by signal name (keep best-scored entry)
    seen: Set[str] = set()
    unique = []
    for sig, score, step in candidates:
        if sig not in seen:
            seen.add(sig)
            unique.append((sig, score, step))

    return unique[:top_n]


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------

def print_trace(signal: str, steps: List[CausalStep],
                G: Optional[nx.DiGraph] = None) -> None:
    """Print the causal chain in a readable tree format."""
    print(f"\n{'='*65}")
    print(f"  Causal chain from: {signal}")
    print(f"{'='*65}")
    if not steps:
        print("  (no upstream drivers found)")
        return

    prev_depth = 0
    for s in steps:
        indent    = "  " + ("    " * (s.depth - 1)) + "<- "
        loc       = f"{s.file}:{s.line}" if s.line else s.file
        edge_tag  = f"[ctrl]" if s.edge_type == "control_dep" else ""
        node_type = G.nodes[s.signal].get("node_type", "") if G else ""
        type_tag  = {
            "constant":  "[CONST]",
            "fsm_state": "[FSM]",
            "protocol":  "[AXI]",
        }.get(node_type, "")
        print(f"{indent}{s.signal}  ({s.transform})  {loc}  {edge_tag}{type_tag}")


def print_root_causes(
    failing: str,
    candidates: List[Tuple[str, float, CausalStep]],
    G: Optional[nx.DiGraph] = None,
) -> None:
    """Print ranked root-cause candidates."""
    print(f"\n{'='*65}")
    print(f"  Top root-cause candidates for: {failing}")
    print(f"{'='*65}")
    if not candidates:
        print("  (none found)")
        return
    for rank, (sig, score, step) in enumerate(candidates, 1):
        loc  = f"{step.file}:{step.line}" if step.line else step.file
        flag = " <- PRIMARY INPUT" if (G and G.in_degree(step.signal) == 0) else ""
        print(f"  #{rank}  score={score:+.0f}  [{step.transform:12s}]  "
              f"{sig:30s}  {loc}  (depth {step.depth}){flag}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _demo(analysis_dir: Path) -> None:
    csv_files = sorted(analysis_dir.glob("*_true_drivers.csv"))
    if not csv_files:
        print(f"No *_true_drivers.csv files found in {analysis_dir}")
        sys.exit(1)

    print(f"Loading {len(csv_files)} CSV file(s):")
    for f in csv_files:
        print(f"  {f.name}")

    G = build_graph(csv_files)
    print(f"\nDesignCausalGraph built:")
    print(f"  Nodes : {G.number_of_nodes()}")
    print(f"  Edges : {G.number_of_edges()}")

    # Signals of interest for this design
    failing_signals = ["RDATA", "BVALID", "BRESP", "wr_en", "fifo_level",
                       "AWREADY", "WREADY", "dout", "full", "empty"]

    for sig in failing_signals:
        if sig not in G:
            continue
        steps = trace_back(sig, G)
        print_trace(sig, steps)
        candidates = rank_root_causes(steps, G)
        print_root_causes(sig, candidates, G)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        analysis_dir = Path(sys.argv[1])
    else:
        # Default: user314 analysis directory
        analysis_dir = Path(
            r"C:\Users\gadap\WaveEye\outputs\user314\analysis"
        )
    _demo(analysis_dir)
