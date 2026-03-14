"""causal_graph.py
=================
Semantic violation → TransformNode embedding for the RCA causal graph.

Every WIDTH_CONSERVATION_VIOLATION or INVERTIBILITY_VIOLATION becomes a
NON_BIJECTIVE_TRANSFORM node positioned between the driving (source) signal
and its destination signal in the logic dependency graph.

The resolver traverses the enriched graph to prove whether a failing protocol
signal is causally downstream of a non-bijective transform, replacing the
coarse STRUCTURAL_UNBOUND classification with a graph-proven causal link.

Public API
----------
TransformNode             — dataclass representing one non-bijective transform
build_transform_nodes()   — convert violation dicts → List[TransformNode]
find_nonbijective_paths() — BFS from failing signals → crossed TransformNodes
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Algebraic property constants
# ---------------------------------------------------------------------------

PROP_WIDTH_LOSS      = "width_loss"        # bits are silently dropped
PROP_FABRICATED_BITS = "fabricated_bits"   # bits are synthesised from constants
PROP_DUPLICATION     = "duplication"       # one source bit fans out to many dst bits

# ---------------------------------------------------------------------------
# Violation class → eligible for TransformNode embedding
# ---------------------------------------------------------------------------

_NONBIJECTIVE_CLASSES: frozenset = frozenset({
    "WIDTH_CONSERVATION_VIOLATION",
    "INVERTIBILITY_VIOLATION",
})

# Violation subtype → algebraic property
_SUBTYPE_PROPERTY: Dict[str, str] = {
    "WIDTH_TRUNCATION":                    PROP_WIDTH_LOSS,
    "WIDTH_DUPLICATION_WITHOUT_MAPPING":   PROP_DUPLICATION,
    "WIDTH_EXTENSION_WITHOUT_SEMANTIC":    PROP_FABRICATED_BITS,
    "NON_INVERTIBLE_COLLAPSE":             PROP_WIDTH_LOSS,
    "NON_INVERTIBLE_DUPLICATION":          PROP_DUPLICATION,
    "SYNTHETIC_DATA":                      PROP_FABRICATED_BITS,
    "INFORMATION_LOSS":                    PROP_WIDTH_LOSS,
}

_IDENT_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')
_KW: frozenset = frozenset({
    "and", "or", "not", "if", "else", "begin", "end",
    "true", "false", "posedge", "negedge", "reg", "wire",
    "input", "output", "inout", "assign",
})


# ---------------------------------------------------------------------------
# TransformNode
# ---------------------------------------------------------------------------

@dataclass
class TransformNode:
    """
    A non-bijective RTL data transform extracted from a semantic violation.

    Algebraic contract (always set by the constructor):
        bijective         = False
        entropy_preserved = False
        reversible        = False

    Graph embedding:
        source_signal --> [ TransformNode ] --> lhs
    """
    node_id:           str
    lhs:               str              # destination signal (LHS of the RTL assignment)
    rhs:               str              # source signal or expression driving lhs
    property:          str              # PROP_WIDTH_LOSS | PROP_FABRICATED_BITS | PROP_DUPLICATION
    bijective:         bool = False
    entropy_preserved: bool = False
    reversible:        bool = False
    source_location:   str  = ""
    rtl_line:          Optional[int] = None
    always_block_id:   Optional[int] = None
    violation:         Dict[str, Any] = field(default_factory=dict)

    def to_graph_node(self) -> Dict[str, Any]:
        """Serialise to a graph-node dict compatible with build_dependency_graph output."""
        return {
            "id":                self.node_id,
            "type":              "NON_BIJECTIVE_TRANSFORM",
            "label": (
                f"{self.lhs} <- [NON_BIJECTIVE:{self.property}] "
                f"{self.rhs[:60]}"
            ),
            "lhs":               self.lhs,
            "rhs":               self.rhs,
            "property":          self.property,
            "bijective":         self.bijective,
            "entropy_preserved": self.entropy_preserved,
            "reversible":        self.reversible,
            "source_location":   self.source_location,
            "rtl_line":          self.rtl_line,
            "always_block_id":   self.always_block_id,
            "violation":         self.violation,
        }


# ---------------------------------------------------------------------------
# Violation → TransformNode conversion
# ---------------------------------------------------------------------------

def _violation_to_transform(
    v: Dict[str, Any],
    node_id: str,
) -> Optional[TransformNode]:
    """
    Convert a single datapath violation dict to a TransformNode.
    Returns None if the violation class is not eligible.
    """
    cls = v.get("class", "")
    if cls not in _NONBIJECTIVE_CLASSES:
        return None

    subtype = v.get("subtype", "")
    prop    = _SUBTYPE_PROPERTY.get(subtype, PROP_WIDTH_LOSS)

    if cls == "WIDTH_CONSERVATION_VIOLATION":
        lhs = v.get("destination_signal") or v.get("lhs") or ""
        rhs = v.get("source_signal")      or v.get("rhs") or ""
    else:
        # INVERTIBILITY_VIOLATION: lhs is the LHS field; rhs is the full expression
        lhs = v.get("lhs") or ""
        rhs = v.get("rhs") or ""
        # Simplify rhs to the leading identifier (first signal name)
        if rhs:
            m = _IDENT_RE.match(rhs.lstrip("{("))
            if m and m.group(1).lower() not in _KW:
                rhs = m.group(1)

    if not lhs:
        return None

    return TransformNode(
        node_id          = node_id,
        lhs              = lhs,
        rhs              = rhs,
        property         = prop,
        bijective        = False,
        entropy_preserved= False,
        reversible       = False,
        source_location  = v.get("source", ""),
        rtl_line         = v.get("rtl_line"),
        always_block_id  = v.get("always_block_id"),
        violation        = v,
    )


def build_transform_nodes(
    datapath_violations: List[Dict[str, Any]],
) -> List[TransformNode]:
    """
    Convert every eligible semantic violation to a TransformNode.

    Eligible classes:
        WIDTH_CONSERVATION_VIOLATION  (subtypes: TRUNCATION, DUPLICATION, EXTENSION)
        INVERTIBILITY_VIOLATION       (subtypes: COLLAPSE, DUPLICATION, SYNTHETIC_DATA,
                                                  INFORMATION_LOSS)

    Each TransformNode carries the algebraic contract:
        bijective         = False
        entropy_preserved = False
        reversible        = False

    Graph embedding:
        rhs_source → TransformNode → lhs_destination

    Returns a list of TransformNodes, one per qualifying violation.
    """
    nodes: List[TransformNode] = []
    for idx, v in enumerate(datapath_violations):
        tn = _violation_to_transform(v, node_id=f"tn_{idx}")
        if tn is not None:
            nodes.append(tn)
    return nodes


# ---------------------------------------------------------------------------
# Signal reachability via the logic_table (driver graph BFS)
# ---------------------------------------------------------------------------

def _reachable_from(
    start: str,
    logic_table: Dict[str, List[Dict[str, Any]]],
    max_depth: int = 10,
) -> Set[str]:
    """
    BFS backward through the logic_table driver graph from *start*.

    Collects every signal name (lowercase, index-stripped) that the start
    signal transitively depends on.  This is used to determine whether any
    TransformNode's destination (lhs) is reachable from a failing protocol
    signal.
    """

    def _norm(name: str) -> str:
        return re.sub(r'\[.*', '', name).lower().strip()

    def _find_key(sig: str) -> Optional[str]:
        key = _norm(sig)
        if key in logic_table:
            return key
        for k in logic_table:
            if _norm(k) == key:
                return k
        return None

    visited: Set[str] = set()
    frontier: List[str] = [_norm(start)]

    for _ in range(max_depth):
        if not frontier:
            break
        next_frontier: List[str] = []
        for sig in frontier:
            if sig in visited:
                continue
            visited.add(sig)
            key = _find_key(sig)
            if key is None:
                continue
            for drv in (logic_table.get(key) or []):
                for text in (str(drv.get("rhs") or ""), str(drv.get("cond") or "")):
                    for m in _IDENT_RE.finditer(text):
                        name = m.group(1)
                        if name.lower() not in _KW:
                            norm = _norm(name)
                            if norm not in visited:
                                next_frontier.append(norm)
        frontier = next_frontier

    return visited


# ---------------------------------------------------------------------------
# Find NON_BIJECTIVE_TRANSFORM nodes upstream of failing signals
# ---------------------------------------------------------------------------

def find_nonbijective_paths(
    logic_table: Dict[str, List[Dict[str, Any]]],
    failing_signals: Set[str],
    transform_nodes: List[TransformNode],
    max_depth: int = 10,
) -> List[TransformNode]:
    """
    Determine which TransformNodes are causally upstream of at least one
    failing protocol signal via the logic_table dependency graph.

    Algorithm:
      1. BFS backward from each failing signal through the driver graph,
         collecting all transitively-needed signal names.
      2. A TransformNode is "crossed" if its lhs (destination) appears in
         the reachable set — meaning the failing signal depends on data that
         passed through a NON_BIJECTIVE_TRANSFORM.
      3. Deduplicate by lhs; return crossed nodes in discovery order.

    Args:
        logic_table:      driver table {signal_name -> [{rhs, cond, ...}]}
        failing_signals:  set of protocol-failing signal names (from findings)
        transform_nodes:  list produced by build_transform_nodes()
        max_depth:        BFS depth cap (default 10)

    Returns:
        Ordered list of TransformNodes causally upstream of any failing signal.
        Empty list if no path exists.
    """
    if not transform_nodes or not failing_signals or not logic_table:
        return []

    # Union of all signals reachable (depended-on) from any failing signal
    reachable: Set[str] = set()
    for sig in failing_signals:
        reachable |= _reachable_from(sig, logic_table, max_depth)
        # Include the failing signal itself (in case it IS the lhs of a transform)
        reachable.add(re.sub(r'\[.*', '', sig).lower().strip())

    crossed: List[TransformNode] = []
    seen_lhs: Set[str] = set()
    for tn in transform_nodes:
        lhs_norm = re.sub(r'\[.*', '', tn.lhs).lower().strip()
        if lhs_norm in reachable and lhs_norm not in seen_lhs:
            crossed.append(tn)
            seen_lhs.add(lhs_norm)

    return crossed
