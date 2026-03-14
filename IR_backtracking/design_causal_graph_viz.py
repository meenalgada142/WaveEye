"""
design_causal_graph_viz.py
==========================
Generates an interactive HTML visualisation of the DesignCausalGraph.

Produces two outputs in the analysis directory:
  causal_graph.html      — interactive Pyvis network (open in browser)
  causal_graph_<sig>.html — per-signal subgraph centred on a failing signal

Usage
-----
    python design_causal_graph_viz.py [analysis_dir] [failing_signal]

    # Default: user314 analysis dir, all key signals
    python design_causal_graph_viz.py

    # Specific signal
    python design_causal_graph_viz.py C:/path/to/analysis RDATA

Dependencies
------------
    pip install networkx pyvis
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import networkx as nx

# ---------------------------------------------------------------------------
# Import graph builder from companion module
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))
from design_causal_graph import (
    build_graph,
    trace_back,
    rank_root_causes,
    _TOP_N,
)

# ---------------------------------------------------------------------------
# Colour / style palettes
# ---------------------------------------------------------------------------

# Primary colours by node_type (Step 4 of spec)
_NODE_COLOUR_BY_TYPE = {
    "signal":         "#b2bec3",   # light grey    — regular RTL signal
    "protocol":       "#00b894",   # teal/green    — AXI protocol signal
    "fsm_state":      "#0984e3",   # blue          — FSM state
    "constant":       "#636e72",   # dark grey     — hex/binary constant
    "comparison":     "#fd79a8",   # pink/rose     — SIGNAL == VALUE comparison node
    "reset_constant": "#55efc4",   # mint green    — RESET_VALUE node
    "unknown":        "#dfe6e9",   # near-white    — unclassified
}

# Secondary colours by transform type (used when node_type == "signal")
_NODE_COLOUR_BY_TRANSFORM = {
    "register":   "#e17055",   # salmon-red   — clocked FF
    "structural": "#e67e22",   # orange       — structural assign
    "mux":        "#f39c12",   # amber        — mux/ternary
    "always":     "#74b9ff",   # sky blue     — combinational always
    "assign":     "#a29bfe",   # lavender     — continuous assign
    "control":    "#95a5a6",   # grey         — condition dependency
    "unknown":    "#dfe6e9",   # near-white
}

_FAILING_COLOUR   = "#d63031"  # vivid red    — the queried failing signal
_ROOTCAUSE_COLOUR = "#6c5ce7"  # vivid purple — top root-cause candidates

# Edge colours
_EDGE_COLOUR = {
    "data_driver": "#fdcb6e",   # warm amber — causal data edge
    "control_dep": "#636e72",   # dark grey  — guard condition dependency
}


def _node_colour(G: nx.DiGraph, node: str, failing: Optional[str],
                 root_set: set) -> str:
    """
    Priority: failing > root-cause > node_type > transform fallback.
    For "signal" nodes, use the transform colour so clocked FFs stand out.
    """
    if node == failing:
        return _FAILING_COLOUR
    if node in root_set:
        return _ROOTCAUSE_COLOUR

    ndata     = G.nodes[node]
    node_type = ndata.get("node_type", "unknown")

    if node_type == "signal":
        transform = ndata.get("transform", "unknown")
        return _NODE_COLOUR_BY_TRANSFORM.get(
            transform, _NODE_COLOUR_BY_TRANSFORM["unknown"])

    return _NODE_COLOUR_BY_TYPE.get(node_type, _NODE_COLOUR_BY_TYPE["unknown"])


def _node_size(G: nx.DiGraph, node: str, failing: Optional[str],
               root_set: set) -> int:
    if node == failing:
        return 40
    if node in root_set:
        return 30
    node_type = G.nodes[node].get("node_type", "signal")
    if node_type == "constant":
        return 10          # constants: small and unobtrusive
    if node_type == "fsm_state":
        return 20          # FSM states: medium
    # signals/protocol: scale by out-degree (more downstream impact → bigger)
    return max(15, min(28, 15 + G.out_degree(node) * 2))


def _node_label(G: nx.DiGraph, node: str) -> str:
    """
    Contextual label based on node_type:
      signal    → "signal_name\n(module)"
      protocol  → "SIGNAL_NAME\n[AXI]"
      fsm_state → "STATE_NAME\n(fsm_signal)"
      constant  → "CONST_0x.."  (no extra context — name says it all)
    """
    ndata     = G.nodes[node]
    node_type = ndata.get("node_type", "signal")

    if node_type == "constant":
        return node

    if node_type == "comparison":
        # Use display_label like "latched == 0b1" or the node ID
        return ndata.get("display_label", node)

    if node_type == "reset_constant":
        return ndata.get("display_label", "RESET\n(0x0)")

    if node_type == "fsm_state":
        # Use precomputed display_label if present
        return ndata.get("display_label", node)

    if node_type == "protocol":
        return f"{node}\n[AXI]"

    # default: signal + module
    module = ndata.get("module", "")
    return f"{node}\n({module})" if module else node


def _edge_title(G: nx.DiGraph, u: str, v: str) -> str:
    """Tooltip shown on hover over an edge."""
    data = G.get_edge_data(u, v) or {}
    etype = data.get("edge_type", "")
    xform = data.get("transform", "")
    file_ = data.get("file", "")
    line_ = data.get("line", "")
    loc   = f"{file_}:{line_}" if line_ else file_
    return f"{u} -> {v}\n{etype} | {xform}\n{loc}"


# ---------------------------------------------------------------------------
# Full-graph render
# ---------------------------------------------------------------------------

def render_full_graph(G: nx.DiGraph, out_path: Path) -> None:
    """Render the entire DesignCausalGraph as an interactive HTML file."""
    try:
        from pyvis.network import Network
    except ImportError:
        print("[SKIP] pyvis not installed — run: pip install pyvis")
        return

    net = Network(
        height="900px", width="100%",
        directed=True,
        bgcolor="#1a1a2e",
        font_color="#ecf0f1",
        notebook=False,
    )
    net.set_options("""
    {
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -8000,
          "centralGravity": 0.3,
          "springLength": 120,
          "springConstant": 0.04,
          "damping": 0.09
        },
        "minVelocity": 0.75
      },
      "edges": {
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.6 } },
        "smooth": { "type": "curvedCW", "roundness": 0.15 }
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 100,
        "navigationButtons": true,
        "keyboard": true
      }
    }
    """)

    for node in G.nodes:
        colour    = _node_colour(G, node, None, set())
        size      = _node_size(G, node, None, set())
        module    = G.nodes[node].get("module", "")
        file_     = G.nodes[node].get("file", "")
        line_     = G.nodes[node].get("line", "")
        transform = G.nodes[node].get("transform", "")
        tooltip   = (f"Signal: {node}\nModule: {module}\n"
                     f"Transform: {transform}\nLoc: {file_}:{line_}")
        net.add_node(
            node,
            label=_node_label(G, node),
            color=colour,
            size=size,
            title=tooltip,
            font={"size": 11, "color": "#ecf0f1"},
        )

    for u, v, data in G.edges(data=True):
        colour = _EDGE_COLOUR.get(data.get("edge_type", ""), "#7f8c8d")
        dashes = data.get("edge_type") == "control_dep"
        net.add_edge(
            u, v,
            color=colour,
            dashes=dashes,
            title=_edge_title(G, u, v),
            width=2 if not dashes else 1,
        )

    net.write_html(str(out_path))
    print(f"[OK] Full graph   -> {out_path}")


# ---------------------------------------------------------------------------
# Per-signal subgraph render
# ---------------------------------------------------------------------------

def render_signal_subgraph(
    G: nx.DiGraph,
    failing: str,
    out_path: Path,
    max_depth: int = 10,
) -> None:
    """
    Render a subgraph showing only the causal ancestors of *failing*,
    highlighting the failing signal and top root-cause candidates.
    """
    try:
        from pyvis.network import Network
    except ImportError:
        print("[SKIP] pyvis not installed — run: pip install pyvis")
        return

    if failing not in G:
        print(f"  [WARN] '{failing}' not in graph — skipping subgraph")
        return

    # Collect nodes in the subgraph via trace_back
    steps    = trace_back(failing, G, max_depth=max_depth)
    top_cands = rank_root_causes(steps, G, top_n=_TOP_N)
    root_set  = {sig for sig, _, _ in top_cands}

    subgraph_nodes = {failing} | {s.signal for s in steps}
    SG = G.subgraph(subgraph_nodes)

    net = Network(
        height="900px", width="100%",
        directed=True,
        bgcolor="#0f0f23",
        font_color="#ecf0f1",
        notebook=False,
    )
    net.set_options("""
    {
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -10000,
          "centralGravity": 0.4,
          "springLength": 150,
          "springConstant": 0.05,
          "damping": 0.09
        },
        "minVelocity": 0.75
      },
      "edges": {
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.7 } },
        "smooth": { "type": "curvedCW", "roundness": 0.2 }
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 80,
        "navigationButtons": true,
        "keyboard": true
      }
    }
    """)

    # Build depth map for border highlighting
    depth_map = {failing: 0}
    for s in steps:
        depth_map[s.signal] = s.depth

    for node in SG.nodes:
        colour    = _node_colour(SG, node, failing, root_set)
        size      = _node_size(SG, node, failing, root_set)
        depth     = depth_map.get(node, 0)
        module    = SG.nodes[node].get("module", "")
        file_     = SG.nodes[node].get("file", "")
        line_     = SG.nodes[node].get("line", "")
        transform = SG.nodes[node].get("transform", "")

        if node == failing:
            label   = f"FAILING\n{node}"
            border  = "#ff0000"
            bwidth  = 4
        elif node in root_set:
            rank    = next(i+1 for i, (s,_,_) in enumerate(top_cands)
                          if s == node)
            score   = next(sc for s, sc, _ in top_cands if s == node)
            label   = f"ROOT #{rank}\n{node}\nscore={score:+.0f}"
            border  = "#9b59b6"
            bwidth  = 3
        else:
            label   = _node_label(SG, node)
            border  = colour
            bwidth  = 1

        node_type = SG.nodes[node].get("node_type", "signal")
        fsm_par   = SG.nodes[node].get("fsm_parents", [])
        tooltip = (
            f"Signal   : {node}\n"
            f"Type     : {node_type}"
            + (f"  (FSM: {', '.join(fsm_par)})" if fsm_par else "") + "\n"
            f"Module   : {module}\n"
            f"Transform: {transform}\n"
            f"Depth    : {depth} hops from {failing}\n"
            f"Loc      : {file_}:{line_}"
        )

        net.add_node(
            node,
            label=label,
            color={"background": colour, "border": border,
                   "highlight": {"background": "#f1c40f", "border": "#e67e22"}},
            size=size,
            title=tooltip,
            borderWidth=bwidth,
            font={"size": 12, "color": "#ecf0f1",
                  "bold": node == failing or node in root_set},
        )

    for u, v, data in SG.edges(data=True):
        colour = _EDGE_COLOUR.get(data.get("edge_type", ""), "#7f8c8d")
        dashes = data.get("edge_type") == "control_dep"
        net.add_edge(
            u, v,
            color=colour,
            dashes=dashes,
            title=_edge_title(SG, u, v),
            width=2 if not dashes else 1,
        )

    # Node-type breakdown for legend
    type_counts: dict = {}
    for n in SG.nodes:
        t = SG.nodes[n].get("node_type", "signal")
        type_counts[t] = type_counts.get(t, 0) + 1

    def _legend_row(colour: str, label: str, count: int) -> str:
        return (f'<span style="color:{colour};">&#9679;</span> '
                f'{label} <span style="color:#aaa;">({count})</span><br>')

    legend_html = f"""
    <div style="position:fixed;top:10px;right:10px;background:rgba(0,0,0,0.82);
                color:#ecf0f1;padding:14px 18px;border-radius:10px;font-size:12px;
                font-family:monospace;z-index:9999;min-width:220px;
                border:1px solid #555;">
      <b style="font-size:13px;">Causal Subgraph</b><br>
      <span style="color:#aaa;font-size:11px;">{failing}</span>
      <hr style="border-color:#444;margin:6px 0;">
      {_legend_row(_FAILING_COLOUR,   "Failing signal",        1)}
      {_legend_row(_ROOTCAUSE_COLOUR, "Root-cause candidates", len(top_cands))}
      <hr style="border-color:#444;margin:6px 0;">
      {_legend_row(_NODE_COLOUR_BY_TYPE['protocol'],       "AXI protocol signal",  type_counts.get('protocol',0))}
      {_legend_row(_NODE_COLOUR_BY_TYPE['fsm_state'],      "FSM state",            type_counts.get('fsm_state',0))}
      {_legend_row(_NODE_COLOUR_BY_TRANSFORM['register'],  "Register (FF)",        type_counts.get('signal',0))}
      {_legend_row(_NODE_COLOUR_BY_TRANSFORM['structural'], "Structural assign",   0)}
      {_legend_row(_NODE_COLOUR_BY_TYPE['comparison'],     "Comparison (==)",      type_counts.get('comparison',0))}
      {_legend_row(_NODE_COLOUR_BY_TYPE['reset_constant'], "Reset value",          type_counts.get('reset_constant',0))}
      {_legend_row(_NODE_COLOUR_BY_TYPE['constant'],       "Constant literal",     type_counts.get('constant',0))}
      <hr style="border-color:#444;margin:6px 0;">
      <span style="color:{_EDGE_COLOUR['data_driver']};">&#9135;&#9135;</span>
        Data driver edge<br>
      <span style="color:{_EDGE_COLOUR['control_dep']};">- -</span>
        Control dependency<br>
      <hr style="border-color:#444;margin:6px 0;">
      <span style="color:#aaa;">Nodes: {SG.number_of_nodes()} &nbsp;
      Edges: {SG.number_of_edges()}</span>
    </div>
    """

    # Write HTML then inject legend before </body>
    html_str = net.generate_html()
    html_str = html_str.replace("</body>", legend_html + "\n</body>")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_str)

    print(f"[OK] Subgraph ({failing:20s}) -> {out_path.name}")
    print(f"     Nodes: {SG.number_of_nodes()}  Edges: {SG.number_of_edges()}")
    if top_cands:
        print(f"     Top root causes:")
        for rank, (sig, score, step) in enumerate(top_cands, 1):
            print(f"       #{rank} {sig}  (score={score:+.0f}, depth={step.depth})")


# ---------------------------------------------------------------------------
# CLI / demo
# ---------------------------------------------------------------------------

def _demo(analysis_dir: Path, target_signal: Optional[str] = None) -> None:
    csv_files = sorted(analysis_dir.glob("*_true_drivers.csv"))
    if not csv_files:
        print(f"No *_true_drivers.csv files found in {analysis_dir}")
        sys.exit(1)

    print(f"Loading {len(csv_files)} CSV file(s):")
    for f in csv_files:
        print(f"  {f.name}")

    G = build_graph(csv_files)
    print(f"\nDesignCausalGraph: {G.number_of_nodes()} nodes, "
          f"{G.number_of_edges()} edges\n")

    out_dir = analysis_dir

    # Full graph
    render_full_graph(G, out_dir / "causal_graph.html")

    # Per-signal subgraphs
    if target_signal:
        signals = [target_signal]
    else:
        # Default: key AXI / FIFO output signals
        signals = [
            "RDATA", "BVALID", "BRESP", "AWREADY", "WREADY",
            "wr_en", "fifo_level", "dout", "full", "empty",
        ]

    print()
    for sig in signals:
        if sig not in G:
            print(f"  [SKIP] '{sig}' not in graph")
            continue
        safe  = sig.replace("/", "_").replace(":", "_")
        opath = out_dir / f"causal_graph_{safe}.html"
        render_signal_subgraph(G, sig, opath)

    print(f"\nAll graphs written to: {out_dir}")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        analysis_dir   = Path(sys.argv[1])
        target_signal  = sys.argv[2] if len(sys.argv) >= 3 else None
    else:
        analysis_dir   = Path(r"C:\Users\gadap\WaveEye\outputs\user314\analysis")
        target_signal  = None

    _demo(analysis_dir, target_signal)
