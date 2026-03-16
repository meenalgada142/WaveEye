"""
Console Diagnosis — Precision RTL Root-Cause Report
====================================================
Produces a ≤15-line enterprise-grade diagnostic block suitable for
senior RTL engineers and verification leads.

Features:
  PART 2 — Canonical AXI4-Lite rule names (no numeric RULE_N in default output)
  PART 5 — Confidence score computed from structural proof, binding, transaction count
  PART 6 — Multi-line labelled format: Primary Failure / Root Cause / Severity /
            Transactions Affected / Confidence / Next Step
  PART 7 — Clean PASS block when no defects detected

Extraction rules:
  - If >10 violations reference the same storage element, treat as ONE defect.
  - Prefer storage element over individual assignments.
  - If protocol failure depends on datapath defect, append:
    "Protocol symptom caused by datapath defect."

Usage:
    from reports.console_diagnosis import generate_console_diagnosis
    print(generate_console_diagnosis(payload))
"""

from __future__ import annotations

from collections import Counter
import re
from typing import Any, Dict, List, Optional

try:
    from protocols.axi_lite.signal_map import RULE_STABILITY_SIGNAL_MAP as _STABILITY_SIGNAL_MAP
except ImportError:
    _STABILITY_SIGNAL_MAP = {}

try:
    from rca_core.deep_backtrack import format_dependency_graph as _format_dependency_graph
except ImportError:
    _format_dependency_graph = None

_BAR        = "─" * 64
_TRACE_BAR  = "─" * 64
_TITLE      = "WaveEye Diagnostic Summary"
_PASS       = "WaveEye Result"

# ── Rule → (direction, request_signal, response_signal) ──────────────────────

_RULE_DIRECTION: Dict[str, tuple] = {
    # (direction, request_signal, response_signal)
    # ── Address / control stability ─────────────────────────────────────
    "RULE_1":  ("read/write", "ARVALID/AWVALID", "ARREADY/AWREADY"),
    "RULE_14": ("read",       "ARVALID",          "ARREADY"),
    "RULE_15": ("write",      "AWVALID",           "AWREADY"),
    # ── VALID persistence ────────────────────────────────────────────────
    "RULE_2":  ("read",   "ARVALID", "ARREADY"),
    "RULE_3":  ("write",  "AWVALID", "AWREADY"),
    "RULE_4":  ("write",  "WVALID",  "WREADY"),
    "RULE_5":  ("read",   "RVALID",  "RREADY"),
    "RULE_6":  ("write",  "BVALID",  "BREADY"),
    # ── Data / response stability ────────────────────────────────────────
    "RULE_7":  ("write",  "WVALID",  "WREADY"),
    "RULE_8":  ("read",   "RVALID",  "RREADY"),
    "RULE_9":  ("write",  "BVALID",  "BREADY"),
    # ── Response ordering / liveness ─────────────────────────────────────
    "RULE_10": ("read",   "ARVALID", "RVALID"),
    "RULE_11": ("write",  "AWVALID", "BVALID"),
    "RULE_12": ("read",   "ARVALID", "RVALID"),
    "RULE_13": ("write",  "AWVALID", "BVALID"),
}

# When the finding carries expected_signal in its evidence, that always
# overrides the rule-direction fallback above for exp_sig.

# ── Violation type per rule (determines Step-2 message) ───────────────────────
# MISSING     : response signal never asserted in the observation window
# UNPROMPTED  : response signal asserted without the required prior transaction
# PERSISTENCE : VALID signal dropped before handshake completed
# STABILITY   : signal value changed while VALID was asserted (before READY)
_RULE_VIOLATION_TYPE: Dict[str, str] = {
    "RULE_1":  "STABILITY",    # ARADDR/AWADDR changed while VALID=1
    "RULE_2":  "PERSISTENCE",  # ARVALID dropped before ARREADY
    "RULE_3":  "PERSISTENCE",  # AWVALID dropped before AWREADY
    "RULE_4":  "PERSISTENCE",  # WVALID  dropped before WREADY
    "RULE_5":  "PERSISTENCE",  # RVALID  dropped before RREADY
    "RULE_6":  "PERSISTENCE",  # BVALID  dropped before BREADY
    "RULE_7":  "STABILITY",    # WDATA/WSTRB changed while WVALID=1
    "RULE_8":  "STABILITY",    # RDATA/RRESP changed while RVALID=1
    "RULE_9":  "STABILITY",    # BRESP changed while BVALID=1
    "RULE_10": "UNPROMPTED",   # RVALID asserted without prior AR handshake
    "RULE_11": "UNPROMPTED",   # BVALID asserted without prior AW+W handshake
    "RULE_12": "MISSING",      # Read response never received
    "RULE_13": "MISSING",      # Write response never received
    "RULE_14": "STABILITY",    # ARPROT changed during AR backpressure
    "RULE_15": "STABILITY",    # AWPROT changed during AW backpressure
}

# ── Canonical rule name mapping (PART 2) ──────────────────────────────────────
# Derived directly from axil4.py rule definitions.
# Format: (canonical_id, amba_spec_section)

_RULE_CANON: Dict[str, tuple] = {
    # Address / control stability
    "RULE_1":  ("AXI4L_ADDR_STABILITY",           "AXI4-Lite Spec §A3.1.2"),
    "RULE_14": ("AXI4L_ARPROT_STABILITY",          "AXI4-Lite Spec §A3.2.1"),
    "RULE_15": ("AXI4L_AWPROT_STABILITY",          "AXI4-Lite Spec §A3.2.1"),
    # VALID persistence (§A3.1.2 — VALID must hold until READY)
    "RULE_2":  ("AXI4L_ARVALID_PERSISTENCE",       "AXI4-Lite Spec §A3.1.2"),
    "RULE_3":  ("AXI4L_AWVALID_PERSISTENCE",       "AXI4-Lite Spec §A3.1.2"),
    "RULE_4":  ("AXI4L_WVALID_PERSISTENCE",        "AXI4-Lite Spec §A3.1.2"),
    "RULE_5":  ("AXI4L_RVALID_PERSISTENCE",        "AXI4-Lite Spec §A3.1.2"),
    "RULE_6":  ("AXI4L_BVALID_PERSISTENCE",        "AXI4-Lite Spec §A3.1.2"),
    # Data/response stability (signal must not change between VALID and handshake)
    "RULE_7":  ("AXI4L_WDATA_STABILITY",           "AXI4-Lite Spec §A3.2.1"),
    "RULE_8":  ("AXI4L_RDATA_STABILITY",           "AXI4-Lite Spec §A3.3.1"),
    "RULE_9":  ("AXI4L_BRESP_STABILITY",           "AXI4-Lite Spec §A3.2.2"),
    # Response ordering (must not fire without prior accepted transaction)
    "RULE_10": ("AXI4L_RVALID_UNPROMPTED",         "AXI4-Lite Spec §A3.3.1"),
    "RULE_11": ("AXI4L_BVALID_UNPROMPTED",         "AXI4-Lite Spec §A3.2.2"),
    # Response liveness (slave must eventually respond)
    "RULE_12": ("AXI4L_READ_RESPONSE_MISSING",     "AXI4-Lite Spec §A3.3.1"),
    "RULE_13": ("AXI4L_WRITE_RESPONSE_MISSING",    "AXI4-Lite Spec §A3.2.1"),
}

_SEVERITY: Dict[str, str] = {
    "TRANSPORT":          "Functional corruption — data integrity failure",
    "DATAPATH":           "Functional corruption — data integrity failure",
    "SEMANTIC_STRUCTURAL":"Structural defect — non-deterministic memory state",
    "PROTOCOL":           "Handshake violation — AXI compliance failure",
    "INCONCLUSIVE":       "Undetermined — additional inputs required",
}


# ── New report helpers ──────────────────────────────────────────────────────────

def _resolve_val_str(sig: str, val: Any, chain: list) -> str:
    """Format a signal value, resolving FSM state names from the condition chain."""
    if val is None:
        return "?"
    for step in (chain or []):
        if step.get("signal", "").upper() == sig.upper():
            rhs = (step.get("active_driver_rhs") or "").strip()
            if rhs and not rhs.isdigit() and rhs not in ("0", "1", "1'b0", "1'b1"):
                return rhs
    try:
        return str(int(val))
    except (TypeError, ValueError):
        return str(val)


def _rtl_location_parts(loc: Any, rtl_line: Any = None) -> tuple[str, str]:
    """Return normalized RTL location text and an explicit line number string."""
    text = str(loc or "").strip()
    line = ""
    if rtl_line not in (None, ""):
        line = str(rtl_line).strip()
    if text and not line:
        match = re.search(r":(\d+)(?::\d+)?$", text)
        if match:
            line = match.group(1)
    return text, line


def _finding_rtl_location(finding: Dict[str, Any]) -> str:
    """Best-effort RTL location for a single protocol finding."""
    ev = finding.get("evidence") or {}
    for key in ("source_location", "rtl_location", "source"):
        loc = ev.get(key)
        if loc:
            return str(loc)
    dg = ev.get("dependency_graph") or {}
    for node in dg.get("nodes") or []:
        if node.get("type") == "driver" and node.get("source_location"):
            return str(node["source_location"])
    return ""


def _group_findings_by_rule(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings by rule_id while preserving first-seen order."""
    grouped: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "UNKNOWN").upper()
        if rule_id not in grouped:
            grouped[rule_id] = {
                "rule_id": rule_id,
                "rep": finding,
                "cycles": [],
                "signals": [],
                "count": 0,
            }
            order.append(rule_id)
        bucket = grouped[rule_id]
        bucket["count"] += 1
        cyc = finding.get("analysis_cycle", finding.get("cycle"))
        if cyc not in bucket["cycles"]:
            bucket["cycles"].append(cyc)
        sig = finding.get("signal")
        if sig and sig not in bucket["signals"]:
            bucket["signals"].append(sig)
    return [grouped[rule_id] for rule_id in order]


def _rule_level_rca_summary(
    rule_id: str,
    rep: Dict[str, Any],
    *,
    primary_rule_id: str,
    root_type: str,
    storage: str,
    dv: List[Dict[str, Any]],
    tv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    pev0: Dict[str, Any],
) -> str:
    """Compact RCA sentence for one unique violation rule."""
    if rule_id == primary_rule_id:
        return _root_cause_desc(root_type, storage, dv, tv, rca, pev0)
    sig = rep.get("signal") or (rep.get("evidence") or {}).get("expected_signal") or "signal"
    _RULE_SUMMARIES = {
        "RULE_2":  f"{sig} dropped before ARREADY completed the handshake.",
        "RULE_3":  f"{sig} dropped before AWREADY completed the handshake.",
        "RULE_4":  f"{sig} dropped before WREADY completed the handshake.",
        "RULE_5":  f"{sig} dropped before RREADY completed the handshake.",
        "RULE_6":  f"{sig} dropped before BREADY completed the handshake.",
        "RULE_10": f"{sig} asserted before the required read-address handshake completed.",
        "RULE_11": f"{sig} asserted before the required write-address and write-data handshakes completed.",
        "RULE_12": f"{sig} never arrived after the read-address handshake.",
        "RULE_13": f"{sig} never arrived after the write transaction completed.",
    }
    if rule_id in _RULE_SUMMARIES:
        return _RULE_SUMMARIES[rule_id]
    detail = str(rep.get("detail") or "").strip()
    if detail:
        return detail
    return f"{sig} violates {rule_id}."


# AXI signal canonical role descriptions (suffix-matched, case-insensitive)
_AXI_SIGNAL_ROLES: Dict[str, str] = {
    "arvalid":  "ARVALID  — master: read address valid",
    "arready":  "ARREADY  — slave:  read address accepted",
    "araddr":   "ARADDR   — master: read address",
    "awvalid":  "AWVALID  — master: write address valid",
    "awready":  "AWREADY  — slave:  write address accepted",
    "awaddr":   "AWADDR   — master: write address",
    "wvalid":   "WVALID   — master: write data valid",
    "wready":   "WREADY   — slave:  write data accepted",
    "wdata":    "WDATA    — master: write data payload",
    "wstrb":    "WSTRB    — master: write byte strobes",
    "bvalid":   "BVALID   — slave:  write response valid",
    "bready":   "BREADY   — master: write response accepted",
    "bresp":    "BRESP    — slave:  write response code",
    "rvalid":   "RVALID   — slave:  read data valid",
    "rready":   "RREADY   — master: read data accepted",
    "rdata":    "RDATA    — slave:  read data payload",
    "rresp":    "RRESP    — slave:  read response code",
}

_SKIP_SIGNALS = frozenset({"rst", "reset", "rst_n", "aresetn", "areset_n", "clk", "clock",
                            "pipeline_output", "addr_width", "data_width", "strb_width",
                            "word_size", "word_width", "valid_addr_width"})


def _axi_role(sig: str) -> str:
    """Return 'SIG [role]' if sig is a known AXI signal, else just sig."""
    s = sig.lower()
    for suffix, role in _AXI_SIGNAL_ROLES.items():
        if s == suffix or s.endswith("_" + suffix):
            return f"{sig}  [{role}]"
    return sig


def _is_noise(sig: str) -> bool:
    s = sig.lower()
    return s in _SKIP_SIGNALS or s.startswith("pipeline_") or s.isdigit()


def _driver_role(rhs: str, cond: str) -> str:
    """Classify what a driver does to its signal."""
    rhs = rhs.strip()
    if rhs in ("1", "1'b1", "1'h1"):
        return "ASSERTS"
    if rhs in ("0", "1'b0", "1'h0"):
        return "RESETS"
    cond_low = cond.strip().lower()
    if not cond or cond_low in ("", "1", "true", "1'b1"):
        # Unconditional → pure pass-through or hold expression
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', rhs):
            return "PASSES"
    return "HOLDS"


_VIOLATION_MODE: Dict[str, str] = {
    # Mode A — NBA scheduling conflict: ASSERT fires but gets overwritten in same cycle
    # Detected by rca_8 SCHEDULING_CANCELLATION / DESIGN_STRUCTURAL_BLOCKAGE mechanism
    # Note: RULE_12/13 may land here when the conflict is proven by rca_8
    # Mode B — Valid persistence: VALID asserted then dropped before handshake
    "AXI4L_BVALID_PERSISTENCE":      "B",
    "AXI4L_RVALID_PERSISTENCE":      "B",
    "AXI4L_AWVALID_PERSISTENCE":     "B",
    "AXI4L_ARVALID_PERSISTENCE":     "B",
    "AXI4L_WVALID_PERSISTENCE":      "B",
    # Mode C — Payload stability: data changed while VALID=1, before READY
    "AXI4L_RDATA_STABILITY":         "C",
    "AXI4L_WDATA_STABILITY":         "C",
    "AXI4L_ADDR_STABILITY":          "C",
    "AXI4L_ARPROT_STABILITY":        "C",
    "AXI4L_AWPROT_STABILITY":        "C",
    "AXI4L_BRESP_STABILITY":         "C",
    # Mode D — Response missing: handshake happened but VALID never issued
    "AXI4L_READ_RESPONSE_MISSING":   "D",
    "AXI4L_WRITE_RESPONSE_MISSING":  "D",
    "AXI4L_RVALID_UNPROMPTED":       "D",
    "AXI4L_BVALID_UNPROMPTED":       "D",
    "AXI4L_OVERLAPPING_TRANSACTION": "D",
}

_MODE_LABELS: Dict[str, str] = {
    "A": "MODE A  Scheduling Conflict  -- asserting driver overwritten in same cycle by another driver",
    "B": "MODE B  Valid Persistence    -- VALID asserted then dropped before handshake completed",
    "C": "MODE C  Payload Stability    -- data/address changed while VALID=1 before READY",
    "D": "MODE D  Response Missing     -- required response (BVALID/RVALID) never asserted after handshake",
}

_MODE_FOCUS: Dict[str, str] = {
    "A": "Root cause: which driver overwrites the ASSERT? Look for a RESETS driver that fires in the same cycle.",
    "B": "Root cause: what clears the signal? The HOLDS driver condition must gate on READY — check if it does.",
    "C": "Root cause: missing VALID/READY gate on payload driver — data updates freely during backpressure.",
    "D": "Root cause: why does the ASSERTS condition never fire? Which term in the condition stays FALSE?",
}


def _render_backtrack_narrative(
    graph: Dict[str, Any],
    rule_id: str = "?",
    analysis_cycle: Any = "?",
    indent: str = "  ",
    violation_class: str = "",
) -> str:
    """
    Human-readable causal backtrack: RTL drive chain + key driver conditions.

    Shows:
      1. Mode label (A/B/C/D) and what to look for
      2. Which signal is under analysis and its RTL drive chain
      3. The key logic signal's driver conditions with role labels
         (ASSERTS / HOLDS / RESETS / PASSES) + active/inactive annotations
    """
    root = (graph.get("root") or "?").strip()
    nodes: List[Dict[str, Any]] = graph.get("nodes") or []
    raw_adjacency: Dict[str, Any] = graph.get("adjacency") or {}
    wf_vals: Dict[str, Any] = graph.get("waveform_values") or {}

    adjacency: Dict[str, List[Dict[str, Any]]] = {
        k.lower(): v for k, v in raw_adjacency.items()
    }

    _idx_re = re.compile(r'\[(\d+)\]$')
    sig_to_drivers: Dict[str, List[Dict[str, Any]]] = {}
    orig_case: Dict[str, str] = {}

    for n in nodes:
        ntype = n.get("type") or ""
        name = (n.get("signal") or n.get("label") or "").strip()
        base_name = _idx_re.sub("", name).strip()
        if base_name:
            orig_case[base_name.lower()] = base_name
        if ntype == "driver":
            sig = (n.get("signal") or "").lower().strip()
            if sig:
                sig_to_drivers.setdefault(sig, []).append(n)

    def _drv_sort_key(n: Dict[str, Any]) -> int:
        m = _idx_re.search(n.get("label", ""))
        return int(m.group(1)) if m else 999

    for sig in sig_to_drivers:
        sig_to_drivers[sig].sort(key=_drv_sort_key)

    orig_case.setdefault(root.lower(), root)

    _KW_LOW = frozenset({
        "and", "or", "not", "if", "else", "true", "false",
        "posedge", "negedge", "reg", "wire", "input", "output",
        "inout", "assign", "begin", "end",
    })
    _IDENT = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')

    def _child_sigs(sig_lower: str) -> List[str]:
        children: set = set()
        for dep in adjacency.get(sig_lower, []):
            if dep.get("kind") == "signal":
                dep_name = (dep.get("name") or "").lower()
                if dep_name and dep_name in sig_to_drivers and dep_name != sig_lower:
                    children.add(dep_name)
        for drv in sig_to_drivers.get(sig_lower, []):
            for text in (drv.get("condition") or "", drv.get("rhs") or ""):
                for m in _IDENT.finditer(text):
                    n2 = m.group(1).lower()
                    if n2 in sig_to_drivers and n2 != sig_lower and n2 not in _KW_LOW:
                        children.add(n2)
        return sorted(children)

    # BFS order of signals reachable from root
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

    # Find the "key logic" signal: FIRST signal in BFS order that has an
    # ASSERT driver (→1). This stays on the register pipeline path and avoids
    # diving into condition-dependency branches (e.g. awready_next).
    key_sig_lower = root.lower()
    for sig in bfs_order:
        for drv in sig_to_drivers.get(sig, []):
            rhs  = (drv.get("rhs") or "").strip()
            cond = (drv.get("condition") or "").strip()
            if _driver_role(rhs, cond) == "ASSERTS":
                key_sig_lower = sig
                break
        else:
            continue
        break

    # Build the drive chain by following only unconditional pass-through
    # assignments from root — this traces the register pipeline, not the
    # condition dependency graph.
    _SIMPLE_SIG_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

    def _src_short(drv: Dict[str, Any]) -> str:
        src = (drv.get("file") or drv.get("source_location") or "").strip()
        m = re.search(r"([^/\\]+:\d+)(?::\d+)?$", src)
        return m.group(1) if m else src

    def _first_src(sig_lower: str) -> str:
        drvs = sig_to_drivers.get(sig_lower, [])
        return _src_short(drvs[0]) if drvs else ""

    # Trace PASSES chain: follow unconditional drivers whose RHS is a bare signal name
    chain_sigs: List[str] = [root.lower()]
    chain_seen: set = {root.lower()}
    cur = root.lower()
    for _ in range(8):
        cur_drvs = sig_to_drivers.get(cur, [])
        pass_target: Optional[str] = None
        for drv in cur_drvs:
            rhs  = (drv.get("rhs") or "").strip()
            cond = (drv.get("condition") or "").strip()
            if _driver_role(rhs, cond) == "PASSES" and _SIMPLE_SIG_RE.match(rhs):
                pass_target = rhs.lower()
                break
        if not pass_target or pass_target in chain_seen or pass_target not in sig_to_drivers:
            break
        chain_sigs.append(pass_target)
        chain_seen.add(pass_target)
        cur = pass_target
        if cur == key_sig_lower:
            break

    # If the PASSES chain didn't reach key_sig, append it if it's in bfs_order
    if key_sig_lower not in chain_seen and key_sig_lower in sig_to_drivers:
        chain_sigs.append(key_sig_lower)
    # Update key_sig to the last element of the chain
    key_sig_lower = chain_sigs[-1]

    def _wf_val(name: str) -> Optional[str]:
        v = wf_vals.get(name)
        if v is None:
            v = wf_vals.get(name.lower())
        return str(v) if v is not None else None

    # ── Build output ──────────────────────────────────────────────────────────
    i = indent
    out: List[str] = []

    # Mode header
    mode = _VIOLATION_MODE.get(violation_class, "")
    if mode:
        out.append(f"{i}{_MODE_LABELS[mode]}")
        out.append(f"{i}{_MODE_FOCUS[mode]}")
        out.append("")

    # Signal header
    root_orig = orig_case.get(root.lower(), root)
    root_wf   = _wf_val(root_orig) or _wf_val(root)
    root_wf_str = f" = {root_wf}" if root_wf is not None else ""
    out.append(f"{i}Primary signal : {root_orig}{root_wf_str}  "
               f"[{rule_id}, cycle {analysis_cycle}]")
    out.append(f"{i}RTL file       : {_first_src(root.lower()) or '(see RTL location above)'}")
    out.append("")

    # Drive chain (collapsed): root ← reg ← next-logic
    if len(chain_sigs) > 1:
        chain_names = [orig_case.get(s, s) for s in chain_sigs]
        chain_srcs  = [_first_src(s) for s in chain_sigs]
        out.append(f"{i}Drive chain (output <-- register <-- combinational logic):")
        out.append(f"{i}  " + "  <--  ".join(chain_names))
        srcs_str = "  |  ".join(f"{n} @ {s}" for n, s in zip(chain_names, chain_srcs) if s)
        if srcs_str:
            out.append(f"{i}  {srcs_str}")
        out.append("")

    # Key logic signal: show its driver conditions with role labels
    key_sig_orig = orig_case.get(key_sig_lower, key_sig_lower)
    key_src      = _first_src(key_sig_lower)
    out.append(f"{i}Key controlling logic : {key_sig_orig}"
               + (f"  ({key_src})" if key_src else ""))

    key_drivers = sig_to_drivers.get(key_sig_lower, [])
    if not key_drivers:
        out.append(f"{i}  (no driver conditions found)")
    else:
        for d_idx, drv in enumerate(key_drivers):
            cond  = (drv.get("condition") or "").strip()
            rhs   = (drv.get("rhs") or "").strip()
            src   = _src_short(drv)
            role  = _driver_role(rhs, cond)
            active = drv.get("condition_active")

            # Active/inactive tag
            if active is True:
                act_tag = "  [ACTIVE at this cycle]"
            elif active is False:
                act_tag = "  [inactive at this cycle]"
            else:
                act_tag = ""

            out.append(f"{i}  D{d_idx} [{role}]{act_tag}")
            if cond:
                # Wrap long conditions at ~72 chars
                cond_prefix = f"{i}    condition : "
                if len(cond_prefix) + len(cond) <= 80:
                    out.append(f"{cond_prefix}{cond}")
                else:
                    # Break on && / || boundaries for readability
                    parts = re.split(r'(\s*&&\s*|\s*\|\|\s*)', cond)
                    line_buf = cond_prefix
                    first = True
                    for part in parts:
                        if not first and len(line_buf) + len(part) > 80:
                            out.append(line_buf)
                            line_buf = f"{i}                 " + part.lstrip()
                        else:
                            line_buf += part
                            first = False
                    if line_buf.strip():
                        out.append(line_buf)
            else:
                out.append(f"{i}    condition : (always / unconditional)")
            out.append(f"{i}    assigns   : {rhs or '?'}  @ {src}")

            # ── Active driver: show each TRUE condition term with waveform values ──
            if active is True:
                true_terms  = drv.get("true_terms")  or []
                false_terms = drv.get("false_terms") or []
                term_vals   = drv.get("term_values") or {}
                if true_terms or false_terms:
                    out.append(f"{i}    evaluated conditions:")
                    for tt in true_terms:
                        sig_refs = [m for m in _IDENT.findall(tt) if m.lower() not in _KW_LOW]
                        sv_parts = []
                        seen_tt: set = set()
                        for sr in sig_refs:
                            if sr.lower() in seen_tt:
                                continue
                            seen_tt.add(sr.lower())
                            v = _wf_val(sr)
                            if v is not None:
                                sv_parts.append(f"{sr}={v}")
                        vals_str = "  [" + ", ".join(sv_parts) + "]" if sv_parts else ""
                        out.append(f"{i}      TRUE  : {tt}{vals_str}")
                    for ft in false_terms:
                        out.append(f"{i}      FALSE : {ft}")
                else:
                    # No per-term breakdown — show all condition signals with values
                    if cond:
                        sig_refs = [m for m in _IDENT.findall(cond) if m.lower() not in _KW_LOW]
                        wf_parts: List[str] = []
                        seen_wf: set = set()
                        for sr in sig_refs:
                            if sr.lower() in seen_wf:
                                continue
                            seen_wf.add(sr.lower())
                            v = _wf_val(sr)
                            if v is not None:
                                wf_parts.append(f"{sr}={v}")
                        if wf_parts:
                            out.append(f"{i}    waveform  : {', '.join(wf_parts)}")

            # ── Inactive driver: show what is blocking it ──────────────────────────
            elif active is False:
                first_false = drv.get("first_false_term")
                false_terms = drv.get("false_terms") or []
                true_terms  = drv.get("true_terms")  or []
                if true_terms or false_terms:
                    out.append(f"{i}    evaluated conditions:")
                    for tt in true_terms:
                        sig_refs = [m for m in _IDENT.findall(tt) if m.lower() not in _KW_LOW]
                        sv_parts = []
                        seen_tt2: set = set()
                        for sr in sig_refs:
                            if sr.lower() in seen_tt2:
                                continue
                            seen_tt2.add(sr.lower())
                            v = _wf_val(sr)
                            if v is not None:
                                sv_parts.append(f"{sr}={v}")
                        vals_str = "  [" + ", ".join(sv_parts) + "]" if sv_parts else ""
                        out.append(f"{i}      TRUE  : {tt}{vals_str}")
                    for ft in false_terms:
                        sig_refs = [m for m in _IDENT.findall(ft) if m.lower() not in _KW_LOW]
                        sv_parts = []
                        seen_ft: set = set()
                        for sr in sig_refs:
                            if sr.lower() in seen_ft:
                                continue
                            seen_ft.add(sr.lower())
                            v = _wf_val(sr)
                            if v is not None:
                                sv_parts.append(f"{sr}={v}")
                        vals_str = "  [" + ", ".join(sv_parts) + "]" if sv_parts else ""
                        out.append(f"{i}      FALSE : {ft}{vals_str}  <-- BLOCKING")
                elif first_false:
                    sig_refs = [m for m in _IDENT.findall(first_false) if m.lower() not in _KW_LOW]
                    sv_parts = []
                    seen_ff: set = set()
                    for sr in sig_refs:
                        if sr.lower() in seen_ff:
                            continue
                        seen_ff.add(sr.lower())
                        v = _wf_val(sr)
                        if v is not None:
                            sv_parts.append(f"{sr}={v}")
                    vals_str = "  [" + ", ".join(sv_parts) + "]" if sv_parts else ""
                    out.append(f"{i}    blocked by: {first_false}{vals_str}")
                else:
                    # No per-term data — show all condition signals with values
                    if cond:
                        sig_refs = [m for m in _IDENT.findall(cond) if m.lower() not in _KW_LOW]
                        wf_parts2: List[str] = []
                        seen_wf2: set = set()
                        for sr in sig_refs:
                            if sr.lower() in seen_wf2:
                                continue
                            seen_wf2.add(sr.lower())
                            v = _wf_val(sr)
                            if v is not None:
                                wf_parts2.append(f"{sr}={v}")
                        if wf_parts2:
                            out.append(f"{i}    waveform  : {', '.join(wf_parts2)}")

            # ── No waveform annotation — show signal values from graph ─────────────
            else:
                if cond:
                    sig_refs = [m for m in _IDENT.findall(cond) if m.lower() not in _KW_LOW]
                    wf_parts3: List[str] = []
                    seen_wf3: set = set()
                    for sr in sig_refs:
                        if sr.lower() in seen_wf3:
                            continue
                        seen_wf3.add(sr.lower())
                        v = _wf_val(sr)
                        if v is not None:
                            wf_parts3.append(f"{sr}={v}")
                    if wf_parts3:
                        out.append(f"{i}    waveform  : {', '.join(wf_parts3)}")

            out.append("")

    return "\n".join(out).rstrip()


def _render_additional_backtrack_text(rep: Dict[str, Any]) -> str:
    """Best-effort causal backtrack text for a non-primary rule finding."""
    ev = rep.get("evidence") or {}
    graph = ev.get("dependency_graph") or {}
    if not isinstance(graph, dict):
        return "No expanded RTL backtrack stored for this rule in the current proof artifact."

    adjacency = graph.get("adjacency") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    has_tree = len(nodes) > 1 or bool(edges) or any(adjacency.values())
    if has_tree:
        try:
            rule_id = str(rep.get("rule_id") or "?")
            analysis_cycle = (ev.get("analysis_cycle") or rep.get("analysis_cycle") or "?")
            # Derive violation class from rule_id → canonical name
            canon_name, _ = _canonical_rule(rule_id)
            violation_class = canon_name or str(
                rep.get("classification") or rep.get("violation_class") or
                rep.get("name") or ""
            )
            rendered = _render_backtrack_narrative(
                graph,
                rule_id=rule_id,
                analysis_cycle=analysis_cycle,
                indent="  ",
                violation_class=violation_class,
            )
        except Exception:
            rendered = ""
        if rendered:
            return rendered

    trigger = str(ev.get("trigger_condition") or "").strip()
    if trigger:
        return (
            "No expanded RTL backtrack stored for this rule in the current proof artifact.\n\n"
            f"Stored trigger evidence:\n  {trigger}"
        )
    return "No expanded RTL backtrack stored for this rule in the current proof artifact."


def _render_additional_rule_report(
    bucket: Dict[str, Any],
    *,
    ordinal: int,
    total: int,
    primary_rule_id: str,
    root_type: str,
    storage: str,
    dv: List[Dict[str, Any]],
    tv: List[Dict[str, Any]],
    rca: Dict[str, Any],
    pev0: Dict[str, Any],
    bar: str,
) -> List[str]:
    """Render one full RCA-style terminal block for a unique non-primary rule."""
    rep = bucket["rep"]
    bucket_rule = bucket["rule_id"]
    canon, spec_ref = _canonical_rule(bucket_rule)
    bucket_name = canon or bucket_rule or "UNKNOWN"
    bucket_signals = ", ".join(bucket["signals"]) if bucket["signals"] else (
        rep.get("signal") or (rep.get("evidence") or {}).get("expected_signal") or "?"
    )
    bucket_cycles = ", ".join(str(c) for c in bucket["cycles"] if c is not None) or "?"
    bucket_loc = _finding_rtl_location(rep)
    bucket_loc_txt, bucket_loc_line = _rtl_location_parts(bucket_loc)
    bucket_problem = str(rep.get("detail") or "").strip() or f"{bucket_signals} violates {bucket_name}."
    bucket_trigger = str((rep.get("evidence") or {}).get("trigger_condition") or "").strip()
    bucket_rca = _rule_level_rca_summary(
        bucket_rule,
        rep,
        primary_rule_id=primary_rule_id,
        root_type=root_type,
        storage=storage,
        dv=dv,
        tv=tv,
        rca=rca,
        pev0=pev0,
    )
    bucket_conclusion = _conclusion_text([], bucket_signals, [], "PROTOCOL", rca, bucket_rule).strip()
    if bucket_conclusion == "Protocol violation confirmed by predicate proof." and bucket_trigger:
        bucket_conclusion = bucket_trigger

    lines: List[str] = [
        "",
        bar,
        f"VIOLATION RCA {ordinal}/{total}",
        bar,
        "",
        "VIOLATION",
        f"  {bucket_name}",
    ]
    if spec_ref:
        lines.append(f"  Spec  : {spec_ref}")
    lines.append(f"  Cycle(s)      : {bucket_cycles}")
    lines.append(f"  Occurrence(s) : {bucket['count']}")
    lines += ["", "AFFECTED SIGNAL", f"  {bucket_signals}"]
    if bucket_loc_txt or bucket_loc_line:
        lines += ["", "RTL LOCATION"]
        if bucket_loc_txt:
            lines.append(f"  {bucket_loc_txt}")
        if bucket_loc_line:
            lines.append(f"  RTL line : {bucket_loc_line}")

    lines += ["", "PROBLEM"]
    lines.extend(f"  {ln}" if ln else "" for ln in bucket_problem.splitlines())

    if bucket_trigger:
        lines += ["", "EVIDENCE"]
        lines.extend(f"  {ln}" if ln else "" for ln in bucket_trigger.splitlines())

    lines += ["", bar, "CAUSAL BACKTRACK", bar]
    lines.extend(_render_additional_backtrack_text(rep).splitlines())

    lines += ["", bar, "ROOT CAUSE", bar]
    lines.extend(bucket_rca.splitlines())

    lines += ["", bar, "CONCLUSION", bar]
    lines.extend(bucket_conclusion.splitlines())
    return lines


def _channel_narrative(rule_id: str, pa_sig: str, missing: List[str]) -> str:
    """One-line narrative of what the missing coordination causes."""
    _NARR = {
        "RULE_13": "AW channel proceeds without coordinating with W or B channels, preventing a valid write response.",
        "RULE_12": "AR channel proceeds without coordinating with R channel, preventing a valid read response.",
        "RULE_11": "BVALID asserted before AW and W handshakes complete.",
        "RULE_10": "RVALID asserted before AR handshake completes.",
        "RULE_3":  "AWVALID deasserted before AWREADY — address phase incomplete.",
        "RULE_2":  "ARVALID deasserted before ARREADY — address phase incomplete.",
        "RULE_4":  "WVALID deasserted before WREADY — write-data phase incomplete.",
    }
    return _NARR.get(rule_id, "")


def _root_cause_narrative(
    pa_sig: str, pred_str: str, missing: List[str], found: List[str],
    root_type: str, rca: Dict, pev0: Dict,
) -> str:
    """Multi-line root cause narrative paragraph."""
    if pa_sig and missing:
        lines = [
            f"{pa_sig} is controlled only by local FSM state",
            "and ignores required AXI channel coordination.",
            "",
        ]
        upper_sig = pa_sig.upper()
        lines.append(f"{upper_sig} logic never checks:")
        for s in missing:
            lines.append(f"    {s}")
        lines += [
            "",
            "This allows the channel to proceed without ensuring",
            "all required AXI handshake dependencies are met.",
        ]
        return "\n".join(lines)

    # Fallback to existing root_cause_desc
    storage = _dominant_storage([], [], pev0)
    return _root_cause_desc(root_type, storage, [], [], rca, pev0)


def _suggested_fix(
    rule_id: str, pa_sig: str, pred_str: str, missing: List[str],
) -> str:
    """Suggested RTL fix text."""
    if not pa_sig or not pred_str:
        return "Review the RTL driver logic for the affected signal."

    existing = [t.strip() for t in pred_str.split("&&") if t.strip()]
    extra    = [s.lower() for s in missing if s.upper() != pa_sig.upper()]
    all_terms = existing + extra

    lines = [f"Add required handshake coordination to {pa_sig} logic:", ""]
    if all_terms:
        lines.append(f"    if ({all_terms[0]} &&")
        for t in all_terms[1:-1]:
            lines.append(f"        {t} &&")
        if len(all_terms) > 1:
            lines.append(f"        {all_terms[-1]})")
    lines += [
        "",
        "Alternative fix:",
        "  Introduce a dedicated FSM state ensuring all required",
        "  handshake signals are verified before proceeding.",
    ]
    return "\n".join(lines)


_RESET_SIGNAL_NAMES = frozenset({
    "aresetn", "rst_n", "rst", "reset", "reset_n", "resetn", "areset_n", "nreset",
})

def _conclusion_text(
    chain: list, pa_sig: str, missing: List[str],
    root_type: str, rca: Dict, rule_id: str,
) -> str:
    """Conclusion narrative derived from chain root and rule effect."""
    lines = []
    if chain:
        fsm_step  = chain[0]
        fsm_sig   = fsm_step.get("signal", "")
        fsm_rhs   = (fsm_step.get("active_driver_rhs") or
                     str(fsm_step.get("value", "?")))
        # Skip reset signals when identifying the causal root —
        # they are guards, not the actual control signal.
        root_step = next(
            (s for s in chain
             if s.get("is_leaf") and s.get("signal", "").lower() not in _RESET_SIGNAL_NAMES),
            next((s for s in chain if s.get("is_leaf")), None),
        )
        root_sig  = (root_step or {}).get("signal", "") if root_step else ""

        if not root_sig or fsm_sig == root_sig or root_sig.lower() in _RESET_SIGNAL_NAMES:
            # The FSM state itself is the root — driven by FSM logic only
            lines.append(
                f"{fsm_sig} is in {fsm_rhs} — FSM advanced to this state "
                f"and no condition causes it to exit."
            )
        else:
            lines.append(
                f"{fsm_sig} reached {fsm_rhs} via {root_sig}, "
                f"but the required AXI handshake was not yet complete."
            )
    _EFFECT: Dict[str, str] = {
        "RULE_13": "AW channel continues accepting addresses but B response is never issued.",
        "RULE_12": "AR channel accepts reads but R response is never issued.",
        "RULE_11": "BVALID fires before the write handshake completes.",
        "RULE_10": "RVALID fires before the read handshake completes.",
        "RULE_2":  "AR handshake is left incomplete — read transaction stalls.",
        "RULE_3":  "AW handshake is left incomplete — write address phase stalls.",
    }
    effect = _EFFECT.get(rule_id, "")
    if effect:
        lines.append(effect)
    if not lines:
        lines.append("Protocol violation confirmed by predicate proof.")
    return "\n".join(lines)


def _best_rtl_location(
    findings: List[Dict], dv: List[Dict], tv: List[Dict], rca: Dict,
) -> str:
    """Return the best available RTL location string."""
    for v in list(dv) + list(tv):
        loc = v.get("source_location") or v.get("source") or (
            f"line {v['rtl_line']}" if v.get("rtl_line") else ""
        )
        if loc:
            return str(loc)
    for f in findings:
        ev = f.get("evidence") or {}
        loc = ev.get("source_location") or ev.get("rtl_location")
        if loc:
            return str(loc)
    pev = rca.get("primary_evidence") or []
    for node_list in [p.get("nodes") or [] for p in pev]:
        for n in node_list:
            if n.get("type") == "driver":
                n_loc = n.get("source_location")
                if n_loc:
                    return str(n_loc)
    return ""


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_console_diagnosis(
    payload: Dict[str, Any],
    fsm_findings: Optional[List[Dict]] = None,
    design_name: Optional[str] = None,
    structural_bugs: Optional[List[Dict]] = None,
) -> str:
    """Return a WaveEye Root Cause Report string."""

    rca      = payload.get("final_rca") or {}
    findings = payload.get("findings") or []
    dv       = payload.get("datapath_violations") or []
    tv       = payload.get("transport_violations") or []
    txns     = payload.get("transactions") or []

    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    if root_type == "PROTOCOL" and not findings:
        root_type = "TRANSPORT" if tv else ("DATAPATH" if dv else "INCONCLUSIVE")

    # PASS case
    is_pass = (
        not findings and not dv and not tv
        and root_type in ("INCONCLUSIVE", None)
        and rca.get("verdict") != "VIOLATED"
    )
    if is_pass:
        return _pass_block(len(txns))

    SEP = "=" * 68
    BAR = "-" * 68

    # Predicate analysis data
    pred_a         = rca.get("predicate_analysis") or {}
    pa_sig         = pred_a.get("signal") or ""
    pred_str       = pred_a.get("driver_predicate") or ""
    pred_loc       = pred_a.get("source_location") or ""
    t_ev           = pred_a.get("t_eval")
    missing        = pred_a.get("missing_signals") or []
    found          = pred_a.get("found_signals") or []
    sec_wave       = pred_a.get("secondary_waveform") or {}
    pred_term_vals = pred_a.get("predicate_term_values") or {}
    ma             = pred_a.get("mode_analysis") or {}
    chain          = ma.get("condition_chain") or []

    # Rule info
    pev   = rca.get("primary_evidence") or []
    pev0  = pev[0] if pev and isinstance(pev[0], dict) else {}
    rule_id         = _extract_rule_id(pev0, findings)
    canon, spec_ref = _canonical_rule(rule_id)
    primary_finding = next(
        (f for f in findings if str(f.get("rule_id") or "").upper() == rule_id),
        findings[0] if findings else {},
    )

    L: List[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    L.append(SEP)
    L.append("WaveEye Root Cause Report")
    if design_name:
        L.append(f"Design: {design_name}")
    L.append(SEP)

    # ── VIOLATION ─────────────────────────────────────────────────────────────
    if findings:
        cycle = (
            pev0.get("analysis_cycle")
            or pev0.get("cycle")
            or primary_finding.get("cycle")
            or primary_finding.get("analysis_cycle")
        )
        L.append("")
        L.append("VIOLATION")
        L.append(f"  {canon or rule_id or 'UNKNOWN'}")
        if spec_ref:
            L.append(f"  Spec  : {spec_ref}")
        if cycle is not None:
            L.append(f"  Cycle : {cycle}")
    elif tv:
        cls = tv[0].get("class") or tv[0].get("subtype") or "TRANSPORT_MISMATCH"
        L += ["", "VIOLATION", f"  {cls}", "  Spec  : AXI4-Lite Transport Layer"]
    elif dv:
        cls = dv[0].get("class") or dv[0].get("subtype") or "STRUCTURAL_DEFECT"
        L += ["", "VIOLATION", f"  {cls}"]

    # ── AFFECTED SIGNAL ───────────────────────────────────────────────────────
    # Prefer the actual violation signal over the predicate analysis subject
    # (pred analysis may run on a different signal when the violation signal
    # has no RTL drivers in the selected module's true_drivers.csv)
    sig_disp = (
        pev0.get("observing_signal") or
        primary_finding.get("signal") or
        pa_sig
    )
    if sig_disp:
        L += ["", "AFFECTED SIGNAL", f"  {sig_disp}"]

    # ── RTL LOCATION ──────────────────────────────────────────────────────────
    loc = pred_loc or _best_rtl_location(findings, dv, tv, rca)
    if loc:
        L += ["", "RTL LOCATION", f"  {loc}"]

    # ── DRIVER PREDICATE ──────────────────────────────────────────────────────
    if pred_str:
        L += ["", "DRIVER PREDICATE", f"  if ({pred_str})", ""]
        if t_ev is not None:
            L.append(f"  Predicate evaluation @ cycle {t_ev}")
            eval_vals: Dict[str, str] = {}
            for s, v in pred_term_vals.items():
                eval_vals[s] = _resolve_val_str(s, v, chain)
            # Add FSM signal from chain step 0 if not already present
            if chain:
                s0 = chain[0]
                s0_sig = s0.get("signal", "")
                if s0_sig and s0_sig not in eval_vals:
                    eval_vals[s0_sig] = _resolve_val_str(s0_sig, s0.get("value"), chain)
            if eval_vals:
                mk = max(len(k) for k in eval_vals)
                for s, v in eval_vals.items():
                    L.append(f"      {s:<{mk}} = {v}")
                L.append("      -> predicate TRUE")

    # ── PROBLEM ───────────────────────────────────────────────────────────────
    if missing:
        L += ["", "PROBLEM",
              "  Predicate does not reference required AXI handshake signals.",
              "", "  Missing dependencies:"]
        for s in missing:
            val = sec_wave.get(s)
            vs  = f" = {val}" if val is not None else ""
            L.append(f"      {s}{vs}")
        narr = _channel_narrative(rule_id, pa_sig, missing)
        if narr:
            L += ["", "  Result:", f"      {narr}"]

    # ── STRUCTURAL ANALYSIS ───────────────────────────────────────────────────
    _sbugs = [b for b in (structural_bugs or []) if b.get("verdict")]
    if _sbugs:
        L += ["", BAR, "STRUCTURAL ANALYSIS", BAR]
        for sb in _sbugs:
            sev  = sb.get("severity") or ""
            conf = sb.get("confidence") or ""
            cyc  = sb.get("cycle")
            suf  = f"  [cycle {cyc}]" if cyc is not None else ""
            L.append(f"{sb['signal']} — {sb['verdict']}  [{sev}]  [{conf}]{suf}")
            L.append(f"  {sb['summary']}")
            L.append("")

    # ── CAUSAL BACKTRACK ──────────────────────────────────────────────────────
    if not chain and pev0:
        # No predicate-analysis chain (promoted raw violation) — fall back to
        # the dependency_graph stored in the primary finding's evidence dict.
        _fb = _render_additional_backtrack_text(pev0)
        _no_bt = "No expanded RTL backtrack stored"
        if _fb and _no_bt not in _fb:
            L += ["", BAR, "CAUSAL BACKTRACK", BAR]
            L.extend(_fb.splitlines())

    if chain:
        L += ["", BAR, "CAUSAL BACKTRACK", BAR]
        start    = ma.get("chain_start_term") or (chain[0].get("term") if chain else "")
        why_cyc  = t_ev if t_ev is not None else ""
        L.append(f"Why {repr(start)} holds at cycle {why_cyc}:" if start
                 else f"Condition trace at cycle {why_cyc}:")
        L.append("")
        for step in chain:
            depth   = step.get("depth", 0)
            term    = step.get("term") or step.get("signal") or ""
            sig     = step.get("signal") or ""
            val     = step.get("value")
            is_leaf = step.get("is_leaf", True)
            reg     = step.get("registered", False)
            cond    = step.get("active_driver_cond") or ""
            rhs     = step.get("active_driver_rhs") or ""
            idx     = step.get("active_driver_idx")
            t_chg   = step.get("transition_cycle")
            src_txt, src_line = _rtl_location_parts(
                step.get("source_location"),
                step.get("rtl_line"),
            )

            ind   = "  " + "  " * depth
            val_s = _resolve_val_str(sig, val, chain)
            t_s   = f"  (last change @ cycle {t_chg})" if t_chg is not None else ""

            L.append(f"{ind}[{depth}] {term}")
            L.append(f"{ind}      {sig} = {val_s}{t_s}")
            if is_leaf:
                L += [f"{ind}      Source : primary input",
                      f"{ind}      No RTL driver",
                      f"{ind}      ROOT"]
            else:
                if src_txt:
                    L.append(f"{ind}      RTL location : {src_txt}")
                if src_line:
                    L.append(f"{ind}      RTL line     : {src_line}")
                if cond:
                    reg_s = "  [registered FF]" if reg else ""
                    L += ["",
                          f"{ind}      Condition:",
                          f"{ind}          if ({cond}){reg_s}"]
            L.append("")

    # ── ROOT CAUSE ────────────────────────────────────────────────────────────
    L += [BAR, "ROOT CAUSE", BAR]
    L.extend(_root_cause_narrative(pa_sig, pred_str, missing, found,
                                   root_type, rca, pev0).splitlines())

    # ── INTRA-CYCLE CANCELLATION PROOF ───────────────────────────────────────
    # When IC evidence is present (e.g. BVALID scheduling conflict), render the
    # explicit SCHEDULING CONFLICT and DRIVER CANCELLATION proof blocks so the
    # output matches the [PROOF]-tagged quality of the causal trace.
    _pev0_ev = pev0.get("evidence") or {}
    ic_ev = _pev0_ev.get("intra_cycle_cancellation") or {}
    if ic_ev.get("detected") and root_type == "PROTOCOL":
        cycle_ic        = (ic_ev.get("anchor_cycle")
                           or ic_ev.get("analysis_cycle")
                           or pev0.get("analysis_cycle"))
        act_drvs        = ic_ev.get("active_drivers") or []
        assert_conds    = ic_ev.get("expected_driver_conditions") or []
        overwrite_conds = ic_ev.get("final_overwrite_conditions") or []
        ic_sig          = (pev0.get("expected_signal")
                           or _pev0_ev.get("expected_signal")
                           or pa_sig)

        asserting   = next((d for d in act_drvs if d.get("rhs_value") == 1), None)
        overwriting = next((d for d in act_drvs if d.get("rhs_value") == 0), None)
        n_conflict  = len(act_drvs)

        a_cond = (asserting.get("condition") if asserting
                  else (assert_conds[0] if assert_conds else "(asserting condition)"))
        o_cond = (overwriting.get("condition") if overwriting
                  else (overwrite_conds[0] if overwrite_conds else "(overwrite condition)"))
        a_idx  = asserting.get("driver_idx", "?") if asserting else "?"
        o_idx  = overwriting.get("driver_idx", "?") if overwriting else "?"

        L += ["", BAR, "SCHEDULING CONFLICT  [PROOF]", BAR]
        L.append(
            f"  Cycle {cycle_ic}: {ic_sig} has {n_conflict} simultaneously active "
            f"drivers with conflicting values."
        )

        L += ["", BAR, "DRIVER CANCELLATION  [PROOF]", BAR]
        L.append(f"  Asserting  (D{a_idx}): if ({a_cond}) \u2192 {ic_sig} = 1")
        L.append(f"  Overwriting (D{o_idx}): if ({o_cond}) \u2192 {ic_sig} = 0")
        L.append(
            f"  \u2192 {ic_sig}=1 is overwritten by the more-specific override "
            f"before handshake completes."
        )

    # ── SECONDARY ISSUES ──────────────────────────────────────────────────────
    unique_rule_findings = _group_findings_by_rule(findings)
    additional_rule_findings = [
        bucket for bucket in unique_rule_findings
        if bucket["rule_id"] != rule_id
    ]
    if additional_rule_findings:
        storage = _dominant_storage(dv, tv, pev0)
        total_rules = len(unique_rule_findings)
        for idx, bucket in enumerate(additional_rule_findings, start=2):
            L.extend(_render_additional_rule_report(
                bucket,
                ordinal=idx,
                total=total_rules,
                primary_rule_id=rule_id,
                root_type=root_type,
                storage=storage,
                dv=dv,
                tv=tv,
                rca=rca,
                pev0=pev0,
                bar=BAR,
            ))

    secondary = [f for f in (fsm_findings or []) if f.get("classification")]
    if secondary:
        L += ["", BAR, "SECONDARY ISSUE", BAR]
        for sf in secondary:
            cls = sf.get("classification") or "?"
            sig = sf.get("fsm_signal") or "?"
            val = sf.get("illegal_value") or "?"
            cyc = sf.get("cycle") or "?"
            fix = sf.get("fix_suggestion") or ""
            L += [cls, "", f"  {sig} = {val} at cycle {cyc}"]
            if fix:
                L += ["", "  Suggested fix:"]
                L.extend(f"      {fl}" for fl in fix.splitlines())

    # ── CONCLUSION ────────────────────────────────────────────────────────────
    L += ["", BAR, "CONCLUSION", BAR]
    L.extend(_conclusion_text(chain, pa_sig, missing, root_type, rca, rule_id).splitlines())
    L.append("")
    evidence_parts = ["predicate analysis"]
    if chain:
        evidence_parts.append("causal backtrack")
    if _sbugs:
        evidence_parts.append("structural analysis")
    if secondary:
        evidence_parts.append("FSM analysis")
    L += [f"Evidence   : {' + '.join(evidence_parts)}",
          SEP]

    return "\n".join(L)


# ── PASS block (PART 7) ────────────────────────────────────────────────────────

def _pass_block(n_transactions: int) -> str:
    return "\n".join([
        _BAR,
        _PASS,
        _BAR,
        "Status                : PASS",
        "Protocol compliance   : Verified",
        "Structural integrity  : Verified",
        f"Transactions analyzed : {n_transactions}",
        "Confidence            : 99%",
        "No defects detected.",
        _BAR,
    ])


# ── Confidence score (PART 5) ─────────────────────────────────────────────────

def _confidence(
    payload: Dict[str, Any],
    rca: Dict[str, Any],
    findings: List[Dict],
    dv: List[Dict],
    tv: List[Dict],
) -> tuple:
    """
    Three-component deterministic confidence score.

    Components (sum to 100 when fully confirmed):
      causal_component  = (causal_bound / total_protocol) * 50
      proof_component   = structural proof authority * 30
      determinism       = transaction reproducibility * 20
      driver_penalty    = -10 if driver DB was not loaded

    Returns (score: int, bullets: List[str]) where bullets explain each component.
    """
    br          = payload.get("binding_result") or {}
    bs          = br.get("summary") or {}
    causal_bound = int(bs.get("causal", 0))
    total_proto  = max(len(findings), 1)

    # ── Component 1: causal binding (0–50 pts) ─────────────────────────
    causal_ratio     = causal_bound / total_proto
    causal_pts       = causal_ratio * 50

    # ── Component 2: structural proof completeness (0–30 pts) ──────────
    authority = rca.get("authority") or ""
    if authority == "PREDICATE_PROOF":
        proof_pts   = 30
        proof_label = "PREDICATE_PROOF authority"
    elif dv or tv:
        proof_pts   = 15
        proof_label = "structural evidence present (no formal proof)"
    else:
        proof_pts   = 0
        proof_label = "no structural evidence"

    # ── Component 3: trace determinism (0–20 pts) ──────────────────────
    txns = len(payload.get("transactions") or [])
    if txns >= 5:
        determ_pts   = 20
        determ_label = f"{txns} transactions (strong reproducibility)"
    elif txns >= 2:
        determ_pts   = 14
        determ_label = f"{txns} transactions (moderate reproducibility)"
    elif txns >= 1:
        determ_pts   = 6
        determ_label = f"{txns} transaction (limited reproducibility)"
    else:
        determ_pts   = 0
        determ_label = "no transactions observed"

    # ── Penalty: driver DB not loaded (−10 pts) ────────────────────────
    has_driver_db    = bool(payload.get("logic_table") or payload.get("driver_table"))
    driver_penalty   = 0 if has_driver_db else -10
    driver_bullet    = None if has_driver_db else "Driver DB not loaded (−10%)"

    raw   = causal_pts + proof_pts + determ_pts + driver_penalty
    score = min(max(round(raw), 10), 99)

    bullets = [
        f"Causal binding: {causal_bound}/{len(findings) or total_proto} violations "
        f"traceable to RTL ({round(causal_pts)}%)",
        f"Structural proof: {proof_label} ({round(proof_pts)}%)",
        f"Trace determinism: {determ_label} ({round(determ_pts)}%)",
    ]
    if driver_bullet:
        bullets.append(driver_bullet)

    return score, bullets


# ── Extraction helpers ─────────────────────────────────────────────────────────

def _extract_rule_id(pev0: Dict, findings: List[Dict]) -> str:
    r = pev0.get("rule_id")
    if r:
        return str(r).upper()
    for f in findings:
        r = f.get("rule_id")
        if r:
            return str(r).upper()
    return ""


def _canonical_rule(rule_id: str):
    """Return (canonical_name, spec_ref) tuple for a RULE_N string."""
    entry = _RULE_CANON.get(rule_id)
    if entry:
        return entry
    return ("", "")


def _dominant_storage(
    dv: List[Dict],
    tv: List[Dict],
    pev0: Dict,
) -> str:
    all_v = list(dv) + list(tv)
    if not all_v:
        return pev0.get("expected_signal") or pev0.get("signal") or ""

    def _dst(v: Dict) -> str:
        return v.get("destination_signal") or v.get("signal") or ""

    counts = Counter(_dst(v) for v in all_v if _dst(v))
    if not counts:
        return _dst(all_v[0]) or pev0.get("expected_signal") or pev0.get("signal") or ""

    top_sig, top_count = counts.most_common(1)[0]
    if top_count > 10:
        return top_sig
    return _dst(all_v[0]) or top_sig or pev0.get("expected_signal") or pev0.get("signal") or ""


def _rtl_location(
    dv: List[Dict],
    tv: List[Dict],
    findings: List[Dict],
    pev0: Dict,
) -> str:
    for v in list(dv) + list(tv):
        loc = v.get("source_location") or v.get("source") or v.get("rtl_line")
        if loc:
            return str(loc)
        blk = v.get("always_block_id")
        if blk is not None:
            return f"always_block {blk}"
    for f in findings:
        ev  = f.get("evidence") or {}
        loc = ev.get("source_location") or ev.get("rtl_location")
        if loc:
            return str(loc)
        # Search dependency graph nodes for the blocking driver's source location.
        nodes = ev.get("dependency_graph", {}).get("nodes") or []
        for n in nodes:
            if n.get("type") == "driver" and n.get("condition_active") is False:
                n_loc = n.get("source_location")
                if n_loc:
                    return str(n_loc)
    return pev0.get("source_location") or "(see appendix)"


def _root_cause_desc(
    root_type: str,
    storage: str,
    dv: List[Dict],
    tv: List[Dict],
    rca: Optional[Dict] = None,
    pev0: Optional[Dict] = None,
) -> str:
    sig = storage or "target signal"
    if root_type == "TRANSPORT":
        first = tv[0] if tv else {}
        strb  = first.get("strobe_signal") or "WSTRB"
        return f"WDATA/WSTRB lane misalignment on {sig} — {strb} not mirrored"
    if root_type in ("DATAPATH", "SEMANTIC_STRUCTURAL"):
        first = dv[0] if dv else {}
        sub   = (first.get("subtype") or "width truncation").lower().replace("_", " ")
        sw    = first.get("inferred_src_width")
        dw    = first.get("inferred_dst_width")
        drop  = f" ({sw}-bit source to {dw}-bit target)" if (sw and dw) else ""
        return f"{sub.capitalize()}{drop} in {sig}"
    # PROTOCOL: check for intra_cycle_cancellation evidence first
    pev    = pev0 or {}
    pev_ev = pev.get("evidence") or {}
    ic     = pev_ev.get("intra_cycle_cancellation") or {}
    if ic.get("detected"):
        exp_sig  = pev.get("expected_signal") or pev_ev.get("expected_signal") or sig
        enable_c = pev.get("enable_condition") or pev_ev.get("enable_condition") or ""
        if enable_c:
            return (
                f"{exp_sig} asserted by ({enable_c}) "
                f"then cancelled by more-specific override"
            )
        return f"{exp_sig} cancelled by simultaneously active override driver"
    # PROTOCOL: use predicate_analysis if available
    pred_a = (rca or {}).get("predicate_analysis") or {}
    ma     = pred_a.get("mode_analysis") or {}

    # ── MODE-C: stability mutation — check ready_gate_absent first ──────────
    if ma.get("mode") == "MODE-C":
        stab_sig  = ma.get("stability_signal") or pred_a.get("signal") or sig
        ready_sig = ma.get("ready_signal") or "READY"
        if ma.get("ready_gate_absent", True):
            return (
                f"{stab_sig} driver has no {ready_sig} gate — "
                f"payload advances freely during backpressure"
            )
        return (
            f"{stab_sig} mutated during {ma.get('valid_signal','VALID')}→{ready_sig} "
            f"window despite {ready_sig} present in driver predicate"
        )

    missing = pred_a.get("missing_signals") or []
    pa_sig  = pred_a.get("signal") or sig
    if missing:
        missing_str = ", ".join(missing)
        return f"{pa_sig} driver predicate missing required dependencies: {missing_str}"
    return f"Always-block NBA override on {sig} — asserting assignment overwritten"


def _next_step(
    root_type: str,
    rtl_location: str,
    storage: str,
    dv: List[Dict],
    rca: Optional[Dict] = None,
    pev0: Optional[Dict] = None,
) -> str:
    # Intentionally non-prescriptive for terminal output.
    return "Remediation guidance suppressed."


# ── Condensed Causal Trace (PART 3) ───────────────────────────────────────────

def _sem_class_local(sv: Dict) -> str:
    """Local transform-semantics classifier — avoids importing rca_8."""
    sub     = (sv.get("subtype") or "").upper()
    cls     = (sv.get("class") or sv.get("violation_class") or "").upper()
    combined = sub + " " + cls
    if "TRUNCATION" in combined or ("WIDTH" in combined and "CONSERVATION" in combined):
        return "WIDTH_TRUNCATION"
    if "COLLAPSE" in combined or "NON_INVERTIBLE" in combined or "INVERTIBILITY" in combined:
        return "NON_BIJECTIVE_CAST"
    if "BIJECTION" in combined:
        return "PARTIAL_ASSIGNMENT"
    if "ALIASING" in combined:
        return "LANE_COLLAPSE"
    if "TRANSPORT" in combined or "STROBE" in combined:
        return "TRANSPORT_MISMATCH"
    return sub or cls or "STRUCTURAL_DEFECT"


def _fmt_condition_chain(chain: list) -> str:
    """
    Format the deep condition chain produced by _backtrack_condition_chain().
    Renders as a multi-line causal trace, e.g.:

        → Condition chain:
          [0] w_state == W_IDLE  →  w_state = 0 (W_IDLE)
              Active driver: if (flush) → W_IDLE  ★ ACTIVE
          [1] flush  →  flush = 1  (master input — root)
    """
    if not chain:
        return ""
    lines = ["    \u2192 Condition chain (deep backtrack):"]
    for step in chain:
        depth   = step.get("depth", 0)
        term    = step.get("term", "")
        sig     = step.get("signal", "")
        val     = step.get("value")
        is_leaf = step.get("is_leaf", True)
        reg     = step.get("registered", False)
        cond    = step.get("active_driver_cond", "")
        rhs     = step.get("active_driver_rhs", "")
        idx     = step.get("active_driver_idx")
        src_txt, src_line = _rtl_location_parts(
            step.get("source_location"),
            step.get("rtl_line"),
        )

        val_str = f" = {val}" if val is not None else ""
        indent  = "    " + "  " * depth
        t_cyc   = step.get("transition_cycle")
        term_display = f"  [{depth}] {term}" if term else f"  [{depth}] {sig}"
        lines.append(f"{indent}{term_display}")
        if sig:
            sig_line = f"{indent}      {sig}{val_str}"
            if t_cyc is not None:
                sig_line += f"  [last changed \u2192 cycle {t_cyc}]"
            if is_leaf:
                sig_line += "  \u2192 master/primary input  \u2014 ROOT"
            elif cond:
                d_lbl   = f"D{idx} " if idx is not None else ""
                reg_sfx = "  [registered FF]" if reg else ""
                sig_line += (
                    f"\n{indent}      Active driver: "
                    f"{d_lbl}if ({cond}) \u2192 {rhs}  \u2605 ACTIVE{reg_sfx}"
                )
                if src_txt:
                    sig_line += f"\n{indent}      RTL location : {src_txt}"
                if src_line:
                    sig_line += f"\n{indent}      RTL line     : {src_line}"
            else:
                sig_line += "  (no active driver resolved \u2014 likely enum-gated FSM)"
            lines.append(sig_line)
    return "\n".join(lines)


def _fmt_backtrack_entry(sig: str, entry: dict) -> str:
    """
    Format one signal from a _backtrack_signal_set result dict.
    Returns a single indented line like:
        read_state = 1  → D2 last transition: if (read_state == WAIT) → RESP  [registered]
        ARVALID    = 1  (master input — no RTL driver in slave)
    """
    val = entry.get("value")
    val_s = f" = {val}" if val is not None else ""
    src_txt, src_line = _rtl_location_parts(
        entry.get("source_location") or entry.get("source"),
        entry.get("rtl_line"),
    )
    if entry.get("is_leaf"):
        return f"    {sig}{val_s}  (master input \u2014 no RTL driver in slave)"
    cond = entry.get("active_driver_cond") or ""
    rhs  = entry.get("active_driver_rhs")  or ""
    idx  = entry.get("active_driver_idx")
    reg  = entry.get("registered", False)
    if cond:
        d_label = f"D{idx} " if idx is not None else ""
        suffix  = "  [registered FF \u2014 transition from prev cycle]" if reg else ""
        line = (
            f"    {sig}{val_s}  \u2192 {d_label}"
            f"{'last transition' if reg else 'active driver'}: if ({cond}) \u2192 {rhs}{suffix}"
        )
        if src_txt:
            line += f"\n      RTL location : {src_txt}"
        if src_line:
            line += f"\n      RTL line     : {src_line}"
        return line
    line = f"    {sig}{val_s}  (registered state \u2014 no transition at this cycle)"
    if src_txt:
        line += f"\n      RTL location : {src_txt}"
    if src_line:
        line += f"\n      RTL line     : {src_line}"
    return line


def _condense_trace(
    payload:         Dict[str, Any],
    rca:             Dict[str, Any],
    findings:        List[Dict],
    dv:              List[Dict],
    tv:              List[Dict],
    pev0:            Dict,
    storage_element: str,
    rtl_location:    str,
) -> str:
    """
    Build the Condensed Causal Trace block.

    Uses causal_bindings (backtracking proof) as primary evidence to name the
    actual RTL signal that caused the protocol violation. Falls back to dv/tv
    when no binding is available.

    Returns a formatted string block ready to print after the main box.
    """
    root_type = rca.get("root_cause_type") or "INCONCLUSIVE"
    rule_id   = _extract_rule_id(pev0, findings)
    direction, req_sig, resp_sig = _RULE_DIRECTION.get(
        rule_id, ("write", "AWVALID", "BVALID")
    )
    # expected_signal / enable_condition may be at top level OR inside evidence
    _pev0_ev = pev0.get("evidence") or {}
    exp_sig  = (pev0.get("expected_signal")
                or _pev0_ev.get("expected_signal")
                or resp_sig)

    # ── Transaction context ───────────────────────────────────────────────
    txns     = payload.get("transactions") or []
    txn0     = txns[0] if txns else {}
    txn_id   = txn0.get("transaction_id")
    accept_c = txn0.get("accept_cycle")
    viol_c   = pev0.get("analysis_cycle")

    # ── Backtracking proof from binding pass ─────────────────────────────
    br              = payload.get("binding_result") or {}
    causal_bindings = br.get("causal_bindings") or []
    # Pick first causal binding as representative proof record
    proof_binding   = causal_bindings[0] if causal_bindings else {}
    proof_viol      = proof_binding.get("violation") or {}
    proof_asn_sig   = proof_binding.get("assignment_signal") or ""
    proof_asn_src   = proof_binding.get("assignment_source") or ""
    proof_addr      = proof_binding.get("address")
    proof_txn_id    = proof_binding.get("transaction_id")

    # ── Representative structural violation (for fallback) ───────────────
    all_v   = list(dv) + list(tv)
    first_v = proof_viol if proof_viol else (all_v[0] if all_v else {})

    dst_raw  = (first_v.get("memory") or first_v.get("destination_signal")
                or storage_element or "target register")
    src_raw  = first_v.get("source_signal") or proof_asn_sig or "WDATA"
    dst_base = dst_raw.split("[")[0].strip()
    src_base = src_raw.split("[")[0].strip()

    # Causal assignment location — prefer binding proof, fall back to rtl_location
    causal_loc = (proof_asn_src or rtl_location or "").strip()
    if not causal_loc or causal_loc == "(see appendix)":
        causal_loc = rtl_location or "RTL location"

    sem_class = _sem_class_local(first_v) if first_v else "STRUCTURAL_DEFECT"
    sw = first_v.get("inferred_src_width") if first_v else None
    dw = first_v.get("inferred_dst_width") if first_v else None

    steps: List[tuple] = []   # (label, detail)

    # Structural-only run: no protocol violations were observed.
    # Avoid protocol-failure wording in this case.
    if not findings and (dv or tv):
        defect_name = sem_class
        loc_note = f" ({causal_loc})" if causal_loc else ""
        steps.append((
            "Structural defect detected",
            f"{defect_name} on {dst_base}{loc_note}.",
        ))
        steps.append((
            "Protocol checker result",
            "No AXI handshake violations detected in this run.",
        ))
        steps.append((
            "Conclusion",
            f"Protocol is compliant for this trace; issue is structural in {dst_base}.",
        ))
        return _format_trace_steps(steps)

    # ── Step 1: Transaction accepted ─────────────────────────────────────
    txn_note = f" (transaction {txn_id})" if txn_id is not None else ""
    addr_note = ""
    if proof_addr is not None:
        addr_note = f" to address 0x{proof_addr:08X}" if isinstance(proof_addr, int) else \
                    f" to address {proof_addr}"
    steps.append((
        f"{direction.capitalize()} transaction accepted",
        f"{req_sig} handshake observed{addr_note}{txn_note}.",
    ))

    # ── Step 2: Violation characterisation (spec-accurate) ───────────────
    viol_type = _RULE_VIOLATION_TYPE.get(rule_id, "MISSING")
    ic_ev     = _pev0_ev.get("intra_cycle_cancellation") or {}
    cancelled = isinstance(ic_ev, dict) and ic_ev.get("detected")

    if viol_type == "STABILITY":
        # Look up the exact payload signal that must be stable for this rule.
        # req_sig is the VALID signal (e.g. RVALID), NOT the payload (RDATA).
        _stab_cfg   = _STABILITY_SIGNAL_MAP.get(rule_id, ())
        stab_sig    = _stab_cfg[0] if _stab_cfg else req_sig
        window_sig  = _stab_cfg[1] if _stab_cfg else req_sig   # VALID signal
        close_sig   = _stab_cfg[2] if _stab_cfg else resp_sig  # READY signal
        _, spec_ref = _RULE_CANON.get(rule_id, ("", "AXI4-Lite Spec §A3.1.2"))
        steps.append((
            f"Signal stability violation — {stab_sig} mutated during {window_sig} window",
            f"{stab_sig} changed value while {window_sig}=1 and {close_sig}=0 — "
            f"{spec_ref} requires {stab_sig} to remain stable from the first "
            f"{window_sig} cycle until {window_sig}∧{close_sig} handshake "
            f"(mutation at cycle {viol_c}).",
        ))
    elif viol_type == "UNPROMPTED":
        steps.append((
            f"Spurious {direction} response detected",
            f"{exp_sig} asserted without a preceding {direction} "
            f"handshake ({req_sig}\u2227{exp_sig.replace('VALID','READY')} "
            f"never completed before cycle {viol_c}).",
        ))
    elif cancelled:
        # Signal was asserted but immediately overwritten — report cycle distance
        # as factual observation, not a spec latency requirement.
        try:
            dist = int(viol_c) - int(accept_c) if (viol_c is not None and accept_c is not None) else None
        except (TypeError, ValueError):
            dist = None
        dist_note = (f" (cycle {accept_c} \u2192 {viol_c})" if dist is not None else "")
        steps.append((
            f"{exp_sig} asserted then immediately cancelled",
            f"{exp_sig} fired at cycle {viol_c} but was overwritten in the same cycle{dist_note}. "
            f"AXI4-Lite requires {exp_sig} to stay high until the handshake partner completes.",
        ))
    elif viol_type == "PERSISTENCE":
        # For persistence violations use resp_sig from _RULE_DIRECTION — the
        # evidence field "expected_signal" can carry a wrong counterpart signal.
        steps.append((
            f"{req_sig} dropped before {direction} handshake completed",
            f"{req_sig} de-asserted before {resp_sig} was received — "
            f"violates AXI4-Lite §A3.1.2 persistence rule "
            f"({req_sig} must stay high until {resp_sig} is asserted).",
        ))
    else:
        # MISSING — response never came; show observation window as context,
        # NOT as a spec latency requirement.
        try:
            window = int(viol_c) - int(accept_c) if (viol_c is not None and accept_c is not None) else None
        except (TypeError, ValueError):
            window = None
        if window and window > 1:
            steps.append((
                f"{exp_sig} never received",
                f"{exp_sig} not observed in the {window}-cycle observation window "
                f"following the {direction} handshake (cycle {accept_c}). "
                f"AXI4-Lite imposes no fixed latency — this window is tool-configured.",
            ))
        else:
            steps.append((
                f"{exp_sig} never received",
                f"{exp_sig} not observed after {direction} handshake. "
                f"AXI4-Lite imposes no fixed latency — slave must eventually respond.",
            ))

    # ── Step 3: Control path validation ──────────────────────────────────
    ch = resp_sig.replace("VALID", "").replace("READY", "") or direction.upper()
    if root_type in ("DATAPATH", "TRANSPORT", "SEMANTIC_STRUCTURAL"):
        steps.append((
            "Control logic evaluated",
            f"{ch}-channel FSM progressed normally — "
            f"no deadlock or state corruption detected.",
        ))
    else:
        steps.append((
            "Control logic evaluated",
            f"FSM state analysis completed — scheduling conflict or "
            f"missing enable condition identified in {ch}-channel logic.",
        ))

    # ── Protocol-only: check IC evidence first, then predicate analysis ──────
    if root_type == "PROTOCOL":
        # ── Priority 1: intra_cycle_cancellation (driver overwrite) ──────────
        ic = _pev0_ev.get("intra_cycle_cancellation") or {}
        if ic.get("detected"):
            cycle      = ic.get("anchor_cycle") or ic.get("analysis_cycle") or viol_c
            act_drvs   = ic.get("active_drivers") or []
            assert_conds   = ic.get("expected_driver_conditions") or []
            overwrite_conds = ic.get("final_overwrite_conditions") or []
            ic_sig = exp_sig  # already resolved above (top-level OR evidence)

            # Find asserting driver (rhs_value == 1) and overwriting (rhs_value == 0)
            asserting  = next((d for d in act_drvs if d.get("rhs_value") == 1), None)
            overwriting = next((d for d in act_drvs if d.get("rhs_value") == 0), None)
            n_conflict = len(act_drvs)

            # Step 3: scheduling conflict detected
            steps.append((
                f"Scheduling conflict detected  [PROOF]",
                f"Cycle {cycle}: {ic_sig} has {n_conflict} simultaneously active "
                f"drivers with conflicting values.",
            ))

            # Step 4: driver cancellation details
            a_cond = (asserting.get("condition") if asserting
                      else (assert_conds[0] if assert_conds else "(asserting condition)"))
            o_cond = (overwriting.get("condition") if overwriting
                      else (overwrite_conds[0] if overwrite_conds else "(overwrite condition)"))
            a_idx  = asserting.get("driver_idx", "?") if asserting else "?"
            o_idx  = overwriting.get("driver_idx", "?") if overwriting else "?"
            steps.append((
                f"Driver cancellation identified  [PROOF]",
                f"Asserting  (D{a_idx}): if ({a_cond}) \u2192 {ic_sig} = 1\n"
                f"    Overwriting (D{o_idx}): if ({o_cond}) \u2192 {ic_sig} = 0\n"
                f"    \u2192 {ic_sig}=1 is overwritten by the more-specific override "
                f"before handshake completes.",
            ))

            steps.append((
                "Conclusion",
                f"{ic_sig} cannot stay asserted \u2014 the more-specific driver "
                f"(D{o_idx}) cancels the assertion at cycle {cycle}. "
                f"Concurrent override forces {ic_sig}=0 in the same cycle.",
            ))
            return _format_trace_steps(steps)

        # ── Priority 2: predicate_analysis (missing required deps) ───────────
        pred_a   = rca.get("predicate_analysis") or {}
        pa_sig   = pred_a.get("signal") or exp_sig
        pred_str = pred_a.get("driver_predicate") or ""
        missing  = pred_a.get("missing_signals") or []
        found    = pred_a.get("found_signals") or []

        if pred_str or pred_a.get("mode_analysis"):
            # t_ev is needed by MODE-A/B/D trace rendering below.
            # Set it unconditionally so it is available even when pred_str is
            # empty (e.g. MODE-C where the stability signal has no logic-table
            # entry and a_cond is set to "").
            t_ev = pred_a.get("t_eval")

            if pred_str:
                # Primary signal value at t_eval — show hex for RTL context.
                # Suppress for MODE-C: mutation values are shown in MODE-C block.
                _ma_mode = (pred_a.get("mode_analysis") or {}).get("mode", "")
                pri_val  = pred_a.get("primary_waveform_value")
                if _ma_mode == "MODE-C":
                    pri_ann = ""  # value shown in MODE-C block instead
                elif pri_val is None:
                    pri_ann = ""
                else:
                    try:
                        pri_ann = f" = 0x{int(pri_val):X}"
                    except (TypeError, ValueError):
                        pri_ann = f" = {pri_val}"
                _pred_loc = pred_a.get("source_location") or ""
                _loc_line = f"\n    RTL location  : {_pred_loc}" if _pred_loc else ""
                steps.append((
                    f"{pa_sig} driver predicate identified  [PROOF]",
                    f"{pa_sig}{pri_ann} @ t_eval={t_ev}\n"
                    f"    Active condition: if ({pred_str})"
                    f"{_loc_line}",
                ))

            # ── MODE-A / B / C / D analysis step ──────────────────────────
            # MODE-A  Unexpected assertion   — signal is 1 when it should not be
            # MODE-B  Early deassertion       — signal asserted but dropped before READY
            # MODE-C  Stability mutation      — payload changed during stability window
            # MODE-D  Missing assertion       — signal never asserted, blocking term found
            ma = pred_a.get("mode_analysis") or {}
            ma_mode    = ma.get("mode", "")
            ma_subtype = ma.get("subtype", "")

            if ma_mode == "MODE-B" and ma_subtype == "BLOCKED_ASSERTER":
                # Early deassertion: asserting driver was outcompeted by overwrite driver.
                # Backtrack TRUE terms of the winning (deassert) driver.
                a_idx  = ma.get("asserting_driver_idx", "?")
                w_idx  = ma.get("winning_driver_idx",   "?")
                a_cond = ma.get("asserting_driver_cond", "")
                w_cond = ma.get("winning_driver_cond",  "")
                w_rhs  = ma.get("winning_driver_rhs",   "0")
                w_terms = ma.get("winning_true_terms") or []
                w_tv    = ma.get("winning_term_values") or {}
                term_detail = ", ".join(
                    f"{t}={'TRUE' if w_tv.get(t) else 'FALSE'}"
                    for t in w_terms
                ) if w_terms else "all terms TRUE"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                steps.append((
                    "MODE-B \u2014 Early deassertion  [PROOF]",
                    f"  D{a_idx} (assert): if ({a_cond}) \u2192 1  [INACTIVE]\n"
                    f"  D{w_idx} (win):    if ({w_cond}) \u2192 {w_rhs}  \u2605 ACTIVE\n"
                    f"    TRUE terms of D{w_idx} @ t_eval={t_ev}: {term_detail}"
                    + (f"\n{_bt_lines}" if _bt_lines else ""),
                ))

            elif ma_mode == "MODE-A" and ma_subtype == "UNEXPECTED_ASSERTION":
                # Unexpected assertion: signal is 1 when it should not be.
                # Backtrack TRUE terms of the active asserting driver.
                a_idx  = ma.get("active_driver_idx", "?")
                a_cond = ma.get("active_driver_cond", "")
                a_rhs  = ma.get("active_driver_rhs",  "1")
                a_terms = ma.get("active_true_terms") or []
                a_tv    = ma.get("active_term_values") or {}
                term_detail = ", ".join(
                    f"{t}={'TRUE' if a_tv.get(t) else 'FALSE'}"
                    for t in a_terms
                ) if a_terms else "all terms TRUE"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                _chain_str = _fmt_condition_chain(ma.get("condition_chain") or [])
                steps.append((
                    "MODE-A \u2014 Unexpected assertion  [PROOF]",
                    f"  D{a_idx} (assert): if ({a_cond}) \u2192 {a_rhs}  \u2605 ACTIVE\n"
                    f"    TRUE terms @ t_eval={t_ev}: {term_detail}"
                    + (f"\n{_bt_lines}" if _bt_lines else "")
                    + (f"\n{_chain_str}" if _chain_str else "")
                    + f"\n  \u21b3 signal fired without required protocol handshake.",
                ))

            elif ma_mode == "MODE-C":
                # Stability mutation: payload changed during VALID → READY window.
                # Backtrack TRUE terms of the active driver that produced the new value.
                stab_sig          = ma.get("stability_signal", pa_sig)
                t_start           = ma.get("t_start", "?")
                t_mut             = ma.get("t_mutation", t_ev)
                val_before        = ma.get("value_before")
                val_after         = ma.get("value_after")
                valid_sig         = ma.get("valid_signal", "VALID")
                ready_sig         = ma.get("ready_signal", "READY")
                ready_gate_absent = ma.get("ready_gate_absent", False)
                a_idx             = ma.get("active_driver_idx", "?")
                a_cond            = ma.get("active_driver_cond", "")
                a_rhs             = ma.get("active_driver_rhs", "")
                a_terms           = ma.get("active_true_terms") or []
                a_tv              = ma.get("active_term_values") or {}
                term_detail = ", ".join(
                    f"{t}={'TRUE' if a_tv.get(t) else 'FALSE'}"
                    for t in a_terms
                ) if a_terms else "all terms TRUE"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                def _fmt_val(v: Any) -> str:
                    if isinstance(v, int) and v > 15:
                        return f"0x{v:X}"
                    return str(v) if v is not None else "?"

                # Root cause verdict depends on whether READY appears anywhere
                # in the stability signal's driver conditions:
                #   absent  → no backpressure gate in RTL → structural root cause
                #   present → READY is referenced but the active predicate allowed
                #             the mutation anyway → predicate correctness issue
                if ready_gate_absent:
                    root_cause_line = (
                        f"  \u21b3 ROOT CAUSE: {stab_sig} driver has no {ready_sig} gate.\n"
                        f"    RTL Fix: gate the update on (!{ready_sig}) or register\n"
                        f"    {stab_sig} at transaction-accept time."
                    )
                else:
                    root_cause_line = (
                        f"  \u21b3 {ready_sig} IS referenced in driver conditions but\n"
                        f"    the active branch at t_mut={t_mut} did not block the update."
                    )

                _mc_loc = ma.get("source_location") or ""
                _mc_loc_line = f"\n    RTL location  : {_mc_loc}" if _mc_loc else ""
                no_drv = (not a_cond and a_rhs == "(driver not in table)")
                if no_drv:
                    drv_line = (
                        f"  Active driver @ t_mut={t_mut}:\n"
                        f"    (not found in driver table — likely combinational wire)\n"
                        f"    No READY gate can exist for a signal absent from the table."
                    )
                else:
                    drv_line = (
                        f"  Active driver @ t_mut={t_mut}:{_mc_loc_line}\n"
                        f"    D{a_idx}: if ({a_cond or '1'}) \u2192 {a_rhs}  \u2605 ACTIVE\n"
                        f"    TRUE terms: {term_detail}"
                        + (f"\n{_bt_lines}" if _bt_lines else "")
                    )
                steps.append((
                    "MODE-C \u2014 Stability mutation  [PROOF]",
                    f"  Stability window  : {valid_sig} asserted @ t={t_start}"
                    f"  until {ready_sig} handshake\n"
                    f"  Signal mutated    : {stab_sig}  "
                    f"{_fmt_val(val_before)} \u2192 {_fmt_val(val_after)}  @ cycle {t_mut}\n"
                    f"\n"
                    + drv_line
                    + f"\n\n{root_cause_line}",
                ))

            elif ma_mode == "MODE-D":
                # Missing assertion: signal never became 1.
                # Backtrack FALSE/blocking terms of the asserting driver.
                a_idx   = ma.get("asserting_driver_idx", "?")
                a_cond  = ma.get("asserting_driver_cond", "")
                blk     = ma.get("blocking_term", "")
                t_terms = ma.get("true_terms")  or []
                f_terms = ma.get("false_terms") or []
                true_str  = ", ".join(f"{t}=TRUE"  for t in t_terms) if t_terms else "\u2014"
                false_str = ", ".join(f"{t}=FALSE" for t in f_terms) if f_terms else "\u2014"
                _bt_lines = "\n".join(
                    _fmt_backtrack_entry(s, e)
                    for s, e in (ma.get("term_backtrack") or {}).items()
                )
                _chain_str = _fmt_condition_chain(ma.get("condition_chain") or [])
                steps.append((
                    "MODE-D \u2014 Missing assertion  [PROOF]",
                    f"  D{a_idx} (assert): if ({a_cond}) \u2192 1  [INACTIVE]\n"
                    f"    TRUE  terms: {true_str}\n"
                    f"    FALSE terms: {false_str}"
                    + (f"\n{_bt_lines}" if _bt_lines else "")
                    + (f"\n{_chain_str}" if _chain_str else "")
                    + f"\n  \u21b3 Backtrack blocking term: '{blk}' \u2014 "
                    f"this is the missing dependency preventing the assertion.",
                ))

            if missing:
                # Use secondary_backtrack for one-level driver trace per signal
                sec_bt = (ma.get("secondary_backtrack") or {}) if ma else {}
                sec_wave = pred_a.get("secondary_waveform") or {}
                bt_detail_lines = []
                for s in (missing + found):
                    if s in sec_bt:
                        bt_detail_lines.append(_fmt_backtrack_entry(s, sec_bt[s]))
                    elif s in sec_wave and sec_wave[s] is not None:
                        bt_detail_lines.append(f"    {s} = {sec_wave[s]}")
                bt_block = ("\n" + "\n".join(bt_detail_lines)) if bt_detail_lines else ""
                found_note = (
                    f"\n    Found in predicate: {', '.join(found)}" if found else ""
                )
                steps.append((
                    "Missing required AXI dependencies  [PROOF]",
                    f"\u2717  Absent from predicate: {', '.join(missing)}{bt_block}\n"
                    f"    \u2192 {pa_sig} is driven by local FSM only \u2014 "
                    f"required handshake signals never gated.{found_note}",
                ))
                # ── Fallback condition chain (enum-unresolvable predicates) ──────
                # When MODE-A/D detection failed (e.g. enum comparison like
                # w_state == W_IDLE can't be evaluated numerically), the chain
                # was built directly from the driver_predicate string.
                _fb_chain = (pred_a.get("mode_analysis") or {}).get("condition_chain")
                _fb_start = (pred_a.get("mode_analysis") or {}).get("chain_start_term", "")
                if _fb_chain and (pred_a.get("mode_analysis") or {}).get("chain_source") == "predicate_fallback":
                    _fb_chain_str = _fmt_condition_chain(_fb_chain)
                    if _fb_chain_str:
                        steps.append((
                            f"Condition chain \u2014 why '{_fb_start}' holds  [PROOF]",
                            _fb_chain_str,
                        ))

                steps.append((
                    "Conclusion",
                    f"Protocol failure is structurally guaranteed \u2014 predicate contains "
                    f"no path to verify {', '.join(missing[:3])}.",
                ))
            else:
                steps.append((
                    "Conclusion",
                    f"Protocol failure is structurally independent \u2014 "
                    f"all required signals found in predicate.",
                ))
        else:
            steps.append((
                "Conclusion",
                f"Protocol failure is structurally independent \u2014 "
                f"no RTL datapath defect confirmed.",
            ))
        return _format_trace_steps(steps)

    # ── Step 4: Backtracking initiated ───────────────────────────────────
    backtrack_target = exp_sig
    steps.append((
        f"Backtracking initiated on {backtrack_target}",
        f"Traced driver tree for {backtrack_target} — enabling condition "
        f"not satisfied at violation cycle.",
    ))

    # ── Step 5: Causal assignment identified (PROOF) ─────────────────────
    if causal_bindings:
        # We have a binding-pass proof: name the exact RTL signal
        id_str = (f"transaction {proof_txn_id}" if proof_txn_id is not None
                  else "observed transaction")
        addr_str = (f" at address 0x{proof_addr:08X}" if isinstance(proof_addr, int)
                    else (f" at address {proof_addr}" if proof_addr is not None else ""))
        steps.append((
            f"Causal assignment identified  [PROOF]",
            f"{proof_asn_sig or src_base} at {causal_loc} bound to {id_str}{addr_str}: "
            f"writes {src_base} → {dst_base}.",
        ))
    else:
        # No binding proof — structural evidence only
        steps.append((
            "Structural assignment located",
            f"{causal_loc}: assigns {src_base} → {dst_base}.",
        ))

    # ── Step 6: Transform confirmed non-bijective ─────────────────────────
    if root_type == "TRANSPORT":
        strb = first_v.get("strobe_signal") if first_v else "WSTRB"
        steps.append((
            "Strobe misalignment confirmed",
            f"WSTRB byte-enables do not mirror the data lane steering "
            f"applied to {src_base}.",
        ))
    else:
        if sw and dw:
            try:
                bits_lost = int(sw) - int(dw)
                steps.append((
                    "Non-bijective transform confirmed",
                    f"{src_base}[{int(sw)-1}:0] truncated to {dst_base}[{int(dw)-1}:0] — "
                    f"{bits_lost} bit{'s' if bits_lost != 1 else ''} lost per write. "
                    f"Distinct inputs collapse to identical stored values.",
                ))
            except (TypeError, ValueError):
                steps.append((
                    "Non-bijective transform confirmed",
                    f"Transform is not reversible — distinct inputs produce "
                    f"identical stored values.",
                ))
        else:
            steps.append((
                "Non-bijective transform confirmed",
                f"Transform on {dst_base} is not reversible — distinct inputs "
                f"produce identical stored values.",
            ))

    # ── Conclusion ────────────────────────────────────────────────────────
    systemic = "systemic " if (len(dv) + len(tv)) > 1 else ""
    steps.append((
        "Conclusion",
        f"Protocol symptom caused by {systemic}{sem_class} in {dst_base}.",
    ))

    # Cap at 8 steps (PART 6)
    steps = steps[:8]
    return _format_trace_steps(steps)


def _format_trace_steps(steps: List[tuple]) -> str:
    """Format (label, detail) step pairs into the Causal Trace block."""
    lines = [_TRACE_BAR, "Causal Trace (Condensed)", _TRACE_BAR]
    for i, (label, detail) in enumerate(steps):
        if i > 0:
            lines.append("")
        if label == "Conclusion":
            lines.append("  Conclusion:")
            lines.append(f"  {detail}")
        else:
            lines.append(f"  {label}")
            lines.append(f"    {detail}")
    lines.append(_TRACE_BAR)
    return "\n".join(lines)
