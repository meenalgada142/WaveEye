from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple


AXI_LITE_SIGNAL_ALIASES: Dict[str, List[str]] = {
    # ── Handshake signals (VALID / READY) ─────────────────────────────────────
    "AWVALID": ["AWVALID", "s_axi_awvalid", "S_AXI_AWVALID",
                 "s_axil_awvalid", "s_axil_a_awvalid", "s_axil_b_awvalid"],
    "AWREADY": ["AWREADY", "s_axi_awready", "S_AXI_AWREADY",
                 "s_axil_awready", "s_axil_a_awready", "s_axil_b_awready"],
    "WVALID":  ["WVALID",  "s_axi_wvalid",  "S_AXI_WVALID",
                 "s_axil_wvalid",  "s_axil_a_wvalid",  "s_axil_b_wvalid"],
    "WREADY":  ["WREADY",  "s_axi_wready",  "S_AXI_WREADY",
                 "s_axil_wready",  "s_axil_a_wready",  "s_axil_b_wready"],
    "BVALID":  ["BVALID",  "s_axi_bvalid",  "S_AXI_BVALID",
                 "s_axil_bvalid",  "s_axil_a_bvalid",  "s_axil_b_bvalid"],
    "BREADY":  ["BREADY",  "s_axi_bready",  "S_AXI_BREADY",
                 "s_axil_bready",  "s_axil_a_bready",  "s_axil_b_bready"],
    "ARVALID": ["ARVALID", "s_axi_arvalid", "S_AXI_ARVALID",
                 "s_axil_arvalid", "s_axil_a_arvalid", "s_axil_b_arvalid"],
    "ARREADY": ["ARREADY", "s_axi_arready", "S_AXI_ARREADY",
                 "s_axil_arready", "s_axil_a_arready", "s_axil_b_arready"],
    "RVALID":  ["RVALID",  "s_axi_rvalid",  "S_AXI_RVALID",
                 "s_axil_rvalid",  "s_axil_a_rvalid",  "s_axil_b_rvalid"],
    "RREADY":  ["RREADY",  "s_axi_rready",  "S_AXI_RREADY",
                 "s_axil_rready",  "s_axil_a_rready",  "s_axil_b_rready"],
    # ── Payload / stability signals (required for MODE-C alias resolution) ─────
    # Without these, _detect_stability_mutation cannot find "RDATA" when the
    # waveform uses the prefixed name "s_axi_rdata".
    "RDATA":   ["RDATA",   "s_axi_rdata",   "S_AXI_RDATA",
                 "m_axi_rdata",   "M_AXI_RDATA"],
    "WDATA":   ["WDATA",   "s_axi_wdata",   "S_AXI_WDATA",
                 "m_axi_wdata",   "M_AXI_WDATA"],
    "WSTRB":   ["WSTRB",   "s_axi_wstrb",   "S_AXI_WSTRB",
                 "m_axi_wstrb",   "M_AXI_WSTRB"],
    "ARADDR":  ["ARADDR",  "s_axi_araddr",  "S_AXI_ARADDR",
                 "m_axi_araddr",  "M_AXI_ARADDR"],
    "AWADDR":  ["AWADDR",  "s_axi_awaddr",  "S_AXI_AWADDR",
                 "m_axi_awaddr",  "M_AXI_AWADDR"],
    "ARPROT":  ["ARPROT",  "s_axi_arprot",  "S_AXI_ARPROT",
                 "m_axi_arprot",  "M_AXI_ARPROT"],
    "AWPROT":  ["AWPROT",  "s_axi_awprot",  "S_AXI_AWPROT",
                 "m_axi_awprot",  "M_AXI_AWPROT"],
    "BRESP":   ["BRESP",   "s_axi_bresp",   "S_AXI_BRESP",
                 "m_axi_bresp",   "M_AXI_BRESP"],
    "RRESP":   ["RRESP",   "s_axi_rresp",   "S_AXI_RRESP",
                 "m_axi_rresp",   "M_AXI_RRESP"],
}


def resolve_signal(name: str, available_signals: Iterable[str]) -> Optional[str]:
    available = list(available_signals)
    available_lut = {s.lower(): s for s in available}
    for candidate in AXI_LITE_SIGNAL_ALIASES.get(name, [name]):
        hit = available_lut.get(candidate.lower())
        if hit:
            return hit
    return None


# ---------------------------------------------------------------------------
# Per-rule signal grouping (mirrors rca_7 step1_grouping fallback table).
#
#   primary   = the VIOLATED slave-driven signal(s) to backtrack via DG +
#               predicate trace.  These are the RTL signals the DUT failed
#               to assert / de-assert correctly.
#   secondary = REQUIRED DEPENDENCY signals whose values explain WHY the
#               primary failed.  Per AXI spec these must appear in the
#               primary signal's RTL driver conditions.  They may be master
#               inputs (not in the logic table) but are always in the waveform.
# ---------------------------------------------------------------------------
RULE_SIGNAL_MAP: Dict[str, Dict[str, List[str]]] = {
    # ── Read channel ──────────────────────────────────────────────────────────
    "RULE_1":  {"primary": ["ARVALID"],              "secondary": ["ARREADY"]},
    "RULE_5":  {"primary": ["RVALID"],               "secondary": ["RREADY"]},
    "RULE_7":  {"primary": ["ARREADY"],              "secondary": ["ARVALID"]},
    "RULE_8":  {"primary": ["ARREADY"],              "secondary": ["ARVALID"]},
    "RULE_9":  {"primary": ["RVALID"],               "secondary": ["ARVALID", "ARREADY"]},
    "RULE_10": {"primary": ["RVALID"],               "secondary": ["ARVALID", "ARREADY"]},
    "RULE_12": {"primary": ["ARREADY"],              "secondary": ["ARVALID", "RVALID", "RREADY"]},
    # ── Write channel ─────────────────────────────────────────────────────────
    "RULE_2":  {"primary": ["AWADDR"],               "secondary": ["AWVALID", "AWREADY"]},
    "RULE_3":  {"primary": ["WDATA", "WSTRB"],       "secondary": ["WVALID", "WREADY"]},
    "RULE_4":  {"primary": ["WDATA", "WSTRB"],       "secondary": ["WREADY"]},
    "RULE_6":  {"primary": ["BVALID"],               "secondary": ["BREADY"]},
    "RULE_11": {"primary": ["BVALID"],               "secondary": ["AWVALID", "AWREADY", "WVALID", "WREADY"]},
    "RULE_13": {"primary": ["AWREADY", "WREADY"],    "secondary": ["AWVALID", "WVALID", "BVALID", "BREADY"]},
    "RULE_14": {"primary": ["AWREADY"],              "secondary": ["AWVALID", "BVALID", "BREADY"]},
    "RULE_15": {"primary": ["BRESP"],                "secondary": ["BVALID", "BREADY"]},
}

# ---------------------------------------------------------------------------
# Per-rule accept-channel handshake pair for t_eval computation.
#
# t_eval = last cycle where (valid && ready) == 1 before the violation + 1.
# This anchors predicate backtracking to the cycle immediately after the
# protocol handshake, mirroring rca_7's step2_75 t_eval derivation.
# Rules not listed here have no well-defined accept event → fall back to
# the violation cycle.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Per-rule stability payload signal mapping (MODE-C RCA).
#
#   Entry: (stability_signal, valid_signal, ready_signal)
#
#   stability_signal = the DATA payload that must not change during the window
#   valid_signal     = the VALID that opens the stability window
#   ready_signal     = the READY that closes the window (handshake)
#
# If the RTL driver of `stability_signal` does not reference `ready_signal`
# in any condition, the signal can freely advance during backpressure —
# that is the structural root cause (missing READY gate in RTL).
# ---------------------------------------------------------------------------
RULE_STABILITY_SIGNAL_MAP: Dict[str, Tuple[str, str, str]] = {
    "RULE_1":  ("ARADDR",  "ARVALID",  "ARREADY"),  # AXI4L_ADDR_STABILITY
    "RULE_7":  ("WDATA",   "WVALID",   "WREADY"),   # AXI4L_WDATA_STABILITY
    "RULE_8":  ("RDATA",   "RVALID",   "RREADY"),   # AXI4L_RDATA_STABILITY
    "RULE_9":  ("BRESP",   "BVALID",   "BREADY"),   # AXI4L_BRESP_STABILITY
    "RULE_14": ("ARPROT",  "ARVALID",  "ARREADY"),  # AXI4L_ARPROT_STABILITY
    "RULE_15": ("AWPROT",  "AWVALID",  "AWREADY"),  # AXI4L_AWPROT_STABILITY
}

# Derived frozenset — the single source of truth for which rules trigger MODE-C.
# rca_8.py imports this instead of maintaining its own hardcoded set.
STABILITY_RULES: frozenset = frozenset(RULE_STABILITY_SIGNAL_MAP.keys())


RULE_ACCEPT_CHANNEL: Dict[str, Tuple[str, str]] = {
    # Read response obligation starts at AR acceptance
    "RULE_5":  ("ARVALID", "ARREADY"),
    "RULE_7":  ("ARVALID", "ARREADY"),
    "RULE_8":  ("ARVALID", "ARREADY"),
    "RULE_9":  ("ARVALID", "ARREADY"),
    "RULE_10": ("ARVALID", "ARREADY"),
    "RULE_12": ("ARVALID", "ARREADY"),
    # Write response obligation starts at AW acceptance
    "RULE_6":  ("AWVALID", "AWREADY"),
    "RULE_11": ("AWVALID", "AWREADY"),
    "RULE_13": ("AWVALID", "AWREADY"),
    "RULE_14": ("AWVALID", "AWREADY"),
}

