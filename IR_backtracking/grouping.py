#!/usr/bin/env python3
"""
AXI4-Lite Violation Analyzer - Standalone Version
All dependencies included in single file

Usage:
    python axi4_analyzer_standalone.py violations.json
    python axi4_analyzer_standalone.py violations.csv
    python axi4_analyzer_standalone.py violations.json --export analysis.json
"""

import json
import csv
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


# ============================================================================
# CORE DATA STRUCTURES
# ============================================================================
# ============================================================================
# CANONICAL SIGNAL REGISTRY (alias resolver)
# ============================================================================

class CanonicalSignalRegistry:
    def __init__(self):
        self.alias_to_canonical = {}
        self.canonical_to_aliases = {}

    def register(self, canonical, *aliases):
        canonical = canonical.upper()

        if canonical not in self.canonical_to_aliases:
            self.canonical_to_aliases[canonical] = set()

        self.canonical_to_aliases[canonical].add(canonical)
        self.alias_to_canonical[canonical] = canonical

        for a in aliases:
            a = a.upper()
            self.alias_to_canonical[a] = canonical
            self.canonical_to_aliases[canonical].add(a)

    def resolve(self, sig):
        if not sig:
            return sig
        return self.alias_to_canonical.get(sig.upper(), sig.upper())

class Channel(Enum):
    """AXI4-Lite channel types"""
    GLOBAL = "GLOBAL"
    AW = "AW"
    W = "W"
    B = "B"
    AR = "AR"
    R = "R"
    WA = "WA"
    RA = "RA"


class SignalRole(Enum):
    """Signal role in protocol violation analysis"""
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"
    CONTEXT = "CONTEXT"
    ELIGIBILITY = "ELIGIBILITY"


@dataclass
class ProtocolRule:
    """Represents a single AXI4-Lite protocol rule"""
    rule_id: str
    channel: Channel
    description: str
    eligibility_bundle: List[str]
    primary_violation_bundle: List[str]
    secondary_context: List[str]
    notes: Optional[str] = None


@dataclass
class ViolationRecord:
    """Represents a single violation from the input file"""
    timestamp: Optional[int] = None
    cycle: Optional[int] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: str = "ERROR"
    message: str = ""
    failing_signals: List[str] = None
    signal_values: Dict[str, any] = None
    
    def __post_init__(self):
        if self.failing_signals is None:
            self.failing_signals = []
        if self.signal_values is None:
            self.signal_values = {}


# ============================================================================
# SIGNAL DATABASE
# ============================================================================

class AXI4LiteSignalDatabase:
    """Complete AXI4-Lite signal classification database"""
    
    def __init__(self):
        self.rules: List[ProtocolRule] = []
        self._initialize_rules()
        # ---- Canonical signal registry ----
        self.sig_registry = CanonicalSignalRegistry()

        # AXI canonical mappings
        self.sig_registry.register("AWVALID", "S_AXIL_AWVALID", "M_AXI_AWVALID")
        self.sig_registry.register("AWREADY", "S_AXIL_AWREADY", "M_AXI_AWREADY")
        self.sig_registry.register("AWADDR",  "S_AXIL_AWADDR",  "M_AXI_AWADDR")
        self.sig_registry.register("AWPROT",  "S_AXIL_AWPROT",  "M_AXI_AWPROT")

        self.sig_registry.register("WVALID", "S_AXIL_WVALID", "M_AXI_WVALID")
        self.sig_registry.register("WREADY", "S_AXIL_WREADY", "M_AXI_WREADY")
        self.sig_registry.register("WDATA",  "S_AXIL_WDATA",  "M_AXI_WDATA")
        self.sig_registry.register("WSTRB",  "S_AXIL_WSTRB",  "M_AXI_WSTRB")

        self.sig_registry.register("BVALID", "S_AXIL_BVALID", "M_AXI_BVALID")
        self.sig_registry.register("BREADY", "S_AXIL_BREADY", "M_AXI_BREADY")
        self.sig_registry.register("BRESP",  "S_AXIL_BRESP",  "M_AXI_BRESP")

        self.sig_registry.register("ARVALID", "S_AXIL_ARVALID", "M_AXI_ARVALID")
        self.sig_registry.register("ARREADY", "S_AXIL_ARREADY", "M_AXI_ARREADY")
        self.sig_registry.register("ARADDR",  "S_AXIL_ARADDR",  "M_AXI_ARADDR")
        self.sig_registry.register("ARPROT",  "S_AXIL_ARPROT",  "M_AXI_ARPROT")

        self.sig_registry.register("RVALID", "S_AXIL_RVALID", "M_AXI_RVALID")
        self.sig_registry.register("RREADY", "S_AXIL_RREADY", "M_AXI_RREADY")
        self.sig_registry.register("RDATA",  "S_AXIL_RDATA",  "M_AXI_RDATA")
        self.sig_registry.register("RRESP",  "S_AXIL_RRESP",  "M_AXI_RRESP")

        self.sig_registry.register("ARESETN", "RST_N", "RESETN")
        self.sig_registry.register("ACLK", "CLK")

    def _initialize_rules(self):
        """Initialize all AXI4-Lite protocol rules with official AMBA spec numbers"""
        
        # GLOBAL RULES - AXI4-Lite Restrictions (Chapter A9)
        self.rules.extend([
            ProtocolRule(
                rule_id="A3.1.2", channel=Channel.GLOBAL,
                description="Reset requirements",
                eligibility_bundle=["ACLK"],
                primary_violation_bundle=["ARESETn"],
                secondary_context=["AWVALID", "AWREADY", "WVALID", "WREADY", "BVALID", "BREADY",
                                 "ARVALID", "ARREADY", "RVALID", "RREADY"],
                notes="AMBA AXI4 A3.1.2: Reset behavior and signal dependencies"
            ),
            ProtocolRule(
                rule_id="A9.3-WRITE", channel=Channel.GLOBAL,
                description="One outstanding write transaction (AXI4-Lite)",
                eligibility_bundle=["AWVALID || WVALID || BVALID"],
                primary_violation_bundle=["AWVALID", "WVALID", "BVALID"],
                secondary_context=["AWREADY", "WREADY", "BREADY"],
                notes="AMBA AXI4 A9.3: AXI4-Lite permits only one outstanding write"
            ),
            ProtocolRule(
                rule_id="A9.3-READ", channel=Channel.GLOBAL,
                description="One outstanding read transaction (AXI4-Lite)",
                eligibility_bundle=["ARVALID || RVALID"],
                primary_violation_bundle=["ARVALID", "RVALID"],
                secondary_context=["ARREADY", "RREADY"],
                notes="AMBA AXI4 A9.3: AXI4-Lite permits only one outstanding read"
            ),
        ])
        
        # WRITE ADDRESS CHANNEL (Chapter A3.3)
        self.rules.extend([
            ProtocolRule(
                rule_id="AW-A3.2.1", channel=Channel.AW,
                description="AWVALID must remain asserted until handshake",
                eligibility_bundle=["AWVALID"],
                primary_violation_bundle=["AWVALID"],
                secondary_context=["AWREADY"],
                notes="AMBA AXI4 A3.2.1: VALID must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="AW-A3.2.2", channel=Channel.AW,
                description="AWADDR must remain stable when AWVALID high and AWREADY low",
                eligibility_bundle=["AWVALID && !AWREADY"],
                primary_violation_bundle=["AWADDR"],
                secondary_context=["AWREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
            ProtocolRule(
                rule_id="AW-A3.2.3", channel=Channel.AW,
                description="AWPROT must remain stable when AWVALID high and AWREADY low",
                eligibility_bundle=["AWVALID && !AWREADY"],
                primary_violation_bundle=["AWPROT"],
                secondary_context=["AWREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
        ])
        
        # WRITE DATA CHANNEL (Chapter A3.4)
        self.rules.extend([
            ProtocolRule(
                rule_id="W-A3.2.1", channel=Channel.W,
                description="WVALID must remain asserted until handshake",
                eligibility_bundle=["WVALID"],
                primary_violation_bundle=["WVALID"],
                secondary_context=["WREADY"],
                notes="AMBA AXI4 A3.2.1: VALID must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="W-A3.2.2", channel=Channel.W,
                description="WDATA must remain stable when WVALID high and WREADY low",
                eligibility_bundle=["WVALID && !WREADY"],
                primary_violation_bundle=["WDATA"],
                secondary_context=["WREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
            ProtocolRule(
                rule_id="W-A3.2.3", channel=Channel.W,
                description="WSTRB must remain stable when WVALID high and WREADY low",
                eligibility_bundle=["WVALID && !WREADY"],
                primary_violation_bundle=["WSTRB"],
                secondary_context=["WREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
        ])
        
        # WRITE RESPONSE CHANNEL (Chapter A3.5)
        self.rules.extend([
            ProtocolRule(
                rule_id="B-A3.3.1", channel=Channel.B,
                description="Write response must be generated after write transaction acceptance",
                eligibility_bundle=["AWVALID && AWREADY", "WVALID && WREADY"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BRESP", "BREADY"],
                notes="AMBA AXI4 A3.3.1: Response depends on address and data acceptance"
            ),
            ProtocolRule(
                rule_id="B-A3.2.2", channel=Channel.B,
                description="BRESP must remain stable when BVALID high and BREADY low",
                eligibility_bundle=["BVALID && !BREADY"],
                primary_violation_bundle=["BRESP"],
                secondary_context=["BREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
            ProtocolRule(
                rule_id="B-A3.2.1", channel=Channel.B,
                description="BVALID must remain asserted until handshake",
                eligibility_bundle=["BVALID"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BREADY"],
                notes="AMBA AXI4 A3.2.1: VALID must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="B-A3.3.2", channel=Channel.B,
                description="Exactly one write response per accepted write transaction",
                eligibility_bundle=["Write acceptance bundle completed"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BREADY"],
                notes="AMBA AXI4 A3.3.2: One response per transaction"
            ),
        ])
        
        # READ ADDRESS CHANNEL (Chapter A4.3)
        self.rules.extend([
            ProtocolRule(
                rule_id="AR-A3.2.1", channel=Channel.AR,
                description="ARVALID must remain asserted until handshake",
                eligibility_bundle=["ARVALID"],
                primary_violation_bundle=["ARVALID"],
                secondary_context=["ARREADY"],
                notes="AMBA AXI4 A3.2.1: VALID must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="AR-A3.2.2", channel=Channel.AR,
                description="ARADDR must remain stable when ARVALID high and ARREADY low",
                eligibility_bundle=["ARVALID && !ARREADY"],
                primary_violation_bundle=["ARADDR"],
                secondary_context=["ARREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
            ProtocolRule(
                rule_id="AR-A3.2.3", channel=Channel.AR,
                description="ARPROT must remain stable when ARVALID high and ARREADY low",
                eligibility_bundle=["ARVALID && !ARREADY"],
                primary_violation_bundle=["ARPROT"],
                secondary_context=["ARREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
        ])
        
        # READ DATA CHANNEL (Chapter A4.4)
        self.rules.extend([
            ProtocolRule(
                rule_id="R-A4.3.1", channel=Channel.R,
                description="Read data must be generated after read address acceptance",
                eligibility_bundle=["ARVALID && ARREADY"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["RREADY", "RDATA", "RRESP"],
                notes="AMBA AXI4 A4.3.1: Response depends on address acceptance"
            ),
            ProtocolRule(
                rule_id="R-A3.2.2", channel=Channel.R,
                description="RDATA must remain stable when RVALID high and RREADY low",
                eligibility_bundle=["RVALID && !RREADY"],
                primary_violation_bundle=["RDATA"],
                secondary_context=["RREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
            ProtocolRule(
                rule_id="R-A3.2.3", channel=Channel.R,
                description="RRESP must remain stable when RVALID high and RREADY low",
                eligibility_bundle=["RVALID && !RREADY"],
                primary_violation_bundle=["RRESP"],
                secondary_context=["RREADY"],
                notes="AMBA AXI4 A3.2.2: Payload must remain stable"
            ),
            ProtocolRule(
                rule_id="R-A3.2.1", channel=Channel.R,
                description="RVALID must remain asserted until handshake",
                eligibility_bundle=["RVALID"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["RREADY"],
                notes="AMBA AXI4 A3.2.1: VALID must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="R-A4.3.2", channel=Channel.R,
                description="Exactly one read response per accepted read transaction",
                eligibility_bundle=["ARVALID && ARREADY"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["RREADY"],
                notes="AMBA AXI4 A4.3.2: One response per transaction"
            ),
        ])
        
        # WRITE ADDRESS CHANNEL (Chapter A3.3)
        self.rules.extend([
            ProtocolRule(
                rule_id="A3.2.1", channel=Channel.AW,
                description="AWVALID must remain asserted until handshake",
                eligibility_bundle=["AWVALID"],
                primary_violation_bundle=["AWVALID"],
                secondary_context=["AWREADY"],
                notes="Once AWVALID is asserted, it must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="A3.2.2", channel=Channel.AW,
                description="AWADDR must remain stable when AWVALID high and AWREADY low",
                eligibility_bundle=["AWVALID && !AWREADY"],
                primary_violation_bundle=["AWADDR"],
                secondary_context=["AWREADY"],
                notes="Address payload must remain stable during valid-not-ready phase"
            ),
            ProtocolRule(
                rule_id="A3.2.3", channel=Channel.AW,
                description="AWPROT must remain stable when AWVALID high and AWREADY low",
                eligibility_bundle=["AWVALID && !AWREADY"],
                primary_violation_bundle=["AWPROT"],
                secondary_context=["AWREADY"],
                notes="Protection attributes must remain stable during valid-not-ready phase"
            ),
        ])
        
        # WRITE DATA CHANNEL (Chapter A3.4)
        self.rules.extend([
            ProtocolRule(
                rule_id="A3.2.1", channel=Channel.W,
                description="WVALID must remain asserted until handshake",
                eligibility_bundle=["WVALID"],
                primary_violation_bundle=["WVALID"],
                secondary_context=["WREADY"],
                notes="Once WVALID is asserted, it must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="A3.2.2", channel=Channel.W,
                description="WDATA must remain stable when WVALID high and WREADY low",
                eligibility_bundle=["WVALID && !WREADY"],
                primary_violation_bundle=["WDATA"],
                secondary_context=["WREADY"],
                notes="Write data must remain stable during valid-not-ready phase"
            ),
            ProtocolRule(
                rule_id="A3.2.3", channel=Channel.W,
                description="WSTRB must remain stable when WVALID high and WREADY low",
                eligibility_bundle=["WVALID && !WREADY"],
                primary_violation_bundle=["WSTRB"],
                secondary_context=["WREADY"],
                notes="Write strobe must remain stable during valid-not-ready phase"
            ),
        ])
        
        # WRITE RESPONSE CHANNEL (Chapter A3.5)
        self.rules.extend([
            ProtocolRule(
                rule_id="A3.3.1", channel=Channel.B,
                description="Write response must be generated after write transaction acceptance",
                eligibility_bundle=["AWVALID && AWREADY", "WVALID && WREADY"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BRESP", "BREADY"],
                notes="BVALID depends on completion of both address and data acceptance"
            ),
            ProtocolRule(
                rule_id="A3.2.2", channel=Channel.B,
                description="BRESP must remain stable when BVALID high and BREADY low",
                eligibility_bundle=["BVALID && !BREADY"],
                primary_violation_bundle=["BRESP"],
                secondary_context=["BREADY"],
                notes="Response encoding must remain stable during valid-not-ready phase"
            ),
            ProtocolRule(
                rule_id="A3.2.1", channel=Channel.B,
                description="BVALID must remain asserted until handshake",
                eligibility_bundle=["BVALID"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BREADY"],
                notes="Once BVALID is asserted, it must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="A3.3.2", channel=Channel.B,
                description="Exactly one write response per accepted write transaction",
                eligibility_bundle=["Write acceptance bundle completed"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BREADY"],
                notes="Response count must match number of accepted write transactions"
            ),
        ])
        
        # READ ADDRESS CHANNEL (Chapter A4.3)
        self.rules.extend([
            ProtocolRule(
                rule_id="A3.2.1", channel=Channel.AR,
                description="ARVALID must remain asserted until handshake",
                eligibility_bundle=["ARVALID"],
                primary_violation_bundle=["ARVALID"],
                secondary_context=["ARREADY"],
                notes="Once ARVALID is asserted, it must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="A3.2.2", channel=Channel.AR,
                description="ARADDR must remain stable when ARVALID high and ARREADY low",
                eligibility_bundle=["ARVALID && !ARREADY"],
                primary_violation_bundle=["ARADDR"],
                secondary_context=["ARREADY"],
                notes="Read address must remain stable during valid-not-ready phase"
            ),
            ProtocolRule(
                rule_id="A3.2.3", channel=Channel.AR,
                description="ARPROT must remain stable when ARVALID high and ARREADY low",
                eligibility_bundle=["ARVALID && !ARREADY"],
                primary_violation_bundle=["ARPROT"],
                secondary_context=["ARREADY"],
                notes="Protection attributes must remain stable during valid-not-ready phase"
            ),
        ])
        
        # READ DATA CHANNEL (Chapter A4.4)
        self.rules.extend([
            ProtocolRule(
                rule_id="A4.3.1", channel=Channel.R,
                description="Read data must be generated after read address acceptance",
                eligibility_bundle=["ARVALID && ARREADY"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["RREADY", "RDATA", "RRESP"],
                notes="RVALID depends on completion of read address acceptance"
            ),
            ProtocolRule(
                rule_id="A3.2.2", channel=Channel.R,
                description="RDATA must remain stable when RVALID high and RREADY low",
                eligibility_bundle=["RVALID && !RREADY"],
                primary_violation_bundle=["RDATA"],
                secondary_context=["RREADY"],
                notes="Read data must remain stable during valid-not-ready phase"
            ),
            ProtocolRule(
                rule_id="A3.2.3", channel=Channel.R,
                description="RRESP must remain stable when RVALID high and RREADY low",
                eligibility_bundle=["RVALID && !RREADY"],
                primary_violation_bundle=["RRESP"],
                secondary_context=["RREADY"],
                notes="Read response must remain stable during valid-not-ready phase"
            ),
            ProtocolRule(
                rule_id="A3.2.1", channel=Channel.R,
                description="RVALID must remain asserted until handshake",
                eligibility_bundle=["RVALID"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["RREADY"],
                notes="Once RVALID is asserted, it must remain asserted until handshake"
            ),
            ProtocolRule(
                rule_id="A4.3.2", channel=Channel.R,
                description="Exactly one read response per accepted read transaction",
                eligibility_bundle=["ARVALID && ARREADY"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["RREADY"],
                notes="Response count must match number of accepted read transactions"
            ),
        ])

        # ================================================================
        # RULE_X ALIASES — Checker-tool rule IDs (e.g. from axil4.py)
        # ================================================================
        # Many checkers emit RULE_1..RULE_14 instead of AMBA section numbers.
        # These entries let get_rule_by_id("RULE_10") resolve directly.
        #
        # CAUSAL DESIGN for RCA:
        #   primary_violation_bundle = signal to BACKTRACK on (slave-driven)
        #   secondary_context        = required AXI DEPENDENCIES that MUST
        #                              appear in primary's RTL driver predicate
        self.rules.extend([
            # --- Read channel ---
            ProtocolRule(
                rule_id="RULE_1", channel=Channel.AR,
                description="ARVALID must remain asserted until ARREADY handshake",
                eligibility_bundle=["ARVALID"],
                primary_violation_bundle=["ARVALID"],
                secondary_context=["ARREADY"],
                notes="Checker RULE_1: VALID stability"
            ),
            ProtocolRule(
                rule_id="RULE_2", channel=Channel.AR,
                description="ARADDR must remain stable while ARVALID high",
                eligibility_bundle=["ARVALID && !ARREADY"],
                primary_violation_bundle=["ARADDR"],
                secondary_context=["ARVALID", "ARREADY"],
                notes="Checker RULE_2: Address stability"
            ),
            ProtocolRule(
                rule_id="RULE_7", channel=Channel.AR,
                description="ARREADY driver must reference ARVALID",
                eligibility_bundle=["ARVALID"],
                primary_violation_bundle=["ARREADY"],
                secondary_context=["ARVALID"],
                notes="Checker RULE_7: ARREADY depends on ARVALID"
            ),
            ProtocolRule(
                rule_id="RULE_8", channel=Channel.AR,
                description="ARADDR stability during valid phase",
                eligibility_bundle=["ARVALID && !ARREADY"],
                primary_violation_bundle=["ARREADY"],
                secondary_context=["ARVALID", "ARADDR"],
                notes="Checker RULE_8: Read address stability"
            ),
            ProtocolRule(
                rule_id="RULE_9", channel=Channel.R,
                description="RVALID must only assert after AR handshake completes",
                eligibility_bundle=["ARVALID && ARREADY"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["ARVALID", "ARREADY"],
                notes="Checker RULE_9: Read response ordering"
            ),
            ProtocolRule(
                rule_id="RULE_10", channel=Channel.R,
                description="Read response without preceding read address handshake",
                eligibility_bundle=["ARVALID && ARREADY"],
                primary_violation_bundle=["RVALID"],
                secondary_context=["ARVALID", "ARREADY"],
                notes="Checker RULE_10: RVALID requires AR handshake first"
            ),
            ProtocolRule(
                rule_id="RULE_12", channel=Channel.AR,
                description="Only one outstanding read transaction (AXI4-Lite)",
                eligibility_bundle=["ARVALID"],
                primary_violation_bundle=["ARREADY"],
                secondary_context=["ARVALID", "RVALID", "RREADY"],
                notes="Checker RULE_12: ARREADY must wait for R completion"
            ),
            # --- Write channel ---
            ProtocolRule(
                rule_id="RULE_3", channel=Channel.AW,
                description="AWVALID must remain asserted until AWREADY handshake",
                eligibility_bundle=["AWVALID"],
                primary_violation_bundle=["AWVALID"],
                secondary_context=["AWREADY"],
                notes="Checker RULE_3: VALID stability"
            ),
            ProtocolRule(
                rule_id="RULE_4", channel=Channel.W,
                description="WDATA/WSTRB must remain stable while WVALID high",
                eligibility_bundle=["WVALID && !WREADY"],
                primary_violation_bundle=["WDATA", "WVALID"],
                secondary_context=["WREADY"],
                notes="Checker RULE_4: Write data stability"
            ),
            ProtocolRule(
                rule_id="RULE_5", channel=Channel.B,
                description="BVALID must only assert after AW+W handshakes complete",
                eligibility_bundle=["AWVALID && AWREADY", "WVALID && WREADY"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["AWVALID", "AWREADY", "WVALID", "WREADY"],
                notes="Checker RULE_5: Write response ordering"
            ),
            ProtocolRule(
                rule_id="RULE_6", channel=Channel.B,
                description="BVALID must remain asserted until BREADY handshake",
                eligibility_bundle=["BVALID"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["BREADY"],
                notes="Checker RULE_6: BVALID stability"
            ),
            ProtocolRule(
                rule_id="RULE_11", channel=Channel.B,
                description="Write response before write transaction completion",
                eligibility_bundle=["AWVALID && AWREADY", "WVALID && WREADY"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["AWVALID", "AWREADY", "WVALID", "WREADY"],
                notes="Checker RULE_11: BVALID requires AW+W handshakes first"
            ),
            ProtocolRule(
                rule_id="RULE_13", channel=Channel.AW,
                description="AW/W must coordinate and complete before new transaction",
                eligibility_bundle=["AWVALID", "WVALID"],
                primary_violation_bundle=["BVALID"],
                secondary_context=["AWVALID", "WVALID", "BVALID", "BREADY"],
                notes="Checker RULE_13: Write outstanding transaction enforcement"
            ),
            ProtocolRule(
                rule_id="RULE_14", channel=Channel.AW,
                description="AWREADY must wait for B completion before new write",
                eligibility_bundle=["AWVALID"],
                primary_violation_bundle=["AWREADY"],
                secondary_context=["AWVALID", "BVALID", "BREADY"],
                notes="Checker RULE_14: One outstanding write enforcement"
            ),
        ])

    def get_rule_by_id(self, rule_id: str) -> Optional[ProtocolRule]:
        """Get a specific rule by its ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None
    
    def get_signal_role_in_rule(self, signal: str, rule_id: str) -> Optional[SignalRole]:
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None

        signal = signal.upper()
        elig = [e.upper() for e in rule.eligibility_bundle]
        prim = [p.upper() for p in rule.primary_violation_bundle]
        sec  = [s.upper() for s in rule.secondary_context]

        if signal in prim:
            return SignalRole.PRIMARY
        if signal in sec:
            return SignalRole.SECONDARY
        if signal in elig or any(signal in expr for expr in elig):
            return SignalRole.ELIGIBILITY

        return None




# ============================================================================
# FILE PARSERS
# ============================================================================

class ViolationFileParser:
    """Parse violations from JSON or CSV files"""
    
    @staticmethod
    def parse_json(filepath: str) -> List[ViolationRecord]:
        """Parse violations from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        violations = []
        
        if isinstance(data, list):
            for item in data:
                violations.append(ViolationFileParser._json_to_record(item))
        elif isinstance(data, dict):
            if 'violations' in data:
                for item in data['violations']:
                    violations.append(ViolationFileParser._json_to_record(item))
            else:
                violations.append(ViolationFileParser._json_to_record(data))
        
        return violations
    
    @staticmethod
    def _json_to_record(item: Dict) -> ViolationRecord:
        """Convert JSON object to ViolationRecord"""
        # RULE_X → AMBA mapping for rules NOT in the direct database.
        # RULE_1..RULE_14 have direct ProtocolRule entries with correct
        # causal primary/secondary, so they are NOT remapped.
        rule_id_map = {
            'RULE_15': 'W-A3.2.3',     # WSTRB stability - AMBA AXI4 A3.2.2
            'RULE_16': 'B-A3.2.2',     # BRESP stability - AMBA AXI4 A3.2.2
            'RULE_17': 'B-A3.3.2',     # One response per write - AMBA AXI4 A3.3.2
            'RULE_18': 'AR-A3.2.3',    # ARPROT stability - AMBA AXI4 A3.2.2
            'RULE_19': 'R-A3.2.2',     # RDATA stability - AMBA AXI4 A3.2.2
            'RULE_20': 'R-A3.2.3',     # RRESP stability - AMBA AXI4 A3.2.2
            'RULE_21': 'R-A4.3.2',     # One response per read - AMBA AXI4 A4.3.2
        }
        
        original_rule_id = item.get('rule_id') or item.get('rule')
        mapped_rule_id = rule_id_map.get(original_rule_id, original_rule_id)
        
        message = item.get('message') or item.get('explanation') or item.get('symptoms', '')
        
        return ViolationRecord(
            timestamp=item.get('timestamp'),
            cycle=item.get('cycle'),
            rule_id=mapped_rule_id,
            rule_name=item.get('rule_name') or item.get('description'),
            severity=item.get('severity', 'ERROR'),
            message=message,
            failing_signals=item.get('failing_signals', []),
            signal_values=item.get('signal_values', {})
        )
    
    @staticmethod
    def parse_csv(filepath: str) -> List[ViolationRecord]:
        """Parse violations from CSV file"""
        violations = []
        
        # RULE_X → AMBA mapping for rules NOT in the direct database.
        # RULE_1..RULE_14 have direct ProtocolRule entries with correct
        # causal primary/secondary, so they are NOT remapped.
        rule_id_map = {
            'RULE_15': 'W-A3.2.3',     # WSTRB stability - AMBA AXI4 A3.2.2
            'RULE_16': 'B-A3.2.2',     # BRESP stability - AMBA AXI4 A3.2.2
            'RULE_17': 'B-A3.3.2',     # One response per write - AMBA AXI4 A3.3.2
            'RULE_18': 'AR-A3.2.3',    # ARPROT stability - AMBA AXI4 A3.2.2
            'RULE_19': 'R-A3.2.2',     # RDATA stability - AMBA AXI4 A3.2.2
            'RULE_20': 'R-A3.2.3',     # RRESP stability - AMBA AXI4 A3.2.2
            'RULE_21': 'R-A4.3.2',     # One response per read - AMBA AXI4 A4.3.2
        }
        
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                failing_signals = []
                if 'failing_signals' in row and row['failing_signals']:
                    failing_signals = [s.strip().upper() for s in row['failing_signals'].split(',')]

                
                signal_values = {}
                for key, value in row.items():
                    if key and key.startswith('signal_') and value:
                        sig_name = key.replace('signal_', '')
                        signal_values[sig_name] = value
                
                original_rule_id = row.get('rule_id') or row.get('rule')
                mapped_rule_id = rule_id_map.get(original_rule_id, original_rule_id)
                
                message = row.get('message') or row.get('explanation', '')
                
                violations.append(ViolationRecord(
                    timestamp=int(row.get('timestamp', 0)) if row.get('timestamp') else None,
                    cycle=int(row.get('cycle', 0)) if row.get('cycle') else None,
                    rule_id=mapped_rule_id,
                    rule_name=row.get('rule_name') or row.get('description'),
                    severity=row.get('severity', 'ERROR'),
                    message=message,
                    failing_signals=failing_signals,
                    signal_values=signal_values
                ))
        
        return violations


# ============================================================================
# ANALYZER
# ============================================================================

class AutomaticViolationAnalyzer:
    """Automatically analyze violations and identify responsible signals"""
    
    def __init__(self):
        self.db = AXI4LiteSignalDatabase()
        self.violations: List[ViolationRecord] = []
        self.analysis_results: List[Dict] = []
    
    def load_violations(self, filepath: str) -> int:
        """Load violations from JSON or CSV file"""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Violation file not found: {filepath}")
        
        if filepath.suffix == '.json':
            self.violations = ViolationFileParser.parse_json(str(filepath))
        elif filepath.suffix == '.csv':
            self.violations = ViolationFileParser.parse_csv(str(filepath))
        else:
            raise ValueError(f"Unsupported file format: {filepath.suffix}. Use .json or .csv")
        
        print(f"Loaded {len(self.violations)} violations from {filepath.name}")
        return len(self.violations)
    
    def _infer_rule_from_message(self, violation: ViolationRecord) -> Optional[str]:
        """Infer rule ID from violation message"""
        message = violation.message.lower() if violation.message else ""
        rule_name = violation.rule_name.lower() if violation.rule_name else ""
        
        combined_text = message + " " + rule_name
        
        if 'multiple outstanding read' in combined_text or \
           ('outstanding' in combined_text and 'read' in combined_text):
            return 'G3'
        if 'multiple outstanding write' in combined_text or \
           ('outstanding' in combined_text and 'write' in combined_text):
            return 'G2'
        
        rule_keywords = {
            'G1': ['reset', 'aresetn'],
            'AW1': ['awvalid', 'asserted until'],
            'AW2': ['awaddr', 'stable'],
            'AW3': ['awprot', 'stable'],
            'W1': ['wvalid', 'asserted until'],
            'W2': ['wdata', 'stable'],
            'W3': ['wstrb', 'stable'],
            'B1': ['bvalid', 'after write'],
            'B2': ['bresp', 'stable'],
            'B3': ['bvalid', 'asserted until'],
            'AR1': ['arvalid', 'asserted until'],
            'AR2': ['araddr', 'stable'],
            'AR3': ['arprot', 'stable'],
            'R1': ['rvalid', 'after read'],
            'R2': ['rdata', 'stable'],
            'R3': ['rresp', 'stable'],
            'R4': ['rvalid', 'asserted until'],
        }
        
        for rule_id, keywords in rule_keywords.items():
            if any(kw in combined_text for kw in keywords):
                return rule_id
        
        return None
    
    def _infer_failing_signals_from_message(self, violation: ViolationRecord) -> List[str]:
        """Extract signal names from violation message"""
        if violation.failing_signals:
            return violation.failing_signals
        
        message = violation.message if violation.message else ""
        
        axi_signals = [
            'AWVALID', 'AWREADY', 'AWADDR', 'AWPROT',
            'WVALID', 'WREADY', 'WDATA', 'WSTRB',
            'BVALID', 'BREADY', 'BRESP',
            'ARVALID', 'ARREADY', 'ARADDR', 'ARPROT',
            'RVALID', 'RREADY', 'RDATA', 'RRESP',
            'ACLK', 'ARESETn'
        ]
        
        found_signals = []
        message_upper = message.upper()
        
        for signal in axi_signals:
            if signal in message_upper:
                found_signals.append(self.db.sig_registry.resolve(signal))

        
        if not found_signals and violation.rule_id:
            if violation.rule_id == 'G3':
                found_signals = ['ARVALID', 'RVALID']
            elif violation.rule_id == 'G2':
                found_signals = ['AWVALID', 'WVALID', 'BVALID']
        
        return found_signals
    
    def analyze_violation(self, violation: ViolationRecord) -> Dict:
        """Analyze a single violation and identify responsible signals"""
        if not violation.rule_id:
            violation.rule_id = self._infer_rule_from_message(violation)
        
        if not violation.failing_signals:
            violation.failing_signals = self._infer_failing_signals_from_message(violation)
        
        if not violation.rule_id:
            return {
                'status': 'UNKNOWN',
                'error': 'Could not determine violated rule',
                'violation': violation
            }
        
        rule = self.db.get_rule_by_id(violation.rule_id)
        if not rule:
            return {
                'status': 'ERROR',
                'error': f'Rule {violation.rule_id} not found in database',
                'violation': violation
            }
        
        primary_signals = []
        secondary_signals = []
        
        for signal in violation.failing_signals:
            signal = self.db.sig_registry.resolve(signal)

            role = self.db.get_signal_role_in_rule(signal, violation.rule_id)
            if role == SignalRole.PRIMARY:
                primary_signals.append(signal)
            elif role == SignalRole.SECONDARY:
                secondary_signals.append(signal)
        
        if not violation.failing_signals:
            primary_signals = rule.primary_violation_bundle
            secondary_signals = rule.secondary_context
        
        if primary_signals:
            root_cause = primary_signals
            cause_type = "PRIMARY"
            recommendation = f"Investigate primary signals: {', '.join(primary_signals)}"
            severity = "CRITICAL"
        elif secondary_signals:
            root_cause = rule.primary_violation_bundle
            cause_type = "SECONDARY_SYMPTOM"
            recommendation = f"Secondary signals ({', '.join(secondary_signals)}) failed. Check primary signals: {', '.join(rule.primary_violation_bundle)}"
            severity = "HIGH"
        else:
            root_cause = rule.primary_violation_bundle
            cause_type = "INFERRED"
            recommendation = f"No specific signals identified. Check primary signals for {violation.rule_id}: {', '.join(rule.primary_violation_bundle)}"
            severity = "MEDIUM"
        
        priority_order = []
        priority_order.extend(rule.primary_violation_bundle)
        for cond in rule.eligibility_bundle:
            signals = cond.replace("&&", " ").replace("||", " ").replace("!", " ").split()
            priority_order.extend([s.strip() for s in signals if s.strip()])
        priority_order.extend(rule.secondary_context)
        
        seen = set()
        unique_priority = []
        for sig in priority_order:
            if sig not in seen and sig:
                seen.add(sig)
                unique_priority.append(sig)
        
        return {
            'status': 'ANALYZED',
            'timestamp': violation.timestamp,
            'cycle': violation.cycle,
            'rule_id': violation.rule_id,
            'rule_description': rule.description,
            'channel': rule.channel.value,
            'severity': severity,
            'original_message': violation.message,
            
            'signals': {
                'primary': primary_signals if primary_signals else rule.primary_violation_bundle,
                'secondary': secondary_signals if secondary_signals else rule.secondary_context,
            },
            
            'root_cause': {
                'signals': root_cause,
                'type': cause_type,
                'recommendation': recommendation
            },
            
            'eligibility': {
                'conditions': rule.eligibility_bundle,
            },
            
            'debug_priority': unique_priority,
            'notes': rule.notes
        }
    
    def analyze_all(self) -> List[Dict]:
        """Analyze all loaded violations"""
        self.analysis_results = []
        
        for violation in self.violations:
            analysis = self.analyze_violation(violation)
            self.analysis_results.append(analysis)
        
        return self.analysis_results
    
    def print_summary(self):
        """Print summary of all violations"""
        if not self.analysis_results:
            print("No violations analyzed. Run analyze_all() first.")
            return
        
        print("\n" + "="*100)
        print("AXI4-LITE VIOLATION ANALYSIS SUMMARY")
        print("="*100)
        print(f"Total Violations: {len(self.analysis_results)}")
        
        by_rule = {}
        for analysis in self.analysis_results:
            rule_id = analysis.get('rule_id', 'UNKNOWN')
            if rule_id not in by_rule:
                by_rule[rule_id] = []
            by_rule[rule_id].append(analysis)
        
        print(f"Unique Rules Violated: {len(by_rule)}")
        print("\nViolations by Rule:")
        for rule_id, violations in sorted(by_rule.items()):
            print(f"  {rule_id}: {len(violations)} violation(s)")
        
        by_severity = {}
        for analysis in self.analysis_results:
            severity = analysis.get('severity', 'UNKNOWN')
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        print("\nViolations by Severity:")
        for severity, count in sorted(by_severity.items()):
            print(f"  {severity}: {count}")
    
    def print_detailed_report(self, limit: Optional[int] = None):
        """Print detailed analysis for each violation"""
        if not self.analysis_results:
            print("No violations analyzed.")
            return
        
        violations_to_show = self.analysis_results[:limit] if limit else self.analysis_results
        
        for i, analysis in enumerate(violations_to_show, 1):
            print("\n" + "="*100)
            print(f"VIOLATION #{i}")
            print("="*100)
            
            if analysis.get('status') == 'ERROR':
                print(f"ERROR: {analysis.get('error')}")
                continue
            
            print(f"Rule ID: {analysis['rule_id']}")
            print(f"Description: {analysis['rule_description']}")
            print(f"Channel: {analysis['channel']}")
            print(f"Severity: {analysis['severity']}")
            
            if analysis.get('timestamp'):
                print(f"Timestamp: {analysis['timestamp']}")
            if analysis.get('cycle'):
                print(f"Cycle: {analysis['cycle']}")
            
            if analysis.get('original_message'):
                print(f"\nOriginal Message: {analysis['original_message']}")
            
            print("\n" + "-"*100)
            print("PRIMARY SIGNALS (Root Cause - Investigate First):")
            print("-"*100)
            for sig in analysis['signals']['primary']:
                print(f"  * {sig}")
            
            print("\n" + "-"*100)
            print("SECONDARY SIGNALS (Likely Symptoms):")
            print("-"*100)
            for sig in analysis['signals']['secondary']:
                print(f"  * {sig}")
            
            print("\n" + "-"*100)
            print("ROOT CAUSE ANALYSIS:")
            print("-"*100)
            print(f"Type: {analysis['root_cause']['type']}")
            print(f"Responsible Signals: {', '.join(analysis['root_cause']['signals'])}")
            print(f"Recommendation: {analysis['root_cause']['recommendation']}")
            
            print("\n" + "-"*100)
            print("DEBUG PRIORITY ORDER:")
            print("-"*100)
            for idx, sig in enumerate(analysis['debug_priority'], 1):
                print(f"  {idx}. {sig}")
            
            print("\n" + "-"*100)
            print("ELIGIBILITY CONDITIONS:")
            print("-"*100)
            print(f"Rule applies when: {' AND '.join(analysis['eligibility']['conditions'])}")
            
            if analysis.get('notes'):
                print("\n" + "-"*100)
                print("NOTES:")
                print("-"*100)
                print(f"  {analysis['notes']}")
    
    def export_analysis(self, output_file: str):
        """Export analysis results to JSON file"""
        if not self.analysis_results:
            print("No violations analyzed.")
            return
        
        export_data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_violations': len(self.analysis_results),
            'violations': self.analysis_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"\nAnalysis exported to {output_file}")
    
    def export_csv_report(self, output_file: str):
        """Export ONLY primary and secondary signals to CSV"""
        if not self.analysis_results:
            print("No violations analyzed.")
            return
        
        rows = []
        for i, analysis in enumerate(self.analysis_results, 1):
            if analysis.get('status') == 'ERROR':
                continue
            
            # Get primary and secondary from the rule definition
            rule_id = analysis['rule_id']
            rule = self.db.get_rule_by_id(rule_id)
            
            if rule:
                # Use EXACT signals from rule definition
                primary = ', '.join(rule.primary_violation_bundle)
                secondary = ', '.join(rule.secondary_context)
                
                rows.append({
                    'violation_num': i,
                    'cycle': analysis.get('cycle', ''),
                    'rule_id': rule_id,
                    'primary_signals': primary,
                    'secondary_signals': secondary
                })
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['violation_num', 'cycle', 'rule_id', 'primary_signals', 'secondary_signals']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"\nSignals CSV exported to {output_file}")
        print(f"Exported {len(rows)} violations")
    
    def export_signals_csv(self, output_file: str):
        """Export PRIMARY and SECONDARY signals from violations to CSV (max 3 per rule)"""
        if not self.analysis_results:
            print("No violations analyzed.")
            return
        
        rows = []
        rule_counts = {}  # Track how many violations we've exported per rule
        
        for i, analysis in enumerate(self.analysis_results, 1):
            if analysis.get('status') == 'ERROR':
                continue
            
            cycle = analysis.get('cycle', '')
            rule_id = analysis['rule_id']
            
            # Limit to 3 violations per rule
            if rule_id not in rule_counts:
                rule_counts[rule_id] = 0
            
            if rule_counts[rule_id] >= 3:
                continue  # Skip this violation, already have 3 for this rule
            
            rule_counts[rule_id] += 1
            
            # Get primary and secondary from the rule
            primary = analysis['signals']['primary']
            secondary = analysis['signals']['secondary']
            
            rows.append({
                'violation_num': i,
                'cycle': cycle,
                'rule_id': rule_id,
                'primary_signals': ', '.join(primary),
                'secondary_signals': ', '.join(secondary)
            })
        
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['violation_num', 'cycle', 'rule_id', 'primary_signals', 'secondary_signals']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"\nSignals CSV exported to {output_file}")
        print(f"Exported {len(rows)} violations (max 3 per rule to avoid repetition)")
        
        # Show summary of what was included
        print(f"\nViolations per rule in output:")
        for rule_id, count in sorted(rule_counts.items()):
            print(f"  {rule_id}: {count} violation(s)")
    
    def print_all_rules(self):
        """Print ALL rules with their PRIMARY and SECONDARY signal groupings"""
        print("\n" + "="*100)
        print("ALL AXI4-LITE RULES - PRIMARY AND SECONDARY SIGNAL GROUPINGS")
        print("="*100)
        print(f"Total Rules: {len(self.db.rules)}\n")
        
        for rule in self.db.rules:
            print("="*100)
            print(f"Rule {rule.rule_id}: {rule.description}")
            print(f"Channel: {rule.channel.value}")
            print("-"*100)
            
            print("PRIMARY SIGNALS (Root Cause):")
            for sig in rule.primary_violation_bundle:
                print(f"  * {sig}")
            
            print("\nSECONDARY SIGNALS (Dependent):")
            for sig in rule.secondary_context:
                print(f"  * {sig}")
            
            print(f"\nEligibility: {' AND '.join(rule.eligibility_bundle)}")
            if rule.notes:
                print(f"Notes: {rule.notes}")
            print("")
        
        print("="*100)
        print(f"END OF ALL {len(self.db.rules)} RULES")
        print("="*100 + "\n")
    
    def print_all_rules(self):
        """Print ALL 23 rules with their signal groupings"""
        print("\n" + "="*100)
        print("ALL AXI4-LITE RULES - PRIMARY AND SECONDARY SIGNAL GROUPINGS")
        print("="*100)
        print(f"Total Rules: {len(self.db.rules)}\n")
        
        for rule in self.db.rules:
            print("="*100)
            print(f"Rule {rule.rule_id}: {rule.description}")
            print(f"Channel: {rule.channel.value}")
            print("-"*100)
            
            print("PRIMARY SIGNALS (Root Cause):")
            for sig in rule.primary_violation_bundle:
                print(f"  * {sig}")
            
            print("\nSECONDARY SIGNALS (Dependent):")
            for sig in rule.secondary_context:
                print(f"  * {sig}")
            
            print("\nEligibility: " + " AND ".join(rule.eligibility_bundle))
            if rule.notes:
                print(f"Notes: {rule.notes}")
            print("")
        
        print("="*100)
        print("END OF RULES")
        print("="*100 + "\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point for automated violation analysis"""
    parser = argparse.ArgumentParser(
        description='AXI4-Lite Automated Violation Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show ALL 23 rules with primary/secondary signals
  python axi4_analyzer_standalone.py --show-all-rules
  
  # Analyze your violations
  python axi4_analyzer_standalone.py violations.json
  python axi4_analyzer_standalone.py violations.csv
  
  # Export results
  python axi4_analyzer_standalone.py violations.json --export analysis.json
  python axi4_analyzer_standalone.py violations.json --export-csv report.csv
  python axi4_analyzer_standalone.py violations.csv --export-signals signals.csv
  
  # Show summary only
  python axi4_analyzer_standalone.py violations.json --summary-only
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='Input violations file (.json or .csv)')
    parser.add_argument('--violations', help='Input violations file (alternative to positional argument)')
    parser.add_argument('--export', '-e', help='Export analysis to JSON file')
    parser.add_argument('--export-csv', '-c', help='Export full analysis to CSV file')
    parser.add_argument('--export-signals', '-S', help='Export just PRIMARY/SECONDARY signals to CSV (no reset/clock)')
    parser.add_argument('--limit', '-l', type=int, help='Limit number of violations to show in detail')
    parser.add_argument('--summary-only', '-s', action='store_true', help='Show only summary, not detailed report')
    parser.add_argument('--show-all-rules', action='store_true', help='Show ALL rules with PRIMARY/SECONDARY signals')
    
    args = parser.parse_args()
    
    # If user just wants to see all rules, show them and exit
    if args.show_all_rules:
        analyzer = AutomaticViolationAnalyzer()
        analyzer.print_all_rules()
        return
    
    # Use --violations if provided, otherwise use positional argument
    input_file = args.violations if args.violations else args.input_file
    
    if not input_file:
        parser.error("Please provide an input file either as positional argument or with --violations")
    
    
    try:
        analyzer = AutomaticViolationAnalyzer()
        num_violations = 0  # will be set after loading
        print("\nLoading violations...")
        if num_violations == 0:
            print("No protocol violations found — exporting empty signals.csv")
            analyzer.analysis_results = []
            analyzer.export_signals_csv('signals.csv')
            return

        
        print("\nAnalyzing violations...")
        analyzer.analyze_all()
        
        analyzer.print_summary()
        
        if not args.summary_only:
            analyzer.print_detailed_report(limit=args.limit)
        
        if args.export:
            analyzer.export_analysis(args.export)
        
        if args.export_csv:
            analyzer.export_csv_report(args.export_csv)
        
        if args.export_signals:
            analyzer.export_signals_csv(args.export_signals)
        else:
            # Auto-export signals.csv by default
            analyzer.export_signals_csv('signals.csv')
        
        print("\n" + "="*100)
        print("Analysis Complete")
        print("="*100 + "\n")
        
    except FileNotFoundError as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()