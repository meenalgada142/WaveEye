#!/usr/bin/env python3
"""
Complete AXI4-Lite Protocol Checker with Detailed Diagnostics
All rules derived directly from AMBA AXI4-Lite specification
Following the FSM + invariant algorithm

SAVE THIS FILE AS: axi4_lite_checker.py
RUN WITH: python axi4_lite_checker.py waveform.csv
"""

import sys
import json
import csv
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def HANDSHAKE(valid: int, ready: int) -> bool:
    """VALID && READY both high"""
    return valid == 1 and ready == 1


def BACKPRESSURE(valid: int, ready: int) -> bool:
    """VALID high but READY low (stalled)"""
    return valid == 1 and ready == 0


def VALID_RISE(valid_curr: int, valid_prev: int) -> bool:
    """VALID went from 0 to 1"""
    return valid_curr == 1 and valid_prev == 0


def VALID_DROP(valid_curr: int, valid_prev: int) -> bool:
    """VALID went from 1 to 0"""
    return valid_curr == 0 and valid_prev == 1


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CycleData:
    """Signal values for one cycle"""
    cycle: int
    signals: Dict[str, Any]
    
    def get_int(self, name: str, default: int = 0) -> int:
        val = self.signals.get(name, default)
        if isinstance(val, str):
            if val in ('1', 'h', 'H'): return 1
            if val in ('0', 'l', 'L'): return 0
        try:
            return int(val) if val is not None else default
        except (ValueError, TypeError):
            return default
    
    def get_hex(self, name: str, default: str = "0x0") -> str:
        val = self.signals.get(name, default)
        if isinstance(val, str) and val.startswith('0x'):
            return val
        try:
            return hex(int(str(val), 0))
        except:
            return default


@dataclass
class ViolationFact:
    """Structured fact dictionary emitted when rule is violated"""
    rule_id: str
    rule_name: str
    cycle: int
    channel: str
    facts: Dict[str, Any]
    severity: str = "ERROR"
    explanation: str = ""
    symptoms: str = ""
    root_cause: str = ""
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def format_detailed(self) -> str:
        """Format violation with full diagnostic information"""
        lines = []
        lines.append(f"+{'=' * 78}+")
        lines.append(f"| {self.rule_id}: {self.rule_name:<70} |")
        lines.append(f"| Cycle: {self.cycle:<71} |")
        lines.append(f"| Severity: {self.severity:<67} |")
        lines.append(f"+{'=' * 78}+")
        
        if self.explanation:
            lines.append(f"| EXPLANATION:{' ' * 65} |")
            for line in self._wrap_text(self.explanation, 76):
                lines.append(f"| {line:<76} |")
            lines.append(f"+{'-' * 78}+")
        
        if self.symptoms:
            lines.append(f"| SYMPTOMS:{' ' * 68} |")
            for line in self._wrap_text(self.symptoms, 76):
                lines.append(f"| {line:<76} |")
            lines.append(f"+{'-' * 78}+")
        
        if self.root_cause:
            lines.append(f"| ROOT CAUSE:{' ' * 66} |")
            for line in self._wrap_text(self.root_cause, 76):
                lines.append(f"| {line:<76} |")
            lines.append(f"+{'-' * 78}+")
        
        if self.recommendation:
            lines.append(f"| RECOMMENDATION:{' ' * 62} |")
            for line in self._wrap_text(self.recommendation, 76):
                lines.append(f"| {line:<76} |")
            lines.append(f"+{'-' * 78}+")
        
        lines.append(f"| TIMING DETAILS:{' ' * 62} |")
        for key, val in self.facts.items():
            fact_line = f"  * {key}: {val}"
            for line in self._wrap_text(fact_line, 76):
                lines.append(f"| {line:<76} |")
        
        lines.append(f"+{'=' * 78}+")
        return '\n'.join(lines)
    
    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to specified width"""
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) + len(current_line) <= width:
                current_line.append(word)
                current_length += len(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines if lines else ['']


# ============================================================================
# RULE 1: Address Stability Under Backpressure
# ============================================================================
class StructuralDependencyRule:
    """
    Detect illegal AXI ready/valid coupling from RTL driver conditions.
    """

    VALID = {"AWVALID","WVALID","ARVALID","RVALID","BVALID"}
    READY = {"AWREADY","WREADY","ARREADY","RREADY","BREADY"}

    def check_driver(self, signal, cond):
        sig = signal.upper()
        cond = cond.upper()

        violations = []

        # VALID cannot depend on READY
        if sig in self.VALID:
            for r in self.READY:
                if r in cond:
                    violations.append(
                        f"{signal} illegally depends on {r}"
                    )

        # READY cannot depend on other channel VALID
        if sig in self.READY:
            for v in self.VALID:
                if v in cond and v.replace("VALID","READY") != sig:
                    violations.append(
                        f"{signal} illegally gated by {v}"
                    )

        return violations

class AddressStabilityRule:
    """RULE 1 -- Address must remain stable while VALID=1 and READY=0"""
    
    def __init__(self, channel: str, valid_sig: str, ready_sig: str, addr_sig: str):
        self.channel = channel
        self.valid_sig = valid_sig
        self.ready_sig = ready_sig
        self.addr_sig = addr_sig
        self.tracking = False
        self.valid_start_cycle = None
        self.addr_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def reset(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.addr_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def process(self, cycle: CycleData):
        valid = cycle.get_int(self.valid_sig)
        ready = cycle.get_int(self.ready_sig)
        addr = cycle.get_hex(self.addr_sig)
        current_cycle = cycle.cycle
        
        if VALID_RISE(valid, self.prev_valid) and BACKPRESSURE(valid, ready):
            self.tracking = True
            self.valid_start_cycle = current_cycle
            self.addr_initial = addr
        
        if self.tracking:
            if HANDSHAKE(valid, ready):
                self.tracking = False
            elif BACKPRESSURE(valid, ready) and addr != self.addr_initial:
                cycles_elapsed = current_cycle - self.valid_start_cycle
                self.violations.append(ViolationFact(
                    rule_id="RULE_1",
                    rule_name=f"{self.channel} Address Stability Violation",
                    cycle=current_cycle,
                    channel=self.channel,
                    severity="ERROR",
                    explanation=f"The {self.channel} address changed during backpressure. Per AXI4-Lite spec, "
                              f"address and control signals must remain stable while VALID is asserted and READY is low.",
                    symptoms=f"VALID was asserted at cycle {self.valid_start_cycle}, but READY remained low (backpressure). "
                           f"After {cycles_elapsed} cycles of waiting, the address changed from {self.addr_initial} to {addr} "
                           f"at cycle {current_cycle}.",
                    root_cause=f"The master changed the address value while the transaction was still pending. "
                             f"This indicates the master logic is not properly holding the address stable during backpressure.",
                    recommendation=f"Fix the master to latch the address when VALID rises and hold it constant until the handshake completes. "
                                 f"Use a register to capture address on VALID assertion and only update after handshake.",
                    facts={
                        "valid_start_cycle": self.valid_start_cycle,
                        "addr_initial": self.addr_initial,
                        "addr_changed": addr,
                        "change_cycle": current_cycle,
                        "cycles_in_backpressure": cycles_elapsed
                    }
                ))
                self.addr_initial = addr
            elif VALID_DROP(valid, self.prev_valid):
                self.tracking = False
        
        self.prev_valid = valid
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 2-6: VALID Stability Rules (All 5 Channels)
# ============================================================================

class ValidStabilityRule:
    """Generic VALID stability rule for any channel"""
    
    def __init__(self, rule_id: str, rule_name: str, valid_sig: str, ready_sig: str, channel: str):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.valid_sig = valid_sig
        self.ready_sig = ready_sig
        self.channel = channel
        self.tracking = False
        self.valid_start_cycle = None
        self.handshake_seen = False
        self.prev_valid = 0
        self.violations = []
    
    def reset(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.handshake_seen = False
        self.prev_valid = 0
        self.violations = []
    
    def process(self, cycle: CycleData):
        valid = cycle.get_int(self.valid_sig)
        ready = cycle.get_int(self.ready_sig)
        current_cycle = cycle.cycle
        
        if VALID_RISE(valid, self.prev_valid):
            self.tracking = True
            self.valid_start_cycle = current_cycle
            self.handshake_seen = False
        
        if self.tracking:
            if HANDSHAKE(valid, ready):
                self.handshake_seen = True
                self.tracking = False
            elif VALID_DROP(valid, self.prev_valid) and not self.handshake_seen:
                cycles_held = current_cycle - self.valid_start_cycle
                self.violations.append(ViolationFact(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    cycle=current_cycle,
                    channel=self.channel,
                    severity="ERROR",
                    explanation=f"{self.valid_sig} was deasserted before a handshake occurred. Per AXI4-Lite specification, "
                              f"once {self.valid_sig} is asserted, it MUST remain asserted until {self.ready_sig} is also high "
                              f"(completing the handshake).",
                    symptoms=f"{self.valid_sig} was asserted at cycle {self.valid_start_cycle} but dropped to 0 at cycle {current_cycle} "
                           f"(after {cycles_held} cycles) without {self.ready_sig} ever being high. The transaction was prematurely withdrawn.",
                    root_cause=f"The logic incorrectly deasserted {self.valid_sig} before seeing {self.ready_sig}=1. This could be due to: "
                             f"(1) a timeout mechanism, (2) incorrect state machine logic, or (3) {self.valid_sig} being driven by "
                             f"a signal that doesn't properly wait for {self.ready_sig}.",
                    recommendation=f"Modify the logic to hold {self.valid_sig} high continuously once asserted, until the handshake "
                                 f"completes ({self.valid_sig} && {self.ready_sig}). Use a registered signal that only clears on handshake completion. "
                                 f"Implementation: {self.valid_sig.lower()}_reg <= set ? 1 : (valid && ready) ? 0 : {self.valid_sig.lower()}_reg.",
                    facts={
                        f"{self.valid_sig.lower()}_asserted_cycle": self.valid_start_cycle,
                        f"{self.valid_sig.lower()}_dropped_cycle": current_cycle,
                        "cycles_held": cycles_held,
                        "handshake_completed": False
                    }
                ))
                self.tracking = False
        
        self.prev_valid = valid
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 7-9: Data/Response Stability Rules
# ============================================================================

class DataStabilityRule:
    """Generic data/response stability rule"""
    
    def __init__(self, rule_id: str, valid_sig: str, ready_sig: str, data_sig: str, strb_sig: str, channel: str):
        self.rule_id = rule_id
        self.valid_sig = valid_sig
        self.ready_sig = ready_sig
        self.data_sig = data_sig
        self.strb_sig = strb_sig
        self.channel = channel
        self.tracking = False
        self.valid_start_cycle = None
        self.data_initial = None
        self.strb_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def reset(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.data_initial = None
        self.strb_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def process(self, cycle: CycleData):
        valid = cycle.get_int(self.valid_sig)
        ready = cycle.get_int(self.ready_sig)
        data = cycle.get_hex(self.data_sig)
        strb = cycle.get_hex(self.strb_sig)
        current_cycle = cycle.cycle
        
        if VALID_RISE(valid, self.prev_valid) and BACKPRESSURE(valid, ready):
            self.tracking = True
            self.valid_start_cycle = current_cycle
            self.data_initial = data
            self.strb_initial = strb
        
        if self.tracking:
            if HANDSHAKE(valid, ready):
                self.tracking = False
            elif BACKPRESSURE(valid, ready):
                cycles_elapsed = current_cycle - self.valid_start_cycle
                
                if data != self.data_initial:
                    self.violations.append(ViolationFact(
                        rule_id=self.rule_id,
                        rule_name=f"{self.data_sig} Changed During Backpressure",
                        cycle=current_cycle,
                        channel=self.channel,
                        severity="ERROR",
                        explanation=f"{self.data_sig} changed while {self.valid_sig} was high and {self.ready_sig} was low. "
                                  f"Per AXI4-Lite spec, data signals must remain stable during backpressure.",
                        symptoms=f"{self.valid_sig} asserted at cycle {self.valid_start_cycle} with {self.data_sig}={self.data_initial}. "
                               f"After {cycles_elapsed} cycles of backpressure, {self.data_sig} changed to {data} at cycle {current_cycle} "
                               f"while still waiting for {self.ready_sig}.",
                        root_cause=f"The {self.data_sig} output is not properly latched or held stable. The data is changing while "
                                 f"waiting for {self.ready_sig}, indicating: (1) {self.data_sig} driven directly from changing source, "
                                 f"(2) insufficient holding logic, or (3) path not properly isolated.",
                        recommendation=f"Latch {self.data_sig} when {self.valid_sig} is asserted and hold until handshake: "
                                     f"{self.data_sig.lower()}_reg <= {self.valid_sig.lower()}_set ? new_data : {self.data_sig.lower()}_reg. "
                                     f"Only update after successful handshake ({self.valid_sig} && {self.ready_sig}).",
                        facts={
                            "valid_start_cycle": self.valid_start_cycle,
                            f"{self.data_sig.lower()}_initial": self.data_initial,
                            f"{self.data_sig.lower()}_changed": data,
                            "change_cycle": current_cycle,
                            "cycles_in_backpressure": cycles_elapsed
                        }
                    ))
                    self.data_initial = data
                
                if strb != self.strb_initial and self.strb_sig != self.data_sig:  # Avoid duplicate for BRESP
                    self.violations.append(ViolationFact(
                        rule_id=self.rule_id,
                        rule_name=f"{self.strb_sig} Changed During Backpressure",
                        cycle=current_cycle,
                        channel=self.channel,
                        severity="ERROR",
                        explanation=f"{self.strb_sig} changed while {self.valid_sig} was high and {self.ready_sig} was low. "
                                  f"Per AXI4-Lite spec, all payload signals must remain stable during backpressure.",
                        symptoms=f"{self.valid_sig} asserted at cycle {self.valid_start_cycle} with {self.strb_sig}={self.strb_initial}. "
                               f"After {cycles_elapsed} cycles of backpressure, {self.strb_sig} changed to {strb} at cycle {current_cycle}.",
                        root_cause=f"The {self.strb_sig} signal is not properly held stable. This indicates it is being "
                                 f"generated dynamically or is tied to non-registered logic that changes during the transaction.",
                        recommendation=f"Latch {self.strb_sig} together with {self.data_sig} when {self.valid_sig} is asserted. "
                                     f"Both signals must be held constant until handshake completion.",
                        facts={
                            "valid_start_cycle": self.valid_start_cycle,
                            f"{self.strb_sig.lower()}_initial": self.strb_initial,
                            f"{self.strb_sig.lower()}_changed": strb,
                            "change_cycle": current_cycle,
                            "cycles_in_backpressure": cycles_elapsed
                        }
                    ))
                    self.strb_initial = strb
            elif VALID_DROP(valid, self.prev_valid):
                self.tracking = False
        
        self.prev_valid = valid
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 10: Read Response Ordering
# ============================================================================

class ReadResponseOrderingRule:
    """RULE 10 -- RVALID cannot assert without prior AR handshake"""
    
    def __init__(self):
        self.ar_handshake_seen = False
        self.last_ar_cycle = None
        self.prev_ar_valid = 0
        self.prev_ar_ready = 0
        self.prev_r_valid = 0
        self.prev_r_ready = 0
        self.violations = []
    
    def reset(self):
        self.ar_handshake_seen = False
        self.last_ar_cycle = None
        self.prev_ar_valid = 0
        self.prev_ar_ready = 0
        self.prev_r_valid = 0
        self.prev_r_ready = 0
        self.violations = []
    
    def process(self, cycle: CycleData):
        ar_valid = cycle.get_int('ARVALID')
        ar_ready = cycle.get_int('ARREADY')
        r_valid = cycle.get_int('RVALID')
        r_ready = cycle.get_int('RREADY')
        current_cycle = cycle.cycle
        
        # Check for new AR handshake
        if HANDSHAKE(ar_valid, ar_ready):
            if not (self.prev_ar_valid == 1 and self.prev_ar_ready == 1):
                self.ar_handshake_seen = True
                self.last_ar_cycle = current_cycle
        
        # Check for RVALID without AR
        if r_valid == 1 and not self.ar_handshake_seen:
            if self.prev_r_valid == 0:
                self.violations.append(ViolationFact(
                    rule_id="RULE_10",
                    rule_name="Read Response Without Read Request",
                    cycle=current_cycle,
                    channel="R",
                    severity="ERROR",
                    explanation="RVALID was asserted without a preceding read address handshake. Per AXI4-Lite spec, "
                              "a read data response must only occur after a completed read address handshake (ARVALID && ARREADY).",
                    symptoms=f"RVALID went high at cycle {current_cycle}, but no AR channel handshake has been observed. "
                           f"The slave is providing read data without receiving a read request from the master.",
                    root_cause="The slave logic is generating read responses independently of read requests. Possible causes: "
                             "(1) slave logic error where RVALID is tied to internal events rather than AR handshakes, "
                             "(2) reset/initialization issue where slave starts with RVALID high, (3) crosstalk or incorrect "
                             "signal routing, (4) state machine bug in slave.",
                    recommendation="Ensure RVALID is only asserted after: (1) AR handshake is detected, (2) read operation completes, "
                                 "(3) previous R handshake cleared the response. Add AR handshake tracking: "
                                 "ar_received <= (arvalid && arready) || (ar_received && !(rvalid && rready)).",
                    facts={
                        "rvalid_cycle": current_cycle,
                        "ar_handshake_seen": self.ar_handshake_seen,
                        "last_ar_cycle": self.last_ar_cycle
                    }
                ))
        
        # Reset after R handshake
        if HANDSHAKE(r_valid, r_ready):
            if not (self.prev_r_valid == 1 and self.prev_r_ready == 1):
                self.ar_handshake_seen = False
        
        self.prev_ar_valid = ar_valid
        self.prev_ar_ready = ar_ready
        self.prev_r_valid = r_valid
        self.prev_r_ready = r_ready
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 11: Write Response Sequencing
# ============================================================================

class WriteResponseSequencingRule:
    """RULE 11 -- BVALID cannot assert before AW + W handshakes complete"""
    
    def __init__(self):
        self.aw_handshake_seen = False
        self.w_handshake_seen = False
        self.aw_cycle = None
        self.w_cycle = None
        self.prev_aw_valid = 0
        self.prev_aw_ready = 0
        self.prev_w_valid = 0
        self.prev_w_ready = 0
        self.prev_b_valid = 0
        self.prev_b_ready = 0
        self.violations = []
    
    def reset(self):
        self.aw_handshake_seen = False
        self.w_handshake_seen = False
        self.aw_cycle = None
        self.w_cycle = None
        self.prev_aw_valid = 0
        self.prev_aw_ready = 0
        self.prev_w_valid = 0
        self.prev_w_ready = 0
        self.prev_b_valid = 0
        self.prev_b_ready = 0
        self.violations = []
    
    def process(self, cycle: CycleData):
        aw_valid = cycle.get_int('AWVALID')
        aw_ready = cycle.get_int('AWREADY')
        w_valid = cycle.get_int('WVALID')
        w_ready = cycle.get_int('WREADY')
        b_valid = cycle.get_int('BVALID')
        b_ready = cycle.get_int('BREADY')
        current_cycle = cycle.cycle
        
        # Check for new AW handshake
        if HANDSHAKE(aw_valid, aw_ready):
            if not (self.prev_aw_valid == 1 and self.prev_aw_ready == 1):
                self.aw_handshake_seen = True
                self.aw_cycle = current_cycle
        
        # Check for new W handshake
        if HANDSHAKE(w_valid, w_ready):
            if not (self.prev_w_valid == 1 and self.prev_w_ready == 1):
                self.w_handshake_seen = True
                self.w_cycle = current_cycle
        
        # Check for BVALID without complete write
        if b_valid == 1 and not (self.aw_handshake_seen and self.w_handshake_seen):
            if self.prev_b_valid == 0:
                self.violations.append(ViolationFact(
                    rule_id="RULE_11",
                    rule_name="Write Response Before Write Completes",
                    cycle=current_cycle,
                    channel="B",
                    severity="ERROR",
                    explanation="BVALID was asserted before both write address and write data handshakes completed. "
                              "Per AXI4-Lite spec, write response must only be issued after BOTH the AW handshake AND W handshake have occurred.",
                    symptoms=f"BVALID went high at cycle {current_cycle}. "
                           f"AW handshake: {'seen at cycle ' + str(self.aw_cycle) if self.aw_handshake_seen else 'NOT seen'}. "
                           f"W handshake: {'seen at cycle ' + str(self.w_cycle) if self.w_handshake_seen else 'NOT seen'}. "
                           f"The slave is responding to an incomplete write transaction.",
                    root_cause="The slave logic is asserting BVALID prematurely. This typically happens when: "
                             "(1) slave doesn't track both AW and W handshakes, (2) write completion logic only waits for one channel, "
                             "(3) pipelined write handling that doesn't verify both phases completed, (4) reset/initialization issue.",
                    recommendation="Implement proper write transaction tracking: maintain flags for AW and W handshakes, "
                                 "only generate BVALID when BOTH are true. Example: "
                                 "aw_rcvd <= (awvalid && awready) || (aw_rcvd && !write_complete); "
                                 "w_rcvd <= (wvalid && wready) || (w_rcvd && !write_complete); "
                                 "bvalid <= (aw_rcvd && w_rcvd && !bvalid_sent).",
                    facts={
                        "bvalid_cycle": current_cycle,
                        "aw_handshake_seen": self.aw_handshake_seen,
                        "w_handshake_seen": self.w_handshake_seen,
                        "aw_cycle": self.aw_cycle,
                        "w_cycle": self.w_cycle
                    }
                ))
        
        # Reset after B handshake
        if HANDSHAKE(b_valid, b_ready):
            if not (self.prev_b_valid == 1 and self.prev_b_ready == 1):
                self.aw_handshake_seen = False
                self.w_handshake_seen = False
                self.aw_cycle = None
                self.w_cycle = None
        
        self.prev_aw_valid = aw_valid
        self.prev_aw_ready = aw_ready
        self.prev_w_valid = w_valid
        self.prev_w_ready = w_ready
        self.prev_b_valid = b_valid
        self.prev_b_ready = b_ready
    
    def get_violations(self):
        return self.violations

"""
AXI4-Lite Checker PART 2 - Rules 12-15 + Engine and CLI

APPEND THIS TO PART 1 (after Rule 11)
Or copy the imports and classes from Part 1, then add this code
"""

# ============================================================================
# RULE 12: Multiple Outstanding Read Transactions (COMPLETE)
# ============================================================================

class OutstandingReadTransactionRule:
    """RULE 12 -- AXI4-Lite allows only one outstanding read transaction"""
    
    def __init__(self):
        self.outstanding = False
        self.ar_cycle = None
        self.prev_ar_valid = 0
        self.prev_ar_ready = 0
        self.prev_r_valid = 0
        self.prev_r_ready = 0
        self.violations = []
        self.transaction_count = 0
    
    def reset(self):
        self.outstanding = False
        self.ar_cycle = None
        self.prev_ar_valid = 0
        self.prev_ar_ready = 0
        self.prev_r_valid = 0
        self.prev_r_ready = 0
        self.violations = []
        self.transaction_count = 0
    
    def process(self, cycle):
        ar_valid = cycle.get_int('ARVALID')
        ar_ready = cycle.get_int('ARREADY')
        r_valid = cycle.get_int('RVALID')
        r_ready = cycle.get_int('RREADY')
        current_cycle = cycle.cycle
        
        # Check for new AR handshake
        if HANDSHAKE(ar_valid, ar_ready):
            if not (self.prev_ar_valid == 1 and self.prev_ar_ready == 1):
                if self.outstanding:
                    cycles_outstanding = current_cycle - self.ar_cycle
                    self.transaction_count += 1
                    self.violations.append(ViolationFact(
                        rule_id="RULE_12",
                        rule_name="Multiple Outstanding Read Transactions",
                        cycle=current_cycle,
                        channel="AR",
                        severity="ERROR",
                        explanation="A second read address handshake occurred while a previous read transaction was still outstanding. "
                                  "AXI4-Lite specification explicitly permits ONLY ONE outstanding read transaction at a time.",
                        symptoms=f"First AR handshake occurred at cycle {self.ar_cycle}, initiating a read transaction. "
                               f"Before the read data response completed (RVALID && RREADY), another AR handshake occurred at cycle {current_cycle}. "
                               f"The first transaction was outstanding for {cycles_outstanding} cycles when this violation occurred.",
                        root_cause="The master issued a new read address before receiving the data from the previous read. "
                                 "This violates AXI4-Lite's single-outstanding transaction rule. Common causes: "
                                 "(1) pipelining logic that doesn't track outstanding transactions, "
                                 "(2) missing back-pressure handling in master read logic, "
                                 "(3) incorrect assumption that AXI4-Lite supports multiple outstanding reads like full AXI4, "
                                 "(4) read request queue not checking for pending responses.",
                        recommendation="Implement an outstanding transaction counter in the master: "
                                     "outstanding_reads <= outstanding_reads + (arvalid && arready) - (rvalid && rready). "
                                     "Before issuing ARVALID, check: if (outstanding_reads > 0) block_new_request. "
                                     "For AXI4-Lite, this means: wait for (RVALID && RREADY) before starting a new read. "
                                     "Add FSM state to track: IDLE -> AR_SENT -> WAIT_R_DATA -> IDLE.",
                        facts={
                            "first_ar_handshake_cycle": self.ar_cycle,
                            "second_ar_handshake_cycle": current_cycle,
                            "cycles_first_transaction_outstanding": cycles_outstanding,
                            "total_violations_so_far": self.transaction_count
                        }
                    ))
                self.outstanding = True
                self.ar_cycle = current_cycle
        
        # Check for R handshake completion
        if HANDSHAKE(r_valid, r_ready):
            if not (self.prev_r_valid == 1 and self.prev_r_ready == 1):
                self.outstanding = False
        
        self.prev_ar_valid = ar_valid
        self.prev_ar_ready = ar_ready
        self.prev_r_valid = r_valid
        self.prev_r_ready = r_ready
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 13: Multiple Outstanding Write Transactions (COMPLETE)
# ============================================================================

class OutstandingWriteTransactionRule:
    """RULE 13 -- AXI4-Lite allows only one outstanding write transaction"""
    
    def __init__(self):
        self.outstanding = False
        self.write_start_cycle = None
        self.prev_aw_valid = 0
        self.prev_aw_ready = 0
        self.prev_w_valid = 0
        self.prev_w_ready = 0
        self.prev_b_valid = 0
        self.prev_b_ready = 0
        self.violations = []
        self.transaction_count = 0
    
    def reset(self):
        self.outstanding = False
        self.write_start_cycle = None
        self.prev_aw_valid = 0
        self.prev_aw_ready = 0
        self.prev_w_valid = 0
        self.prev_w_ready = 0
        self.prev_b_valid = 0
        self.prev_b_ready = 0
        self.violations = []
        self.transaction_count = 0
    
    def process(self, cycle):
        aw_valid = cycle.get_int('AWVALID')
        aw_ready = cycle.get_int('AWREADY')
        w_valid = cycle.get_int('WVALID')
        w_ready = cycle.get_int('WREADY')
        b_valid = cycle.get_int('BVALID')
        b_ready = cycle.get_int('BREADY')
        current_cycle = cycle.cycle
        
        # Check for new AW handshake
        if HANDSHAKE(aw_valid, aw_ready):
            if not (self.prev_aw_valid == 1 and self.prev_aw_ready == 1):
                if self.outstanding:
                    cycles_outstanding = current_cycle - self.write_start_cycle
                    self.transaction_count += 1
                    self.violations.append(ViolationFact(
                        rule_id="RULE_13",
                        rule_name="Multiple Outstanding Write Transactions",
                        cycle=current_cycle,
                        channel="AW",
                        severity="ERROR",
                        explanation="A second write address handshake occurred while a previous write transaction was still outstanding. "
                                  "AXI4-Lite specification explicitly permits ONLY ONE outstanding write transaction at a time.",
                        symptoms=f"First write transaction started at cycle {self.write_start_cycle}. "
                               f"Before the write response completed (BVALID && BREADY), another AW handshake occurred at cycle {current_cycle}. "
                               f"The first transaction was outstanding for {cycles_outstanding} cycles when this violation occurred.",
                        root_cause="The master issued a new write address before receiving the write response from the previous write. "
                                 "This violates AXI4-Lite's single-outstanding transaction rule. Common causes: "
                                 "(1) pipelining logic that doesn't track outstanding writes, "
                                 "(2) write buffer that queues multiple writes without checking for pending responses, "
                                 "(3) incorrect assumption that AXI4-Lite supports write pipelining like full AXI4, "
                                 "(4) missing dependency tracking between write channels and response channel.",
                        recommendation="Implement an outstanding write transaction tracker in the master: "
                                     "outstanding_writes <= outstanding_writes + ((awvalid && awready) || (wvalid && wready)) - (bvalid && bready). "
                                     "Before issuing AWVALID for a new write, verify: if (outstanding_writes > 0) block_new_write. "
                                     "For AXI4-Lite, maintain FSM: IDLE -> WRITE_ACTIVE -> WAIT_B_RESP -> IDLE. "
                                     "Only transition to IDLE after receiving B channel handshake.",
                        facts={
                            "first_write_start_cycle": self.write_start_cycle,
                            "second_aw_handshake_cycle": current_cycle,
                            "cycles_first_transaction_outstanding": cycles_outstanding,
                            "total_violations_so_far": self.transaction_count
                        }
                    ))
                if not self.outstanding:
                    self.outstanding = True
                    self.write_start_cycle = current_cycle
        
        # Check for B handshake completion
        if HANDSHAKE(b_valid, b_ready):
            if not (self.prev_b_valid == 1 and self.prev_b_ready == 1):
                self.outstanding = False
        
        self.prev_aw_valid = aw_valid
        self.prev_aw_ready = aw_ready
        self.prev_w_valid = w_valid
        self.prev_w_ready = w_ready
        self.prev_b_valid = b_valid
        self.prev_b_ready = b_ready
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 14: ARPROT Stability Under Backpressure (COMPLETE)
# ============================================================================

class ARControlStabilityRule:
    """RULE 14 -- ARPROT must remain stable during backpressure"""
    
    def __init__(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.arprot_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def reset(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.arprot_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def process(self, cycle):
        valid = cycle.get_int('ARVALID')
        ready = cycle.get_int('ARREADY')
        arprot = cycle.get_hex('ARPROT')
        current_cycle = cycle.cycle
        
        if VALID_RISE(valid, self.prev_valid) and BACKPRESSURE(valid, ready):
            self.tracking = True
            self.valid_start_cycle = current_cycle
            self.arprot_initial = arprot
        
        if self.tracking:
            if HANDSHAKE(valid, ready):
                self.tracking = False
            elif BACKPRESSURE(valid, ready) and arprot != self.arprot_initial:
                cycles_elapsed = current_cycle - self.valid_start_cycle
                self.violations.append(ViolationFact(
                    rule_id="RULE_14",
                    rule_name="ARPROT Changed During Backpressure",
                    cycle=current_cycle,
                    channel="AR",
                    severity="ERROR",
                    explanation="ARPROT (protection attributes) changed while ARVALID was high and ARREADY was low. "
                              "Per AXI4-Lite spec, all control signals must remain stable during backpressure.",
                    symptoms=f"ARVALID asserted at cycle {self.valid_start_cycle} with ARPROT={self.arprot_initial}. "
                           f"After {cycles_elapsed} cycles of backpressure, ARPROT changed to {arprot} at cycle {current_cycle}.",
                    root_cause="The protection attribute signal is not properly latched with the address. ARPROT may be: "
                             "(1) driven from dynamic logic that changes during transaction, (2) not registered together with ARADDR, "
                             "(3) tied to mode signals that can change.",
                    recommendation="Latch ARPROT together with ARADDR when ARVALID is asserted. All AR channel signals "
                                 "(address and control) must be captured as a complete set and held stable until handshake completion.",
                    facts={
                        "valid_start_cycle": self.valid_start_cycle,
                        "arprot_initial": self.arprot_initial,
                        "arprot_changed": arprot,
                        "change_cycle": current_cycle,
                        "cycles_in_backpressure": cycles_elapsed
                    }
                ))
                self.arprot_initial = arprot
            elif VALID_DROP(valid, self.prev_valid):
                self.tracking = False
        
        self.prev_valid = valid
    
    def get_violations(self):
        return self.violations


# ============================================================================
# RULE 15: AWPROT Stability Under Backpressure (COMPLETE)
# ============================================================================

class AWControlStabilityRule:
    """RULE 15 -- AWPROT must remain stable during backpressure"""
    
    def __init__(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.awprot_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def reset(self):
        self.tracking = False
        self.valid_start_cycle = None
        self.awprot_initial = None
        self.prev_valid = 0
        self.violations = []
    
    def process(self, cycle):
        valid = cycle.get_int('AWVALID')
        ready = cycle.get_int('AWREADY')
        awprot = cycle.get_hex('AWPROT')
        current_cycle = cycle.cycle
        
        if VALID_RISE(valid, self.prev_valid) and BACKPRESSURE(valid, ready):
            self.tracking = True
            self.valid_start_cycle = current_cycle
            self.awprot_initial = awprot
        
        if self.tracking:
            if HANDSHAKE(valid, ready):
                self.tracking = False
            elif BACKPRESSURE(valid, ready) and awprot != self.awprot_initial:
                cycles_elapsed = current_cycle - self.valid_start_cycle
                self.violations.append(ViolationFact(
                    rule_id="RULE_15",
                    rule_name="AWPROT Changed During Backpressure",
                    cycle=current_cycle,
                    channel="AW",
                    severity="ERROR",
                    explanation="AWPROT (protection attributes) changed while AWVALID was high and AWREADY was low. "
                              "Per AXI4-Lite spec, all control signals must remain stable during backpressure.",
                    symptoms=f"AWVALID asserted at cycle {self.valid_start_cycle} with AWPROT={self.awprot_initial}. "
                           f"After {cycles_elapsed} cycles of backpressure, AWPROT changed to {awprot} at cycle {current_cycle}.",
                    root_cause="The write protection attribute signal is not properly latched with the address. AWPROT may be: "
                             "(1) driven from dynamic logic that changes during transaction, (2) not registered together with AWADDR, "
                             "(3) tied to mode signals that can change.",
                    recommendation="Latch AWPROT together with AWADDR when AWVALID is asserted. All AW channel signals "
                                 "(address and control) must be captured as a complete set and held stable until handshake completion.",
                    facts={
                        "valid_start_cycle": self.valid_start_cycle,
                        "awprot_initial": self.awprot_initial,
                        "awprot_changed": awprot,
                        "change_cycle": current_cycle,
                        "cycles_in_backpressure": cycles_elapsed
                    }
                ))
                self.awprot_initial = awprot
            elif VALID_DROP(valid, self.prev_valid):
                self.tracking = False
        
        self.prev_valid = valid
    
    def get_violations(self):
        return self.violations

def run_structural_checks(logic):
    """
    Run RTL-level AXI legality checks (independent of waveform).
    'logic' must be the parsed driver table you already generate.
    """
    checker = StructuralDependencyRule()
    findings = []

    for signal, drivers in logic.items():
        for drv in drivers:
            cond = drv.get("cond", "")
            violations = checker.check_driver(signal, cond)
            for v in violations:
                findings.append({
                    "signal": signal,
                    "predicate": cond,
                    "issue": v
                })

    return findings

# ============================================================================
# RULE ENGINE (COMPLETE)
# ============================================================================

class CompleteAXI4LiteChecker:
    def __init__(self, logic=None):
        self.logic = logic

        self.rules = [
            # Address stability rules (Rules 1)
            AddressStabilityRule('AR', 'ARVALID', 'ARREADY', 'ARADDR'),
            AddressStabilityRule('AW', 'AWVALID', 'AWREADY', 'AWADDR'),
            
            # VALID persistence rules (Rules 2-6)
            ValidStabilityRule("RULE_2", "ARVALID Deasserted Before Handshake", 'ARVALID', 'ARREADY', 'AR'),
            ValidStabilityRule("RULE_3", "AWVALID Deasserted Before Handshake", 'AWVALID', 'AWREADY', 'AW'),
            ValidStabilityRule("RULE_4", "WVALID Deasserted Before Handshake", 'WVALID', 'WREADY', 'W'),
            ValidStabilityRule("RULE_5", "RVALID Deasserted Before Handshake", 'RVALID', 'RREADY', 'R'),
            ValidStabilityRule("RULE_6", "BVALID Deasserted Before Handshake", 'BVALID', 'BREADY', 'B'),
            
            # Data and response stability rules (Rules 7-9)
            DataStabilityRule("RULE_7", 'WVALID', 'WREADY', 'WDATA', 'WSTRB', 'W'),
            DataStabilityRule("RULE_8", 'RVALID', 'RREADY', 'RDATA', 'RRESP', 'R'),
            DataStabilityRule("RULE_9", 'BVALID', 'BREADY', 'BRESP', 'BRESP', 'B'),
            
            # Ordering and sequencing rules (Rules 10-11)
            ReadResponseOrderingRule(),
            WriteResponseSequencingRule(),
            
            # Outstanding transaction rules (Rules 12-13)
            OutstandingReadTransactionRule(),
            OutstandingWriteTransactionRule(),
            
            # Control signal stability rules (Rules 14-15)
            ARControlStabilityRule(),
            AWControlStabilityRule(),
        ]
    def run(self, waveform_data, verbose: bool = True):
        """
        Execute full AXI analysis pipeline:

            STEP 1 — Structural legality (RTL predicates)
            STEP 2 — Temporal protocol verification (waveform)
            STEP 3 — Aggregate violations
        """

        if verbose:
            print("\n[AXI CHECKER] Starting analysis pipeline...")

        violations = []

        if self.logic is None:
            if verbose:
                print("[STRUCTURAL] No driver database provided -> SKIPPED\n")
        else:
            if verbose:
                print("[STRUCTURAL] Driver database loaded")
                print(f"[STRUCTURAL] Signals with drivers: {len(self.logic)}")

            total_preds = sum(len(v) for v in self.logic.values())
            if verbose:
                print(f"[STRUCTURAL] Auditing {total_preds} driver predicates...")

            structural_issues = run_structural_checks(self.logic)

            if verbose:
                if not structural_issues:
                    print("[STRUCTURAL] PASS — No illegal VALID/READY coupling found\n")
                else:
                    print(f"[STRUCTURAL] FAIL — {len(structural_issues)} violations detected\n")

                # Convert structural findings into RULE_1 protocol violations
                for s in structural_issues:
                    violations.append(ViolationFact(
                        rule_id="RULE_1",
                        rule_name="VALID/READY Independence Violation",
                        cycle="",                     # structural → no cycle
                        channel="AXI_STRUCT",
                        severity="ERROR",

                        explanation=(
                            "AXI protocol requires VALID and READY to be generated "
                            "independently. RTL introduces an illegal dependency."
                        ),

                        symptoms=f"{s['signal']} driven by predicate: {s['predicate']}",

                        root_cause=(
                            f"{s['signal']} illegally depends on handshake signal. "
                            "This creates circular wait conditions and can block responses."
                        ),

                        recommendation=(
                            "Remove VALID/READY coupling. READY must be driven from FSM "
                            "state, not gated by VALID. Register the decision internally."
                        ),

                        facts={
                            "signal": s["signal"],
                            "predicate": s["predicate"],
                            "structural": True
                        }
                    ))



        # -------------------------------------------------
        # STEP 2 — TEMPORAL PROTOCOL CHECKS (Waveform-time)
        # -------------------------------------------------
        if verbose:
            print("[TEMPORAL] Running protocol rule engine...")

        for cycle in waveform_data:
            for rule in self.rules:
                rule.process(cycle)

        if verbose:
            print("[TEMPORAL] Completed waveform sweep")

        # Collect rule violations
        for rule in self.rules:
            rule_violations = rule.get_violations()
            if rule_violations:
                violations.extend(rule_violations)

        if verbose:
            print(f"[TEMPORAL] Collected {len(violations)} total violations\n")

        # -------------------------------------------------
        # STEP 3 — RETURN RESULTS
        # -------------------------------------------------
        return violations




# ============================================================================
# WAVEFORM LOADER (COMPLETE)
# ============================================================================

# In axil4.py, find the load_csv_waveform function and REPLACE it with this:
def load_csv_waveform(filepath, verbose: bool = False):
    """Load waveform from CSV file with IR builder format (2-row header)"""
    data = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        # First, detect delimiter
        first_line = f.readline()
        f.seek(0)
        
        # Check if tab-delimited
        if '\t' in first_line:
            delimiter = '\t'
            if verbose:
                print("[DEBUG] Detected TAB-delimited file")
        else:
            delimiter = ','
            if verbose:
                print("[DEBUG] Detected comma-delimited file")

        reader = csv.reader(f, delimiter=delimiter)

        # Skip first row (signal types)
        row1_types = next(reader)
        if verbose:
            print(f"[DEBUG] Row 1 (types) has {len(row1_types)} columns")

        # Second row is actual signal names
        signal_names = next(reader)
        if verbose:
            print(f"[DEBUG] Row 2 (names) has {len(signal_names)} columns")
        

        def normalize_axi_name(sig: str):
            s = sig.lower()


            def match(keyword):
                return keyword in s

            if match('awvalid'): return 'AWVALID'
            if match('awready'): return 'AWREADY'
            if match('awaddr'):  return 'AWADDR'
            if match('awprot'):  return 'AWPROT'

            if match('wvalid'):  return 'WVALID'
            if match('wready'):  return 'WREADY'
            if match('wdata'):   return 'WDATA'
            if match('wstrb'):   return 'WSTRB'

            if match('bvalid'):  return 'BVALID'
            if match('bready'):  return 'BREADY'
            if match('bresp'):   return 'BRESP'

            if match('arvalid'): return 'ARVALID'
            if match('arready'): return 'ARREADY'
            if match('araddr'):  return 'ARADDR'
            if match('arprot'):  return 'ARPROT'

            if match('rvalid'):  return 'RVALID'
            if match('rready'):  return 'RREADY'
            if match('rdata'):   return 'RDATA'
            if match('rresp'):   return 'RRESP'

            return sig


        remapped_names = [normalize_axi_name(sig.strip()) for sig in signal_names]

        EXPECTED_AXI = [
            'AWVALID','AWREADY','AWADDR',
            'WVALID','WREADY','WDATA',
            'BVALID','BREADY',
            'ARVALID','ARREADY','ARADDR',
            'RVALID','RREADY'
        ]

        found = set(remapped_names)
        missing = [s for s in EXPECTED_AXI if s not in found]

        if verbose:
            print("\n[AXI NORMALIZATION CHECK]")
            print(f"Total signals after normalization: {len(remapped_names)}")
            for s in EXPECTED_AXI:
                status = "OK" if s in found else "MISSING"
                print(f"  {s:8s} : {status}")
            if missing:
                print("\n[WARNING] Missing AXI signals detected:")
                print("  ", missing)
            else:
                print("\n[OK] All required AXI signals detected")
            print(f"[DEBUG] Remapped to {len(remapped_names)} signals")

        # Check if we found AXI signals
        axi_signals = ['ARVALID', 'ARREADY', 'RVALID', 'RREADY']
        found = [s for s in axi_signals if s in remapped_names]
        if verbose:
            if found:
                print(f"[DEBUG] [OK] Found AXI signals: {found}")
            else:
                print("[WARNING] [FAIL] No AXI signals found!")
                print(f"[DEBUG] First 20 signals: {remapped_names[:20]}")
        
        # Read data rows
        cycle = 0
        for row in reader:
            if not row or len(row) < 2:
                continue
            
            # Skip rows that are all empty
            if all(not cell.strip() for cell in row):
                continue
            
            cycle += 1
            
            # Build signal dictionary
            signals = {}
            for i, sig_name in enumerate(remapped_names):
                if i < len(row):
                    val = row[i].strip()
                    # Convert 'x' to 0
                    if val == 'x' or val == 'X':
                        val = '0'
                    signals[sig_name] = val
            
            data.append(CycleData(cycle=cycle, signals=signals))
        
        if verbose:
            print(f"[DEBUG] [OK] Loaded {len(data)} cycles")
        return data


# ============================================================================
# REPORTING (CONSOLE ONLY — no JSON/CSV here)
# ============================================================================

def report_violations_text(violations, detailed=True, show_all=False):
    """
    Pretty-print violations to console.

    NOTE:
    JSON/CSV generation is handled in main().
    This function is intentionally TEXT-ONLY to avoid format-state bugs.
    """

    print("=" * 80)
    print("AXI4-LITE PROTOCOL VIOLATIONS - DIAGNOSTIC REPORT")
    print(f"Total Violations: {len(violations)}")
    print("=" * 80)

    if not violations:
        print("\n[OK] No violations detected — Protocol compliant.\n")
        return

    # ------------------------------------------------------------------
    # Group violations by rule
    # ------------------------------------------------------------------
    by_rule = {}
    for v in violations:
        by_rule.setdefault(v.rule_id, []).append(v)

    # ------------------------------------------------------------------
    # Summary Section
    # ------------------------------------------------------------------
    print("\n[SUMMARY]")
    print("-" * 80)

    for rule_id in sorted(by_rule.keys()):
        rv = by_rule[rule_id]
        first = rv[0]
        print(f"{rule_id}: {first.rule_name}")
        print(f"  Count   : {len(rv)}")
        print(f"  Severity: {first.severity}")
        print(f"  Cycles  : {rv[0].cycle} → {rv[-1].cycle}")
        print()

    # ------------------------------------------------------------------
    # Detailed Section
    # ------------------------------------------------------------------
    if not detailed:
        return

    print("\n" + "=" * 80)
    print("DETAILED VIOLATION REPORTS")
    print("=" * 80)

    for rule_id in sorted(by_rule.keys()):
        rv = by_rule[rule_id]

        print(f"\n{'=' * 80}")
        print(f"{rule_id}: {len(rv)} violation(s)")
        print(f"{'=' * 80}\n")

        # Show limited sample unless requested
        display_count = len(rv) if show_all else min(3, len(rv))

        for i, v in enumerate(rv[:display_count], 1):
            print(v.format_detailed())
            print()

        if len(rv) > display_count:
            print(f"... {len(rv) - display_count} more occurrences hidden")
            print("(use --show-all to display everything)\n")


def load_backtracking_csv(path):
    """Load backtracking CSV and include always_block_id"""
    logic = {}

    with open(path, encoding='utf-8-sig', errors='replace') as f:
        r = csv.DictReader(f)
        for row in r:
            sig = row.get("signal", "").strip()

            # Skip separators / junk rows
            if not sig or sig.startswith("---") or sig == "NEXT DRIVER":
                continue

            block_id_str = row.get("always_block_id", "").strip()
            block_id = int(block_id_str) if block_id_str.isdigit() else None

            logic.setdefault(sig, []).append({
                "cond": (row.get("condition") or "").strip(),
                "rhs": (row.get("rhs") or "").strip(),
                "assign_type": (row.get("assign_type") or "").strip(),
                "sensitivity": (row.get("sensitivity") or "").strip(),
                "always_block_id": block_id,
            })

    print(f"[STRUCT] Loaded driver DB for {len(logic)} signals from {path}")
    return logic

# ============================================================================
# CLI (COMPLETE)
# ============================================================================

def main():
    import argparse
    from pathlib import Path
    
    parser = argparse.ArgumentParser(
        description='AXI4-Lite Protocol Checker with Detailed Diagnostics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Rules Implemented (All with detailed diagnostics):
  RULE_1:  Address Stability (ARADDR/AWADDR)
  RULE_2:  ARVALID Persistence
  RULE_3:  AWVALID Persistence
  RULE_4:  WVALID Persistence
  RULE_5:  RVALID Persistence
  RULE_6:  BVALID Persistence
  RULE_7:  Write Data Stability (WDATA/WSTRB)
  RULE_8:  Read Data Stability (RDATA/RRESP)
  RULE_9:  Write Response Stability (BRESP)
  RULE_10: Read Response Ordering
  RULE_11: Write Response Sequencing
  RULE_12: Single Outstanding Read
  RULE_13: Single Outstanding Write
  RULE_14: AR Control Stability (ARPROT)
  RULE_15: AW Control Stability (AWPROT)

Examples:
  python axi4_lite_checker.py waveform.csv
  python axi4_lite_checker.py waveform.csv --show-all
  python axi4_lite_checker.py waveform.csv --summary-only
        """
    )


    parser.add_argument('waveform', type=Path, help='CSV waveform file')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--show-all', action='store_true')
    parser.add_argument('--summary-only', action='store_true')
    parser.add_argument('--output-dir', type=Path, default=Path('.'), help='Output directory for JSON/CSV files')
    parser.add_argument('--drivers', type=Path, default=None, help='Optional backtracking CSV for structural driver checks')
    
    args = parser.parse_args()
            # ------------------------------------------------------------------
    # STRUCTURAL AXI CHECK (RTL legality)
    # ------------------------------------------------------------------
    logic = None

    if args.drivers:
        print(f"[BOOT] Loading structural drivers from {args.drivers}")
        logic = load_backtracking_csv(args.drivers)
    else:
        print("[BOOT] No --drivers supplied → structural RCA disabled")

    logic_file = Path("true_drivers.json")

    print(f"[BOOT] Looking for structural driver file: {logic_file}")

    if logic_file.exists():
        print("[BOOT] Found true_drivers.json — structural analysis ENABLED")
        with open(logic_file) as f:
            logic = json.load(f)
    else:
        print("[BOOT] true_drivers.json NOT found — structural analysis DISABLED")


    try:
        if args.verbose:
            print(f"Loading {args.waveform}...")
        
        waveform_data = load_csv_waveform(args.waveform)
        
        if args.verbose:
            print(f"Loaded {len(waveform_data)} cycles")
            print("Running complete AXI4-Lite protocol checks (15 rules)...")
        
        checker = CompleteAXI4LiteChecker(logic=logic)

        violations = checker.run(waveform_data)
        
        if args.verbose:
            print(f"Found {len(violations)} violation(s)")
        
        # Auto-generate JSON and CSV files
        json_path = args.output_dir / 'violations.json'
        csv_path = args.output_dir / 'violations.csv'
        
        # Write JSON
        with open(json_path, 'w') as f:
            json.dump([v.to_dict() for v in violations], f, indent=2)
        print(f"[OK] Generated {json_path}")
        
        # Write CSV
        with open(csv_path, 'w', newline='') as f:
            if violations:
                all_fact_keys = set()
                for v in violations:
                    all_fact_keys.update(v.facts.keys())
                fact_keys = sorted(all_fact_keys)
                
                header = ['rule_id', 'rule_name', 'cycle', 'channel', 'severity', 
                          'explanation', 'symptoms', 'root_cause', 'recommendation']
                header.extend([f'fact_{k}' for k in fact_keys])
                
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                
                for v in violations:
                    row = {
                        'rule_id': v.rule_id,
                        'rule_name': v.rule_name,
                        'cycle': v.cycle,
                        'channel': v.channel,
                        'severity': v.severity,
                        'explanation': v.explanation,
                        'symptoms': v.symptoms,
                        'root_cause': v.root_cause,
                        'recommendation': v.recommendation
                    }
                    for fk in fact_keys:
                        row[f'fact_{fk}'] = v.facts.get(fk, '')
                    writer.writerow(row)
            else:
                f.write("rule_id,rule_name,cycle,channel,severity,explanation,symptoms,root_cause,recommendation\n")
        print(f"[OK] Generated {csv_path}")
        
        # Print text summary to console
        print("\n" + "="*80)
        print("VIOLATION SUMMARY")
        print("="*80)
        
        if not violations:
            print("\n[OK] No violations detected - Protocol compliant!\n")
        else:
            by_rule = {}
            for v in violations:
                if v.rule_id not in by_rule:
                    by_rule[v.rule_id] = []
                by_rule[v.rule_id].append(v)
            
            print(f"\nTotal violations: {len(violations)}")
            print("\nBy rule:")
            for rule_id in sorted(by_rule.keys()):
                rule_violations = by_rule[rule_id]
                print(f"  {rule_id}: {len(rule_violations):3d} violations - {rule_violations[0].rule_name}")
                print(f"          Cycles {rule_violations[0].cycle} to {rule_violations[-1].cycle}")
            
            # Show detailed violation reports unless summary-only
            if not args.summary_only:
                print("\n" + "="*80)
                print("DETAILED VIOLATION REPORTS")
                print("="*80)
                
                for rule_id in sorted(by_rule.keys()):
                    rule_violations = by_rule[rule_id]
                    print(f"\n{'='*80}")
                    print(f"  {rule_id}: {len(rule_violations)} violation(s)")
                    print(f"{'='*80}\n")
                    
                    # Show first 3 or all if show_all is True
                    display_count = len(rule_violations) if args.show_all else min(3, len(rule_violations))
                    
                    for i, v in enumerate(rule_violations[:display_count], 1):
                        print(v.format_detailed())
                        print()
                    
                    if len(rule_violations) > display_count:
                        print(f"  ... and {len(rule_violations) - display_count} more similar violations")
                        print(f"  (Use --show-all to see all violations)\n")
                
                print("\n" + "="*80)
                print("Next step: Run RCA analysis:")

        
        print("="*80 + "\n")
        
        sys.exit(1 if violations else 0)
    
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
