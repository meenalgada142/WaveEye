import json
import re
import sys
import csv
import os

classification_json = """
{
  "Control_Signals": [
    "we","write_enable","read_enable","chip_select","cs","stb","enable",
    "wr_en","rd_en","clk_en","ready","ack","grant_out","stall","wait",
    "valid","valid_out","req","cmd_valid","cmd_ready","done","busy","idle",
    "grant","ack_in","ready_in","int","irq","irq_out","intr","int_req",
    "interrupt","interrupt_in","alert","gpio_in","gpio_out","sensor_in","led","pwm_out",
    "data_valid","data_ready"
  ],
  "FSM_States": [
    "IDLE","RESP","GO","ONE","BUSY","START","STOP"
  ],
  "Status_Flags": [
    "status","error","flag","overflow","underflow","zero","carry","full","empty"
  ]
}
"""
signals_db = json.loads(classification_json)
FSM_STATES = set(signals_db["FSM_States"])
CONTROL_SIGNALS = set(signals_db["Control_Signals"])
STATUS_FLAGS = set(signals_db["Status_Flags"])

CLOCK_KEYWORDS = {"clk","clock","aclk","mclk","sys_clk","core_clk","sclk","bclk","pclk"}
RESET_ACTIVE_LOW = {"resetn","rst_n","aresetn","reset_l","nreset","sys_resetn"}
RESET_ACTIVE_HIGH = {"reset","rst","areset","sys_reset","por"}
SV_KEYWORDS = {"if","else","begin","end","case","endcase","default","posedge","negedge"}

def is_literal(token: str) -> bool:
    return re.match(r"^\d+$", token) or re.match(r"^\d+'[bhdo][0-9a-fA-F]+$", token)

def is_keyword(token: str) -> bool:
    return token in SV_KEYWORDS

def is_fsm_signal(sig: str) -> bool:
    return "state" in sig.lower()

def is_fsm_state(sig: str) -> bool:
    return sig in FSM_STATES

def is_clock_signal(sig: str) -> bool:
    return sig.lower() in CLOCK_KEYWORDS

def is_reset_low(sig: str) -> bool:
    return sig.lower() in RESET_ACTIVE_LOW

def is_reset_high(sig: str) -> bool:
    return sig.lower() in RESET_ACTIVE_HIGH

def is_control_signal(sig: str) -> bool:
    return sig.lower() in CONTROL_SIGNALS

def is_data_signal(sig: str) -> bool:
    return "data" in sig.lower()

def is_addr_signal(sig: str) -> bool:
    return "addr" in sig.lower()

def is_status_flag(sig: str) -> bool:
    return sig.lower() in STATUS_FLAGS

def classify_addr_signal(lhs: str, rhs: str, signal_classifications: dict, parameters: set):
    if lhs in parameters or rhs in parameters:
        return
    if is_addr_signal(lhs):
        signal_classifications[lhs] = "ADDR_output"
    if is_addr_signal(rhs):
        signal_classifications[rhs] = "ADDR_input"

def detect_module_parameters(rtl_lines):
    parameters = set()
    text = " ".join(rtl_lines)

    # ORIGINAL REGEX preserved exactly
    param_blocks = re.findall(r"#\s*\(\s*(parameter\s+.*?\))\s*\)", text, re.DOTALL)
    for block in param_blocks:
        cleaned = re.sub(r"//.*?$|/\*.*?\*/", "", block)
        parts = cleaned.split(",")
        for part in parts:
            match = re.match(r"\s*parameter\s+(\w+)", part.strip())
            if not match:
                match = re.match(r"\s*(\w+)\s*(?:=|$)", part.strip())
            if match:
                parameters.add(match.group(1))

    inline_params = re.findall(r"#\(\s*parameter\s+(\w+)", text)
    for p in inline_params:
        parameters.add(p)

    for line in rtl_lines:
        line = re.sub(r"//.*$", "", line).strip()
        match = re.match(r"parameter\s+(\w+)", line)
        if match:
            parameters.add(match.group(1))

    return parameters

def detect_module_name(rtl_lines):
    for line in rtl_lines:
        line = line.strip()
        match = re.match(r"module\s+(\w+)", line)
        if match:
            return match.group(1)
    return "unknown_module"

def extract_signal_declarations(rtl_lines):
    decls = {}
    for line in rtl_lines:
        line = line.strip()
        if re.match(r"^(input|output|inout|reg|wire|parameter)\b", line):
            width_match = re.search(r"\[(\d+):(\d+)\]", line)
            width = 1
            if width_match:
                msb, lsb = map(int, width_match.groups())
                width = abs(msb - lsb) + 1
            names = re.findall(r"\b\w+\b", line)
            for name in names:
                if name not in {"input","output","inout","reg","wire","parameter"}:
                    decls[name] = width
    return decls

def analyze_rtl(rtl_lines: list):
    parameters = detect_module_parameters(rtl_lines)
    declarations = extract_signal_declarations(rtl_lines)
    mux_inputs_detected = set()
    signal_classifications = {}

    print("Parameters Detected:")
    for p in sorted(parameters):
        signal_classifications[p] = "parameter"
        print(f"{p} -> parameter")

    print("\nSignal Classification:")
    for line in rtl_lines:

        sens_match = re.search(r"always\s*@\((.*?)\)", line)
        if sens_match:
            sens_text = sens_match.group(1)
            tokens = re.findall(r"\b\w+\b", sens_text)
            for sig in tokens:
                if sig in parameters:
                    signal_classifications[sig] = "parameter"
                    continue
                if is_clock_signal(sig):
                    signal_classifications[sig] = "clock"
                elif is_reset_low(sig):
                    signal_classifications[sig] = "reset_active_low"
                elif is_reset_high(sig):
                    signal_classifications[sig] = "reset_active_high"

        assigns = re.findall(r"(\w+)\s*(?:<=|=)\s*([\w\[\]:]+)", line)
        for lhs, rhs in assigns:
            if lhs in parameters:
                signal_classifications[lhs] = "parameter"
                continue
            if rhs in parameters:
                signal_classifications[rhs] = "parameter"
                continue
            if is_status_flag(lhs):
                signal_classifications[lhs] = "status_flag"
                continue

            classify_addr_signal(lhs, rhs, signal_classifications, parameters)

            if is_clock_signal(lhs):
                signal_classifications[lhs] = "clock"
                continue
            if is_reset_low(lhs):
                signal_classifications[lhs] = "reset_active_low"
                continue
            if is_reset_high(lhs):
                signal_classifications[lhs] = "reset_active_high"
                continue
            if is_literal(lhs) or is_keyword(lhs):
                continue
            if is_fsm_signal(lhs):
                signal_classifications[lhs] = "fsm_control"
            elif lhs in mux_inputs_detected:
                signal_classifications[lhs] = "mux_output"
            else:
                if lhs not in signal_classifications:
                    signal_classifications[lhs] = "control_output"

            if is_fsm_state(rhs):
                signal_classifications[rhs] = "fsm_state"

        if re.search(r"\bif\s*\(", line) or re.search(r"\bcase\s*\(", line):
            tokens = re.findall(r"\b\d+'[bhdo][0-9a-fA-F]+\b|\b\w+\b", line)
            for sig in set(tokens):
                if sig in parameters:
                    signal_classifications[sig] = "parameter"
                    continue
                if is_addr_signal(sig):
                    signal_classifications[sig] = "Address_register"
                    continue
                if is_clock_signal(sig):
                    signal_classifications[sig] = "clock"
                    continue
                if is_reset_low(sig):
                    signal_classifications[sig] = "reset_active_low"
                    continue
                if is_reset_high(sig):
                    signal_classifications[sig] = "reset_active_high"
                    continue
                if is_literal(sig) or is_keyword(sig):
                    continue
                if is_fsm_signal(sig):
                    signal_classifications[sig] = "fsm_control"
                    continue
                if is_fsm_state(sig):
                    signal_classifications[sig] = "fsm_state"
                    continue
                width = declarations.get(sig, 1)
                if width > 1:
                    mux_inputs_detected.add(sig)
                    if sig not in signal_classifications:
                        signal_classifications[sig] = "mux_input"
                else:
                    if sig not in signal_classifications:
                        signal_classifications[sig] = "control_input"

    if not signal_classifications:
        print("No signals classified.")
    else:
        for sig, cls in signal_classifications.items():
            print(f"{sig} -> {cls}")

    return signal_classifications


def load_rtl_input(path):
    """NEW: Accept directory or single file"""
    if os.path.isdir(path):
        lines = []
        for f in sorted(os.listdir(path)):
            if f.endswith(".v") or f.endswith(".sv"):
                with open(os.path.join(path, f)) as src:
                    lines.extend([ln.strip() for ln in src if ln.strip()])
        return lines
    else:
        with open(path) as f:
            return [ln.strip() for ln in f if ln.strip()]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python classify_signals.py <rtl_file_or_folder> <output_prefix>")
        sys.exit(1)

    rtl_input = sys.argv[1]
    out_prefix = sys.argv[2]

    rtl_lines = load_rtl_input(rtl_input)
    module_name = detect_module_name(rtl_lines)

    classifications = analyze_rtl(rtl_lines)

    json_path = f"{out_prefix}_signals.json"
    with open(json_path, "w") as jf:
        json.dump({"module": module_name, "signals": classifications}, jf, indent=2)

    csv_path = f"{out_prefix}_signals.csv"
    with open(csv_path, "w", newline="") as cf:
        w = csv.writer(cf)
        w.writerow([f"module: {module_name}"])
        w.writerow(["signal", "classification"])
        for sig, cls in classifications.items():
            w.writerow([sig, cls])
