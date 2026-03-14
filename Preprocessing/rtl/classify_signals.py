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

CLOCK_KEYWORDS = {"clk","clock","aclk","mclk","sys_clk","core_clk","sclk","bclk","pclk","S_AXI_ACLK"}
RESET_ACTIVE_LOW = {
    "resetn","rst_n","aresetn","reset_l",
    "nreset","sys_resetn","s_axi_aresetn"
}

RESET_ACTIVE_HIGH = {
    "reset","rst","areset","sys_reset","por"
}
SV_KEYWORDS = {"if","else","begin","end","case","endcase","default","posedge","negedge"}
AXIL_WRITE_ADDR = {
    "s_axil_awvalid", "s_axil_awready", "s_axil_awaddr", "s_axil_awprot",
    "s_axi_awvalid", "s_axi_awready", "s_axi_awaddr", "s_axi_awprot",
    "awvalid", "awready", "awaddr", "awprot", "arrready"
}
AXI_SUFFIX_MAP = {
    "awvalid": "axil_aw_channel",
    "awready": "axil_aw_channel",
    "awaddr":  "axil_aw_channel",
    "awprot":  "axil_aw_channel",

    "wvalid": "axil_w_channel",
    "wready": "axil_w_channel",
    "wdata":  "axil_w_channel",
    "wstrb":  "axil_w_channel",

    "bvalid": "axil_b_channel",
    "bready": "axil_b_channel",
    "bresp":  "axil_b_channel",

    "arvalid": "axil_ar_channel",
    "arready": "axil_ar_channel",
    "araddr":  "axil_ar_channel",
    "arprot":  "axil_ar_channel",

    "rvalid": "axil_r_channel",
    "rready": "axil_r_channel",
    "rdata":  "axil_r_channel",
    "rresp":  "axil_r_channel",
}




def normalize_signal_name(sig: str):
    """
    Return a clean Verilog identifier or None for malformed tokens.
    """
    if sig is None:
        return None
    s = str(sig).strip()
    if not s:
        return None
    if "." in s:
        s = s.split(".")[-1]
    s = re.sub(r"\[[^\]]*\]", "", s).strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
        return s
    return None

def classify_axi_signal(sig: str):
    norm = normalize_signal_name(sig)
    if not norm:
        return None

    s = norm.lower()

    for suffix, cls in AXI_SUFFIX_MAP.items():
        if s.endswith(suffix):
            return cls

    return None

def extract_axi_interface(sig: str):
    norm = normalize_signal_name(sig)
    if not norm:
        return None

    s = norm.lower()

    for suffix in AXI_SUFFIX_MAP:
        if s.endswith(suffix):
            prefix = s[:-len(suffix)]
            return prefix.rstrip("_")

    return None
def is_literal(token: str) -> bool:
    return re.match(r"^\d+$", token) or re.match(r"^\d+'[bhdo][0-9a-fA-F]+$", token)

def is_keyword(token: str) -> bool:
    return token in SV_KEYWORDS

def is_fsm_signal(sig: str) -> bool:
    return "state" in sig.lower()

def is_fsm_state(sig: str) -> bool:
    return sig in FSM_STATES

def is_clock_signal(sig: str) -> bool:
    s = sig.lower()
    for k in CLOCK_KEYWORDS:
        if k.lower() in s:
            return True
    return False

def is_reset_low(sig: str) -> bool:
    s = sig.lower()
    return any(k in s for k in RESET_ACTIVE_LOW)

def is_reset_high(sig: str) -> bool:
    s = sig.lower()
    return any(k in s for k in RESET_ACTIVE_HIGH)


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

    # Extract parameter block using balanced parentheses so we never
    # stray past the closing ')(' that ends the #(...) section.
    m = re.search(r'#\s*\(', text)
    if m:
        depth, i = 1, m.end()
        while i < len(text) and depth > 0:
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
            i += 1
        param_block = text[m.end():i - 1]
        for pm in re.finditer(r'\bparameter\s+(?:\w+\s+)?(\w+)', param_block):
            parameters.add(pm.group(1))

    # Line-by-line standalone parameter declarations
    for line in rtl_lines:
        line = re.sub(r"//.*$", "", line).strip()
        match = re.match(r"parameter\s+(?:\w+\s+)?(\w+)", line)
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

    full_text = "\n".join(rtl_lines)

    # Remove comments
    full_text = re.sub(r"//.*?$|/\*.*?\*/", "", full_text, flags=re.MULTILINE | re.DOTALL)

    # Extract module header ports
    m = re.search(r"module\s+\w+\s*(#\s*\(.*?\))?\s*\((.*?)\);\s*", full_text, re.DOTALL)
    if m:
        port_block = m.group(2)

        # Split by commas
        entries = port_block.split(",")

        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue

            # Remove direction + types
            entry = re.sub(r"\b(input|output|inout|wire|reg|logic|signed)\b", "", entry)

            # Remove widths
            entry = re.sub(r"\[[^\]]*\]", "", entry)

            entry = entry.strip()
            if entry:
                decls[entry] = 1

    # Extract internal reg/wire declarations
    for line in rtl_lines:
        line = re.sub(r"//.*$", "", line).strip()

        m = re.match(r"(reg|wire|logic)\b(.*?);", line)
        if not m:
            continue

        body = m.group(2)
        body = re.sub(r"\[[^\]]*\]", "", body)
        names = [x.strip() for x in body.split(",")]

        for n in names:
            if n:
                decls[n] = 1

    return decls

def collect_missing_waveform_signals(
    waveform_signals: set,
    rtl_lines: list,
    declared_signals: set
):
    """
    Find signals that:
      - Exist in waveform
      - Are NOT declared in RTL
      - Appear anywhere inside conditional logic blocks
      - Are NOT LHS of any assignment
    """

    import re

    # -------------------------------------------------
    # Step 1: collect LHS signals
    # -------------------------------------------------
    lhs_signals = set()
    for line in rtl_lines:
        line = re.sub(r"//.*$", "", line)
        assigns = re.findall(r"\b(\w+)\s*(?:<=|=)", line)
        for lhs in assigns:
            lhs_signals.add(lhs)

    # -------------------------------------------------
    # Step 2: collect all signals inside conditional blocks
    # -------------------------------------------------
    used_in_conditionals = set()

    inside_conditional = False
    block_depth = 0

    for raw_line in rtl_lines:
        line = re.sub(r"//.*$", "", raw_line).strip()

        if not line:
            continue

        # Detect start of conditional
        if re.search(r"\bif\b|\bcase\b|\belse\b", line):
            inside_conditional = True

        # Track begin/end depth
        if "begin" in line:
            block_depth += 1
        if "end" in line:
            block_depth -= 1
            if block_depth <= 0:
                inside_conditional = False
                block_depth = 0

        # If inside conditional, collect tokens
        if inside_conditional:
            tokens = re.findall(r"\b\w+\b", line)
            for tok in tokens:
                if (
                    tok in waveform_signals
                    and tok not in declared_signals
                    and tok not in lhs_signals
                ):
                    used_in_conditionals.add(tok)

        # Also capture sensitivity list signals
        sens_match = re.search(r"always\s*@\((.*?)\)", line)
        if sens_match:
            tokens = re.findall(r"\b\w+\b", sens_match.group(1))
            for tok in tokens:
                if (
                    tok in waveform_signals
                    and tok not in declared_signals
                    and tok not in lhs_signals
                ):
                    used_in_conditionals.add(tok)

    return used_in_conditionals


def extract_ports_from_module_header(rtl_lines):
    ports = set()
    text = " ".join(rtl_lines)

    m = re.search(r"module\s+\w+\s*\((.*?)\);", text, re.DOTALL)
    if not m:
        return ports

    body = m.group(1)
    tokens = re.findall(r"\b\w+\b", body)

    skip = {"input","output","inout","wire","reg","logic"}
    for t in tokens:
        if t not in skip:
            ports.add(t)

    return ports


def analyze_rtl(rtl_lines: list):
    parameters = detect_module_parameters(rtl_lines)
    declarations = extract_signal_declarations(rtl_lines)
    mux_inputs_detected = set()
    signal_classifications = {}

    # --- ADD: merge header ports into declarations ---
    header_ports = extract_ports_from_module_header(rtl_lines)
    for p in header_ports:
        declarations.setdefault(p, 1)

    print("Parameters Detected:")
    for p in sorted(parameters):
        signal_classifications[p] = "parameter"
        print(f"{p} -> parameter")

    # ------------------------------------------------------------
    # STEP 1: classify declared ports FIRST
    # ------------------------------------------------------------
    for sig in declarations:
        sig = normalize_signal_name(sig)
        if not sig:
            continue
        axi_cls = classify_axi_signal(sig)
        if axi_cls:
            signal_classifications[sig] = axi_cls
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

    print("\nSignal Classification:")
    for line in rtl_lines:

        # --- sensitivity list ---
        sens_match = re.search(r"always\s*@\((.*?)\)", line)
        if sens_match:
            tokens = re.findall(r"\b\w+\b", sens_match.group(1))
            for sig in tokens:
                sig = normalize_signal_name(sig)
                if not sig:
                    continue
                if sig in parameters:
                    signal_classifications[sig] = "parameter"
                elif is_clock_signal(sig):
                    signal_classifications[sig] = "clock"
                elif is_reset_low(sig):
                    signal_classifications[sig] = "reset_active_low"
                elif is_reset_high(sig):
                    signal_classifications[sig] = "reset_active_high"

        assigns = re.findall(r"(\w+)\s*(?:<=|=)\s*([^\s;]+)", line)
        for lhs, rhs in assigns:
            lhs = normalize_signal_name(lhs)
            if not lhs:
                continue

            if lhs in parameters:
                signal_classifications[lhs] = "parameter"
                continue

            rhs_clean = normalize_signal_name(rhs.split("[")[0])
            if not rhs_clean:
                rhs_clean = rhs.split("[")[0].strip()

            axi_cls = classify_axi_signal(lhs)
            if axi_cls:
                signal_classifications[lhs] = axi_cls
                continue

            classify_addr_signal(lhs, rhs_clean, signal_classifications, parameters)

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
            else:
                signal_classifications.setdefault(lhs, "signal")

            if is_fsm_state(rhs_clean):
                signal_classifications[rhs_clean] = "fsm_state"

        # --- condition usage ---
        if re.search(r"\bif\s*\(", line) or re.search(r"\bcase\s*\(", line):
            tokens = re.findall(r"\b\d+'[bhdo][0-9a-fA-F]+\b|\b\w+\b", line)
            for sig in set(tokens):
                sig = normalize_signal_name(sig)
                if not sig:
                    continue

                if is_keyword(sig) or is_literal(sig):
                    continue


                if sig in parameters:
                    signal_classifications[sig] = "parameter"
                elif is_clock_signal(sig):
                    signal_classifications[sig] = "clock"
                elif is_reset_low(sig):
                    signal_classifications[sig] = "reset_active_low"
                elif is_reset_high(sig):
                    signal_classifications[sig] = "reset_active_high"
                elif is_addr_signal(sig):
                    signal_classifications.setdefault(sig, "Address_register")
                elif is_fsm_signal(sig):
                    signal_classifications[sig] = "fsm_control"
                elif sig not in signal_classifications:
                    signal_classifications[sig] = "signal"

    for sig, cls in signal_classifications.items():
        print(f"{sig} -> {cls}")

    return signal_classifications






def load_rtl_input(path):
    """Accept directory or single file. UTF-8 safe for Windows."""
    def read_file(fp):
        # FIXED: Explicitly use UTF-8 encoding with error handling
        with open(fp, encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip()]

    if os.path.isdir(path):
        lines = []
        for f in sorted(os.listdir(path)):
            if f.endswith(".v") or f.endswith(".sv"):
                lines.extend(read_file(os.path.join(path, f)))
        return lines
    else:
        return read_file(path)


def classify_waveform_only_signals(
    waveform_signals: set,
    rtl_lines: list,
    classifications: dict,
    parameters: set
):
    """
    Classify waveform signals not already present
    using ONLY existing classification categories.
    """

    # Collect LHS assignments
    lhs_signals = set()
    for line in rtl_lines:
        line = re.sub(r"//.*$", "", line)
        assigns = re.findall(r"\b(\w+)\s*(?:<=|=)", line)
        for lhs in assigns:
            lhs_signals.add(lhs)

    for sig in waveform_signals:
        sig = normalize_signal_name(sig)
        if not sig:
            continue

        # Skip if already classified
        if sig in classifications:
            continue

        # Parameter
        if sig in parameters:
            classifications[sig] = "parameter"
            continue

        # AXI
        axi_cls = classify_axi_signal(sig)
        if axi_cls:
            classifications[sig] = axi_cls
            continue

        # Clock / Reset
        if is_clock_signal(sig):
            classifications[sig] = "clock"
            continue

        if is_reset_low(sig):
            classifications[sig] = "reset_active_low"
            continue

        if is_reset_high(sig):
            classifications[sig] = "reset_active_high"
            continue

        # FSM
        if is_fsm_signal(sig):
            classifications[sig] = "fsm_control"
            continue

        # Address
        if is_addr_signal(sig):
            if sig in lhs_signals:
                classifications[sig] = "ADDR_output"
            else:
                classifications[sig] = "ADDR_input"
            continue

        # Control/Data fallback using your existing logic
        if is_control_signal(sig):
            if sig in lhs_signals:
                classifications[sig] = "control_output"
            else:
                classifications[sig] = "control_input"
            continue

        if is_data_signal(sig):
            if sig in lhs_signals:
                classifications[sig] = "control_output"
            else:
                classifications[sig] = "control_input"
            continue

        # Final fallback — signal doesn't match any known heuristic;
        # label as "signal" rather than guessing direction.
        classifications[sig] = "signal"
if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Usage: python classify_signals.py <rtl_file_or_folder> <output_prefix>")
        sys.exit(1)

    rtl_input = sys.argv[1]
    out_prefix = sys.argv[2]

    # --------------------------------------------------
    # Load RTL
    # --------------------------------------------------
    rtl_lines = load_rtl_input(rtl_input)
    module_name = detect_module_name(rtl_lines)

    classifications = analyze_rtl(rtl_lines)

    # --------------------------------------------------
    # OPTIONAL waveform classification (hardcoded filename)
    # --------------------------------------------------
    waveform_csv = f"{out_prefix}_waveform.csv"

    if os.path.exists(waveform_csv):
        print("\n[INFO] Performing waveform classification...")

        with open(waveform_csv, "r", encoding="utf-8") as wf:
            first = wf.readline()
            if not first:
                header = []
            else:
                delim = "\t" if first.count("\t") > first.count(",") else ","
                wf.seek(0)
                reader = csv.reader(wf, delimiter=delim)
                header = next(reader)

        # --- Normalize waveform signals ---
        waveform_signals = set()
        for sig in header:
            sig = sig.strip()
            if sig == "time_ns":
                continue
            norm = normalize_signal_name(sig)
            if norm:
                waveform_signals.add(norm)

        parameters = detect_module_parameters(rtl_lines)

        classify_waveform_only_signals(
            waveform_signals,
            rtl_lines,
            classifications,
            parameters
        )

    # --------------------------------------------------
    # Export JSON
    # --------------------------------------------------
    json_path = f"{out_prefix}_signals.json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump({"module": module_name, "signals": classifications}, jf, indent=2)

    # --------------------------------------------------
    # Export CSV
    # --------------------------------------------------
    csv_path = f"{out_prefix}_signals.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        w = csv.writer(cf)
        w.writerow([f"module: {module_name}"])
        w.writerow(["signal", "classification"])
        for sig, cls in classifications.items():
            w.writerow([sig, cls])

    print(f"\n[OK] Generated:")
    print(f"  {json_path}")
    print(f"  {csv_path}")
