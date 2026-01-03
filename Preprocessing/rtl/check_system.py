import re
import json
import sys

def strip_comments(s: str) -> str:
    s = re.sub(r"//.*", "", s)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return s

def detect_module_name(rtl_lines):
    for raw in rtl_lines:
        line = strip_comments(raw).strip()
        m = re.match(r"\s*module\s+(\w+)", line)
        if m:
            return m.group(1)
    return "unknown_module"

def detect_ports_and_signals(rtl_lines):
    ports, signals = [], []
    header_lines, in_header = [], False
    for raw in rtl_lines:
        line = strip_comments(raw)
        if re.match(r"\s*module\s+\w+", line):
            in_header = True
        if in_header:
            header_lines.append(line)
            if ");" in line:
                break
    header_text = " ".join(header_lines)
    ports += re.findall(
        r"(?:input|output|inout)\s+(?:wire|reg|logic|bit)?\s*(?:\[[^\]]+\]\s*)?(\w+)",
                        header_text
    )
    for raw in rtl_lines:
        line = strip_comments(raw)
        signals += re.findall(
            r"\b(?:wire|reg|logic|bit)\b\s*(?:\[[^\]]+\]\s*)?(\w+)", line
        )
    return sorted(set(ports)), sorted(set(signals))

def accumulate_until_close(rtl_lines, start_index):
    block = strip_comments(rtl_lines[start_index])
    i = start_index + 1
    while i < len(rtl_lines) and ");" not in rtl_lines[i]:
        block += " " + strip_comments(rtl_lines[i])
        i += 1
    if i < len(rtl_lines):
        block += " " + strip_comments(rtl_lines[i])
    return block, i

def extract_port_pairs(port_block: str):
    return [(p, s.strip()) for p, s in re.findall(r"\.(\w+)\s*\(\s*([^)]+?)\s*\)", port_block)]

def detect_instantiations(rtl_lines):
    instantiations = []
    i, n = 0, len(rtl_lines)
    while i < n:
        line = strip_comments(rtl_lines[i])
        m_inline = re.match(r"\s*(\w+)\s*(?:#\([^)]*\))?\s+([A-Za-z_]\w*)\s*\(", line)
        if m_inline:
            submodule, inst_name = m_inline.groups()
            full_block, i = accumulate_until_close(rtl_lines, i)
            m_pos = re.search(re.escape(inst_name) + r"\s*\(", full_block)
            port_block = full_block[m_pos.end():] if m_pos else full_block
            connections = {p: s for p, s in extract_port_pairs(port_block)}
            instantiations.append({"submodule": submodule, "instance": inst_name, "connections": connections})
            i += 1
            continue
        m_params_start = re.match(r"\s*(\w+)\s*#\s*\(", line)
        if m_params_start:
            submodule = m_params_start.group(1)
            j, inst_line_idx, inst_name = i, None, None
            while j < n:
                candidate = strip_comments(rtl_lines[j])
                m_inst = re.search(r"\)\s+([A-Za-z_]\w*)\s*\(", candidate)
                if m_inst:
                    inst_name = m_inst.group(1)
                    inst_line_idx = j
                    break
                j += 1
            if inst_line_idx is not None:
                full_block, i = accumulate_until_close(rtl_lines, inst_line_idx)
                m_pos = re.search(re.escape(inst_name) + r"\s*\(", full_block)
                port_block = full_block[m_pos.end():] if m_pos else full_block
                connections = {p: s for p, s in extract_port_pairs(port_block)}
                instantiations.append({"submodule": submodule, "instance": inst_name, "connections": connections})
                i += 1
                continue
        i += 1
    return instantiations

def analyze_system(files):
    system = {"modules": {}, "connections": []}
    for fname in files:
        with open(fname, "r") as f:
            content = strip_comments(f.read())
        rtl_lines = [line.rstrip() for line in content.splitlines() if line.strip()]
        module_name = detect_module_name(rtl_lines)
        ports, signals = detect_ports_and_signals(rtl_lines)
        system["modules"][module_name] = {"ports": ports, "signals": signals}
        insts = detect_instantiations(rtl_lines)
        for inst in insts:
            for port, sig in inst["connections"].items():
                system["connections"].append({
                    "parent_module": module_name,
                    "child_module": inst["submodule"],
                    "instance": inst["instance"],
                    "child_port": port,
                    "parent_signal": sig
                })
    return system

def tokenize_signal_expr(expr: str):
    return re.findall(r"[A-Za-z_]\w*", expr)

def flatten_connections(system):
    flattened = []
    by_parent = {}
    for conn in system["connections"]:
        by_parent.setdefault(conn["parent_module"], []).append(conn)
    for parent_mod, conns in by_parent.items():
        for conn in conns:
            child_mod = conn["child_module"]
            upstream_port = conn["child_port"]
            upstream_sig_expr = conn["parent_signal"]
            if child_mod in by_parent:
                for inner in by_parent[child_mod]:
                    inner_expr_tokens = set(tokenize_signal_expr(inner["parent_signal"]))
                    if upstream_port in inner_expr_tokens:
                        flattened.append({
                            "from_module": parent_mod,
                            "from_signal_expr": upstream_sig_expr,
                            "to_module": inner["child_module"],
                            "to_signal": inner["child_port"],
                            "via_instance": conn["instance"],
                            "via_module": child_mod,
                            "inner_expr": inner["parent_signal"]
                        })
    return flattened

def detect_missing_connections(system):
    issues = []
    module_ports = {mod: info["ports"] for mod, info in system["modules"].items()}
    instances = {}
    for conn in system["connections"]:
        inst = conn["instance"]
        submodule = conn["child_module"]
        instances.setdefault(inst, {"submodule": submodule, "ports": set()})
        instances[inst]["ports"].add(conn["child_port"])
    for inst, info in instances.items():
        submodule = info["submodule"]
        all_ports = set(module_ports.get(submodule, []))
        connected = info["ports"]
        missing = sorted(all_ports - connected)
        if missing:
            issues.append({"instance": inst, "submodule": submodule, "missing_ports": missing})
    return issues
def extract_signal_declarations(rtl_lines):
    """
    Extract signal declarations and their widths from RTL.
    Handles both numeric ranges [31:0] and parameterized ranges like [DATA_WIDTH-1:0] or [PTR_WIDTH:0].
    Returns a dict mapping signal name -> width (int or symbolic string).
    """
    decls = {}
    for line in rtl_lines:
        line = line.strip()
        if re.match(r"^(input|output|inout|reg|wire|parameter|localparam)\b", line):
            width = 1

            # Numeric ranges [msb:lsb]
            m_num = re.search(r"\[(\d+)\s*:\s*(\d+)\]", line)
            if m_num:
                msb, lsb = map(int, m_num.groups())
                width = abs(msb - lsb) + 1
            else:
                # Parameterized ranges like [DATA_WIDTH-1:0] or [PTR_WIDTH:0]
                m_param = re.search(r"\[(\w+)(?:\s*-\s*1)?\s*:\s*0\]", line)
                if m_param:
                    width = m_param.group(1)  # symbolic width name

            # Collect declared names
            names = re.findall(r"\b\w+\b", line)
            for name in names:
                if name not in {"input","output","inout","reg","wire","parameter","localparam"}:
                    decls[name] = width
    return decls


def is_literal(token: str) -> bool:
    # Matches numeric constants or SystemVerilog literals like 8'hFF
    return re.match(r"^\d+$", token) or re.match(r"^\d+'[bhdo][0-9a-fA-F]+$", token)

def is_keyword(token: str) -> bool:
    # Basic SV keywords you want to skip
    SV_KEYWORDS = {"if","else","begin","end","case","endcase","default","posedge","negedge"}
    return token in SV_KEYWORDS

def is_fsm_state(sig: str) -> bool:
    # FSM states you want to skip (extend as needed)
    FSM_STATES = {"IDLE","RESP","GO","ONE","BUSY","START","STOP"}
    return sig in FSM_STATES


def detect_width_mismatches(rtl_lines):
    """
    Compare declared widths of signals against how they're used in assignments.
    Only report genuine mismatches (numeric vs numeric differences).
    Skip symbolic widths unless they clearly conflict with numeric widths.
    """

    decls = extract_signal_declarations(rtl_lines)
    issues = []

    assigns = re.findall(r"(\w+)\s*(?:<=|=)\s*([\w\[\]:]+)", " ".join(rtl_lines))
    for lhs, rhs in assigns:
        # Skip literals, keywords, FSM states
        if is_literal(rhs) or is_keyword(rhs) or is_fsm_state(rhs):
            continue

        lhs_w = decls.get(lhs, 1)

        # Determine RHS width
        rhs_w = 1
        m = re.search(r"\[(\d+)\s*:\s*(\d+)\]", rhs)
        if m:
            msb, lsb = map(int, m.groups())
            rhs_w = abs(msb - lsb) + 1
        else:
            m_param = re.search(r"\[(\w+)(?:\s*-\s*1)?\s*:\s*0\]", rhs)
            if m_param:
                rhs_w = m_param.group(1)  # symbolic width name
            else:
                rhs_w = decls.get(rhs, 1)

        # Only report mismatches when both sides are numeric and unequal
        if isinstance(lhs_w, int) and isinstance(rhs_w, int):
            if lhs_w != rhs_w:
                issues.append({
                    "lhs": lhs,
                    "lhs_width": lhs_w,
                    "rhs": rhs,
                    "rhs_width": rhs_w
                })
        # If symbolic width is involved, skip unless lhs is numeric and clearly different
        elif isinstance(rhs_w, str) and isinstance(lhs_w, int):
            # Don't flag if symbolic width could plausibly equal lhs_w
            continue

    return issues

# ---------- Main ----------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python classify_system.py <rtl_file1> <rtl_file2> ... <output_prefix>")
        sys.exit(1)

    *rtl_files, out_prefix = sys.argv[1:]
    system_info = analyze_system(rtl_files)

    print("\n🔍 System Modules Detected:")
    for mod, info in system_info["modules"].items():
        ports_str = ", ".join(info["ports"]) if info["ports"] else "(none)"
        signals_str = ", ".join(info["signals"]) if info["signals"] else "(none)"
        print(f"  • {mod} (ports: {ports_str}; signals: {signals_str})")

    print("\n🔗 Direct Connections:")
    if not system_info["connections"]:
        print("  (none)")
    else:
        for conn in system_info["connections"]:
            print(f"  • {conn['instance']}.{conn['child_port']} → {conn['parent_signal']} "
                  f"(submodule: {conn['child_module']}, parent: {conn['parent_module']})")

    flattened = flatten_connections(system_info)
    print("\n🔗 Flattened Connectivity:")
    if not flattened:
        print("  (none)")
    else:
        for f in flattened:
            print(f"  • {f['from_module']}.{f['from_signal_expr']} → {f['to_module']}.{f['to_signal']} "
                  f"(via {f['via_instance']} [{f['via_module']}] using '{f['inner_expr']}')")

        # Collect missing connectivity
    missing = detect_missing_connections(system_info)
    print("\n✅ Connectivity Check:")
    if not missing:
        print("  All ports connected.")
    else:
        for issue in missing:
            print(f" ⚠️ • Instance {issue['instance']} ({issue['submodule']}) "
                  f"is missing ports: {', '.join(issue['missing_ports'])}")
            
        # Width mismatch detection
    all_mismatches = []
for fname in rtl_files:
    with open(fname, "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    all_mismatches.extend(detect_width_mismatches(lines))

if not all_mismatches:
    print("\n✅ Width Mismatches:\n   No mismatches found.")
else:
    print("\n⚠️ Width Mismatches:")
    for issue in all_mismatches:
        print(f"  • {issue['lhs']} expects width {issue['lhs_width']}, "
              f"connected to {issue['rhs']} (width {issue['rhs_width']})")



    # Save JSON including all results
    out = {
        "modules": system_info["modules"],
        "connections_direct": system_info["connections"],
        "connections_flattened": flattened,
        "missing_connectivity": missing
    }
    json_path = f"{out_prefix}_system.json"
    with open(json_path, "w") as jf:
        json.dump(out, jf, indent=2)
    print(f"\nSystem connectivity written to {json_path}")
