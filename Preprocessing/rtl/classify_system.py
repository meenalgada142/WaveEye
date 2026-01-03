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
                    inner_tokens = set(tokenize_signal_expr(inner["parent_signal"]))
                    if upstream_port in inner_tokens:
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
        expected = set(module_ports.get(submodule, []))
        connected = info["ports"]
        missing = sorted(expected - connected)

        if missing:
            issues.append({
                "instance": inst,
                "submodule": submodule,
                "missing_ports": missing
            })
    return issues


# ---------- Main ----------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python classify_system.py <rtl_file1> <rtl_file2> ... <output_prefix>")
        sys.exit(1)

    *rtl_files, out_prefix = sys.argv[1:]
    system_info = analyze_system(rtl_files)

    print("\nSystem Modules Detected:")
    for mod, info in system_info["modules"].items():
        print(f"  - {mod} (ports: {', '.join(info['ports'])}; signals: {', '.join(info['signals'])})")

    print("\nDirect Connections:")
    if not system_info["connections"]:
        print("  (none)")
    else:
        for conn in system_info["connections"]:
            print(f"  - {conn['instance']}.{conn['child_port']} -> {conn['parent_signal']} "
                  f"(submodule: {conn['child_module']}, parent: {conn['parent_module']})")

    flattened = flatten_connections(system_info)

    print("\nFlattened Connectivity:")
    if not flattened:
        print("  (none)")
    else:
        for f in flattened:
            print(f"  - {f['from_module']}.{f['from_signal_expr']} -> {f['to_module']}.{f['to_signal']} "
                  f"(via {f['via_instance']} [{f['via_module']}] using '{f['inner_expr']}')")

    missing = detect_missing_connections(system_info)

    print("\nConnectivity Check:")
    if not missing:
        print("  All ports connected.")
    else:
        for issue in missing:
            print(f"  - Instance {issue['instance']} ({issue['submodule']}) missing ports: {', '.join(issue['missing_ports'])}")

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
