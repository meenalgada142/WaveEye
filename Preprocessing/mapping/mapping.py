import os
import csv
import json
import argparse
import pandas as pd
import re
import sys


def normalize(name):
    """
    Normalize signal name for matching
    
    Examples:
      soc_tb.dut.uart_busy → uart_busy
      soc_tb.dut.u_uart.tx_busy → u_uart.tx_busy
      reg0[31:0] → reg0
    """
    # Remove testbench hierarchy (soc_tb.dut., tb., top., etc.)
    name = re.sub(r'^[^.]*\.dut\.', '', name)
    name = re.sub(r'^[^.]*\.tb\.', '', name)
    name = re.sub(r'^top\.', '', name)
    
    # Remove array indexing
    name = re.sub(r"\[.*?\]", "", name)
    
    return name.lower()


def load_metadata(path):
    """Load either CSV or JSON metadata."""
    if path.lower().endswith(".csv"):
        return load_metadata_csv(path)
    elif path.lower().endswith(".json"):
        return load_metadata_json(path)
    else:
        raise ValueError("Expected metadata as CSV or JSON")


def load_metadata_csv(path):
    with open(path, newline='') as f:
        next(f)
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        signal_col = next(h for h in headers if "signal" in h.lower())
        class_col = next(h for h in headers if "class" in h.lower())

        mapping = {}
        clock_signals = []

        for row in reader:
            sig = row[signal_col].strip()
            cls = row[class_col].strip()
            mapping[sig] = cls
            if cls.lower() == "clock":
                clock_signals.append(sig)

        return mapping, clock_signals


def load_metadata_json(path):
    with open(path) as f:
        data = json.load(f)
    mapping = data.get("signals", {})
    clock_signals = [s for s, c in mapping.items() if c.lower() == "clock"]
    return mapping, clock_signals


def load_connectivity(path):
    """Load connectivity JSON from classify_system.py (optional)"""
    if not path or not os.path.exists(path):
        return None
    
    with open(path) as f:
        return json.load(f)


def build_connection_map(connectivity):
    """
    Build bidirectional mapping of connected signals
    
    Creates multiple variations for matching:
      - parent.signal
      - instance.port
      - just signal name
      - just port name
    
    Returns: {signal_name: [connected_signals], ...}
    """
    if not connectivity:
        return {}
    
    conn_map = {}
    
    # Process direct connections
    for conn in connectivity.get('connections_direct', []):
        parent_mod = conn['parent_module']
        parent_sig = conn['parent_signal']
        instance = conn['instance']
        child_port = conn['child_port']
        
        # Create multiple name variations for matching
        # Parent signal variations
        parent_names = [
            parent_sig,                           # uart_busy
            f"{parent_mod}.{parent_sig}",        # soc_periph_top.uart_busy
            parent_sig.split('[')[0]             # uart_busy (without array index)
        ]
        
        # Child signal variations
        child_names = [
            child_port,                           # tx_busy
            f"{instance}.{child_port}",          # u_uart.tx_busy
            child_port.split('[')[0]             # tx_busy (without array index)
        ]
        
        # Create bidirectional mapping with all variations
        for parent_name in parent_names:
            for child_name in child_names:
                conn_map.setdefault(parent_name, []).append(child_name)
                conn_map.setdefault(child_name, []).append(parent_name)
    
    # Remove duplicates
    for key in conn_map:
        conn_map[key] = list(set(conn_map[key]))
    
    return conn_map


def find_connected_signal(sig_name, headers, conn_map):
    """
    Find a connected signal that exists in the waveform
    
    Returns: (column_name, column_index) or (None, None)
    """
    if not conn_map or sig_name not in conn_map:
        return None, None
    
    # Try each connected signal
    for connected_sig in conn_map[sig_name]:
        # Strategy 1: Exact match
        if connected_sig in headers:
            return connected_sig, headers.index(connected_sig)
        
        # Strategy 2: Normalized match
        norm_target = normalize(connected_sig)
        for i, h in enumerate(headers):
            if normalize(h) == norm_target:
                return h, i
        
        # Strategy 3: Last component match (for child signals)
        # e.g., "tx_busy" matches "u_uart.tx_busy"
        target_base = connected_sig.split('.')[-1]
        for i, h in enumerate(headers):
            h_base = h.split('.')[-1]
            h_base = re.sub(r'\[.*?\]', '', h_base)  # Remove array indices
            if h_base.lower() == target_base.lower():
                return h, i
        
        # Strategy 4: Instance.port match (for parent signals)
        # e.g., "uart_busy" matches "soc_tb.dut.uart_busy"
        for i, h in enumerate(headers):
            if h.endswith('.' + connected_sig) or h.endswith('_' + connected_sig):
                return h, i
    
    return None, None


def load_waveform(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def match_waveform_signals(waveform_row, metadata_map):
    """
    Match waveform signals to metadata signals
    
    Handles hierarchical names:
      soc_tb.dut.uart_busy → uart_busy
      soc_tb.dut.u_uart.tx_busy → u_uart.tx_busy → tx_busy
    """
    mapping = {}
    
    # Create normalized versions of metadata signals
    meta_norm = {}
    for meta_sig in metadata_map:
        # Try multiple normalization levels
        norm1 = normalize(meta_sig)  # Full normalization
        norm2 = meta_sig.split('.')[-1].lower()  # Just last component
        meta_norm[norm1] = meta_sig
        meta_norm[norm2] = meta_sig

    for wf_sig in waveform_row.keys():
        # Try different matching strategies
        
        # Strategy 1: Full normalized match
        cleaned = normalize(wf_sig)
        if cleaned in meta_norm:
            mapping[wf_sig] = meta_norm[cleaned]
            continue
        
        # Strategy 2: Last component match
        wf_base = wf_sig.split('.')[-1]
        wf_base = re.sub(r'\[.*?\]', '', wf_base).lower()
        if wf_base in meta_norm:
            mapping[wf_sig] = meta_norm[wf_base]
            continue
        
        # Strategy 3: Instance.signal match (e.g., u_uart.tx_busy)
        if '.' in cleaned:
            parts = cleaned.split('.')
            if len(parts) >= 2:
                # Try last 2 components
                two_level = '.'.join(parts[-2:])
                if two_level in meta_norm:
                    mapping[wf_sig] = meta_norm[two_level]
                    continue

    return mapping


def is_empty_value(val):
    """
    Check if value is truly empty (missing from waveform)
    
    Note: 'x' and 'z' are VALID HDL values (unknown/high-impedance)
          and should be propagated across modules!
    """
    v = val.strip()
    # Only treat completely empty/missing as "empty"
    return not v or v in ['', '-', '?']


def build_table(metadata_map, clock_signals, waveform, output_path, connectivity=None):
    signal_map = match_waveform_signals(waveform[0], metadata_map)
    
    # Build connection map if connectivity provided
    conn_map = build_connection_map(connectivity) if connectivity else {}
    
    # Track which signals were filled from connections
    filled_signals = []

    clock_column = None
    for wf_sig, meta_sig in signal_map.items():
        if meta_sig in clock_signals:
            clock_column = meta_sig
            break

    rows = []
    for row in waveform:

        # --- FIX: auto-detect time column (time_ps / time_ns / time_us) ---
        time_col = next(c for c in row.keys() if c.startswith("time_"))
        e = {time_col: row[time_col]}
        # ------------------------------------------------------------------

        # insert clock
        if clock_column:
            wf_sig = next((k for k, v in signal_map.items() if v == clock_column), None)
            e[clock_column] = row.get(wf_sig, "")

        # insert all other metadata signals
        for meta_sig in metadata_map:
            if meta_sig == clock_column:
                continue
            
            # Find waveform signal for this metadata signal
            wf_sig = next((k for k, v in signal_map.items() if v == meta_sig), None)
            value = row.get(wf_sig, "") if wf_sig else ""
            
            # If value is empty and we have connectivity, try to fill from connected signal
            # Note: 'x' and 'z' are valid HDL values and will be propagated
            if is_empty_value(value) and conn_map:
                # Try to find connected signal with value
                connected_name, connected_col = find_connected_signal(meta_sig, list(row.keys()), conn_map)
                
                if connected_col is not None and connected_name:
                    connected_value = row.get(connected_name, "")
                    
                    if not is_empty_value(connected_value):
                        value = connected_value
                        # Only add to filled_signals if not already tracked
                        if not any(sig == meta_sig for sig, _ in filled_signals):
                            filled_signals.append((meta_sig, connected_name))
            
            e[meta_sig] = value

        rows.append(e)

    df = pd.DataFrame(rows)

    # FIX: use detected time column instead of hardcoded "time_ps"
    ordered = [time_col]
    if clock_column:
        ordered.append(clock_column)
    ordered += [s for s in metadata_map if s not in ordered]

    df = df[ordered]

    # FIX: class row uses the detected time column
    class_row = []
    for col in df.columns:
        if col == time_col:
            class_row.append("")
        elif col == clock_column:
            class_row.append("clock")
        else:
            class_row.append(metadata_map.get(col, "other"))

    with open(output_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(class_row)
        w.writerow(df.columns.tolist())
        w.writerows(df.values.tolist())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Map waveform values to RTL signals with cross-module support")
    parser.add_argument("metadata_file", help="Path to signals.json or signals.csv")
    parser.add_argument("waveform_csv", help="Waveform CSV generated by VCD converter")
    parser.add_argument("output_csv", nargs='?', help="Output CSV path (optional, auto-generated if not provided)")
    parser.add_argument("--connectivity", "-c", help="Optional: system connectivity JSON from classify_system.py", default=None)
    parser.add_argument("--rtl-name", help="RTL module name for output file (e.g., 'uart_tx')")
    args = parser.parse_args()
    
    try:
        # Auto-generate output name if not provided
        if not args.output_csv:
            if args.rtl_name:
                # Use provided RTL name
                args.output_csv = f"{args.rtl_name}_mapped.csv"
            else:
                # Extract from waveform filename
                base = os.path.splitext(os.path.basename(args.waveform_csv))[0]
                args.output_csv = f"{base}_mapped.csv"

        metadata_map, clock_signals = load_metadata(args.metadata_file)
        waveform = load_waveform(args.waveform_csv)
        
        # Load connectivity if provided
        connectivity = load_connectivity(args.connectivity) if args.connectivity else None

        build_table(metadata_map, clock_signals, waveform, args.output_csv, connectivity)
        
        # Success message (ASCII-safe for Windows)
        print(f"OK: {args.output_csv}")
        
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)