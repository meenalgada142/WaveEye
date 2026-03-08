#!/usr/bin/env python3
import csv
import re
import sys
from collections import defaultdict
from alias_engine import AliasEngine


alias_engine = AliasEngine()

# ============================================================
# Literal parsing
# ============================================================
verilog_bin_re = re.compile(r"^(\d+)'b([01_]+)$", re.IGNORECASE)
verilog_hex_re = re.compile(r"^(\d+)'h([0-9a-fA-F_]+)$", re.IGNORECASE)
verilog_dec_re = re.compile(r"^(\d+)'d(\d+)$", re.IGNORECASE)
_SIMPLE_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

def parse_literal_token(tok):
    if tok is None:
        return None
    s = str(tok).strip()
    if s == "":
        return None
    if re.fullmatch(r"[01_]{2,}", s):
        return int(s.replace("_", ""), 2)
    if (m := verilog_bin_re.match(s)):
        return int(m.group(2).replace("_", ""), 2)
    if (m := verilog_hex_re.match(s)):
        return int(m.group(2).replace("_", ""), 16)
    if (m := verilog_dec_re.match(s)):
        return int(m.group(2))
    if s in ("0", "1"):
        return int(s)
    if re.fullmatch(r"[+-]?\d+", s):
        return int(s)
    return None


def eval_rhs_numeric(expr, rowext):
    if expr is None or str(expr).strip() == "":
        return None
    n = normalize_expr(expr)
    env = build_eval_locals(rowext)
    all_binary, in_width = rhs_all_binary_and_width(expr, rowext)
    try:
        res = eval(n, {"__builtins__": None}, env)
    except Exception:
        return None
    if all_binary:
        if isinstance(res, bool):
            res_int = int(res)
        else:
            try:
                res_int = int(res)
            except Exception:
                return None
        if res_int >= 0:
            res_bits = bin(res_int)[2:]
        else:
            return res_int
        out_width = len(res_bits)
        width = max(in_width, out_width)
        return format(res_int, f"0{width}b")
    if isinstance(res, bool):
        return int(res)
    try:
        return int(res)
    except Exception:
        return None

def rhs_all_binary_and_width(expr, rowext):
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr or "")
    if not ids:
        return False, 0
    widths = []
    for idf in ids:
        raw = rowext.get(idf, None)
        if raw is None:
            return False, 0
        if not re.fullmatch(r"[01_]+", str(raw)):
            return False, 0
        widths.append(len(str(raw).replace("_", "")))
    return True, (max(widths) if widths else 0)

def normalize_expr(expr):
    e = expr.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"(?<![=!])!(?![=])", " not ", e)
    return e

def build_eval_locals(row):
    """
    Build evaluation environment from row.
    Includes all signals, using get_signal_value to handle aliases.
    Missing signals default to 0 for boolean evaluation.
    """
    env = {}
    # First, get all signal names that might be referenced
    all_signals = set(row.keys())
    
    # Also check for signals in alias chains
    for sig in row.keys():
        for alias in alias_engine.chain(sig):
            all_signals.add(alias)
    
    # Build environment with all signals
    for sig in all_signals:
        # Try to get value using get_signal_value (handles aliases)
        val = get_signal_value(sig, row)
        if val is not None:
            p = parse_literal_token(val)
            if p is not None:
                env[sig] = p
            elif val == "":
                env[sig] = 0  # Empty string means 0
            elif val in ("0", "1"):
                env[sig] = int(val)
        else:
            # Signal not found, default to 0 for boolean evaluation
            env[sig] = 0
    
    return env

def strip_outer_parens(s):
    if not s:
        return s
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        encloses_all = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    encloses_all = False
                    break
        if not encloses_all or depth != 0:
            break
        s = s[1:-1].strip()
    return s
# ============================================================
# Alias helpers
# ============================================================
def get_signal_value(sig, row):
    """
    Robust alias resolver:
    1) If signal has a value -> use it
    2) Check all forward aliases via alias_engine.chain(sig)
    3) Check every other signal in waveform for alias relationships
    """
    # --- 1) Direct CSV value ---
    if sig in row and row[sig] != "":
        return row[sig]

    # --- 2) Forward alias chain ---
    fwd = alias_engine.chain(sig)
    for a in fwd[1:]:
        if a in row and row[a] != "":
            return row[a]

    # --- 3) FULL SCAN: check every waveform signal for alias relationships ---
    for other in row.keys():
        if other == sig:
            continue

        chain_other = alias_engine.chain(other)

        # other is alias of sig
        if sig in chain_other[1:] and row[other] != "":
            return row[other]

        # sig is alias of other
        if other in fwd[1:] and row[other] != "":
            return row[other]

    # No value found
    return None

def expand_row_with_aliases(row):
    ext = dict(row)
    for s, v in row.items():
        for a in alias_engine.chain(s)[1:]:
            if a not in ext or ext[a] == "":
                ext[a] = v
    return ext



# ============================================================
# CSV loaders
# ============================================================
def load_alias_csv(path):
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            vals = list(row.values())
            if len(vals) >= 2 and vals[0] and vals[1]:
                alias_engine.add_alias(vals[0].strip(), vals[1].strip())

def load_waveform_csv(path):
    with open(path) as f:
        rows = list(csv.reader(f))
    cls = [c.strip() for c in rows[0]]
    hdr = [h.strip() for h in rows[1]]
    wave = []
    for r in rows[2:]:
        r += [""] * (len(hdr) - len(r))
        wave.append({hdr[i]: r[i].strip() for i in range(len(hdr))})
    return wave, hdr, cls

def load_ss_backtrack_csv(path):
    d = {}
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            sig = row.get("signal", "").strip()
            if not sig:
                continue

            cond = (row.get("condition") or "").strip()

            drv = {
                "cond": cond,
                "rhs": (row.get("rhs") or "").strip(),
                "sensitivity": (row.get("sensitivity") or "").strip(),
            }

            # ================= STEP 1 (HERE) =================
            # Mark unconditional / default drivers ONCE
            drv["unconditional"] = (
                cond == "" or
                cond.lower() == "default" or
                cond.lower() == "else"
            )
            # ==================================================

            d.setdefault(sig, []).append(drv)
    return d

# ============================================================
# Clock helpers
# ============================================================
def detect_clock(path):
    with open(path) as f:
        rows = list(csv.reader(f))
    for c, h in zip(rows[0], rows[1]):
        if c.strip().lower() == "clock":
            return h
    return None

def is_posedge(wave, clk, i):
    if i == 0:
        return False
    return parse_literal_token(wave[i-1].get(clk)) == 0 and \
           parse_literal_token(wave[i].get(clk)) == 1

def find_next_update_edge(wave, clk, i):
    for j in range(i + 1, len(wave)):
        if is_posedge(wave, clk, j):
            return j
    return None
def get_edge_type(drv):
    """
    Derive edge type from sensitivity string.
    Default = posedge (safe for sequential logic).
    """
    sens = (drv.get("sensitivity") or "").lower()
    edge = set()
    if "negedge" in sens:
        edge.add("negedge")
    if "posedge" in sens or not edge:
        edge.add("posedge")
    return edge
# ============================================================
# RESET NORMALIZATION (CRITICAL, RESTORED)
# ============================================================

_reset_collapse_pat = re.compile(r'(?:\bnot\b|\!|\~)\s*(?:\(\s*)*1(?:\s*\))*', re.IGNORECASE)
_reset_collapse_outer_pat = re.compile(r'(?:(?:\bnot\b|\!|\~)\s*)+\(?\s*1\s*\)?', re.IGNORECASE)

def normalize_reset_in_expr(cond, reset_signal):
    if not cond or not reset_signal:
        return cond
    pat = re.compile(rf"(?:\(!\s*{re.escape(reset_signal)}\s*\)|!\s*{re.escape(reset_signal)}\b|\b{re.escape(reset_signal)}\b)")
    out = pat.sub("1", cond)
    prev = None
    while prev != out:
        prev = out
        out = _reset_collapse_outer_pat.sub("1", out)
    out = re.sub(r'\(+\s*1\s*\)+', '1', out)
    return out


def condition_is_only_reset(cond, reset_signal):
    if not cond or not reset_signal:
        return False
    if "case_item:" in cond:
        return False
    tmp = normalize_reset_in_expr(cond, reset_signal)
    tmp2 = re.sub(r'\s+', '', tmp)
    tmp2 = tmp2.replace('1', '')
    tmp2 = tmp2.replace('&&', '').replace('||', '').replace('and', '').replace('or', '')
    tmp2 = re.sub(r'[()]+', '', tmp2)
    tmp2 = re.sub(r'[=!<>+\-\*/\[\]]', '', tmp2)
    return tmp2 == ""

# ============================================================
# SPILT CONITIONS
# ============================================================
def split_conditions(expr):
    if not expr:
        return []

    expr = expr.strip()
    out = []
    buf = []
    depth = 0
    i = 0

    while i < len(expr):
        c = expr[i]

        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1

        if depth == 0 and expr[i:i+2] == "&&":
            token = "".join(buf).strip()
            if token:
                out.append(token)
            buf = []
            i += 2
            continue

        if depth == 0 and expr[i:i+2] == "||":
            token = "".join(buf).strip()
            if token:
                out.append(token)
            buf = []
            i += 2
            continue

        buf.append(c)
        i += 1

    token = "".join(buf).strip()
    if token:
        out.append(token)

    return out   # [OK] THIS WAS MISSING


# ============================================================
# FSM HELPERS
# ============================================================

def detect_fsm_regs(classifications, header):
    fsm_regs = []
    fsm_states = []
    for c, h in zip(classifications, header):
        if c.lower() == "fsm_control":
            fsm_regs.append(h)
        elif c.lower() == "fsm_state":
            fsm_states.append(h)
    return fsm_regs, fsm_states

def build_fsm_encodings(classifications, header, wave):
    enc = {}
    if not wave:
        return enc
    for c, h in zip(classifications, header):
        if c.lower() == "fsm_state":
            raw = wave[0].get(h)
            enc[h] = parse_literal_token(raw) or 0
    # FSM encodings trace removed - only trace mismatches now
    return enc



# ============================================================
# Expression evaluation
# ============================================================
def is_wildcard_literal(s):
    return isinstance(s, str) and re.fullmatch(r"\d+'b[01\?]+", s)
def eval_wildcard_eq(signal_val, pattern):
    """
    signal_val: int
    pattern: string like 4'b1???
    """
    bits = pattern.split("'b")[1]

    mask = 0
    value = 0
    for i, b in enumerate(bits):
        bitpos = len(bits) - 1 - i
        if b in "01":
            mask |= (1 << bitpos)
            if b == "1":
                value |= (1 << bitpos)

    return (signal_val & mask) == value
def strip_outer_parens(s):
    if not s:
        return s
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        encloses_all = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    encloses_all = False
                    break
        if not encloses_all or depth != 0:
            break
        s = s[1:-1].strip()
    return s
def eval_expr(expr, row, *, fsm_regs=None, fsm_enc=None):
    """
    Evaluate expression, handling bit slices, comparisons, and simple signals.
    FSM equality is handled ONLY when applicable.
    """
    if not expr:
        return True

    expr = strip_outer_parens(expr.strip())

    # Fast-path literals/keywords so conditions like "true" don't fall
    # through to Python eval() as unknown identifiers.
    expr_l = expr.lower()
    if expr_l in ("true", "1'b1", "1'h1", "1'd1", "1"):
        return 1
    if expr_l in ("false", "1'b0", "1'h0", "1'd0", "0"):
        return 0
    lit = parse_literal_token(expr)
    if lit is not None:
        return lit

    # Fast-path: simple undecorated signal name — avoids build_eval_locals + eval()
    # for the most common leaf case (e.g. "AWVALID", "BVALID", "write_state")
    if _SIMPLE_IDENT_RE.fullmatch(expr):
        raw = row.get(expr)
        if raw is not None and raw != "":
            p = parse_literal_token(raw)
            if p is not None:
                return int(p)
            try:
                return int(raw)
            except (ValueError, TypeError):
                return None
        # Signal not directly in row — try alias resolution
        val = get_signal_value(expr, row)
        if val is not None:
            p = parse_literal_token(val)
            if p is not None:
                return int(p)
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
        return None  # Unknown signal: return None (not 0) so callers treat as missing

    # ------------------------------
    # FIX: handle !(sub-expression)
    # ------------------------------
    if expr.startswith("!"):
        inner = strip_outer_parens(expr[1:].strip())
        v = eval_expr(inner, row, fsm_regs=fsm_regs, fsm_enc=fsm_enc)
        if v is None:
            return None
        return not bool(v)
    try:
        # --------------------------------------------------
        # Handle comparisons / bit slices
        # --------------------------------------------------
        if (
            "==" in expr or "!=" in expr or "<=" in expr or ">=" in expr
            or "<" in expr or ">" in expr or "[" in expr
        ):
            parts = split_conditions(expr)

            if len(parts) == 1:
                part = parts[0].strip()

                comp_match = re.match(r"(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)", part)
                if comp_match:
                    left_expr = comp_match.group(1).strip()
                    op = comp_match.group(2).strip()
                    right_expr = comp_match.group(3).strip()

                    # --------------------------------------------------
                    # FSM EQUALITY HOOK (ONLY ADDITION)
                    # --------------------------------------------------
                    # FIX: fsm_regs may be a tuple (regs_list, states_list)
                    # or a flat list. Normalise to a flat set of signal names
                    # before doing the 'in' membership check.
                    _fsm_sig_set = set()
                    if fsm_regs:
                        if isinstance(fsm_regs, tuple):
                            for _part in fsm_regs:
                                if isinstance(_part, (list, tuple)):
                                    _fsm_sig_set.update(_part)
                                elif isinstance(_part, str):
                                    _fsm_sig_set.add(_part)
                        elif isinstance(fsm_regs, (list, set)):
                            _fsm_sig_set.update(fsm_regs)
                    if (
                        _fsm_sig_set and fsm_enc and
                        op == "==" and
                        left_expr in _fsm_sig_set and
                        right_expr in fsm_enc
                    ):
                        raw = row.get(left_expr)
                        reg_val = parse_literal_token(raw)
                        enc_val = fsm_enc.get(right_expr)

                        if reg_val is None or enc_val is None:
                            return None

                        return reg_val == enc_val

                    # --------------------------------------------------
                    # ORIGINAL LEFT SIDE HANDLING
                    # --------------------------------------------------
                    left_sig_match = re.match(
                        r"([A-Za-z_][A-Za-z0-9_]*)(?:\[(.*?)\])?",
                        left_expr
                    )
                    if left_sig_match:
                        base = left_sig_match.group(1)
                        slice_part = left_sig_match.group(2)
                        raw_left = get_signal_value(base, row)
                        if raw_left is None:
                            raw_left = row.get(base, "?")
                        parsed_left = parse_literal_token(raw_left)
                        if parsed_left is None:
                            try:
                                parsed_left = int(raw_left)
                            except:
                                parsed_left = None

                        if slice_part and parsed_left is not None:
                            try:
                                if ":" in slice_part:
                                    msb, lsb = map(int, slice_part.split(":"))
                                    width = msb - lsb + 1
                                    mask = (1 << width) - 1
                                    parsed_left = (parsed_left >> lsb) & mask
                                else:
                                    idx = int(slice_part)
                                    parsed_left = (parsed_left >> idx) & 1
                            except:
                                pass

                        left_val = parsed_left
                    else:
                        left_val = eval_expr(left_expr, row,
                                             fsm_regs=fsm_regs,
                                             fsm_enc=fsm_enc)

                    # --------------------------------------------------
                    # RHS (unchanged)
                    # --------------------------------------------------
                    right_val = parse_literal_token(right_expr)
                    if right_val is None:
                        right_val = eval_expr(right_expr, row,
                                               fsm_regs=fsm_regs,
                                               fsm_enc=fsm_enc)

                    if left_val is not None and right_val is not None:
                        if op == "==":
                            return left_val == right_val
                        elif op == "!=":
                            return left_val != right_val
                        elif op == "<=":
                            return left_val <= right_val
                        elif op == ">=":
                            return left_val >= right_val
                        elif op == "<":
                            return left_val < right_val
                        elif op == ">":
                            return left_val > right_val

                    return None

        # --------------------------------------------------
        # Boolean logic (UNCHANGED)
        # --------------------------------------------------
        if "&&" in expr or "||" in expr or " and " in expr.lower() or " or " in expr.lower():
            def _split_bool_ops_top(e: str):
                terms = []
                ops = []
                buf = []
                depth = 0
                i = 0
                while i < len(e):
                    ch = e[i]
                    if ch == "(":
                        depth += 1
                        buf.append(ch)
                        i += 1
                        continue
                    if ch == ")":
                        depth -= 1
                        buf.append(ch)
                        i += 1
                        continue
                    if depth == 0 and e[i:i+2] in ("&&", "||"):
                        term = "".join(buf).strip()
                        if term:
                            terms.append(term)
                        ops.append(e[i:i+2])
                        buf = []
                        i += 2
                        continue
                    if depth == 0 and e[i:i+5].lower() == " and ":
                        term = "".join(buf).strip()
                        if term:
                            terms.append(term)
                        ops.append("&&")
                        buf = []
                        i += 5
                        continue
                    if depth == 0 and e[i:i+4].lower() == " or ":
                        term = "".join(buf).strip()
                        if term:
                            terms.append(term)
                        ops.append("||")
                        buf = []
                        i += 4
                        continue
                    buf.append(ch)
                    i += 1
                tail = "".join(buf).strip()
                if tail:
                    terms.append(tail)
                return terms, ops

            terms, ops = _split_bool_ops_top(expr)
            if not terms:
                return None

            values = [eval_expr(t, row, fsm_regs=fsm_regs, fsm_enc=fsm_enc) for t in terms]
            if any(v is None for v in values):
                return None

            acc = bool(values[0])
            for idx, op in enumerate(ops):
                rhs = bool(values[idx + 1]) if (idx + 1) < len(values) else False
                if op == "&&":
                    acc = acc and rhs
                else:
                    acc = acc or rhs
            return acc

        # --------------------------------------------------
        # Fallback (UNCHANGED)
        # --------------------------------------------------
        return eval(
            normalize_expr(expr),
            {"__builtins__": None},
            build_eval_locals(row)
        )

    except Exception:
        return None



# ============================================================
# Window grouping
# ============================================================
def group_windows(mis):
    by = defaultdict(list)
    for m in mis:
        by[m["signal"]].append(m)
    out = {}
    for sig, arr in by.items():
        arr = sorted(arr, key=lambda x: x["i"])
        s = p = arr[0]["i"]
        win = []
        for m in arr[1:]:
            if m["i"] == p + 1:
                p = m["i"]
            else:
                win.append((s, p))
                s = p = m["i"]
        win.append((s, p))
        out[sig] = win
    return out

"""
========================================================================
PASTE THESE FUNCTIONS INTO YOUR utils.py FILE
========================================================================

Add these functions to handle concatenation, bit slicing, and bit selection.
These enhance the existing eval_expr() function.

Usage in analyse.py:
    rhs_val = eval_rhs_expression(rhs, curr_row)
========================================================================
"""

import re
from typing import Optional


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def parse_bit_width(literal: str) -> Optional[int]:
    """
    Extract bit width from Verilog literal.
    Examples: 8'h00 -> 8, 32'b0 -> 32, 1'b1 -> 1
    """
    if "'" in literal:
        try:
            return int(literal.split("'")[0])
        except:
            return None
    return None


# ============================================================
# BIT OPERATIONS
# ============================================================

def eval_bit_selection(expr: str, row: dict) -> Optional[int]:
    """
    Evaluate bit selection: signal[index]
    Example: shift_reg[7] -> extracts bit 7 from shift_reg
    
    Args:
        expr: Expression like "signal[3]" or "data[7]"
        row: Current waveform row as dict
    
    Returns:
        Integer value of selected bit (0 or 1), or None
    """
    # Match pattern: identifier[number]
    match = re.match(r'^(\w+)\[(\d+)\]$', expr.strip())
    if not match:
        return None
    
    signal_name, index_str = match.groups()
    index = int(index_str)
    
    # Get signal value from waveform
    raw_value = row.get(signal_name, None)
    if raw_value is None:
        return None
    
    # Parse the signal value (use existing parse_literal_token)
    signal_val = parse_literal_token(str(raw_value))
    if signal_val is None:
        return None
    
    # Extract the specific bit
    bit_val = (signal_val >> index) & 1
    return bit_val


def eval_bit_slice(expr: str, row: dict) -> Optional[int]:
    """
    Evaluate bit slicing: signal[high:low]
    Example: shift_reg[6:0] -> extracts bits 6 down to 0
    
    Args:
        expr: Expression like "signal[7:0]" or "data[15:8]"
        row: Current waveform row as dict
    
    Returns:
        Integer value of sliced bits, or None
    """
    # Match pattern: identifier[high:low]
    match = re.match(r'^(\w+)\[(\d+):(\d+)\]$', expr.strip())
    if not match:
        return None
    
    signal_name, high_str, low_str = match.groups()
    high = int(high_str)
    low = int(low_str)
    
    if high < low:
        return None  # Invalid slice
    
    # Get signal value from waveform
    raw_value = row.get(signal_name, None)
    if raw_value is None:
        return None
    
    # Parse the signal value
    signal_val = parse_literal_token(str(raw_value))
    if signal_val is None:
        return None
    
    # Extract the bit slice
    width = high - low + 1
    mask = (1 << width) - 1
    sliced_val = (signal_val >> low) & mask
    
    return sliced_val


# ============================================================
# CONCATENATION
# ============================================================

def eval_concatenation(expr: str, row: dict) -> Optional[int]:
    """
    Evaluate Verilog concatenation: {part1, part2, part3, ...}
    
    Examples:
      {shift_reg[6:0], serial_in}
      {8'h00, data}
      {24'b0, dout}
      {status[1:0], count, flag}
    
    Args:
        expr: Concatenation expression
        row: Current waveform row as dict
    
    Returns:
        Concatenated integer value, or None if evaluation fails
    """
    expr = expr.strip()
    
    # Must be wrapped in braces
    if not (expr.startswith("{") and expr.endswith("}")):
        return None
    
    inner = expr[1:-1].strip()
    
    # Split by commas, respecting nested braces
    parts = []
    buf = []
    brace_level = 0
    
    for ch in inner:
        if ch == '{':
            brace_level += 1
            buf.append(ch)
        elif ch == '}':
            brace_level -= 1
            buf.append(ch)
        elif ch == ',' and brace_level == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    
    # Don't forget the last part
    if buf:
        parts.append("".join(buf).strip())
    
    # Evaluate each part and concatenate (MSB first)
    result = 0
    
    for part in parts:
        part = part.strip()
        part_value = None
        part_width = None
        
        # Try to evaluate the part
        # 1. Check if it's a literal (e.g., 8'h00, 1'b1)
        lit = parse_literal_token(part)
        if lit is not None:
            part_value = lit
            part_width = parse_bit_width(part)
            if part_width is None:
                # For plain integers, calculate width
                part_width = part_value.bit_length() if part_value > 0 else 1
        
        # 2. Check if it's a bit slice (e.g., signal[7:0])
        elif '[' in part and ':' in part:
            part_value = eval_bit_slice(part, row)
            if part_value is not None:
                match = re.match(r'\w+\[(\d+):(\d+)\]', part)
                if match:
                    high, low = int(match.group(1)), int(match.group(2))
                    part_width = high - low + 1
        
        # 3. Check if it's a bit selection (e.g., signal[3])
        elif '[' in part and ']' in part:
            part_value = eval_bit_selection(part, row)
            if part_value is not None:
                part_width = 1  # Single bit
        
        # 4. Check if it's a signal name
        else:
            raw = row.get(part, None)
            if raw is not None:
                part_value = parse_literal_token(str(raw))
                if part_value is not None:
                    # Infer width from the string representation
                    raw_str = str(raw).replace("_", "")
                    if "'b" in raw_str:
                        part_width = len(raw_str.split("'b")[1])
                    elif "'h" in raw_str:
                        part_width = len(raw_str.split("'h")[1]) * 4
                    else:
                        part_width = part_value.bit_length() if part_value > 0 else 1
        
        # If we couldn't evaluate this part, fail
        if part_value is None or part_width is None:
            return None
        
        # Shift and concatenate
        result = (result << part_width) | part_value
    
    return result


# ============================================================
# REPLICATION
# ============================================================

def eval_replication(expr: str, row: dict) -> Optional[int]:
    """
    Evaluate replication: {count{pattern}}
    Example: {4{2'b01}} -> 8'b01010101
    
    Args:
        expr: Replication expression
        row: Current waveform row as dict
    
    Returns:
        Replicated value, or None
    """
    # Match pattern: {count{pattern}}
    match = re.match(r'^\{(\d+)\{(.+)\}\}$', expr.strip())
    if not match:
        return None
    
    count_str, pattern = match.groups()
    count = int(count_str)
    
    # Evaluate the pattern
    pattern_val = parse_literal_token(pattern)
    if pattern_val is None:
        # Try other evaluation methods
        if '{' in pattern:
            pattern_val = eval_concatenation(pattern, row)
        elif '[' in pattern:
            if ':' in pattern:
                pattern_val = eval_bit_slice(pattern, row)
            else:
                pattern_val = eval_bit_selection(pattern, row)
        else:
            raw = row.get(pattern, None)
            if raw:
                pattern_val = parse_literal_token(str(raw))
    
    if pattern_val is None:
        return None
    
    # Get pattern width
    pattern_width = parse_bit_width(pattern)
    if pattern_width is None:
        pattern_width = pattern_val.bit_length() if pattern_val > 0 else 1
    
    # Replicate the pattern
    result = 0
    for _ in range(count):
        result = (result << pattern_width) | pattern_val
    
    return result


# ============================================================
# UNIVERSAL RHS EVALUATOR (USE THIS!)
# ============================================================

def eval_rhs_expression(expr: str, row: dict) -> Optional[int]:
    """
    Universal RHS expression evaluator.
    Handles literals, signals, bit operations, and concatenations.
    
    THIS IS THE MAIN FUNCTION TO USE!
    
    Args:
        expr: Right-hand side expression
        row: Current waveform row as dict
    
    Returns:
        Evaluated integer value, or None
    
    Examples:
        eval_rhs_expression("8'h00", row)                    -> 0
        eval_rhs_expression("shift_reg[7]", row)             -> 0 or 1
        eval_rhs_expression("shift_reg[6:0]", row)           -> sliced value
        eval_rhs_expression("{shift_reg[6:0], serial_in}", row) -> concatenated value
    """
    if not expr:
        return None
    
    expr = expr.strip()
    
    # 1. Try literal
    lit = parse_literal_token(expr)
    if lit is not None:
        return lit
    
    # 2. Try replication: {count{pattern}}
    if expr.count('{') == 2 and expr.count('}') == 2:
        rep = eval_replication(expr, row)
        if rep is not None:
            return rep
    
    # 3. Try concatenation: {a, b, c}
    if expr.startswith('{') and expr.endswith('}'):
        concat = eval_concatenation(expr, row)
        if concat is not None:
            return concat
    
    # 4. Try bit slice: signal[high:low]
    if '[' in expr and ':' in expr:
        slice_val = eval_bit_slice(expr, row)
        if slice_val is not None:
            return slice_val
    
    # 5. Try bit selection: signal[index]
    if '[' in expr and ']' in expr:
        bit_val = eval_bit_selection(expr, row)
        if bit_val is not None:
            return bit_val
    
    # 6. Try signal lookup (alias-aware)
    raw = get_signal_value(expr, row)
    if raw is None:
        raw = row.get(expr, None)
    if raw is not None:
        return parse_literal_token(str(raw))
    
    # 7. Final fallback: evaluate expression using ONLY waveform-resolved vars.
    # Do NOT default unknown identifiers to 0.
    try:
        py_expr = normalize_expr(expr)
        env = {}
        ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr)
        reserved = {"and", "or", "not", "if", "else"}

        for tok in ids:
            if tok in reserved:
                continue
            if tok in ("true", "True"):
                env[tok] = 1
                continue
            if tok in ("false", "False"):
                env[tok] = 0
                continue

            raw_tok = get_signal_value(tok, row)
            if raw_tok is None:
                raw_tok = row.get(tok, None)
            if raw_tok is None:
                return None

            parsed_tok = parse_literal_token(str(raw_tok))
            if parsed_tok is None:
                return None
            env[tok] = parsed_tok

        res = eval(py_expr, {"__builtins__": None}, env)
        if isinstance(res, bool):
            return int(res)
        try:
            return int(res)
        except Exception:
            return None
    except Exception:
        return None
