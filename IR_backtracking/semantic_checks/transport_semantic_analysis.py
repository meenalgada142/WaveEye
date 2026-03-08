#!/usr/bin/env python3
"""
transport_semantic_analysis.py
================================
IR-level (pre-waveform) checker for AXI transport-path semantic mismatches.

Detects misaligned payload transformations between related AXI signals:
  - Replicated WDATA with incorrectly shifted WSTRB
  - Address-dependent lane-steering errors
  - Off-by-one / off-by-constant shift bugs
  - Missing address dependency in strobe expressions
  - Incorrect scaling during width conversion
  - Non-monotone address transforms (ordering violations)

Runs purely on IR records — no waveform required.
Integrated by ir_builder.py after detect_memory_write_semantic_mismatch().

Public API:
    violations = detect_transport_semantic_mismatch(ir_records)
    violations = detect_address_monotonicity_violation(ir_records)

TRANSPORT_ALIGNMENT_VIOLATION dict:
    {
        "class":               "TRANSPORT_ALIGNMENT_VIOLATION",
        "subtype":             "WSTRB_DATA_MISALIGNMENT",
        "confidence":          "HIGH",
        "always_block_id":     <int | None>,
        "rtl_line":            <int | None>,
        "source_signal":       <str>,   # replicated data signal
        "destination_signal":  <str>,   # wide-bus data LHS
        "strobe_signal":       <str>,   # WSTRB LHS
        "replication_factor":  <str>,   # K in {(K){X}}
        "shift_expression":    <str>,   # raw extracted shift
        "affine_offset":       <int|str>, # B in A*x + B; 0 = correct
        "bug_pattern":         <str>,   # human description
        "explanation":         <str>,   # one-line RCA explanation
        "signals_involved":    [<str>], # all affected signals
    }

ADDRESS_MONOTONICITY_VIOLATION dict:
    {
        "class":           "ADDRESS_MONOTONICITY_VIOLATION",
        "subtype":         "ADDRESS_COLLAPSE" | "ORDER_REVERSAL" |
                           "MONOTONICITY_EDGE_RISK" | "NON_MONOTONIC_UNKNOWN",
        "always_block_id": <int | None>,
        "rtl_line":        <int | None>,
        "lhs":             <str>,   # address destination signal
        "rhs":             <str>,   # raw transform expression
        "coefficient":     <int | None>,   # A in A*x + B
        "offset":          <int | None>,   # B in A*x + B
        "risk":            "alias" | "reversal" | "unknown",
        "impact":          "Write/read ordering may not be preserved",
    }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Replication: {(K){X}}  or  {K{X}}  (Verilog concat/replicate)
# Source signal allows ':' so that bit-select subscripts like [7:0] are captured.
_REPLICATE_RE = re.compile(
    r'\{\s*\(?'                           # opening brace + optional (
    r'([^){\s]+)'                         # K  — replication factor
    r'\)?\s*\{'                           # ) optional + inner {
    r'\s*([A-Za-z_][A-Za-z0-9_.$\[\]:]*)'  # X — source signal (allows [7:0])
    r'\s*\}\s*\}',                        # }}
    re.IGNORECASE,
)

# Left shift in WSTRB RHS:  expr << shift_amount
# Greedy match for amount (stops at ; or end-of-string).
# Trailing unbalanced ')' are stripped in _extract_shift.
_SHIFT_BASE_RE = re.compile(
    r'(?P<base>[A-Za-z_][A-Za-z0-9_.$\[\]]*)'
    r'\s*<<\s*'
    r'(?P<amount>[^;]+)',
    re.IGNORECASE,
)

# Affine pattern:  (addr_signal + C) * factor   or   addr_signal * factor
# Captures the inner additive expression and factor separately.
_AFFINE_MUL_RE = re.compile(
    r'\(\s*(?P<inner>[^)]+?)\s*\)\s*\*\s*(?P<factor>[A-Za-z0-9_]+)'
    r'|'
    r'(?P<sig_only>[A-Za-z_][A-Za-z0-9_]*)\s*\*\s*(?P<factor2>[A-Za-z0-9_]+)',
    re.IGNORECASE,
)

# Additive offset in inner expression:  sig + C  or  sig - C
_INNER_OFFSET_RE = re.compile(
    r'(?P<sig>[A-Za-z_][A-Za-z0-9_]*)'
    r'\s*(?P<op>[+\-])\s*'
    r'(?P<const>[A-Za-z0-9_]+)',
    re.IGNORECASE,
)

# Identifier pattern
_IDENT_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')

# WSTRB-like signal name suffixes
_WSTRB_SUFFIXES = ("wstrb", "_wstrb", "strb", "_strb", "wbe", "_wbe")
# WDATA-like signal name suffixes
_WDATA_SUFFIXES = ("wdata", "_wdata", "writedata", "_writedata")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_wstrb_signal(name: str) -> bool:
    n = name.lower()
    return any(n.endswith(s) or s.lstrip("_") in n for s in _WSTRB_SUFFIXES)


def _is_wdata_signal(name: str) -> bool:
    n = name.lower()
    return any(n.endswith(s) or s.lstrip("_") in n for s in _WDATA_SUFFIXES)


def _extract_replication(rhs: str) -> Optional[Tuple[str, str]]:
    """
    Return (factor, source_signal) if rhs contains a replication expression
    {(K){X}}, else None.
    """
    m = _REPLICATE_RE.search(rhs or "")
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return None


def _extract_shift(rhs: str) -> Optional[Tuple[str, str]]:
    """
    Return (base_signal, shift_amount_expr) if rhs is a left-shift expression,
    else None.

    Uses a greedy match to capture the full shift amount (including nested parens
    like ``((addr + 1) * 4)``), then strips trailing unbalanced closing parens
    that were not part of the expression (e.g. when the shift appears inside a
    larger expression).
    """
    m = _SHIFT_BASE_RE.search(rhs or "")
    if not m:
        return None

    base   = m.group("base").strip()
    amount = m.group("amount").strip()

    # Strip any trailing whitespace or comment fragments
    amount = amount.rstrip()

    # Remove trailing ')' that are not balanced by a '(' within amount
    while amount.endswith(")") and amount.count("(") < amount.count(")"):
        amount = amount[:-1].rstrip()

    if not amount:
        return None

    return base, amount


# ---------------------------------------------------------------------------
# Affine extractor
# ---------------------------------------------------------------------------

def _parse_affine_shift(expr: str) -> Dict[str, Any]:
    """
    Parse a shift-amount expression into affine form:  A * addr_signal + B

    Returns dict:
        addr_signal  -- identifier used as address index (or None)
        factor       -- multiplicative factor token (or None)
        offset       -- additive constant B (0 means correct, non-zero = bug)
        raw          -- original expression string
        verdict      -- "OK" | "OFF_BY_CONSTANT" | "NO_ADDR_DEP" | "CONSTANT_ONLY"

    Valid form:   addr_signal * STRB_WIDTH      → offset=0, verdict=OK
    Bug forms:
        (addr_signal + C) * STRB_WIDTH          → offset=C,  verdict=OFF_BY_CONSTANT
        (addr_signal - C) * STRB_WIDTH          → offset=-C, verdict=OFF_BY_CONSTANT
        constant                                 → verdict=CONSTANT_ONLY
        expr without addr_signal                 → verdict=NO_ADDR_DEP
    """
    expr = expr.strip()

    # Strip balanced outer parentheses:
    #   ((awaddr + 1) * 4)  →  (awaddr + 1) * 4
    #   ((addr) * 4)        →  (addr) * 4
    while (expr.startswith("(") and expr.endswith(")")
           and expr[1:-1].count("(") == expr[1:-1].count(")")):
        expr = expr[1:-1].strip()

    result: Dict[str, Any] = {
        "addr_signal": None,
        "factor":      None,
        "offset":      0,
        "raw":         expr,
        "verdict":     "UNKNOWN",
    }

    # Case 1: pure constant (no identifier at all)
    idents = _IDENT_RE.findall(expr)
    if not idents:
        result["verdict"] = "CONSTANT_ONLY"
        return result

    # Case 2: try affine mul match: (inner) * factor  OR  sig * factor
    m = _AFFINE_MUL_RE.search(expr)
    if m:
        if m.group("inner") is not None:
            # (inner) * factor
            inner  = m.group("inner").strip()
            factor = m.group("factor").strip()
            result["factor"] = factor

            # Parse inner for additive offset
            om = _INNER_OFFSET_RE.match(inner)
            if om:
                result["addr_signal"] = om.group("sig")
                op    = om.group("op")
                const = om.group("const")
                # Try to evaluate const numerically
                try:
                    cval = int(const, 0)
                except ValueError:
                    cval = const   # symbolic offset (still a bug)
                result["offset"]  = -cval if op == "-" else cval
                result["verdict"] = "OFF_BY_CONSTANT"
            else:
                # inner is just a plain identifier
                result["addr_signal"] = inner
                result["offset"]      = 0
                result["verdict"]     = "OK"
        else:
            # sig * factor (no parentheses)
            result["addr_signal"] = m.group("sig_only").strip()
            result["factor"]      = m.group("factor2").strip()
            result["offset"]      = 0
            result["verdict"]     = "OK"
        return result

    # Case 3: expression has identifiers but no mul pattern → no addr dep
    result["addr_signal"] = idents[0] if idents else None
    result["verdict"] = "NO_ADDR_DEP"
    return result


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_transport_semantic_mismatch(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Scan IR records for AXI transport-path misalignment bugs.

    Algorithm:
      STEP 1  Build per-always-block index.
      STEP 2  Find DATA_REPLICATION_SITEs (WDATA replications).
      STEP 3  For each replication site, search the same block for a
              STROBE_TRANSFORM_SITE (WSTRB left shift).
      STEP 4  Symbolically analyse the strobe shift expression (affine form).
      STEP 5  Cross-validate: if shift is incorrect → emit violation.

    Returns list of violation dicts.
    """
    violations: List[Dict[str, Any]] = []

    # ── STEP 1: group IR records by always_block_id ──────────────────────────
    blocks: Dict[Any, List[Dict[str, Any]]] = {}
    for rec in ir_records:
        bid = rec.get("always_block_id")   # may be None for continuous assigns
        blocks.setdefault(bid, []).append(rec)

    # ── STEP 2 + 3: scan each block for replication + strobe ────────────────
    for bid, recs in blocks.items():
        replication_sites: List[Dict[str, Any]] = []
        strobe_sites:      List[Dict[str, Any]] = []

        for rec in recs:
            sig = (rec.get("signal") or "").strip()
            rhs = (rec.get("rhs")    or "").strip()

            # Detect DATA_REPLICATION_SITE
            rep = _extract_replication(rhs)
            if rep is not None and _is_wdata_signal(sig):
                factor, src_sig = rep
                replication_sites.append({
                    "rec":             rec,
                    "destination":     sig,
                    "source":          src_sig,
                    "factor":          factor,
                    "rtl_line":        rec.get("line"),
                })

            # Detect STROBE_TRANSFORM_SITE
            if _is_wstrb_signal(sig):
                shift = _extract_shift(rhs)
                if shift is not None:
                    base_sig, amount_expr = shift
                    strobe_sites.append({
                        "rec":         rec,
                        "strobe_sig":  sig,
                        "base_sig":    base_sig,
                        "amount_expr": amount_expr,
                        "rtl_line":    rec.get("line"),
                    })

        # ── STEP 4 + 5: cross-validate replication vs strobe ─────────────────
        for rep_site in replication_sites:
            if not strobe_sites:
                # Replication without any strobe transformation in same block.
                violations.append(_make_violation(
                    subtype="MISSING_STROBE_TRANSFORM",
                    bug_pattern=(
                        "WDATA is replicated but no corresponding WSTRB "
                        "shift exists in the same always block."
                    ),
                    explanation=(
                        f"Signal '{rep_site['destination']}' replicates "
                        f"'{rep_site['source']}' by factor {rep_site['factor']} "
                        "but no WSTRB steering was found. All byte lanes receive "
                        "the same strobe, causing writes to the wrong lanes."
                    ),
                    bid=bid,
                    rtl_line=rep_site["rtl_line"],
                    src=rep_site["source"],
                    dst=rep_site["destination"],
                    strobe_sig="(none)",
                    factor=rep_site["factor"],
                    shift_expr="(absent)",
                    affine_offset=None,
                ))
                continue

            for strobe_site in strobe_sites:
                # ── STEP 4: parse the shift amount ───────────────────────────
                affine = _parse_affine_shift(strobe_site["amount_expr"])
                verdict = affine["verdict"]

                if verdict == "OK":
                    continue   # correct steering — no violation

                # ── STEP 5: emit violation ────────────────────────────────────
                if verdict == "OFF_BY_CONSTANT":
                    bug = (
                        f"Shift expression contains constant offset "
                        f"(+{affine['offset']}), violating lane-mapping identity "
                        f"A*addr + 0. Writes land in offset-by-{affine['offset']} lanes."
                    )
                    expl = (
                        f"WSTRB steering for '{strobe_site['strobe_sig']}' uses "
                        f"'{strobe_site['amount_expr']}': address signal "
                        f"'{affine['addr_signal']}' has a non-zero additive offset "
                        f"({affine['offset']}), causing byte-lane steering to be off "
                        "by a constant. This does not match the WDATA replication "
                        f"lane mapping for '{rep_site['destination']}'."
                    )
                elif verdict == "CONSTANT_ONLY":
                    bug = (
                        "Strobe shift amount is a compile-time constant — no "
                        "address dependency. Byte lanes are always steered to "
                        "the same position regardless of the AXI address."
                    )
                    expl = (
                        f"WSTRB '{strobe_site['strobe_sig']}' is shifted by "
                        f"a constant '{strobe_site['amount_expr']}' with no "
                        "address-derived index. All transactions use the same "
                        "byte lane, which is incorrect for a width-converting adapter."
                    )
                else:  # NO_ADDR_DEP or UNKNOWN
                    bug = (
                        "Shift expression does not contain an address-derived "
                        "multiplicative term. Lane steering is not address-dependent."
                    )
                    expl = (
                        f"WSTRB '{strobe_site['strobe_sig']}' shift expression "
                        f"'{strobe_site['amount_expr']}' lacks a clear "
                        "addr_signal * STRB_WIDTH term. Cannot prove correct "
                        "byte-lane steering for replicated WDATA."
                    )

                violations.append(_make_violation(
                    subtype="WSTRB_DATA_MISALIGNMENT",
                    bug_pattern=bug,
                    explanation=expl,
                    bid=bid,
                    rtl_line=strobe_site["rtl_line"],
                    src=rep_site["source"],
                    dst=rep_site["destination"],
                    strobe_sig=strobe_site["strobe_sig"],
                    factor=rep_site["factor"],
                    shift_expr=strobe_site["amount_expr"],
                    affine_offset=affine.get("offset"),
                ))

    return violations


# ---------------------------------------------------------------------------
# Violation dict builder
# ---------------------------------------------------------------------------

def _make_violation(
    subtype: str,
    bug_pattern: str,
    explanation: str,
    bid: Any,
    rtl_line: Optional[int],
    src: str,
    dst: str,
    strobe_sig: str,
    factor: str,
    shift_expr: str,
    affine_offset: Any,
) -> Dict[str, Any]:
    return {
        "class":              "TRANSPORT_ALIGNMENT_VIOLATION",
        "subtype":            subtype,
        "confidence":         "HIGH",
        "always_block_id":    bid,
        "rtl_line":           rtl_line,
        "source_signal":      src,
        "destination_signal": dst,
        "strobe_signal":      strobe_sig,
        "replication_factor": factor,
        "shift_expression":   shift_expr,
        "affine_offset":      affine_offset,
        "bug_pattern":        bug_pattern,
        "explanation":        explanation,
        "signals_involved":   [dst, strobe_sig, src],
    }


# ---------------------------------------------------------------------------
# Address Monotonicity helpers
# ---------------------------------------------------------------------------

# AXI address signal name detector
_ADDR_NAME_RE = re.compile(
    r'(?:aw|ar|[wr])?addr(?:_|\[|$)',
    re.IGNORECASE,
)

# Operators that unconditionally break monotonicity
_NON_MONOTONE_OP_RE = re.compile(r'%|\^|>>|\btable\s*\[', re.IGNORECASE)


def _is_addr_signal(name: str) -> bool:
    """Return True if name looks like an AXI address bus signal."""
    n = name.lower()
    # Explicit AXI channel names
    if any(x in n for x in ("awaddr", "araddr", "waddr", "raddr")):
        return True
    # Generic 'addr' as a complete word segment (not mid-identifier)
    return bool(re.search(r'(?:^|_)addr(?:_|\[|$)', n))


def _try_parse_int(s: str) -> Optional[int]:
    try:
        return int(s.strip(), 0)
    except (ValueError, TypeError):
        return None


def _classify_addr_transform(rhs: str, src_sig: str) -> Dict[str, Any]:
    """
    Classify *rhs* as an affine transform of *src_sig*: f(x) = A*x + B.

    Returns a dict with keys:
        transform  -- IDENTITY | SHIFT | SHIFT_ADD | SHIFT_MINUS |
                      SCALE | SCALE_ADD | SCALE_MINUS |
                      ADD | SUBTRACT | NEG_SUBTRACT |
                      NON_AFFINE | CONSTANT | COMPLEX
        coeff      -- integer A  (None when unknown)
        offset     -- integer B  (0 when absent)
    """
    s = rhs.strip()
    esc = re.escape(src_sig)

    # ── Non-monotone operators (%  ^  >>  table[) ─────────────────────────
    if _NON_MONOTONE_OP_RE.search(s):
        return {"transform": "NON_AFFINE", "coeff": None, "offset": 0}

    # ── src_sig must appear as a whole token ──────────────────────────────
    if not re.search(rf'\b{esc}\b', s, re.IGNORECASE):
        return {"transform": "CONSTANT", "coeff": 0, "offset": 0}

    # ── IDENTITY: just src_sig, possibly bit-sliced ───────────────────────
    if re.fullmatch(rf'\s*{esc}(\s*\[[\w:+\-*\s]+\])?\s*', s, re.IGNORECASE):
        return {"transform": "IDENTITY", "coeff": 1, "offset": 0}

    # ── NEG_SUBTRACT:  C - src_sig  (A = -1) ─────────────────────────────
    # C may be a SV numeric literal: 42  or  8'hFF  or  16'b0101 etc.
    _sv_const = r"\d+(?:'[bBdDhHoO][0-9a-fA-FxXzZ_]*)?"
    m = re.fullmatch(rf'\s*(?P<c>{_sv_const})\s*-\s*{esc}\s*', s, re.IGNORECASE)
    if m:
        raw_c = m.group("c")
        parsed_c = _try_parse_int(raw_c.split("'")[0]) if "'" in raw_c else _try_parse_int(raw_c)
        return {"transform": "NEG_SUBTRACT", "coeff": -1,
                "offset": parsed_c if parsed_c is not None else 0}

    # ── SHIFT variants:  src_sig << k  ± C ───────────────────────────────
    m = re.search(
        rf'\(?\s*{esc}\s*<<\s*(?P<k>\d+)\s*\)?\s*-\s*(?P<c>\d+)',
        s, re.IGNORECASE,
    )
    if m:
        return {"transform": "SHIFT_MINUS",
                "coeff": 1 << int(m.group("k")),
                "offset": -int(m.group("c"))}

    m = re.search(
        rf'\(?\s*{esc}\s*<<\s*(?P<k>\d+)\s*\)?\s*\+\s*(?P<c>\d+)',
        s, re.IGNORECASE,
    )
    if m:
        return {"transform": "SHIFT_ADD",
                "coeff": 1 << int(m.group("k")),
                "offset": int(m.group("c"))}

    m = re.search(rf'\b{esc}\s*<<\s*(?P<k>\d+)', s, re.IGNORECASE)
    if m:
        remainder = s[:m.start()] + s[m.end():]
        if not re.search(r'[+\-]', remainder):
            return {"transform": "SHIFT",
                    "coeff": 1 << int(m.group("k")),
                    "offset": 0}

    # ── SCALE variants:  src_sig * N  or  N * src_sig  ± C ───────────────
    m = re.search(
        rf'(?:{esc}\s*\*\s*(?P<n1>\d+)|(?P<n2>\d+)\s*\*\s*{esc})',
        s, re.IGNORECASE,
    )
    if m:
        n = int(m.group("n1") or m.group("n2"))
        rest = s[m.end():].strip()
        m2 = re.match(r'-\s*(\d+)\s*$', rest)
        m3 = re.match(r'\+\s*(\d+)\s*$', rest)
        if m2:
            return {"transform": "SCALE_MINUS", "coeff": n,
                    "offset": -int(m2.group(1))}
        if m3:
            return {"transform": "SCALE_ADD", "coeff": n,
                    "offset": int(m3.group(1))}
        return {"transform": "SCALE", "coeff": n, "offset": 0}

    # ── SUBTRACT / ADD:  src_sig ± C ─────────────────────────────────────
    m = re.fullmatch(rf'\s*{esc}\s*-\s*(?P<c>\d+)\s*', s, re.IGNORECASE)
    if m:
        return {"transform": "SUBTRACT", "coeff": 1,
                "offset": -int(m.group("c"))}

    m = re.fullmatch(rf'\s*{esc}\s*\+\s*(?P<c>\d+)\s*', s, re.IGNORECASE)
    if m:
        return {"transform": "ADD", "coeff": 1, "offset": int(m.group("c"))}

    return {"transform": "COMPLEX", "coeff": None, "offset": 0}


def _check_addr_monotonicity(
    transform: str,
    coeff: Optional[int],
    offset: int,
) -> Optional[Dict[str, Any]]:
    """
    Map (transform, A, B) to a violation descriptor, or return None if safe.

    Safe transforms:  IDENTITY, SHIFT, SHIFT_ADD, SCALE, SCALE_ADD, ADD
    (A > 0 and B >= 0 → strictly monotone non-decreasing)
    """
    if transform == "NON_AFFINE":
        return {"subtype": "NON_MONOTONIC_UNKNOWN",
                "risk": "unknown", "coefficient": None, "offset": None}

    if transform == "CONSTANT" or coeff == 0:
        return {"subtype": "ADDRESS_COLLAPSE",
                "risk": "alias", "coefficient": 0, "offset": offset}

    if transform == "NEG_SUBTRACT" or (coeff is not None and coeff < 0):
        return {"subtype": "ORDER_REVERSAL",
                "risk": "reversal", "coefficient": coeff, "offset": offset}

    # A > 0 but B < 0 → small inputs may produce wrap-around / aliasing
    if coeff is not None and coeff > 0 and offset < 0:
        return {"subtype": "MONOTONICITY_EDGE_RISK",
                "risk": "alias", "coefficient": coeff, "offset": offset}

    return None   # safe


# Transforms that are unconditionally safe (A > 0, B >= 0 by construction).
# SCALE / SCALE_ADD / SCALE_MINUS are NOT listed here because their safety
# depends on the coefficient value (coeff=0 → ADDRESS_COLLAPSE).
_ADDR_SAFE_TRANSFORMS = frozenset(
    {"IDENTITY", "SHIFT", "SHIFT_ADD", "ADD", "COMPLEX"}
)


def detect_address_monotonicity_violation(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Scan IR records for address-signal assignments whose transform violates
    or risks violating monotone non-decreasing address ordering.

    Algorithm:
      For each IR record whose LHS base signal is an AXI address signal:
        1. Find the driving source identifier in the RHS.
           (Prefer an address-like identifier; fall back to first identifier.)
        2. Classify the RHS expression relative to that source (affine form
           f(x) = A*x + B plus non-affine operator detection).
        3. Evaluate monotonicity of (A, B):
             A == 0                 → ADDRESS_COLLAPSE
             A <  0                 → ORDER_REVERSAL
             A >  0, B < 0          → MONOTONICITY_EDGE_RISK
             %, ^, >>, table[...]   → NON_MONOTONIC_UNKNOWN
        4. Skip COMPLEX / IDENTITY / obviously-safe forms.

    Returns a list of violation dicts with
    ``"class" == "ADDRESS_MONOTONICITY_VIOLATION"``.
    """
    violations: List[Dict[str, Any]] = []

    for rec in ir_records:
        sig = (rec.get("signal") or "").strip()
        rhs = (rec.get("rhs")    or "").strip()
        if not sig or not rhs:
            continue

        # Strip any bit-select from LHS to get base signal name
        lhs_base = re.sub(r'\[.*', "", sig).strip()
        if not _is_addr_signal(lhs_base):
            continue

        # Find the source identifier driving this address computation.
        # Prefer an address-signal identifier; fall back to first identifier.
        idents = _IDENT_RE.findall(rhs)
        if not idents:
            continue   # pure constant literal — skip

        src_sig = next((i for i in idents if _is_addr_signal(i)), idents[0])

        info      = _classify_addr_transform(rhs, src_sig)
        transform = info["transform"]
        coeff     = info["coeff"]
        offset    = info["offset"]

        if transform in _ADDR_SAFE_TRANSFORMS:
            continue

        viol = _check_addr_monotonicity(transform, coeff, offset)
        if viol is None:
            continue

        violations.append({
            "class":           "ADDRESS_MONOTONICITY_VIOLATION",
            "subtype":         viol["subtype"],
            "always_block_id": rec.get("always_block_id"),
            "rtl_line":        rec.get("line"),
            "lhs":             sig,
            "rhs":             rhs,
            "coefficient":     viol["coefficient"],
            "offset":          viol["offset"],
            "risk":            viol["risk"],
            "impact":          "Write/read ordering may not be preserved",
        })

    return violations


# ---------------------------------------------------------------------------
# CLI entry point (for standalone testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python transport_semantic_analysis.py <ir.json>")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as fh:
        ir = json.load(fh)

    viols = detect_transport_semantic_mismatch(ir)
    if viols:
        print(f"\n[TRANSPORT] {len(viols)} violation(s) detected:\n")
        for v in viols:
            print(f"  [{v['class']}] subtype={v['subtype']}  "
                  f"block={v['always_block_id']}  line={v['rtl_line']}")
            print(f"    signals: {v['signals_involved']}")
            print(f"    bug:     {v['bug_pattern']}")
            print(f"    explain: {v['explanation']}")
            print()
        print(json.dumps(viols, indent=2))
    else:
        print("[TRANSPORT] No transport semantic mismatches detected.")

    addr_viols = detect_address_monotonicity_violation(ir)
    if addr_viols:
        print(f"\n[ADDR_MONO] {len(addr_viols)} violation(s) detected:\n")
        for v in addr_viols:
            print(f"  [{v['class']}] subtype={v['subtype']}  "
                  f"block={v['always_block_id']}  line={v['rtl_line']}")
            print(f"    lhs={v['lhs']}  rhs={v['rhs']}")
            print(f"    coeff={v['coefficient']}  offset={v['offset']}  risk={v['risk']}")
            print()
    else:
        print("[ADDR_MONO] No address monotonicity violations detected.")
