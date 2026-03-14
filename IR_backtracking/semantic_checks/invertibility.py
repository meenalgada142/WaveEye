#!/usr/bin/env python3
"""
invertibility.py
=================
IR-level checker for non-invertible datapath transport transformations.

A transport transformation T is invertible iff there exists a deterministic
inverse  T^{-1}  such that  T^{-1}(T(x)) = x.

This checker statically identifies four failure modes:

  DUPLICATION     -- input bits fan-out to multiple output positions.
                     e.g. {N{s_data}}  or  {s_data[7:0], s_data[7:0]}
                     Cannot reconstruct which copy was the original.

  COLLAPSE        -- irreversible bitwise merge of two signals.
                     e.g. s_data ^ mask  or  s_data & write_mask inside concat.
                     Original bit values are destroyed.

  INFORMATION_LOSS -- input bits have no corresponding output position.
                     e.g. s_data << 8  (upper k bits are shifted out).
                     Reconstruction is impossible.

  SYNTHETIC_DATA  -- output bits carry constants with no input dependency.
                     e.g. {16'b0, s_data}  (the upper 16 bits are fabricated).
                     Output has more information than the input.

Runs purely on IR records — no waveform required.
Suppression: add  // waveeye: intentional_encoding  comment in RTL
to silence false positives for deliberate encoding transforms.

Public API:
    violations = detect_invertibility_violation(ir_records)

Each violation dict:
    {
        "class":           "INVERTIBILITY_VIOLATION",
        "subtype":         "NON_INVERTIBLE_DUPLICATION" |
                           "NON_INVERTIBLE_COLLAPSE"    |
                           "INFORMATION_LOSS"           |
                           "SYNTHETIC_DATA",
        "always_block_id": <int | None>,
        "rtl_line":        <int | None>,
        "lhs":             <str>,   # output signal
        "rhs":             <str>,   # full RHS expression
        "details":         <str>,   # human-readable explanation
        "impact":          "Transformation cannot be reversed; not a legal transport",
    }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Replication: {N{X}} or {(N){X}} — must match the ENTIRE string
_INV_REP_RE = re.compile(
    r'^\s*\{\s*\(?\s*(\d+)\s*\)?\s*\{([^{}]+)\}\s*\}\s*$',
    re.IGNORECASE,
)

# Simple identifier (possibly with a single static slice): sig  or  sig[hi:lo]
_INV_SIG_RE = re.compile(
    r'^\s*([A-Za-z_]\w*)\s*(?:\[(\d+)\s*:\s*(\d+)\])?\s*$'
)

# SV numeric literal:  42  8'hFF  16'b0101_1100  etc.
_INV_CONST_RE = re.compile(
    r"^\s*\d+(?:'[bBdDhHoO][0-9a-fA-FxXzZ_]*)?\s*$",
    re.IGNORECASE,
)

# Left-shift: sig << k  (whole expression)
_INV_LSHIFT_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_.$\[\]]*)\s*<<\s*(\d+)\s*$',
    re.IGNORECASE,
)

# Bitwise collapse operators: ^  &(single)  |(single)
# Excludes logical && and || via negative lookahead/lookbehind.
_COLLAPSE_OP_RE = re.compile(
    r'\^|(?<![&])&(?![&])|(?<![|])\|(?![|])',
)

# All [hi:lo] slices anywhere in an expression — used to build width table
_SLICE_SCAN_RE = re.compile(r'([A-Za-z_]\w*)\s*\[(\d+)\s*:\s*(\d+)\]')

# Suppression annotation: // waveeye: intentional_encoding
_SUPPRESSION_RE = re.compile(r'waveeye\s*:\s*intentional_encoding', re.IGNORECASE)

# Minimum inferred width for a signal before we apply the check.
# Skips 1-4 bit control/flag signals.
_MIN_WIDTH = 4


# ---------------------------------------------------------------------------
# Width table
# ---------------------------------------------------------------------------

def _inv_build_width_table(ir_records: List[Dict[str, Any]]) -> Dict[str, int]:
    """Infer signal widths from [hi:lo] slices in all LHS and RHS fields."""
    table: Dict[str, int] = {}
    for rec in ir_records:
        for text in (rec.get("signal") or "", rec.get("rhs") or ""):
            for m in _SLICE_SCAN_RE.finditer(text):
                name = m.group(1)
                w = int(m.group(2)) + 1   # hi + 1
                if w > table.get(name, 0):
                    table[name] = w
    return table


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------

def _has_suppression(rec: Dict[str, Any]) -> bool:
    """Return True if any field of rec carries the suppression annotation."""
    for field in ("source", "guard", "rhs"):
        if _SUPPRESSION_RE.search(rec.get(field) or ""):
            return True
    return False


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------

def _is_candidate(
    lhs_base: str,
    rhs: str,
    width_table: Dict[str, int],
) -> bool:
    """
    Return True if this assignment is worth checking for invertibility.

    We include:
    - Signals with inferred width >= _MIN_WIDTH (wide bus)
    - Any concat with >= 2 elements (clearly a bus-packing operation)
    - Any top-level replication {N{X}}
    """
    if width_table.get(lhs_base, 0) >= _MIN_WIDTH:
        return True
    s = rhs.strip()
    if s.startswith("{") and s.endswith("}"):
        elems = _split_concat(s)
        if elems and len(elems) >= 2:
            return True
        if _INV_REP_RE.match(s):
            return True
    return False


def _rhs_is_structural(rhs: str) -> bool:
    """
    Return True if rhs is a structural (non-arithmetic) expression.

    Structural means: concat, replication, simple signal, slice, or shift.
    Excludes expressions with + - * / (arithmetic intent).
    """
    s = rhs.strip()
    if s.startswith("{") and s.endswith("}"):
        return True
    if _INV_SIG_RE.match(s):
        return True
    if _INV_LSHIFT_RE.match(s):
        return True
    # Bitwise-only (no arithmetic) — collapse candidates
    if _COLLAPSE_OP_RE.search(s) and not re.search(r'(?<![<>])[+\-\*](?![>])', s):
        return True
    return False


# ---------------------------------------------------------------------------
# Concat splitter: {A, B, C} → ["A", "B", "C"]
# ---------------------------------------------------------------------------

def _split_concat(s: str) -> Optional[List[str]]:
    """
    Split a top-level concatenation {…} into its comma-separated elements.
    Respects nested braces so that {N{X}, Y} → ["{N{X}}", "Y"] etc.
    Returns None if s is not a brace-delimited expression.
    """
    s = s.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    inner = s[1:-1]
    elements: List[str] = []
    depth = 0
    buf: List[str] = []
    for ch in inner:
        if ch == "{":
            depth += 1
            buf.append(ch)
        elif ch == "}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            elements.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        elements.append("".join(buf).strip())
    return elements or None


# ---------------------------------------------------------------------------
# Element classification helpers
# ---------------------------------------------------------------------------

def _elem_is_const(s: str) -> bool:
    """
    Return True if this concat element is a constant (literal or constant-only
    replication like {4{1'b0}}).
    """
    s = s.strip()
    if _INV_CONST_RE.match(s):
        return True
    # Replicated constant: element is  N{X}  (outer braces stripped by _split_concat)
    candidate = ("{" + s + "}") if not s.startswith("{") else s
    m = _INV_REP_RE.match(candidate)
    if m and _INV_CONST_RE.match(m.group(2).strip()):
        return True
    return False


def _elem_base_signal(s: str) -> Optional[str]:
    """
    Return the base signal name from a concat element (strip slices/subscripts).
    Returns None for constant elements.
    """
    s = s.strip()
    if _elem_is_const(s):
        return None
    base = re.sub(r'\[.*', '', s).strip()
    return base or None


def _elem_has_bitwise_op(s: str) -> bool:
    """Return True if element contains a bitwise collapse operator."""
    return bool(_COLLAPSE_OP_RE.search(s))


def _elem_is_replication(s: str) -> Tuple[bool, int, str]:
    """
    If element is a replication N{X} (with outer braces stripped), return
    (True, N, body).  Otherwise return (False, 0, "").
    """
    s = s.strip()
    candidate = ("{" + s + "}") if not s.startswith("{") else s
    m = _INV_REP_RE.match(candidate)
    if m:
        return True, int(m.group(1)), m.group(2).strip()
    return False, 0, ""


# ---------------------------------------------------------------------------
# Violation factory
# ---------------------------------------------------------------------------

def _make_inv_violation(
    vtype: str,
    lhs: str,
    rhs: str,
    details: str,
    bid: Any,
    lineno: Optional[int],
) -> Dict[str, Any]:
    return {
        "class":           "INVERTIBILITY_VIOLATION",
        "subtype":         vtype,
        "always_block_id": bid,
        "rtl_line":        lineno,
        "lhs":             lhs,
        "rhs":             rhs,
        "details":         details,
        "impact":          "Transformation cannot be reversed; not a legal transport",
    }


# ---------------------------------------------------------------------------
# Individual violation checkers
# ---------------------------------------------------------------------------

def _check_collapse(
    rhs: str,
    lhs: str,
    bid: Any,
    lineno: Optional[int],
) -> Optional[Dict[str, Any]]:
    """
    NON_INVERTIBLE_COLLAPSE: bitwise ^, &, | applied to data signals.

    Fires on:
      - Top-level bitwise op: data ^ mask
      - Bitwise op inside a concat element: {data[31:16], data[15:0] ^ mask}
    """
    _OP_NAME = {"^": "XOR", "&": "AND (bitwise)", "|": "OR (bitwise)"}

    s = rhs.strip()

    # ── Top-level expression ──────────────────────────────────────────────
    # Replication {N{X}} never uses ^/&/| so exclude it first
    if not _INV_REP_RE.match(s) and _COLLAPSE_OP_RE.search(s):
        # Only fire if the rhs is NOT purely a concat (inner elements checked
        # separately below); this catches standalone  data ^ mask  forms.
        if not (s.startswith("{") and s.endswith("}")):
            m = _COLLAPSE_OP_RE.search(s)
            op = m.group(0) if m else "?"
            return _make_inv_violation(
                "NON_INVERTIBLE_COLLAPSE",
                lhs, rhs,
                f"Bitwise {_OP_NAME.get(op, op)} applied to '{lhs}': original "
                "bit values are destroyed. No inverse mapping exists.",
                bid, lineno,
            )

    # ── Inside concat elements ────────────────────────────────────────────
    elements = _split_concat(s)
    if elements:
        for elem in elements:
            if not _elem_is_const(elem) and _elem_has_bitwise_op(elem):
                m = _COLLAPSE_OP_RE.search(elem)
                op = m.group(0) if m else "?"
                return _make_inv_violation(
                    "NON_INVERTIBLE_COLLAPSE",
                    lhs, rhs,
                    f"Concat element '{elem[:80]}' contains bitwise "
                    f"{_OP_NAME.get(op, op)}: bit values are destroyed; "
                    "no inverse mapping exists.",
                    bid, lineno,
                )

    return None


def _check_replication_duplication(
    rhs: str,
    lhs: str,
    bid: Any,
    lineno: Optional[int],
) -> Optional[Dict[str, Any]]:
    """
    NON_INVERTIBLE_DUPLICATION via {N{X}} with N > 1.

    Also checks inside concat: {Y, {N{X}}} — replication of a non-constant
    element inside a larger packing concat.
    """
    s = rhs.strip()

    # Case A: entire rhs is a replication
    m = _INV_REP_RE.match(s)
    if m:
        n = int(m.group(1))
        body = m.group(2).strip()
        if n > 1 and not _INV_CONST_RE.match(body):
            return _make_inv_violation(
                "NON_INVERTIBLE_DUPLICATION",
                lhs, rhs,
                f"'{body}' is replicated {n}× (each input bit appears at {n} "
                "output positions). Cannot determine which replica was the "
                "original; inverse is undefined.",
                bid, lineno,
            )
        return None   # N==1 or constant body — safe

    # Case B: replication inside a concat
    elements = _split_concat(s)
    if elements:
        for elem in elements:
            is_rep, n, body = _elem_is_replication(elem)
            if is_rep and n > 1 and not _INV_CONST_RE.match(body):
                return _make_inv_violation(
                    "NON_INVERTIBLE_DUPLICATION",
                    lhs, rhs,
                    f"Concat element '{elem}' replicates '{body}' {n}× inside "
                    "the packed output. Inverse mapping is undefined.",
                    bid, lineno,
                )

    return None


def _check_concat_duplication(
    rhs: str,
    lhs: str,
    bid: Any,
    lineno: Optional[int],
) -> Optional[Dict[str, Any]]:
    """
    NON_INVERTIBLE_DUPLICATION via {A, A} — the EXACT SAME bit range of a
    signal appears in multiple concat positions.

    e.g. {data[7:0], data[7:0]}   → DUPLICATION (same [7:0] twice)
    but  {data[31:16], data[15:0]} → SAFE        (non-overlapping split)
    """
    elements = _split_concat(rhs.strip())
    if not elements or len(elements) < 2:
        return None

    # Build keys: (base_signal, hi, lo) for sliced elements;
    #             (base_signal, None, None) for unsliced identifiers.
    # Only exact key equality triggers a duplication report.
    _SLICED_RE = re.compile(r'^([A-Za-z_]\w*)\s*\[(\d+)\s*:\s*(\d+)\]$')

    seen: Dict[Tuple, List[str]] = {}
    for elem in elements:
        if _elem_is_const(elem):
            continue
        s = elem.strip()
        m = _SLICED_RE.match(s)
        if m:
            key: Tuple = (m.group(1), int(m.group(2)), int(m.group(3)))
        else:
            base = re.sub(r'\[.*', '', s).strip()
            if not base:
                continue
            key = (base, None, None)
        seen.setdefault(key, []).append(elem)

    duplicated = {k: occ for k, occ in seen.items() if len(occ) > 1}
    if not duplicated:
        return None

    k, occurrences = next(iter(duplicated.items()))
    sig_desc = k[0] if k[1] is None else f"{k[0]}[{k[1]}:{k[2]}]"
    return _make_inv_violation(
        "NON_INVERTIBLE_DUPLICATION",
        lhs, rhs,
        f"Bit range '{sig_desc}' appears {len(occurrences)} times in concat "
        f"{occurrences}. Cannot reconstruct which copy was the original; "
        "inverse mapping is undefined.",
        bid, lineno,
    )


def _check_synthetic(
    rhs: str,
    lhs: str,
    bid: Any,
    lineno: Optional[int],
) -> Optional[Dict[str, Any]]:
    """
    SYNTHETIC_DATA: constant literals injected as concat elements.
    e.g.  {16'b0, s_data}  or  {s_data[7:0], 8'hFF}

    Only fires for mixed signal+constant concat; pure constant RHS is ignored.
    """
    elements = _split_concat(rhs.strip())
    if not elements or len(elements) < 2:
        return None

    const_elems = [e for e in elements if _elem_is_const(e)]
    signal_elems = [e for e in elements if not _elem_is_const(e)]

    # Must have at least one signal element (otherwise it's a pure constant init)
    if not const_elems or not signal_elems:
        return None

    examples = const_elems[:3]
    return _make_inv_violation(
        "SYNTHETIC_DATA",
        lhs, rhs,
        f"Concat injects constant literal(s) {examples} into output fields "
        "that carry no input signal. Those output bits are fabricated — "
        "they have no corresponding input to invert back to.",
        bid, lineno,
    )


def _check_info_loss(
    rhs: str,
    lhs: str,
    bid: Any,
    lineno: Optional[int],
    width_table: Dict[str, int],
) -> Optional[Dict[str, Any]]:
    """
    INFORMATION_LOSS via left-shift: sig << k drops the upper k bits of sig.
    """
    m = _INV_LSHIFT_RE.match(rhs.strip())
    if not m:
        return None

    src_sig = m.group(1).strip()
    k = int(m.group(2))
    if k == 0:
        return None   # zero shift is safe (identity)

    src_base = re.sub(r'\[.*', '', src_sig).strip()
    src_w = width_table.get(src_base)

    detail = (
        f"Left-shift by {k}: the upper {k} bit(s) of '{src_sig}' "
        "are shifted out of the output word."
    )
    if src_w:
        detail += (
            f" Source inferred as {src_w}-bit; "
            f"bits [{src_w - 1}:{src_w - k}] are lost."
        )
    detail += " Reconstruction is impossible without the dropped bits."

    return _make_inv_violation(
        "INFORMATION_LOSS",
        lhs, rhs,
        detail,
        bid, lineno,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_invertibility_violation(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Scan IR records for non-invertible datapath transport transformations.

    Algorithm (per IR record):
      1. Skip suppressed records (// waveeye: intentional_encoding).
      2. Skip narrow or non-structural signals.
      3. Check, in priority order:
           A. NON_INVERTIBLE_COLLAPSE   -- bitwise ^/&/| on data
           B. NON_INVERTIBLE_DUPLICATION -- {N{X}} or {A, A}
           C. SYNTHETIC_DATA            -- constants in concat
           D. INFORMATION_LOSS          -- left-shift drops bits
      4. Emit at most one violation per record (highest priority wins).

    Returns a list of violation dicts with
    ``"class" == "INVERTIBILITY_VIOLATION"``.
    """
    violations: List[Dict[str, Any]] = []
    width_table = _inv_build_width_table(ir_records)

    for rec in ir_records:
        sig = (rec.get("signal") or "").strip()
        rhs = (rec.get("rhs")    or "").strip()
        if not sig or not rhs:
            continue

        if _has_suppression(rec):
            continue

        lhs_base = re.sub(r'\[.*', '', sig).strip()

        # Gate: must be a candidate (wide bus or clearly structural/packed)
        if not _is_candidate(lhs_base, rhs, width_table):
            continue

        # Gate: must look like a transport (structural) expression
        if not _rhs_is_structural(rhs):
            continue

        bid    = rec.get("always_block_id")
        lineno = rec.get("line")

        viol = (
            _check_collapse(rhs, sig, bid, lineno)
            or _check_replication_duplication(rhs, sig, bid, lineno)
            or _check_concat_duplication(rhs, sig, bid, lineno)
            or _check_synthetic(rhs, sig, bid, lineno)
            or _check_info_loss(rhs, sig, bid, lineno, width_table)
        )
        if viol:
            violations.append(viol)

    return violations


# ---------------------------------------------------------------------------
# CLI entry point (for standalone testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python invertibility.py <ir.json>")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as fh:
        ir = json.load(fh)

    viols = detect_invertibility_violation(ir)
    if viols:
        print(f"\n[INVERTIBILITY] {len(viols)} violation(s):\n")
        for v in viols:
            print(f"  [{v['subtype']}]  block={v['always_block_id']}  "
                  f"line={v['rtl_line']}")
            print(f"    lhs={v['lhs']}")
            print(f"    rhs={v['rhs']}")
            print(f"    {v['details']}")
            print()
        print(json.dumps(viols, indent=2))
    else:
        print("[INVERTIBILITY] No invertibility violations detected.")
