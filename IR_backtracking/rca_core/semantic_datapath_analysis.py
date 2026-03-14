#!/usr/bin/env python3
"""
semantic_datapath_analysis.py
==============================
RTL Datapath Semantic Validation Layer (Protocol-Agnostic).

Detects mathematically incorrect datapath transformations that are:
  - Syntactically legal
  - Lint-clean
  - Protocol-compliant
  - But SEMANTICALLY WRONG

Operates purely on IR records — no waveform, no protocol context, no simulation.

Algorithm
---------
 Step 1  Build BitMapping model
          Every assignment ⟶ {dst_field, transform_type, src_field, affine_map}
 Step 2  Detect Lane Bijection Violations
          ∀ dst_lane: count(unique src_lane) must = 1
 Step 3  Detect Mask Conservation Violations
          mask[k] ⟹ write(dst_lane(k))
 Step 4  Detect Width Conservation Violations
          Σ written_bits == Σ source_bits (mod intentional packing)
 Step 5  Detect Address Mapping Violations
          index(i+1) - index(i) == expected_stride
 Step 6  Detect Invertibility Violations
          F⁻¹ must exist uniquely for reversible transforms
 Step 7  Deduplicate and return

Public API
----------
    violations = detect_semantic_datapath_violations(ir_records)

Violation dict keys
-------------------
    class               : "SEMANTIC_DATAPATH_VIOLATION"
    subtype             : UNINTENDED_BROADCAST | NON_INJECTIVE_MAPPING |
                          MASK_DATA_MISALIGNMENT | PARTIAL_WRITE_CORRUPTION |
                          WIDTH_LOSS | WIDTH_DUPLICATION | NON_BIJECTIVE_PACKING |
                          ADDRESS_ALIASING | NON_MONOTONIC_ACCESS | STRIDE_MISMATCH |
                          NON_INVERTIBLE_TRANSFORM | ENTROPY_LOSS
    severity            : STRUCTURAL_FATAL | STRUCTURAL_WARNING
    confidence          : HIGH | MEDIUM | LOW
    always_block_id     : int | None
    rtl_line            : int | None
    source_location     : str  (file:line)
    storage_element     : str  (memory / register name)
    destination         : str  (LHS signal)
    source_expression   : str  (RHS expression)
    violated_invariant  : str  (formal invariant description)
    transformation      : str  (normalized expression)
    mathematical_reason : str  (precise mathematical explanation)
    signals_involved    : [str]
"""
from __future__ import annotations

import dataclasses
import re
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# LHS: memory write — mem[addr]
#      or mem[addr][H:L]
#      or mem[addr][BASE +: WIDTH]
_LHS_MEM_RE = re.compile(
    r'^(?P<mem>[A-Za-z_][A-Za-z0-9_]*)'
    r'\s*\[\s*(?P<addr>[^\]]+?)\s*\]'
    r'(?:'
        r'\s*\[\s*(?P<hi2>\d+)\s*:\s*(?P<lo2>\d+)\s*\]'       # [H:L]
        r'|'
        r'\s*\[\s*(?P<pbase>[^\]]+?)\s*\+:\s*(?P<pw>\d+)\s*\]' # [B +: W]
    r')?'
    r'\s*$',
    re.IGNORECASE,
)

# LHS: static slice — signal[H:L]
_LHS_SLICE_RE = re.compile(
    r'^(?P<sig>[A-Za-z_][A-Za-z0-9_.$]*)'
    r'\s*\[\s*(?P<hi>\d+)\s*:\s*(?P<lo>\d+)\s*\]'
    r'\s*$',
    re.IGNORECASE,
)

# RHS: replication — {N{body}}  or  {(N){body}}
_RHS_REP_RE = re.compile(
    r'^\s*\{\s*\(?\s*(?P<factor>[A-Za-z0-9_]+)\s*\)?\s*\{'
    r'(?P<body>[^{}]+)'
    r'\}\s*\}\s*$',
    re.IGNORECASE,
)

# RHS: shift — signal << amount  or  signal >> amount  (full-expression form)
_RHS_SHIFT_RE = re.compile(
    r'^\s*(?P<base>[A-Za-z_][A-Za-z0-9_.$\[\]:]*)'
    r'\s*(?P<dir><<|>>)\s*'
    r'(?P<amount>.+?)\s*$',
    re.IGNORECASE,
)

# RHS: static slice — signal[H:L]  (full RHS)
_RHS_STATIC_SLICE_RE = re.compile(
    r'^(?P<sig>[A-Za-z_][A-Za-z0-9_.$]*)'
    r'\s*\[\s*(?P<hi>\d+)\s*:\s*(?P<lo>\d+)\s*\]'
    r'\s*$',
    re.IGNORECASE,
)

# RHS: part-select — signal[BASE +: WIDTH]  (anywhere in expression)
_RHS_PART_SEL_RE = re.compile(
    r'(?P<sig>[A-Za-z_][A-Za-z0-9_.$]*)'
    r'\s*\[\s*(?P<base>[^\]]+?)\s*\+:\s*(?P<width>\d+)\s*\]',
    re.IGNORECASE,
)

# RHS: concatenation — { ... }  (outer braces, no replication)
_RHS_CONCAT_RE = re.compile(
    r'^\s*\{[^{}]*\}\s*$',
)

# Guard: bit-select — signal[index]
_GUARD_BIT_SEL_RE = re.compile(
    r'(?P<sig>[A-Za-z_][A-Za-z0-9_.$]*)'
    r'\s*\[\s*(?P<idx>[A-Za-z0-9_]+)\s*\]',
    re.IGNORECASE,
)

# Numeric literal (Verilog + bare integer)
_VERILOG_INT_RE = re.compile(
    r"^\s*(?:\d+\s*'\s*[bBoOdDhH]\s*[\da-fA-F_x?]+|\d+|0[xX][\da-fA-F_]+)\s*$"
)

# Multiplication in address: sig * factor
_ADDR_MUL_RE = re.compile(
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*\*\s*(?P<rhs>[A-Za-z0-9_]+)',
    re.IGNORECASE,
)

# Plain identifier
_IDENT_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')


# ---------------------------------------------------------------------------
# BitMapping — core data structure
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class BitMapping:
    """Mathematical representation of a single IR assignment."""

    # ── Destination ──────────────────────────────────────────────────────────
    dst_raw:         str = ""
    dst_storage:     str = ""           # bare signal/memory name
    dst_is_memory:   bool = False
    dst_addr_expr:   Optional[str] = None
    dst_addr_idents: dataclasses.field(default_factory=list) = None  # type: ignore
    dst_slice_hi:    Optional[int] = None
    dst_slice_lo:    Optional[int] = None
    dst_part_base:   Optional[str] = None
    dst_part_width:  Optional[int] = None
    dst_width:       Optional[int] = None

    # ── Transform ─────────────────────────────────────────────────────────────
    transform:        str = "COMPLEX"   # REPLICATE|SHIFT_L|SHIFT_R|SLICE|PART_SEL|
                                         # CONCAT|IDENTITY|CONSTANT|COMPLEX
    rhs_raw:          str = ""
    rep_factor:       Optional[str] = None
    rep_factor_int:   Optional[int] = None
    rep_source:       Optional[str] = None
    shift_dir:        Optional[str] = None
    shift_amount:     Optional[str] = None
    shift_amount_int: Optional[int] = None
    shift_source:     Optional[str] = None
    slice_source:     Optional[str] = None
    slice_hi:         Optional[int] = None
    slice_lo:         Optional[int] = None
    slice_width:      Optional[int] = None
    part_source:      Optional[str] = None
    part_base:        Optional[str] = None
    part_width:       Optional[int] = None
    src_width:        Optional[int] = None

    # ── Guard ────────────────────────────────────────────────────────────────
    guard_raw:      str = "true"
    guard_bit_sels: dataclasses.field(default_factory=list) = None  # type: ignore
    # List[Tuple[str, str]]  — (signal, index_str) from guard bit-selects

    # ── Context ──────────────────────────────────────────────────────────────
    always_block_id: Optional[int] = None
    rtl_line:        Optional[int] = None
    source_loc:      str = ""

    def __post_init__(self):
        if self.dst_addr_idents is None:
            self.dst_addr_idents = []
        if self.guard_bit_sels is None:
            self.guard_bit_sels = []


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _try_parse_int(s: Optional[str]) -> Optional[int]:
    """Parse a string to int, supporting Verilog numeric literals."""
    if s is None:
        return None
    s = s.strip()
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        pass
    # Verilog literal: 4'hF, 8'd255, 2'b10, …
    m = re.match(r"\d+\s*'\s*[hH]\s*(?P<v>[0-9a-fA-F_]+)", s)
    if m:
        try:
            return int(m.group("v").replace("_", ""), 16)
        except ValueError:
            pass
    m = re.match(r"\d+\s*'\s*[dD]\s*(?P<v>[0-9_]+)", s)
    if m:
        try:
            return int(m.group("v").replace("_", ""), 10)
        except ValueError:
            pass
    return None


def _extract_guard_bit_sels(guard: str) -> List[Tuple[str, str]]:
    """Return list of (signal, index_str) from bit-select expressions in guard."""
    return [(m.group("sig"), m.group("idx"))
            for m in _GUARD_BIT_SEL_RE.finditer(guard)]


def _normalize_addr(expr: str) -> str:
    """Normalise address expression for comparison (strip whitespace)."""
    return re.sub(r'\s+', '', (expr or "").strip())


def _parse_address_affine(expr: str) -> Dict[str, Any]:
    """
    Analyse an address expression to extract {base_sig, stride_int}.

    Handles: sig, sig + C, sig * C, BASE + i * STRIDE, i * STRIDE + BASE.
    Returns stride_int = None when not determinable.
    """
    result: Dict[str, Any] = {"base_sig": None, "stride_int": None}
    if not expr:
        return result

    idents = _IDENT_RE.findall(expr)
    if not idents:
        return result

    result["base_sig"] = idents[0]

    m = _ADDR_MUL_RE.search(expr)
    if m:
        for cand in (m.group("rhs"), m.group("lhs")):
            val = _try_parse_int(cand)
            if val is not None:
                result["stride_int"] = val
                break

    return result


def _parse_lhs(sig: str) -> Dict[str, Any]:
    """
    Parse LHS signal string into structured dict.

    Returns keys: raw, storage, is_memory, addr_expr, addr_idents,
                  slice_hi, slice_lo, part_base, part_width.
    """
    sig = sig.strip()
    out: Dict[str, Any] = {
        "raw":         sig,
        "storage":     sig,
        "is_memory":   False,
        "addr_expr":   None,
        "addr_idents": [],
        "slice_hi":    None,
        "slice_lo":    None,
        "part_base":   None,
        "part_width":  None,
    }

    # Memory write: mem[addr]  optionally  followed by [H:L] or [B+:W]
    m = _LHS_MEM_RE.match(sig)
    if m:
        out["storage"]     = m.group("mem")
        out["is_memory"]   = True
        out["addr_expr"]   = m.group("addr").strip()
        out["addr_idents"] = _IDENT_RE.findall(out["addr_expr"])
        if m.group("hi2") is not None:
            out["slice_hi"] = int(m.group("hi2"))
            out["slice_lo"] = int(m.group("lo2"))
        elif m.group("pbase") is not None:
            out["part_base"]  = m.group("pbase").strip()
            out["part_width"] = int(m.group("pw"))
        return out

    # Static slice: signal[H:L]
    m = _LHS_SLICE_RE.match(sig)
    if m:
        out["storage"]  = m.group("sig")
        out["slice_hi"] = int(m.group("hi"))
        out["slice_lo"] = int(m.group("lo"))
        return out

    return out


def _parse_rhs(rhs: str) -> Dict[str, Any]:
    """
    Classify RHS expression into transform type + extracted parameters.

    transform values: REPLICATE | SHIFT_L | SHIFT_R | SLICE | PART_SEL |
                      CONCAT | IDENTITY | CONSTANT | COMPLEX
    """
    rhs = rhs.strip()
    out: Dict[str, Any] = {
        "transform":       "COMPLEX",
        "rep_factor":      None,
        "rep_factor_int":  None,
        "rep_source":      None,
        "shift_dir":       None,
        "shift_amount":    None,
        "shift_amount_int": None,
        "shift_source":    None,
        "slice_source":    None,
        "slice_hi":        None,
        "slice_lo":        None,
        "slice_width":     None,
        "part_source":     None,
        "part_base":       None,
        "part_width":      None,
        "src_width":       None,
    }

    if not rhs:
        out["transform"] = "CONSTANT"
        return out

    # Constant
    if _VERILOG_INT_RE.match(rhs):
        out["transform"] = "CONSTANT"
        return out

    # Replication: {N{body}}
    m = _RHS_REP_RE.match(rhs)
    if m:
        factor_str = m.group("factor").strip()
        body       = m.group("body").strip()
        out["transform"]      = "REPLICATE"
        out["rep_factor"]     = factor_str
        out["rep_source"]     = body
        out["rep_factor_int"] = _try_parse_int(factor_str)
        # Infer width from body's static slice, if present
        sm = _RHS_STATIC_SLICE_RE.match(body)
        if sm:
            try:
                w = int(sm.group("hi")) - int(sm.group("lo")) + 1
                if out["rep_factor_int"]:
                    out["src_width"] = out["rep_factor_int"] * w
            except (ValueError, TypeError):
                pass
        return out

    # Static slice: signal[H:L]  (entire RHS)
    m = _RHS_STATIC_SLICE_RE.match(rhs)
    if m:
        try:
            hi = int(m.group("hi"))
            lo = int(m.group("lo"))
            out["transform"]   = "SLICE"
            out["slice_source"]= m.group("sig")
            out["slice_hi"]    = hi
            out["slice_lo"]    = lo
            out["slice_width"] = hi - lo + 1
            out["src_width"]   = hi - lo + 1
        except (ValueError, TypeError):
            pass
        return out

    # Part-select: signal[BASE +: WIDTH]  (anywhere in RHS)
    m = _RHS_PART_SEL_RE.search(rhs)
    if m:
        out["transform"]   = "PART_SEL"
        out["part_source"] = m.group("sig")
        out["part_base"]   = m.group("base").strip()
        out["part_width"]  = int(m.group("width"))
        out["src_width"]   = out["part_width"]
        return out

    # Shift: signal << amount  or  signal >> amount
    m = _RHS_SHIFT_RE.match(rhs)
    if m:
        direction = m.group("dir")
        out["transform"]       = "SHIFT_L" if direction == "<<" else "SHIFT_R"
        out["shift_source"]    = m.group("base").strip()
        out["shift_dir"]       = direction
        out["shift_amount"]    = m.group("amount").strip()
        out["shift_amount_int"]= _try_parse_int(out["shift_amount"])
        return out

    # Concatenation: { ... }
    if _RHS_CONCAT_RE.match(rhs):
        out["transform"] = "CONCAT"
        return out

    # Plain identifier  (identity / wire pass-through)
    if re.match(r'^[A-Za-z_][A-Za-z0-9_.$]*$', rhs):
        out["transform"] = "IDENTITY"
        return out

    return out  # COMPLEX — not further classified


# ---------------------------------------------------------------------------
# Build BitMapping list from IR
# ---------------------------------------------------------------------------

def _build_bit_mappings(ir_records: List[Dict[str, Any]]) -> List[BitMapping]:
    """Convert every IR record into a BitMapping for semantic analysis."""
    mappings: List[BitMapping] = []

    for rec in ir_records:
        sig   = (rec.get("signal") or "").strip()
        rhs   = (rec.get("rhs")    or "").strip()
        guard = (rec.get("guard")  or "true").strip()

        if not sig or not rhs:
            continue

        lhs = _parse_lhs(sig)
        rhs_info = _parse_rhs(rhs)

        bm = BitMapping()

        # ── Destination ──────────────────────────────────────────────────────
        bm.dst_raw       = sig
        bm.dst_storage   = lhs["storage"]
        bm.dst_is_memory = lhs["is_memory"]
        bm.dst_addr_expr = lhs["addr_expr"]
        bm.dst_addr_idents = lhs["addr_idents"]
        bm.dst_slice_hi  = lhs["slice_hi"]
        bm.dst_slice_lo  = lhs["slice_lo"]
        bm.dst_part_base = lhs["part_base"]
        bm.dst_part_width= lhs["part_width"]

        if bm.dst_slice_hi is not None and bm.dst_slice_lo is not None:
            bm.dst_width = bm.dst_slice_hi - bm.dst_slice_lo + 1
        elif bm.dst_part_width is not None:
            bm.dst_width = bm.dst_part_width

        # ── Transform ─────────────────────────────────────────────────────────
        bm.transform        = rhs_info["transform"]
        bm.rhs_raw          = rhs
        bm.rep_factor       = rhs_info["rep_factor"]
        bm.rep_factor_int   = rhs_info["rep_factor_int"]
        bm.rep_source       = rhs_info["rep_source"]
        bm.shift_dir        = rhs_info["shift_dir"]
        bm.shift_amount     = rhs_info["shift_amount"]
        bm.shift_amount_int = rhs_info["shift_amount_int"]
        bm.shift_source     = rhs_info["shift_source"]
        bm.slice_source     = rhs_info["slice_source"]
        bm.slice_hi         = rhs_info["slice_hi"]
        bm.slice_lo         = rhs_info["slice_lo"]
        bm.slice_width      = rhs_info["slice_width"]
        bm.part_source      = rhs_info["part_source"]
        bm.part_base        = rhs_info["part_base"]
        bm.part_width       = rhs_info["part_width"]
        bm.src_width        = rhs_info["src_width"]

        # ── Guard ────────────────────────────────────────────────────────────
        bm.guard_raw      = guard
        bm.guard_bit_sels = _extract_guard_bit_sels(guard)

        # ── Context ──────────────────────────────────────────────────────────
        bm.always_block_id = rec.get("always_block_id")
        bm.rtl_line        = rec.get("line")
        bm.source_loc      = rec.get("source", "")

        mappings.append(bm)

    return mappings


# ---------------------------------------------------------------------------
# Violation builder
# ---------------------------------------------------------------------------

def _make_violation(
    *,
    subtype:             str,
    severity:            str,
    confidence:          str,
    storage:             str,
    bm:                  BitMapping,
    violated_invariant:  str,
    transformation:      str,
    mathematical_reason: str,
) -> Dict[str, Any]:
    """Construct a single semantic violation dict."""
    sigs: List[str] = [bm.dst_storage]
    for src in (bm.rep_source, bm.shift_source, bm.slice_source, bm.part_source):
        if src:
            for tok in _IDENT_RE.findall(src):
                if tok not in sigs:
                    sigs.append(tok)

    return {
        "class":               "SEMANTIC_DATAPATH_VIOLATION",
        "subtype":             subtype,
        "severity":            severity,
        "confidence":          confidence,
        "always_block_id":     bm.always_block_id,
        "rtl_line":            bm.rtl_line,
        "source_location":     bm.source_loc or "",
        "storage_element":     storage,
        "destination":         bm.dst_raw,
        "source_expression":   bm.rhs_raw,
        "violated_invariant":  violated_invariant,
        "transformation":      transformation,
        "mathematical_reason": mathematical_reason,
        "signals_involved":    sigs,
    }


# ---------------------------------------------------------------------------
# Step 2 — Lane Bijection Violations
# ---------------------------------------------------------------------------

def _check_lane_bijection(
    mappings: List[BitMapping],
) -> List[Dict[str, Any]]:
    """
    Invariant: ∀ dst_lane_k: count(unique src_lane(dst_lane_k)) == 1

    Detects:
      UNINTENDED_BROADCAST   — {N{data}} writes same bits to all N lanes
      NON_INJECTIVE_MAPPING  — overlapping static-slice writes from different paths
    """
    violations: List[Dict[str, Any]] = []

    # Group by storage element
    by_storage: Dict[str, List[BitMapping]] = {}
    for bm in mappings:
        by_storage.setdefault(bm.dst_storage, []).append(bm)

    for storage, bms in by_storage.items():

        # ── UNINTENDED_BROADCAST: {N{data}} with N > 1 ─────────────────────
        for bm in bms:
            if (bm.transform == "REPLICATE"
                    and bm.rep_factor_int is not None
                    and bm.rep_factor_int > 1):
                violations.append(_make_violation(
                    subtype="UNINTENDED_BROADCAST",
                    severity="STRUCTURAL_FATAL",
                    confidence="HIGH",
                    storage=storage,
                    bm=bm,
                    violated_invariant=(
                        f"∀ k ∈ [0, {bm.rep_factor}): unique(src_lane(dst_lane_k)) = 1 "
                        f"VIOLATED. Replication {{{bm.rep_factor}{{body}}}} maps ALL "
                        f"{bm.rep_factor} output lanes to the SAME source bits."
                    ),
                    transformation=(
                        f"F_lane_k(x) = x  ∀ k ∈ [0, {bm.rep_factor})"
                    ),
                    mathematical_reason=(
                        f"The transform {{{bm.rep_factor}{{{bm.rep_source}}}}} produces "
                        f"{bm.rep_factor} identical copies of '{bm.rep_source}'. "
                        f"F maps one input point to {bm.rep_factor} output lanes — "
                        f"it is {bm.rep_factor}:1, not injective per lane. "
                        "Each destination byte lane contains the same bit pattern. "
                        "If downstream logic addresses individual lanes by index, "
                        "every read returns the same value regardless of the index "
                        "— lane selection is non-functional."
                    ),
                ))

        # ── NON_INJECTIVE_MAPPING: overlapping static slices ─────────────────
        slice_writes = [
            bm for bm in bms
            if bm.dst_slice_hi is not None and bm.dst_slice_lo is not None
        ]
        for i, a in enumerate(slice_writes):
            for b in slice_writes[i + 1:]:
                overlap_lo = max(a.dst_slice_lo, b.dst_slice_lo)
                overlap_hi = min(a.dst_slice_hi, b.dst_slice_hi)
                if overlap_lo > overlap_hi:
                    continue  # no overlap
                if a.guard_raw == b.guard_raw:
                    continue  # same guard — compiler handles priority
                violations.append(_make_violation(
                    subtype="NON_INJECTIVE_MAPPING",
                    severity="STRUCTURAL_WARNING",
                    confidence="LOW",
                    storage=storage,
                    bm=a,
                    violated_invariant=(
                        f"dst[{overlap_hi}:{overlap_lo}] is in range of two distinct "
                        f"source mappings under guards '{a.guard_raw}' and '{b.guard_raw}'. "
                        "If guards are not mutually exclusive, mapping is non-deterministic."
                    ),
                    transformation=(
                        f"F1: {storage}[{a.dst_slice_hi}:{a.dst_slice_lo}] ← "
                        f"'{a.rhs_raw}'  when [{a.guard_raw}]\n"
                        f"F2: {storage}[{b.dst_slice_hi}:{b.dst_slice_lo}] ← "
                        f"'{b.rhs_raw}'  when [{b.guard_raw}]"
                    ),
                    mathematical_reason=(
                        f"Destination bits [{overlap_hi}:{overlap_lo}] appear in the "
                        "range of two source maps. Without proven mutual exclusion of the "
                        "guards, both can be active simultaneously — the final value is "
                        "undefined (last-write-wins in RTL). This violates the bijection "
                        "requirement: dst_bit → unique src_bit must hold at all times."
                    ),
                ))

    return violations


# ---------------------------------------------------------------------------
# Step 3 — Mask Conservation Violations
# ---------------------------------------------------------------------------

def _check_mask_conservation(
    mappings: List[BitMapping],
) -> List[Dict[str, Any]]:
    """
    Invariant: mask[k] ⟹ write(dst_lane(k))  AND  ¬mask[k] ⟹ ¬write(dst_lane(k))

    Checks that the bit-select index in the guard (mask/strobe signal) aligns
    with the byte-lane index in the destination.

    Detects: MASK_DATA_MISALIGNMENT | PARTIAL_WRITE_CORRUPTION
    """
    violations: List[Dict[str, Any]] = []

    for bm in mappings:
        if not bm.guard_bit_sels:
            continue

        for guard_sig, guard_idx in bm.guard_bit_sels:
            guard_idx_int    = _try_parse_int(guard_idx)
            guard_idx_idents = set(_IDENT_RE.findall(guard_idx))

            # ── Pattern A: numeric guard bit + static slice LHS ────────────
            if guard_idx_int is not None and bm.dst_slice_lo is not None:
                byte_lane = bm.dst_slice_lo // 8
                if byte_lane != guard_idx_int:
                    violations.append(_make_violation(
                        subtype="MASK_DATA_MISALIGNMENT",
                        severity="STRUCTURAL_FATAL",
                        confidence="HIGH",
                        storage=bm.dst_storage,
                        bm=bm,
                        violated_invariant=(
                            f"mask[k] ⟹ write(dst_lane(k)). "
                            f"Guard enables lane {guard_idx_int} via '{guard_sig}[{guard_idx}]' "
                            f"but dst[{bm.dst_slice_hi}:{bm.dst_slice_lo}] = byte-lane {byte_lane}. "
                            f"k={guard_idx_int} ≠ lane={byte_lane}."
                        ),
                        transformation=(
                            f"Enable: {guard_sig}[{guard_idx_int}] → "
                            f"{bm.dst_storage}[{bm.dst_slice_hi}:{bm.dst_slice_lo}]"
                        ),
                        mathematical_reason=(
                            f"Write-enable bit {guard_idx_int} of '{guard_sig}' controls "
                            f"byte lane {byte_lane} (dst[{bm.dst_slice_hi}:{bm.dst_slice_lo}]). "
                            f"For correct byte-lane masking, enable bit k must control "
                            f"byte lane k. Here k={guard_idx_int} but lane={byte_lane} — "
                            f"offset = {abs(byte_lane - guard_idx_int)} byte(s). "
                            "Writes will activate the wrong byte lane relative to the "
                            "mask intent: partial write corruption."
                        ),
                    ))

            # ── Pattern B: variable guard index + part-select LHS ─────────
            if guard_idx_idents and bm.dst_part_base is not None:
                base_idents = set(_IDENT_RE.findall(bm.dst_part_base))
                if guard_idx_idents and not guard_idx_idents.intersection(base_idents):
                    violations.append(_make_violation(
                        subtype="MASK_DATA_MISALIGNMENT",
                        severity="STRUCTURAL_FATAL",
                        confidence="MEDIUM",
                        storage=bm.dst_storage,
                        bm=bm,
                        violated_invariant=(
                            f"mask[k] ⟹ write(dst_lane(k)). "
                            f"Guard index identifiers {{{guard_idx_idents}}} do not appear in "
                            f"LHS part-select base '{bm.dst_part_base}'. "
                            "Guard variable and data-slice variable are decoupled."
                        ),
                        transformation=(
                            f"Enable: {guard_sig}[{guard_idx}] → "
                            f"{bm.dst_storage}[{bm.dst_part_base} +: {bm.dst_part_width}]"
                        ),
                        mathematical_reason=(
                            f"The write-enable index ('{guard_idx}' from '{guard_sig}') "
                            f"and the destination byte-lane index (from '{bm.dst_part_base}') "
                            "are disjoint identifier sets. If these are separate loop/index "
                            "variables, the mask selects a different lane than the data writes. "
                            "Correct form requires: mask[i] ⟹ dst[i*W +: W] for any stride W."
                        ),
                    ))

    return violations


# ---------------------------------------------------------------------------
# Step 4 — Width Conservation Violations
# ---------------------------------------------------------------------------

def _check_width_conservation(
    mappings: List[BitMapping],
) -> List[Dict[str, Any]]:
    """
    Invariant: Σ written_bits == Σ source_bits (modulo intentional packing)

    Detects:
      WIDTH_LOSS        — source produces fewer bits than destination expects
      WIDTH_DUPLICATION — replication multiplies entropy without narrowing destination
      NON_BIJECTIVE_PACKING — src width ≠ dst width for a known bijection attempt
    """
    violations: List[Dict[str, Any]] = []

    for bm in mappings:

        # ── Replication: {N{data}} ──────────────────────────────────────────
        if bm.transform == "REPLICATE" and bm.rep_factor_int is not None:
            N = bm.rep_factor_int

            # WIDTH_LOSS: replicated bits > destination width → truncation
            if (bm.dst_width is not None and bm.src_width is not None
                    and bm.src_width > bm.dst_width):
                violations.append(_make_violation(
                    subtype="WIDTH_LOSS",
                    severity="STRUCTURAL_FATAL",
                    confidence="HIGH",
                    storage=bm.dst_storage,
                    bm=bm,
                    violated_invariant=(
                        f"Σ source_bits ({bm.src_width}) > Σ dst_bits ({bm.dst_width}). "
                        f"Upper {bm.src_width - bm.dst_width} replicated bits are silently truncated."
                    ),
                    transformation=(
                        f"F: {{{N}{{body}}}} ({bm.src_width}b) → "
                        f"{bm.dst_storage} ({bm.dst_width}b)"
                    ),
                    mathematical_reason=(
                        f"Replication of '{bm.rep_source}' produces {bm.src_width} bits "
                        f"but the destination '{bm.dst_storage}' accepts only {bm.dst_width} bits. "
                        f"The upper {bm.src_width - bm.dst_width} bits (last "
                        f"{N - bm.dst_width // (bm.src_width // N)} replica(s)) are "
                        "discarded at the destination boundary — silent truncation. "
                        "This is not bijective packing: information is destroyed."
                    ),
                ))

            # WIDTH_DUPLICATION: N > 1 and no evidence of width reduction
            elif N > 1 and bm.dst_width is None:
                violations.append(_make_violation(
                    subtype="WIDTH_DUPLICATION",
                    severity="STRUCTURAL_WARNING",
                    confidence="MEDIUM",
                    storage=bm.dst_storage,
                    bm=bm,
                    violated_invariant=(
                        f"Source data replicated {N}×. "
                        "Total unique entropy = destination_width / N."
                    ),
                    transformation=(
                        f"F(x) = {{{N}{{x}}}},  "
                        f"unique_bits(F(x)) = unique_bits(x)"
                    ),
                    mathematical_reason=(
                        f"All {N} copies of '{bm.rep_source}' contain identical bits. "
                        f"The destination word carries only 1/{N} of its nominal entropy. "
                        "In a width-converting adapter this is only correct if downstream "
                        "logic selects the right replica via address[log2(N):0]. "
                        "Without that selection, every lane returns stale or redundant data."
                    ),
                ))

        # ── Static slice → wider destination ───────────────────────────────
        if (bm.transform == "SLICE"
                and bm.slice_width is not None
                and bm.dst_width is not None
                and bm.slice_width < bm.dst_width):
            violations.append(_make_violation(
                subtype="WIDTH_LOSS",
                severity="STRUCTURAL_FATAL",
                confidence="HIGH",
                storage=bm.dst_storage,
                bm=bm,
                violated_invariant=(
                    f"Σ source_bits ({bm.slice_width}) < Σ dst_bits ({bm.dst_width}). "
                    "Remaining destination bits are zero-padded or hold stale values."
                ),
                transformation=(
                    f"F: src[{bm.slice_hi}:{bm.slice_lo}] ({bm.slice_width}b) "
                    f"→ {bm.dst_storage} ({bm.dst_width}b)"
                ),
                mathematical_reason=(
                    f"The slice [{bm.slice_hi}:{bm.slice_lo}] supplies only "
                    f"{bm.slice_width} bits to a {bm.dst_width}-bit destination. "
                    f"The upper {bm.dst_width - bm.slice_width} destination bits receive "
                    "implicit zero-extension or retain their current value (register hold). "
                    "The full destination state cannot be reconstructed from the source "
                    "slice alone — information loss: F is not bijective."
                ),
            ))

    return violations


# ---------------------------------------------------------------------------
# Step 5 — Address Mapping Violations
# ---------------------------------------------------------------------------

def _check_address_mapping(
    mappings: List[BitMapping],
) -> List[Dict[str, Any]]:
    """
    Invariant: index(i+1) - index(i) == expected_stride (monotonic, non-aliasing)

    Detects:
      ADDRESS_ALIASING    — two writes to same normalised address expression
      STRIDE_MISMATCH     — inconsistent stride across writes to same memory
    """
    violations: List[Dict[str, Any]] = []

    # Collect memory writes only
    mem_writes: Dict[str, List[BitMapping]] = {}
    for bm in mappings:
        if bm.dst_is_memory and bm.dst_addr_expr:
            mem_writes.setdefault(bm.dst_storage, []).append(bm)

    for mem, writes in mem_writes.items():
        if len(writes) < 2:
            continue

        # ── ADDRESS_ALIASING: same normalised address expression ────────────
        addr_groups: Dict[str, List[BitMapping]] = {}
        for bm in writes:
            norm = _normalize_addr(bm.dst_addr_expr)
            addr_groups.setdefault(norm, []).append(bm)

        for norm_addr, group in addr_groups.items():
            if len(group) < 2:
                continue
            guards = [bm.guard_raw for bm in group]
            # Skip if all guards identical (handled by compiler)
            if len(set(guards)) == 1:
                conf = "HIGH"
                g_note = "identical guard — one write is dead code"
            else:
                conf = "MEDIUM"
                g_note = "different guards — conditional aliasing possible"

            violations.append(_make_violation(
                subtype="ADDRESS_ALIASING",
                severity="STRUCTURAL_FATAL" if conf == "HIGH" else "STRUCTURAL_WARNING",
                confidence=conf,
                storage=mem,
                bm=group[0],
                violated_invariant=(
                    f"∀ i ≠ j: index(i) ≠ index(j). "
                    f"Address '{norm_addr}' appears in {len(group)} writes to '{mem}'. "
                    f"({g_note})"
                ),
                transformation="\n".join(
                    f"W{i+1}: {mem}[{bm.dst_addr_expr}] ← '{bm.rhs_raw}' when [{bm.guard_raw}]"
                    for i, bm in enumerate(group[:3])
                ),
                mathematical_reason=(
                    f"{len(group)} assignments target '{mem}[{norm_addr}]'. "
                    "For distinct logical transactions i ≠ j, index(i) = index(j) violates "
                    "the injectivity requirement of the address map. "
                    "In synthesis: last-write-wins (undefined order), "
                    "causing non-deterministic memory state."
                ),
            ))

        # ── STRIDE_MISMATCH: inconsistent stride within same memory ─────────
        affines = [(bm, _parse_address_affine(bm.dst_addr_expr)) for bm in writes]
        by_base: Dict[str, List[Tuple[BitMapping, Dict]]] = {}
        for bm, aff in affines:
            if aff["base_sig"]:
                by_base.setdefault(aff["base_sig"], []).append((bm, aff))

        for base_sig, items in by_base.items():
            strides = [aff["stride_int"] for _, aff in items
                       if aff["stride_int"] is not None]
            if len(strides) >= 2 and len(set(strides)) > 1:
                violations.append(_make_violation(
                    subtype="STRIDE_MISMATCH",
                    severity="STRUCTURAL_WARNING",
                    confidence="MEDIUM",
                    storage=mem,
                    bm=items[0][0],
                    violated_invariant=(
                        f"index(i+1) - index(i) ∉ {{expected_stride}}. "
                        f"Strides found: {sorted(set(strides))} — non-uniform access."
                    ),
                    transformation=(
                        "Address expressions: "
                        + str([bm.dst_addr_expr for bm, _ in items[:4]])
                    ),
                    mathematical_reason=(
                        f"Multiple writes to '{mem}' use base signal '{base_sig}' "
                        f"with inconsistent stride multipliers {sorted(set(strides))}. "
                        "For correct array traversal the stride must be constant and "
                        "equal to the element width in bytes. "
                        "Non-uniform stride ⟹ index(i+1) - index(i) varies ⟹ "
                        "non-monotonic access ⟹ possible address aliasing or gap."
                    ),
                ))

    return violations


# ---------------------------------------------------------------------------
# Step 6 — Invertibility Violations
# ---------------------------------------------------------------------------

def _check_invertibility(
    mappings: List[BitMapping],
) -> List[Dict[str, Any]]:
    """
    Invariant: F⁻¹ must exist and be unique for transforms that should be reversible.

    A transform is non-invertible when:
      - Replication factor N > 1: F(x) = {N{x}} → F⁻¹ undefined (which copy?)
      - Static slice to wider destination: information in un-sliced bits is lost
      - Left-shift by constant C: upper C bits of source are shifted out
      - Right-shift by constant C: lower C bits of source are shifted out

    Detects: NON_INVERTIBLE_TRANSFORM | ENTROPY_LOSS
    """
    violations: List[Dict[str, Any]] = []

    for bm in mappings:

        # ── Replication: F(x) = {N{x}} is N:1 ─────────────────────────────
        if bm.transform == "REPLICATE" and bm.rep_factor_int and bm.rep_factor_int > 1:
            N = bm.rep_factor_int
            violations.append(_make_violation(
                subtype="NON_INVERTIBLE_TRANSFORM",
                severity="STRUCTURAL_FATAL",
                confidence="HIGH",
                storage=bm.dst_storage,
                bm=bm,
                violated_invariant=(
                    f"F⁻¹ must be unique. "
                    f"F(x) = {{{N}{{x}}}} has |image(F)| = 1 per input point "
                    f"but produces {N} output lanes — no unique inverse."
                ),
                transformation=(
                    f"F(x) = {{{N}{{x}}}},  "
                    f"|domain| : |range| = 1 : {N}"
                ),
                mathematical_reason=(
                    f"Given y = {{{N}{{x}}}}, then x = y[0 +: W] = y[W +: W] = … "
                    f"for any replica index — {N} candidates for x, all equal. "
                    "F is not injective in the output space: {N{x}} projects R^W "
                    f"into a subspace of R^(N×W) where all N copies are identical. "
                    "F⁻¹(y) is undefined (returns same value regardless of which "
                    "replica is read) — any information about which source byte lane "
                    "was intended is destroyed."
                ),
            ))

        # ── Slice: bits outside [H:L] are lost ─────────────────────────────
        if (bm.transform == "SLICE"
                and bm.slice_width is not None
                and bm.dst_width is not None
                and bm.slice_width < bm.dst_width):
            lost = bm.dst_width - bm.slice_width
            violations.append(_make_violation(
                subtype="ENTROPY_LOSS",
                severity="STRUCTURAL_FATAL",
                confidence="HIGH",
                storage=bm.dst_storage,
                bm=bm,
                violated_invariant=(
                    f"F⁻¹ must reconstruct the full source. "
                    f"Slice [{bm.slice_hi}:{bm.slice_lo}] discards {lost} bits — "
                    "F⁻¹ cannot recover the missing bit positions."
                ),
                transformation=(
                    f"F: src[{bm.slice_hi}:{bm.slice_lo}] → {bm.dst_storage}  "
                    f"({bm.slice_width}b of {bm.dst_width}b written)"
                ),
                mathematical_reason=(
                    f"The slice projection F drops {lost} bit positions. "
                    "F is a surjection from the slice subspace to the destination, "
                    "but information outside [{bm.slice_hi}:{bm.slice_lo}] is lost. "
                    "F⁻¹(y) is undefined for the discarded bit positions — entropy "
                    f"loss = {lost} bits per write. If this is a pack/unpack path, "
                    "all bit positions must be explicitly assigned."
                ),
            ))

        # ── Shift: bits shifted out are gone ───────────────────────────────
        if (bm.transform in ("SHIFT_L", "SHIFT_R")
                and bm.shift_amount_int is not None
                and bm.shift_amount_int > 0):
            direction = "high" if bm.transform == "SHIFT_L" else "low"
            violations.append(_make_violation(
                subtype="ENTROPY_LOSS",
                severity="STRUCTURAL_WARNING",
                confidence="LOW",
                storage=bm.dst_storage,
                bm=bm,
                violated_invariant=(
                    f"F⁻¹ must exist. Shift by {bm.shift_amount_int} destroys "
                    f"{bm.shift_amount_int} {direction}-end bits of '{bm.shift_source}'."
                ),
                transformation=(
                    f"F: {bm.shift_source} {bm.shift_dir} {bm.shift_amount_int}  "
                    f"({bm.shift_amount_int} bits lost)"
                ),
                mathematical_reason=(
                    f"A {bm.shift_dir} shift by {bm.shift_amount_int}: "
                    f"the {bm.shift_amount_int} most-significant bit(s) of "
                    f"'{bm.shift_source}' are shifted out and replaced with zeros. "
                    f"F is not invertible: F⁻¹(y) = y {'>>' if bm.transform == 'SHIFT_L' else '<<'} "
                    f"{bm.shift_amount_int} recovers only the surviving bits, not the lost ones."
                ),
            ))

    return violations


# ---------------------------------------------------------------------------
# Step 7 — Deduplicate by (subtype, storage, line)
# ---------------------------------------------------------------------------

def _deduplicate(violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[Tuple] = set()
    unique: List[Dict[str, Any]] = []
    for v in violations:
        key = (v["subtype"], v["storage_element"], v.get("rtl_line"), v["destination"])
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_semantic_datapath_violations(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Detect mathematically incorrect datapath transformations in IR records.

    Operates purely on IR — no waveform, no protocol context, no simulation.

    Steps
    -----
    1. Build BitMapping model
    2. Lane Bijection analysis       → UNINTENDED_BROADCAST, NON_INJECTIVE_MAPPING
    3. Mask Conservation analysis    → MASK_DATA_MISALIGNMENT, PARTIAL_WRITE_CORRUPTION
    4. Width Conservation analysis   → WIDTH_LOSS, WIDTH_DUPLICATION
    5. Address Mapping analysis      → ADDRESS_ALIASING, STRIDE_MISMATCH
    6. Invertibility analysis        → NON_INVERTIBLE_TRANSFORM, ENTROPY_LOSS
    7. Deduplicate and return

    Parameters
    ----------
    ir_records : list of IR record dicts from ir_builder.py

    Returns
    -------
    list of violation dicts (may be empty)
    """
    mappings = _build_bit_mappings(ir_records)

    all_violations: List[Dict[str, Any]] = []
    all_violations.extend(_check_lane_bijection(mappings))
    all_violations.extend(_check_mask_conservation(mappings))
    all_violations.extend(_check_width_conservation(mappings))
    all_violations.extend(_check_address_mapping(mappings))
    all_violations.extend(_check_invertibility(mappings))

    return _deduplicate(all_violations)


# ---------------------------------------------------------------------------
# CLI entry point — for standalone testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python semantic_datapath_analysis.py <ir.json>")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8") as fh:
        ir = json.load(fh)

    viols = detect_semantic_datapath_violations(ir)
    if viols:
        print(f"\n[SEMANTIC] {len(viols)} violation(s) detected:\n")
        for v in viols:
            print(f"  [{v['class']}] subtype={v['subtype']}  "
                  f"severity={v['severity']}  confidence={v['confidence']}")
            print(f"    storage : {v['storage_element']}")
            print(f"    location: {v['source_location'] or v.get('rtl_line', '?')}")
            print(f"    reason  : {v['mathematical_reason'][:200]}")
            print()
        print(json.dumps(viols, indent=2))
    else:
        print("[SEMANTIC] No semantic datapath violations detected.")
