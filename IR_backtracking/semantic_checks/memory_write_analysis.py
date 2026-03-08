"""
Memory Write Semantic Mismatch Detector
========================================

Static IR analysis pass that detects incorrect byte-lane mapping, aliasing,
or collapsed slices when multiple always blocks write into the same memory.

Runs BEFORE waveform/protocol analysis — purely structural reasoning on IR.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# AST node types for expressions (kept as lightweight tuples/dataclasses)
# We preserve AST structure — never stringify for comparison.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ASTConst:
    """Integer constant."""
    value: int


@dataclass(frozen=True)
class ASTVar:
    """Named variable (signal, parameter, loop iterator)."""
    name: str


@dataclass(frozen=True)
class ASTBinOp:
    """Binary arithmetic operation."""
    op: str          # '+', '-', '*', '/'
    left: Any        # AST node
    right: Any       # AST node


@dataclass(frozen=True)
class ASTUnknown:
    """Opaque expression that could not be parsed further."""
    text: str


# ---------------------------------------------------------------------------
# Affine form:  A*var + B   (or just B when var is None)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AffineForm:
    """Canonical affine representation: coeff * var + offset."""
    coeff: int                  # A
    var: Optional[str]          # loop iterator name (None → constant)
    offset: int                 # B

    def is_constant(self) -> bool:
        return self.var is None or self.coeff == 0


# ---------------------------------------------------------------------------
# Write-site descriptor
# ---------------------------------------------------------------------------

@dataclass
class WriteSite:
    always_block_id: Optional[int]
    index_expr_ast: Any                 # AST of the address expression
    slice_base_expr_ast: Any            # AST of the part-select base
    slice_width: Optional[int]          # width of the part-select
    rhs_slice_expr_ast: Any             # AST of the RHS slice (if any)
    loop_iterator: Optional[str]        # iterator var if inside for-loop
    write_enable_condition: str         # guard expression
    raw_signal: str                     # original LHS text
    raw_rhs: str                        # original RHS text
    source: str = ""                    # source location


@dataclass
class MemoryWriteInfo:
    memory_name: str
    write_sites: List[WriteSite] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Violation records
# ---------------------------------------------------------------------------

@dataclass
class MemoryWriteViolation:
    violation_type: str          # "BYTE_LANE_COLLAPSE" | "WRITE_ALIASING_BUG"
    memory: str
    always_block_id: Optional[int]
    expected_mapping: str
    actual_mapping: str
    detail: str
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "DATAPATH_VIOLATION",
            "class": self.violation_type,
            "memory": self.memory,
            "always_block_id": self.always_block_id,
            "expected": self.expected_mapping,
            "actual": self.actual_mapping,
            "impact": self.detail,
            "source": self.source,
        }


# ===================================================================
#  STEP 0 — Expression parser  (IR text → AST)
# ===================================================================

# Regex patterns for Verilog-style tokens
_SV_LIT = re.compile(r"^(\d+)'([bBdDhHoO])([0-9a-fA-FxXzZ_]+)$")
_DECIMAL = re.compile(r"^(\d+)$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parse_sv_literal(token: str) -> Optional[int]:
    """Parse a SystemVerilog literal to int, if possible."""
    token = token.strip()
    m = _DECIMAL.match(token)
    if m:
        return int(m.group(1))
    m = _SV_LIT.match(token)
    if m:
        base_ch = m.group(2).lower()
        digits = m.group(3).replace("_", "")
        if any(c in digits.lower() for c in ("x", "z")):
            return None
        base_map = {"b": 2, "o": 8, "d": 10, "h": 16}
        try:
            return int(digits, base_map.get(base_ch, 10))
        except ValueError:
            return None
    return None


def _tokenize_expr(text: str) -> List[str]:
    """Split an arithmetic expression into tokens."""
    tokens: List[str] = []
    i = 0
    s = text.strip()
    n = len(s)
    while i < n:
        ch = s[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "+-*/()":
            tokens.append(ch)
            i += 1
            continue
        # Accumulate identifier/number/SV-literal
        j = i
        while j < n and s[j] not in " +-*/()":
            j += 1
        tokens.append(s[i:j])
        i = j
    return tokens


def parse_expr_to_ast(text: str) -> Any:
    """
    Parse a simple arithmetic expression into an AST.
    Supports: +, -, *, identifiers, integer literals, SV literals, parens.
    """
    text = text.strip()
    if not text:
        return ASTConst(0)

    tokens = _tokenize_expr(text)
    if not tokens:
        return ASTUnknown(text)

    pos = [0]  # mutable index

    def peek() -> Optional[str]:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume() -> str:
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_add() -> Any:
        node = parse_mul()
        while peek() in ("+", "-"):
            op = consume()
            right = parse_mul()
            node = ASTBinOp(op, node, right)
        return node

    def parse_mul() -> Any:
        node = parse_unary()
        while peek() == "*":
            consume()
            right = parse_unary()
            node = ASTBinOp("*", node, right)
        return node

    def parse_unary() -> Any:
        if peek() == "-":
            consume()
            child = parse_primary()
            return ASTBinOp("*", ASTConst(-1), child)
        return parse_primary()

    def parse_primary() -> Any:
        tok = peek()
        if tok is None:
            return ASTUnknown("")
        if tok == "(":
            consume()
            node = parse_add()
            if peek() == ")":
                consume()
            return node
        consume()
        lit = _parse_sv_literal(tok)
        if lit is not None:
            return ASTConst(lit)
        if _IDENT.match(tok):
            return ASTVar(tok)
        return ASTUnknown(tok)

    try:
        result = parse_add()
        return result
    except Exception:
        return ASTUnknown(text)


# ===================================================================
#  STEP 1 — Identify candidate memories from IR
# ===================================================================

# Pattern: mem[index_expr]  or  mem[index_expr][slice]
_MEM_WRITE_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)"       # memory name
    r"\[([^\]]+)\]"                      # [index_expr]
    r"(?:\[([^\]]*)\])?"                 # optional [slice_expr]  (might be part-select)
    r"$"
)

# Part-select pattern:  base +: width   or   base -: width
_PART_SELECT_RE = re.compile(
    r"^\s*(.+?)\s*(\+:|-:)\s*(.+?)\s*$"
)

# Fixed bit-range: high : low
_FIXED_RANGE_RE = re.compile(
    r"^\s*(.+?)\s*:\s*(.+?)\s*$"
)

# Loop guard pattern emitted by ir_builder:  FOR(init; cond; step)
_FOR_GUARD_RE = re.compile(
    r"FOR\(\s*(?:(?:int|integer|genvar)\s+)?([A-Za-z_]\w*)\s*=\s*(\d+)\s*;"
    r"\s*\1\s*[<>!=]+\s*(\S+)\s*;"
    r"\s*\1\s*(?:\+\+|=\s*\1\s*\+\s*\d+)"
    r"\s*\)"
)


def _extract_loop_iterator(guard: str) -> Optional[str]:
    """Extract the loop iterator variable from a FOR(...) guard fragment."""
    m = _FOR_GUARD_RE.search(guard)
    if m:
        return m.group(1)
    # Simpler fallback: look for FOR(<ident> = ...
    m2 = re.search(r"FOR\(\s*(?:(?:int|integer|genvar)\s+)?([A-Za-z_]\w*)\s*=", guard)
    if m2:
        return m2.group(1)
    return None


def _parse_lhs_signal(signal_text: str) -> Optional[Tuple[str, str, Optional[str]]]:
    """
    Parse a memory-write LHS into (memory_name, index_expr, slice_expr_or_None).
    Returns None if not a memory write pattern.
    """
    s = signal_text.strip()
    # Handle nested brackets more robustly
    # Pattern: NAME [ idx ] [ slice ]  or  NAME [ idx ]
    if not s or "[" not in s:
        return None

    # Find memory name (everything before first '[')
    bracket_pos = s.index("[")
    mem_name = s[:bracket_pos].strip()
    if not mem_name or not _IDENT.match(mem_name):
        return None

    rest = s[bracket_pos:]

    # Extract bracket groups
    groups: List[str] = []
    depth = 0
    start = -1
    for i, ch in enumerate(rest):
        if ch == "[":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0 and start >= 0:
                groups.append(rest[start:i].strip())
                start = -1

    if not groups:
        return None

    index_expr = groups[0]
    slice_expr = groups[1] if len(groups) > 1 else None
    return mem_name, index_expr, slice_expr


def _parse_slice_expr(slice_text: str) -> Tuple[Any, Optional[int]]:
    """
    Parse a slice expression into (base_ast, width).
    Handles:
      - base +: width   →  (parse(base), width_int)
      - high : low      →  (parse(low), high - low + 1)
      - single_expr     →  (parse(expr), 1)
    """
    if slice_text is None:
        return ASTConst(0), None

    s = slice_text.strip()

    # Part-select: base +: width
    m = _PART_SELECT_RE.match(s)
    if m:
        base_text = m.group(1).strip()
        direction = m.group(2).strip()
        width_text = m.group(3).strip()
        base_ast = parse_expr_to_ast(base_text)
        width_val = _parse_sv_literal(width_text)
        if width_val is None:
            # Width is a parameter — keep as AST
            width_ast = parse_expr_to_ast(width_text)
            if isinstance(width_ast, ASTConst):
                width_val = width_ast.value
            elif isinstance(width_ast, ASTVar):
                # Cannot resolve parameter width statically; mark as unknown
                width_val = None
        return base_ast, width_val

    # Fixed range: high : low
    m = _FIXED_RANGE_RE.match(s)
    if m:
        high_text = m.group(1).strip()
        low_text = m.group(2).strip()
        high_val = _parse_sv_literal(high_text)
        low_val = _parse_sv_literal(low_text)
        low_ast = parse_expr_to_ast(low_text)
        if high_val is not None and low_val is not None:
            width = abs(high_val - low_val) + 1
            return low_ast, width
        return low_ast, None

    # Single bit
    return parse_expr_to_ast(s), 1


def _parse_rhs_slice(rhs_text: str, mem_name: str) -> Any:
    """Extract slice information from the RHS expression if it references data."""
    s = rhs_text.strip()
    # Look for patterns like wdata[WORD*i +: WORD] or data_in[base +: width]
    if "[" in s:
        bracket_pos = s.index("[")
        rest = s[bracket_pos:]
        groups: List[str] = []
        depth = 0
        start = -1
        for i, ch in enumerate(rest):
            if ch == "[":
                if depth == 0:
                    start = i + 1
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0 and start >= 0:
                    groups.append(rest[start:i].strip())
                    start = -1
        # Return AST of last bracket group (the data slice)
        if groups:
            last = groups[-1]
            m = _PART_SELECT_RE.match(last)
            if m:
                return parse_expr_to_ast(m.group(1).strip())
            return parse_expr_to_ast(last)
    return ASTUnknown(s)


# ===================================================================
#  STEP 2 — Extract write semantics per site
# ===================================================================

def collect_memory_writes(ir_records: List[Dict[str, Any]]) -> Dict[str, MemoryWriteInfo]:
    """
    STEP 1 + STEP 2: Scan IR for memory array writes, group by memory name,
    and extract per-site write semantics.
    """
    memories: Dict[str, MemoryWriteInfo] = {}

    for rec in ir_records:
        sig_text = (rec.get("signal") or "").strip()
        if not sig_text or "[" not in sig_text:
            continue

        parsed = _parse_lhs_signal(sig_text)
        if parsed is None:
            continue

        mem_name, index_expr_text, slice_text = parsed

        # Only consider nonblocking assignments (memory writes in clocked blocks)
        # but also allow blocking for combinational memories.
        timing = (rec.get("timing") or "").strip()
        always_block_id = rec.get("always_block_id")

        # Skip continuous assigns — they are not memory writes.
        if (rec.get("process") or "").strip() == "assign":
            continue

        # If there is no slice, this is a whole-word write — not a byte-lane issue.
        if slice_text is None:
            # Still record it so cross-port checks can see whole-word vs sliced.
            slice_base_ast = ASTConst(0)
            slice_width = None
        else:
            slice_base_ast, slice_width = _parse_slice_expr(slice_text)

        guard = (rec.get("guard") or "true").strip()
        loop_iter = _extract_loop_iterator(guard)

        index_ast = parse_expr_to_ast(index_expr_text)
        rhs_text = (rec.get("rhs") or "").strip()
        rhs_slice_ast = _parse_rhs_slice(rhs_text, mem_name)

        ws = WriteSite(
            always_block_id=always_block_id,
            index_expr_ast=index_ast,
            slice_base_expr_ast=slice_base_ast,
            slice_width=slice_width,
            rhs_slice_expr_ast=rhs_slice_ast,
            loop_iterator=loop_iter,
            write_enable_condition=guard,
            raw_signal=sig_text,
            raw_rhs=rhs_text,
            source=(rec.get("source") or ""),
        )

        if mem_name not in memories:
            memories[mem_name] = MemoryWriteInfo(memory_name=mem_name)
        memories[mem_name].write_sites.append(ws)

    return memories


# ===================================================================
#  STEP 3 — Normalize slice form to canonical affine
# ===================================================================

def _ast_to_affine(ast_node: Any, iterator: Optional[str]) -> Optional[AffineForm]:
    """
    Attempt to convert an AST into affine form:  A * iterator + B.
    Returns None if the expression is not affine in the iterator.
    """
    if isinstance(ast_node, ASTConst):
        return AffineForm(coeff=0, var=iterator, offset=ast_node.value)

    if isinstance(ast_node, ASTVar):
        if iterator and ast_node.name == iterator:
            return AffineForm(coeff=1, var=iterator, offset=0)
        # Treat other variables as opaque constants for affine analysis
        # (they don't depend on the iterator).
        return AffineForm(coeff=0, var=iterator, offset=0)

    if isinstance(ast_node, ASTBinOp):
        left_af = _ast_to_affine(ast_node.left, iterator)
        right_af = _ast_to_affine(ast_node.right, iterator)
        if left_af is None or right_af is None:
            return None

        if ast_node.op == "+":
            return AffineForm(
                coeff=left_af.coeff + right_af.coeff,
                var=iterator,
                offset=left_af.offset + right_af.offset,
            )
        if ast_node.op == "-":
            return AffineForm(
                coeff=left_af.coeff - right_af.coeff,
                var=iterator,
                offset=left_af.offset - right_af.offset,
            )
        if ast_node.op == "*":
            # At most one side may depend on iterator for result to be affine.
            if left_af.coeff == 0:
                # left is constant
                return AffineForm(
                    coeff=left_af.offset * right_af.coeff,
                    var=iterator,
                    offset=left_af.offset * right_af.offset,
                )
            if right_af.coeff == 0:
                # right is constant
                return AffineForm(
                    coeff=right_af.offset * left_af.coeff,
                    var=iterator,
                    offset=right_af.offset * left_af.offset,
                )
            # Both sides depend on iterator → quadratic, not affine.
            return None

    # ASTUnknown or anything else
    return None


def normalize_slice_affine(site: WriteSite) -> Optional[AffineForm]:
    """
    STEP 3: Convert the slice base expression of a WriteSite into
    canonical affine form:  A * i + B.
    """
    return _ast_to_affine(site.slice_base_expr_ast, site.loop_iterator)


# ===================================================================
#  STEP 4 — Derive lane mapping function
# ===================================================================

@dataclass(frozen=True)
class LaneFunction:
    """lane(i) = lane_coeff * i + lane_offset  (integer division already applied)."""
    lane_coeff: int
    lane_offset: int
    word_size: Optional[int]
    iterator: Optional[str]

    def is_identity(self) -> bool:
        """Correct mapping: lane(i) = i."""
        return self.lane_coeff == 1 and self.lane_offset == 0

    def describe(self) -> str:
        if self.iterator:
            if self.lane_coeff == 0:
                return f"lane({self.iterator}) = {self.lane_offset}"
            parts = []
            if self.lane_coeff != 1:
                parts.append(f"{self.lane_coeff}*{self.iterator}")
            else:
                parts.append(self.iterator)
            if self.lane_offset != 0:
                parts.append(f" + {self.lane_offset}" if self.lane_offset > 0
                             else f" - {-self.lane_offset}")
            return f"lane({self.iterator}) = {''.join(parts)}"
        return f"lane = {self.lane_offset}"


def derive_lane_function(site: WriteSite) -> Optional[LaneFunction]:
    """
    STEP 4: For a WriteSite, compute  lane(i) = base(i) / WORD_SIZE.
    Correct AXI-lite byte write must have lane(i) = i.
    """
    word_size = site.slice_width
    if word_size is None or word_size == 0:
        return None

    affine = normalize_slice_affine(site)
    if affine is None:
        return None

    # lane(i) = (A*i + B) / WORD_SIZE
    # For this to be an integer function we need A % WORD_SIZE == 0
    # and B % WORD_SIZE == 0.
    if affine.coeff % word_size != 0 and affine.coeff != 0:
        # Non-integer lane mapping — treat as misaligned.
        return LaneFunction(
            lane_coeff=0,
            lane_offset=0,
            word_size=word_size,
            iterator=site.loop_iterator,
        )

    lane_coeff = affine.coeff // word_size if affine.coeff != 0 else 0
    lane_offset = affine.offset // word_size if word_size != 0 else 0

    return LaneFunction(
        lane_coeff=lane_coeff,
        lane_offset=lane_offset,
        word_size=word_size,
        iterator=site.loop_iterator,
    )


# ===================================================================
#  STEP 5 — Cross-port equivalence check
# ===================================================================

def _lane_functions_equivalent(a: LaneFunction, b: LaneFunction) -> bool:
    """Symbolic equivalence: two lane functions produce the same mapping."""
    return a.lane_coeff == b.lane_coeff and a.lane_offset == b.lane_offset


# ===================================================================
#  STEP 6 — Detect aliasing even without loop variable
# ===================================================================

def _is_aliasing_bug(site: WriteSite) -> bool:
    """
    If the slice base does NOT depend on the loop iterator,
    every iteration writes the same lane → WRITE_ALIASING_BUG.
    """
    if site.loop_iterator is None:
        # Not inside a loop — no aliasing from iteration.
        return False
    affine = normalize_slice_affine(site)
    if affine is None:
        # Cannot determine — be conservative.
        return False
    # If coefficient of iterator is 0, slice does not vary with loop.
    return affine.coeff == 0


# ===================================================================
#  MAIN PASS — detect_memory_write_semantic_mismatch
# ===================================================================

def detect_memory_write_semantic_mismatch(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Top-level analysis pass.  Returns a list of structural violation records.

    This must run BEFORE waveform/protocol analysis.
    Detection relies purely on IR math equivalence — no waveform correlation.
    """
    violations: List[MemoryWriteViolation] = []

    # STEP 1 + 2: Collect memory write info
    memories = collect_memory_writes(ir_records)

    for mem_name, mem_info in memories.items():
        sites = mem_info.write_sites

        # --- STEP 6: Aliasing detection per site ---
        for site in sites:
            if _is_aliasing_bug(site):
                violations.append(MemoryWriteViolation(
                    violation_type="WRITE_ALIASING_BUG",
                    memory=mem_name,
                    always_block_id=site.always_block_id,
                    expected_mapping=f"{site.slice_width}*{site.loop_iterator}" if site.slice_width and site.loop_iterator else "varies with iterator",
                    actual_mapping="0 (constant — does not depend on loop iterator)",
                    detail=(
                        f"Slice base in '{site.raw_signal}' does not depend on loop "
                        f"iterator '{site.loop_iterator}'. Every iteration overwrites "
                        f"the same byte lane, collapsing the write."
                    ),
                    source=site.source,
                ))

        # --- STEP 4: Derive lane functions for each site ---
        site_lanes: List[Tuple[WriteSite, LaneFunction]] = []
        for site in sites:
            lf = derive_lane_function(site)
            if lf is not None:
                site_lanes.append((site, lf))

        # --- STEP 4 continued: Check each site for identity violation ---
        for site, lf in site_lanes:
            if site.loop_iterator and not lf.is_identity():
                # Only flag if this site is inside a loop (byte-lane iteration).
                # A non-loop site writing a fixed lane is not inherently wrong
                # unless cross-port mismatch exists (checked below).
                violations.append(MemoryWriteViolation(
                    violation_type="BYTE_LANE_COLLAPSE",
                    memory=mem_name,
                    always_block_id=site.always_block_id,
                    expected_mapping=f"lane({site.loop_iterator}) = {site.loop_iterator}",
                    actual_mapping=lf.describe(),
                    detail=(
                        f"Memory '{mem_name}' byte-lane mapping is not identity. "
                        f"Expected lane(i)=i but got {lf.describe()}. "
                        f"This causes cross-port incoherent writes."
                    ),
                    source=site.source,
                ))

        # --- STEP 5: Cross-port equivalence check ---
        if len(site_lanes) >= 2:
            # Group by always_block_id (each block is a "port")
            by_block: Dict[Optional[int], List[Tuple[WriteSite, LaneFunction]]] = {}
            for site, lf in site_lanes:
                by_block.setdefault(site.always_block_id, []).append((site, lf))

            block_ids = sorted(by_block.keys(), key=lambda x: (x is None, x))
            if len(block_ids) >= 2:
                # Compare all pairs of ports
                for i_idx in range(len(block_ids)):
                    for j_idx in range(i_idx + 1, len(block_ids)):
                        bid_a = block_ids[i_idx]
                        bid_b = block_ids[j_idx]
                        lanes_a = by_block[bid_a]
                        lanes_b = by_block[bid_b]
                        # Compare representative lane functions
                        for (site_a, lf_a) in lanes_a:
                            for (site_b, lf_b) in lanes_b:
                                if not _lane_functions_equivalent(lf_a, lf_b):
                                    violations.append(MemoryWriteViolation(
                                        violation_type="BYTE_LANE_COLLAPSE",
                                        memory=mem_name,
                                        always_block_id=site_b.always_block_id,
                                        expected_mapping=lf_a.describe(),
                                        actual_mapping=lf_b.describe(),
                                        detail=(
                                            f"Cross-port lane function mismatch on memory "
                                            f"'{mem_name}'. Block {bid_a} uses "
                                            f"{lf_a.describe()} but block {bid_b} uses "
                                            f"{lf_b.describe()}. This causes cross-port "
                                            f"incoherent writes."
                                        ),
                                        source=site_b.source,
                                    ))

    # --- STEP 7: Emit RCA-level root cause artifacts ---
    # De-duplicate violations by (memory, always_block_id, type)
    seen_keys: set = set()
    unique_violations: List[Dict[str, Any]] = []
    for v in violations:
        key = (v.violation_type, v.memory, v.always_block_id, v.actual_mapping)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique_violations.append(v.to_dict())

    return unique_violations


# ===================================================================
#  STEP 8 — Integration: downgrade protocol violations
# ===================================================================

def apply_datapath_priority(
    findings: List[Dict[str, Any]],
    datapath_violations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    If any DATAPATH_VIOLATION exists, downgrade all protocol-level findings
    to SECONDARY_SYMPTOM, because the protocol failure is derivative of the
    structural datapath bug, not independently causal.

    Returns the (possibly modified) findings list.
    """
    if not datapath_violations:
        return findings

    for f in findings:
        original_class = f.get("classification", "")
        if original_class == "DATAPATH_VIOLATION":
            continue
        f["original_classification"] = original_class
        f["classification"] = "SECONDARY_SYMPTOM"
        f["secondary_reason"] = (
            "Downgraded: structural DATAPATH_VIOLATION detected — "
            "protocol failure is derivative, not causal."
        )

    return findings


# ---------------------------------------------------------------------------
# Lane Bijection Detector (focused, engineer-friendly)
# ---------------------------------------------------------------------------

def detect_lane_bijection_violation(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Detect byte-lane aliasing caused by a loop-indexed memory write where the
    part-select base does NOT depend on the loop iterator.

    Bug pattern detected:
        for (i = 0; i < N; i++) begin
            mem[addr][0 +: WORD_SIZE] <= data[i*WORD_SIZE +: WORD_SIZE];
        end
            ↑ base is constant 0 — every iteration writes the same lane

    Valid pattern (no violation):
        mem[addr][i*WORD_SIZE +: WORD_SIZE] <= data[i*WORD_SIZE +: WORD_SIZE];

    Each violation dict:
        class           : "LANE_BIJECTION_VIOLATION"
        memory          : str
        always_block_id : int | None
        expected        : str  (expected pattern)
        actual          : str  (what was found)
        impact          : str  (engineer-friendly explanation)
        source          : str
    """
    memories = collect_memory_writes(ir_records)
    violations: List[Dict[str, Any]] = []
    seen: set = set()

    for mem_name, mem_info in memories.items():
        for site in mem_info.write_sites:

            # Only check sites inside a loop (loop_iterator must be present)
            if not site.loop_iterator:
                continue

            # Normalise the slice base to affine form A*i + B
            affine = normalize_slice_affine(site)
            if affine is None:
                continue

            iterator  = site.loop_iterator
            word_size = site.slice_width or 0

            # ── Case 1: base is constant — does NOT depend on loop variable ──
            if affine.is_constant():
                key = (mem_name, site.always_block_id, "const_base")
                if key in seen:
                    continue
                seen.add(key)
                const_val = affine.offset
                violations.append({
                    "class":           "LANE_BIJECTION_VIOLATION",
                    "memory":          mem_name,
                    "always_block_id": site.always_block_id,
                    "expected":        f"mem[addr][{iterator}*{word_size} +: {word_size}]",
                    "actual":          f"mem[addr][{const_val} +: {word_size}] (constant — "
                                       f"independent of {iterator})",
                    "impact": (
                        f"Detected byte-lane aliasing in memory write to '{mem_name}'.\n"
                        f"All {iterator}-loop iterations write to the same destination "
                        f"slice [{const_val} +: {word_size or '?'}].\n"
                        f"Expected each iteration to target a unique byte lane.\n"
                        f"Later writes overwrite earlier ones — silent data corruption.\n"
                        f"RTL location: {site.source or '(unknown)'}."
                    ),
                    "source": site.source,
                })
                continue

            # ── Case 2: base depends on iterator but with wrong stride/offset ──
            # Valid form: A*i where A == word_size and B == 0
            bad_coeff  = word_size > 0 and affine.coeff not in (0, word_size)
            bad_offset = affine.offset != 0

            if bad_coeff or bad_offset:
                key = (mem_name, site.always_block_id, "wrong_multiplier")
                if key in seen:
                    continue
                seen.add(key)
                actual_desc   = (f"{affine.coeff}*{iterator}"
                                 + (f" + {affine.offset}" if affine.offset > 0
                                    else f" - {-affine.offset}" if affine.offset < 0
                                    else ""))
                expected_desc = f"{word_size}*{iterator}"
                impact_parts  = [
                    f"Detected incorrect byte-lane mapping in memory write to '{mem_name}'.",
                    f"Slice base '{actual_desc}' does not produce a 1:1 lane mapping "
                    f"for iterator '{iterator}'.",
                ]
                if bad_coeff:
                    impact_parts.append(
                        f"Wrong stride: {affine.coeff} (found) vs {word_size} (expected). "
                        "Stride must equal the element width so each iteration targets "
                        "a distinct lane."
                    )
                if bad_offset:
                    impact_parts.append(
                        f"Non-zero offset {affine.offset} shifts all lanes by a constant — "
                        "off-by-N byte-lane error."
                    )
                impact_parts.append(
                    f"Lane bijection violated: lane(i) must equal i for all values of '{iterator}'."
                )
                violations.append({
                    "class":           "LANE_BIJECTION_VIOLATION",
                    "memory":          mem_name,
                    "always_block_id": site.always_block_id,
                    "expected":        f"mem[addr][{expected_desc} +: {word_size}]",
                    "actual":          f"mem[addr][{actual_desc} +: {word_size}]",
                    "impact":          "\n".join(impact_parts),
                    "source":          site.source,
                })

    return violations


# ---------------------------------------------------------------------------
# Mask Conservation Detector (data ↔ strobe steering alignment)
# ---------------------------------------------------------------------------

# Replication pattern in RHS: {N{body}}
_MCR_REP_RE = re.compile(
    r'^\s*\{\s*\(?\s*([A-Za-z0-9_/]+)\s*\)?\s*\{([^{}]+)\}\s*\}\s*$',
    re.IGNORECASE,
)
# Shift pattern in RHS: base << amount
_MCR_SHIFT_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_.$\[\]:]*)\s*(<<|>>)\s*(.+)',
    re.IGNORECASE,
)
# Wdata / wstrb suffix detection
_DATA_SUFFIX_RE  = re.compile(r'wdata|writedata|_data', re.IGNORECASE)
_STRB_SUFFIX_RE  = re.compile(r'wstrb|wbe|_strb|_be',   re.IGNORECASE)


def _classify_rhs(rhs: str) -> Dict[str, Any]:
    """Return {type, base, extra} for a RHS expression."""
    rhs = rhs.strip()
    m = _MCR_REP_RE.match(rhs)
    if m:
        return {"type": "REPLICATE", "base": m.group(2).strip(), "extra": m.group(1).strip()}
    m = _MCR_SHIFT_RE.match(rhs)
    if m:
        return {"type": "SHIFT", "base": m.group(1).strip(),
                "extra": m.group(3).strip(), "dir": m.group(2)}
    return {"type": "IDENTITY", "base": rhs, "extra": None}


def detect_mask_conservation_violation(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Detect cases where WDATA and WSTRB are steered differently, breaking
    the invariant: mask[k] ⟹ write(data_lane(k)).

    Checks within each always block:
      - Both data and strobe signals must use the same steering expression.
      - If WDATA is replicated but WSTRB is shifted (or vice-versa), flag.
      - If both are shifted but by different amounts, flag.
      - If shift amount contains an off-by-one additive offset, flag.

    Violation subtypes:
        DATA_REPLICATION_WITHOUT_MASK_MAPPING — {N{data}} vs shifted strobe
        TRANSPORT_OFFSET_MISMATCH             — same type but different expressions
        MASK_STROBE_TYPE_MISMATCH             — fundamentally different transforms
    """
    # Group IR by always_block_id
    blocks: Dict[Any, List[Dict[str, Any]]] = {}
    for rec in ir_records:
        bid = rec.get("always_block_id")
        blocks.setdefault(bid, []).append(rec)

    violations: List[Dict[str, Any]] = []

    for bid, recs in blocks.items():
        # Separate data and strobe assignments
        data_recs  = [r for r in recs if _DATA_SUFFIX_RE.search(r.get("signal", ""))]
        strobe_recs = [r for r in recs if _STRB_SUFFIX_RE.search(r.get("signal", ""))]

        if not data_recs or not strobe_recs:
            continue  # no pair in this block

        for drec in data_recs:
            for srec in strobe_recs:
                d_info = _classify_rhs(drec.get("rhs", ""))
                s_info = _classify_rhs(srec.get("rhs", ""))

                d_sig  = drec.get("signal", "?")
                s_sig  = srec.get("signal", "?")
                d_rhs  = drec.get("rhs", "?")
                s_rhs  = srec.get("rhs", "?")
                src    = drec.get("source", "")

                # ── Case 1: WDATA replicated, WSTRB shifted (or vice versa) ──
                if d_info["type"] == "REPLICATE" and s_info["type"] == "SHIFT":
                    violations.append({
                        "class":           "MASK_CONSERVATION_VIOLATION",
                        "subtype":         "DATA_REPLICATION_WITHOUT_MASK_MAPPING",
                        "memory":          d_sig,
                        "always_block_id": bid,
                        "expected":        "Both WDATA and WSTRB use equivalent steering",
                        "actual":          (f"WDATA: {d_sig} = {{N{{data}}}} (replicated)\n"
                                            f"WSTRB: {s_sig} = ... << ... (shifted)"),
                        "impact": (
                            "Mask conservation violated.\n"
                            f"'{d_sig}' replicates data across all byte lanes.\n"
                            f"'{s_sig}' uses a positional shift — strobe and data are not "
                            "steered equivalently.\n"
                            "Byte enables no longer correspond to the transported data lanes.\n"
                            "Writes will update unintended byte locations."
                        ),
                        "data_signal":   d_sig,
                        "strobe_signal": s_sig,
                        "data_rhs":      d_rhs,
                        "strobe_rhs":    s_rhs,
                        "source":        src,
                    })

                elif d_info["type"] == "SHIFT" and s_info["type"] == "REPLICATE":
                    violations.append({
                        "class":           "MASK_CONSERVATION_VIOLATION",
                        "subtype":         "DATA_REPLICATION_WITHOUT_MASK_MAPPING",
                        "memory":          d_sig,
                        "always_block_id": bid,
                        "expected":        "Both WDATA and WSTRB use equivalent steering",
                        "actual":          (f"WDATA: {d_sig} = ... << ... (shifted)\n"
                                            f"WSTRB: {s_sig} = {{N{{strobe}}}} (replicated)"),
                        "impact": (
                            "Mask conservation violated.\n"
                            f"'{s_sig}' replicates the strobe while '{d_sig}' shifts data.\n"
                            "Strobe position and data position diverge after conversion.\n"
                            "Writes will update unintended byte locations."
                        ),
                        "data_signal":   d_sig,
                        "strobe_signal": s_sig,
                        "data_rhs":      d_rhs,
                        "strobe_rhs":    s_rhs,
                        "source":        src,
                    })

                # ── Case 2: Both shifted but different expressions ────────────
                elif d_info["type"] == "SHIFT" and s_info["type"] == "SHIFT":
                    d_amount = d_info.get("extra", "")
                    s_amount = s_info.get("extra", "")
                    if d_amount and s_amount and d_amount.strip() != s_amount.strip():
                        # Check for off-by-one additive offset in either amount
                        _offset_re = re.compile(
                            r'\(\s*[A-Za-z_][A-Za-z0-9_]*\s*[+\-]\s*\d+\s*\)',
                            re.IGNORECASE,
                        )
                        has_d_offset = bool(_offset_re.search(d_amount))
                        has_s_offset = bool(_offset_re.search(s_amount))
                        subtype = ("TRANSPORT_OFFSET_MISMATCH"
                                   if (has_d_offset or has_s_offset)
                                   else "MASK_STROBE_TYPE_MISMATCH")
                        violations.append({
                            "class":           "MASK_CONSERVATION_VIOLATION",
                            "subtype":         subtype,
                            "memory":          d_sig,
                            "always_block_id": bid,
                            "expected":        (f"data_shift_expr == strobe_shift_expr; "
                                                f"both should equal the same address-derived amount"),
                            "actual":          (f"WDATA shift: '{d_amount}'\n"
                                                f"WSTRB shift: '{s_amount}'"),
                            "impact": (
                                "Mask conservation violated.\n"
                                f"WDATA transformation ({d_sig}) and WSTRB steering "
                                f"({s_sig}) use different shift amounts.\n"
                                f"WDATA shift: '{d_amount}'\n"
                                f"WSTRB shift: '{s_amount}'\n"
                                + ("Off-by-one offset detected in shift expression — "
                                   "byte enables are shifted by a constant relative to data.\n"
                                   if (has_d_offset or has_s_offset) else "")
                                + "Writes will update unintended byte locations."
                            ),
                            "data_signal":   d_sig,
                            "strobe_signal": s_sig,
                            "data_rhs":      d_rhs,
                            "strobe_rhs":    s_rhs,
                            "source":        src,
                        })

    return violations


# ---------------------------------------------------------------------------
# Width Conservation Detector
# ---------------------------------------------------------------------------
# Width inference: static slice [hi:lo] → hi-lo+1.
# Part-select [base +: width] or [base -: width] → width.
_WC_STATIC_SLICE_RE = re.compile(
    r'\[\s*(\d+)\s*:\s*(\d+)\s*\]$'
)
_WC_PART_SEL_RE = re.compile(
    r'\[.*?[+-]:\s*(\d+)\s*\]$'
)
# Replication: {N{body}}
_WC_REP_RE = re.compile(
    r'^\s*\{\s*\(?\s*(\d+)\s*\)?\s*\{([^{}]+)\}\s*\}\s*$',
    re.IGNORECASE,
)
# Concatenation: {a, b, c, ...}  — top-level braces only
_WC_CONCAT_RE = re.compile(r'^\s*\{.*\}\s*$', re.DOTALL)
# Shift-only: sig << N  or  sig >> N  (no concat, no replicate)
_WC_SHIFT_RE = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_.$\[\]:]*\s*(<<|>>)\s*\S+\s*$',
    re.IGNORECASE,
)
# Constant-looking tokens
_WC_CONST_RE = re.compile(r"^\d+('([bBdDhHoO])[0-9a-fA-FxXzZ_]+)?$")


def _infer_width_from_expr(expr: str) -> Optional[int]:
    """Best-effort static width from a Verilog expression string."""
    s = (expr or "").strip()
    if not s:
        return None
    # [hi:lo]
    m = _WC_STATIC_SLICE_RE.search(s)
    if m:
        hi, lo = int(m.group(1)), int(m.group(2))
        return abs(hi - lo) + 1
    # [base +: W] or [base -: W]
    m = _WC_PART_SEL_RE.search(s)
    if m:
        return int(m.group(1))
    # {N{body}}
    m = _WC_REP_RE.match(s)
    if m:
        n = int(m.group(1))
        body_w = _infer_width_from_expr(m.group(2).strip())
        if body_w is not None:
            return n * body_w
        return None
    # SV literal: N'b..., N'h..., etc.
    sv_m = re.match(r"^(\d+)'[bBdDhHoO][0-9a-fA-FxXzZ_]+$", s)
    if sv_m:
        return int(sv_m.group(1))
    return None


# Build a cheap signal→width table from all records.
# Scans both LHS and RHS; records the MAXIMUM slice width seen per signal
# (hi+1 from [hi:lo] is a conservative lower-bound on the full signal width).
_WC_SLICE_SCAN_RE = re.compile(r'([A-Za-z_]\w*)\s*\[(\d+)\s*:\s*(\d+)\]')

def _build_width_table(ir_records: List[Dict[str, Any]]) -> Dict[str, int]:
    table: Dict[str, int] = {}
    for rec in ir_records:
        for text in (rec.get("signal") or "", rec.get("rhs") or ""):
            if not text:
                continue
            for m in _WC_SLICE_SCAN_RE.finditer(text):
                name = m.group(1)
                hi   = int(m.group(2))
                # hi+1 is the minimum full width (slice goes up to bit hi)
                w = hi + 1
                if name not in table or w > table[name]:
                    table[name] = w
    return table


def _classify_rhs_width(rhs: str) -> Dict[str, Any]:
    """
    Classify RHS and return:
      transform  : IDENTITY | TRUNCATION | EXTENSION | DUPLICATION | REPOSITION | CONSTANT | UNKNOWN
      src_signal : bare name of primary source signal (if identifiable)
      src_width  : inferred width of source slice (if any)
      rep_factor : replication factor (DUPLICATION only)
      const_bits : number of constant padding bits (EXTENSION only)
    """
    rhs = (rhs or "").strip()

    # Replication: {N{body}}
    m = _WC_REP_RE.match(rhs)
    if m:
        n = int(m.group(1))
        body = m.group(2).strip()
        src = re.sub(r'\[.*$', '', body).strip()
        body_w = _infer_width_from_expr(body) or _infer_width_from_expr(src)
        return {"transform": "DUPLICATION", "src_signal": src,
                "src_width": body_w, "rep_factor": n, "const_bits": 0}

    # Concatenation: {a, b, ...}
    if _WC_CONCAT_RE.match(rhs):
        # Split top-level commas
        inner = rhs.strip()[1:-1]
        parts: List[str] = []
        depth = 0
        buf: List[str] = []
        for ch in inner:
            if ch == '{': depth += 1
            elif ch == '}': depth -= 1
            if ch == ',' and depth == 0:
                parts.append(''.join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        if buf:
            parts.append(''.join(buf).strip())

        const_bits = 0
        data_parts: List[str] = []
        for p in parts:
            if _WC_CONST_RE.match(p.strip()):
                w = _infer_width_from_expr(p.strip())
                const_bits += w if w else 0
            else:
                data_parts.append(p.strip())

        src = re.sub(r'\[.*$', '', data_parts[0]).strip() if data_parts else ""
        src_width = sum(
            (_infer_width_from_expr(p) or 0) for p in data_parts
        ) or None
        return {"transform": "EXTENSION", "src_signal": src,
                "src_width": src_width, "rep_factor": 1, "const_bits": const_bits}

    # Shift-only
    if _WC_SHIFT_RE.match(rhs):
        src = re.sub(r'\s*(<<|>>).*$', '', rhs).strip()
        src = re.sub(r'\[.*$', '', src).strip()
        src_w = _infer_width_from_expr(rhs.split('<<')[0].split('>>')[0].strip())
        return {"transform": "REPOSITION", "src_signal": src,
                "src_width": src_w, "rep_factor": 1, "const_bits": 0}

    # Bare slice of a signal
    if re.search(r'\[', rhs):
        src = re.sub(r'\[.*$', '', rhs).strip()
        src_w = _infer_width_from_expr(rhs)
        return {"transform": "TRUNCATION", "src_signal": src,
                "src_width": src_w, "rep_factor": 1, "const_bits": 0}

    # Pure constant
    if _WC_CONST_RE.match(rhs):
        return {"transform": "CONSTANT", "src_signal": "",
                "src_width": _infer_width_from_expr(rhs), "rep_factor": 1, "const_bits": 0}

    # Plain identifier — identity pass-through
    if re.match(r'^[A-Za-z_][A-Za-z0-9_.$]*$', rhs):
        return {"transform": "IDENTITY", "src_signal": rhs,
                "src_width": None, "rep_factor": 1, "const_bits": 0}

    return {"transform": "UNKNOWN", "src_signal": "",
            "src_width": None, "rep_factor": 1, "const_bits": 0}


def detect_width_conservation_violation(
    ir_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Detect datapath assignments where the information content of the RHS
    is not conserved by the LHS transformation.

    Violation subtypes:
        WIDTH_TRUNCATION                  — slice drops upper bits of source
        WIDTH_DUPLICATION_WITHOUT_MAPPING — {N{src}} with no matching lane steering
        WIDTH_EXTENSION_WITHOUT_SEMANTIC  — zero/constant padding with no defined meaning

    Returns violation dicts compatible with the datapath violation channel:
        class, subtype, always_block_id, source_signal, destination_signal,
        inferred_src_width, inferred_dst_width, transform_type,
        impact, source
    """
    width_table = _build_width_table(ir_records)
    violations: List[Dict[str, Any]] = []

    for rec in ir_records:
        # Skip continuous assigns — they are intentional port wiring.
        if (rec.get("process") or "").strip() == "assign":
            continue

        lhs = (rec.get("signal") or "").strip()
        rhs = (rec.get("rhs") or "").strip()
        if not lhs or not rhs:
            continue

        # Infer destination width from LHS
        lhs_base = re.sub(r'\[.*$', '', lhs).strip()
        dst_w = _infer_width_from_expr(lhs) or width_table.get(lhs_base)

        info = _classify_rhs_width(rhs)
        transform = info["transform"]
        src_sig = info["src_signal"]
        rhs_width = info["src_width"]   # width of the RHS expression itself (slice width)

        # src_full_w = full width of the source signal, from table (NOT the slice width).
        src_base   = re.sub(r'\[.*$', '', src_sig).strip() if src_sig else ""
        src_full_w = width_table.get(src_base)   # None if unknown

        bid     = rec.get("always_block_id")
        src_loc = rec.get("source", "")
        lineno  = rec.get("line")

        # ── Case 1: Truncation — RHS slice is narrower than the source signal ─
        if transform == "TRUNCATION" and src_full_w and rhs_width and rhs_width < src_full_w:
            m_s = _WC_STATIC_SLICE_RE.search(rhs)
            if m_s:
                hi         = int(m_s.group(1))
                dropped_hi = src_full_w - 1 - hi
                if dropped_hi > 0:
                    violations.append({
                        "class":               "WIDTH_CONSERVATION_VIOLATION",
                        "subtype":             "WIDTH_TRUNCATION",
                        "always_block_id":     bid,
                        "rtl_line":            lineno,
                        "source_signal":       src_sig,
                        "destination_signal":  lhs,
                        "inferred_src_width":  src_full_w,
                        "inferred_dst_width":  rhs_width,
                        "transform_type":      "TRUNCATION",
                        "impact": (
                            "Width conservation violated.\n"
                            f"'{lhs}' receives only [{hi}:0] of '{src_sig}' "
                            f"(width {src_full_w}).\n"
                            f"Upper {dropped_hi} bit(s) [bits {hi+1}–{src_full_w-1}] are "
                            "silently discarded.\n"
                            "Operation is not bijective — payload bits are lost.\n"
                            "Cannot recover original value from destination."
                        ),
                        "source": src_loc,
                    })

        # ── Case 2: Duplication without lane mapping ──────────────────────────
        elif transform == "DUPLICATION":
            n = info["rep_factor"]
            body_w = rhs_width  # width of one replica (from _classify_rhs_width)
            if n > 1:
                # Check if any record in the same block does lane-selective
                # writes (part-select on LHS using same source).
                block_recs = [
                    r for r in ir_records
                    if r.get("always_block_id") == bid
                    and r.get("signal", "") != lhs
                ]
                has_lane_steering = any(
                    re.search(r'\[.*\+:', r.get("signal", ""))
                    for r in block_recs
                )
                if not has_lane_steering:
                    violations.append({
                        "class":               "WIDTH_CONSERVATION_VIOLATION",
                        "subtype":             "WIDTH_DUPLICATION_WITHOUT_MAPPING",
                        "always_block_id":     bid,
                        "rtl_line":            lineno,
                        "source_signal":       src_sig,
                        "destination_signal":  lhs,
                        "inferred_src_width":  body_w,
                        "inferred_dst_width":  (body_w * n) if body_w else None,
                        "transform_type":      "DUPLICATION",
                        "rep_factor":          n,
                        "impact": (
                            "Width conservation violated.\n"
                            f"'{lhs}' = {{{n}{{{src_sig}}}}} replicates the source "
                            f"{n}× without any matching lane-steering logic.\n"
                            f"All {n} output lanes carry identical data.\n"
                            "The transformation is not invertible — "
                            f"{n} output bits map to each single input bit.\n"
                            "No lane bijection exists; entropy collapses to "
                            f"1/{n} of destination width.\n"
                            "This is a width adapter bug: use lane-selective "
                            "part-select writes instead."
                        ),
                        "source": src_loc,
                    })

        # ── Case 3: Extension with constant padding ───────────────────────────
        elif transform == "EXTENSION" and info["const_bits"] > 0:
            violations.append({
                "class":               "WIDTH_CONSERVATION_VIOLATION",
                "subtype":             "WIDTH_EXTENSION_WITHOUT_SEMANTIC",
                "always_block_id":     bid,
                "rtl_line":            lineno,
                "source_signal":       src_sig,
                "destination_signal":  lhs,
                "inferred_src_width":  src_full_w,
                "inferred_dst_width":  dst_w,
                "transform_type":      "EXTENSION",
                "const_padding_bits":  info["const_bits"],
                "impact": (
                    "Width conservation violated.\n"
                    f"'{lhs}' zero/constant-extends '{src_sig}' by "
                    f"{info['const_bits']} bit(s) with no defined semantic.\n"
                    "The added bits carry no information — the transformation "
                    "changes the numeric value without specifying intent.\n"
                    "Legal extensions require an explicit semantic: "
                    "address scaling, packing rule, or sign extension.\n"
                    "Without this, downstream logic may misinterpret the value."
                ),
                "source": src_loc,
            })

    return violations
