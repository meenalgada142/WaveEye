"""
merge_true_drivers.py
=====================
Preprocessing step for RTL causal analysis.

Merges multiple per-module true_drivers CSV files into a single
design_true_drivers.csv with namespaced signal identifiers to avoid
collisions in the global design graph.

Rules
-----
- Signal column:    module.signal_name
- RHS expression:   prefix identifiers, leave constants/FSM-states untouched
- Condition expr:   prefix signal identifiers, leave FSM state names untouched
- File column:      unchanged (source location preserved)

FSM state names (ALL_CAPS_UNDERSCORE tokens) are NOT prefixed.
Numeric / Verilog constants (0, 0x10, 8'h10, 4'b0000) are NOT prefixed.

Usage
-----
    python merge_true_drivers.py <dir_with_csvs> [output_file]

    # Example
    python merge_true_drivers.py ./analysis ./analysis/design_true_drivers.csv

    # Default output: design_true_drivers.csv next to the input CSVs
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Verilog numeric literal: optional_width ' base digits  (e.g. 8'h10, 4'b0101)
_VERILOG_LITERAL_RE = re.compile(
    r"\b\d*'[bBoOhHdD][0-9A-Fa-fxXzZ_]+\b"
)

# Plain integer or hex constant: 0, 123, 0x1F
_PLAIN_CONST_RE = re.compile(r"\b0[xX][0-9A-Fa-f]+\b|\b\d+\b")

# FSM state: ALL_CAPS token, at least 2 chars, may contain digits/underscores
# e.g. IDLE, READ_ADDR, STATE_0
_FSM_STATE_RE = re.compile(r"\b([A-Z][A-Z0-9_]{1,})\b")

# General identifier: starts with letter/underscore, may have dots/brackets already
_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")


def _is_constant_token(token: str) -> bool:
    """Return True if the token is a numeric constant."""
    return bool(_PLAIN_CONST_RE.fullmatch(token)) or bool(_VERILOG_LITERAL_RE.fullmatch(token))


def _is_fsm_state(token: str) -> bool:
    """
    Return True if token looks like a FSM state constant
    (ALL_CAPS_WITH_OPTIONAL_DIGITS, length >= 2).
    Heuristic: all uppercase letters + digits + underscores, starts with A-Z.
    """
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]+", token))


def _prefix_identifiers(expr: str, module: str, prefix_fsm: bool = False) -> str:
    """
    Prefix every bare identifier in *expr* with ``module.``.

    - Numeric/Verilog literals are never prefixed.
    - FSM state names (ALL_CAPS) are never prefixed (unless prefix_fsm=True).
    - Tokens that already contain a dot are not re-prefixed.
    - SV keywords (posedge, negedge, or, and, not, if, else) are skipped.

    The function handles expressions like:
        write_state == IDLE
        count_internal == 0
        AWADDR == 8'h10
        latched | irq_in
        4'b0000
    """
    if not expr or not expr.strip():
        return expr

    _SV_KEYWORDS = frozenset({
        "posedge", "negedge", "or", "and", "not", "if", "else",
        "begin", "end", "always", "assign", "wire", "reg", "logic",
        "input", "output", "inout", "module", "endmodule",
    })

    # We process token by token, preserving whitespace/punctuation.
    # Strategy: find all identifier spans, decide whether to prefix them.
    result = []
    pos = 0
    for m in _IDENT_RE.finditer(expr):
        # Append any gap before this match
        result.append(expr[pos:m.start()])
        token = m.group(1)
        pos = m.end()

        # Skip if already namespaced (has a dot before it)
        before = expr[:m.start()]
        if before.endswith("."):
            result.append(token)
            continue

        # Skip SV keywords
        if token in _SV_KEYWORDS:
            result.append(token)
            continue

        # Skip Verilog literal placeholders (injected by _prefix_rhs)
        if token.startswith("VLIT") and token.endswith("PH"):
            result.append(token)
            continue

        # Skip pure FSM state names (unless caller wants them prefixed)
        if not prefix_fsm and _is_fsm_state(token):
            result.append(token)
            continue

        # Skip pure integer tokens (matched as identifiers only if starts with letter)
        # (The _IDENT_RE won't match pure digits — this is belt-and-suspenders)
        if _is_constant_token(token):
            result.append(token)
            continue

        # Prefix
        result.append(f"{module}.{token}")

    # Append tail
    result.append(expr[pos:])
    return "".join(result)


def _prefix_rhs(rhs: str, module: str) -> str:
    """Prefix signal identifiers in an RHS expression."""
    if not rhs:
        return rhs
    # First protect Verilog literals from being mangled by the identifier regex
    # by temporarily replacing them with placeholders.
    placeholders: List[str] = []

    def _stash(m: re.Match) -> str:
        idx = len(placeholders)
        placeholders.append(m.group(0))
        return f"VLIT{idx}PH"  # starts with V (letter) but has unique suffix pattern

    rhs_protected = _VERILOG_LITERAL_RE.sub(_stash, rhs)
    rhs_prefixed = _prefix_identifiers(rhs_protected, module, prefix_fsm=False)

    # Restore Verilog literals
    for i, lit in enumerate(placeholders):
        rhs_prefixed = rhs_prefixed.replace(f"VLIT{i}PH", lit)

    return rhs_prefixed


def _prefix_condition(cond: str, module: str) -> str:
    """Prefix signal identifiers in a condition expression (FSM states untouched)."""
    return _prefix_rhs(cond, module)  # same logic — FSM states are untouched


# ---------------------------------------------------------------------------
# Module name extraction
# ---------------------------------------------------------------------------

def _module_name(csv_path: Path) -> str:
    """Extract module name from filename: foo_true_drivers.csv → foo."""
    stem = csv_path.stem  # e.g. "interrupt_controller_true_drivers"
    if stem.endswith("_true_drivers"):
        return stem[: -len("_true_drivers")]
    return stem


# ---------------------------------------------------------------------------
# Core merge
# ---------------------------------------------------------------------------

def merge_true_drivers(
    csv_paths: List[Path],
    output_path: Path,
) -> int:
    """
    Merge and namespace all CSV files into *output_path*.

    Returns the total number of rows written.
    """
    total_rows = 0
    writer: Optional[csv.DictWriter] = None
    fieldnames: Optional[List[str]] = None

    with open(output_path, "w", newline="", encoding="utf-8") as out_fh:
        for csv_path in csv_paths:
            module = _module_name(csv_path)
            with open(csv_path, newline="", encoding="utf-8") as in_fh:
                reader = csv.DictReader(in_fh)

                if fieldnames is None:
                    fieldnames = list(reader.fieldnames or [])
                    # Add module column if not present
                    if "module" not in fieldnames:
                        fieldnames = ["module"] + fieldnames
                    writer = csv.DictWriter(out_fh, fieldnames=fieldnames,
                                            extrasaction="ignore")
                    writer.writeheader()

                for row in reader:
                    sig = (row.get("signal") or "").strip()

                    # Blank rows — write as empty row (preserves visual grouping)
                    if not sig:
                        writer.writerow({k: "" for k in fieldnames})
                        total_rows += 1
                        continue

                    # Pass through separator rows as-is (e.g. "--- NEXT DRIVER ---")
                    if sig.startswith("---") or sig.startswith("==="):
                        row["module"] = module
                        writer.writerow(row)
                        total_rows += 1
                        continue

                    # Namespace the primary signal
                    if "." not in sig:
                        row["signal"] = f"{module}.{sig}"

                    # Namespace RHS identifiers
                    rhs = (row.get("rhs") or "").strip()
                    if rhs:
                        row["rhs"] = _prefix_rhs(rhs, module)

                    # Namespace condition identifiers
                    cond = (row.get("condition") or "").strip()
                    if cond:
                        row["condition"] = _prefix_condition(cond, module)

                    # Namespace parent/alias_chain columns if present
                    for col in ("parent", "alias_chain"):
                        val = (row.get(col) or "").strip()
                        if val and "." not in val:
                            row[col] = f"{module}.{val}"

                    # Inject module column
                    row["module"] = module

                    writer.writerow(row)
                    total_rows += 1

    return total_rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("Usage: merge_true_drivers.py <dir_with_csvs> [output_file]")
        sys.exit(1)

    input_dir = Path(args[0])
    if not input_dir.is_dir():
        print(f"Error: '{input_dir}' is not a directory")
        sys.exit(1)

    csv_files = sorted(
        f for f in input_dir.glob("*_true_drivers.csv")
        if f.name != "design_true_drivers.csv"
    )
    if not csv_files:
        print(f"No *_true_drivers.csv files found in {input_dir}")
        sys.exit(1)

    if len(args) >= 2:
        output_path = Path(args[1])
    else:
        output_path = input_dir / "design_true_drivers.csv"

    print(f"Merging {len(csv_files)} module(s) -> {output_path}")
    for f in csv_files:
        mod = _module_name(f)
        print(f"  {mod:40s}  ({f.name})")

    n = merge_true_drivers(csv_files, output_path)
    print(f"\nWrote {n} rows to {output_path}")


if __name__ == "__main__":
    main()
