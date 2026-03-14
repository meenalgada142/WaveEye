#!/usr/bin/env python3
"""
FSM Encoding Extractor
=====================

Extracts ALL FSM encodings from RTL:
  1. typedef enum
  2. localparam / parameter

NO waveform
NO guessing
NO external JSON inputs
"""

import os
import pyslang
import json
from pathlib import Path

_PROD_VERBOSE: bool = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def parse_literal_token(txt):
    if not txt:
        return None

    t = txt.strip().lower()

    if "'b" in t:
        return int(t.split("'b")[1], 2)
    if t.startswith("0x"):
        return int(t, 16)
    if t.isdigit():
        return int(t)

    return None


# ------------------------------------------------------------
# Enum extraction
# ------------------------------------------------------------

def extract_enums(root):
    enums = {}

    def visit(node):
        if node is None:
            return

        if node.kind.name == "TypedefDeclaration":
            enum_type = node.type
            if enum_type and enum_type.kind.name == "EnumType":
                enum_name = node.name.valueText
                members = {}
                value = 0

                for m in enum_type.members:
                    if isinstance(m, pyslang.DeclaratorSyntax):
                        members[m.name.valueText] = value
                        value += 1

                enums[enum_name] = members

        if hasattr(node, "members"):
            for m in node.members:
                visit(m)

    visit(root)
    return enums


# ------------------------------------------------------------
# Localparam / parameter extraction
# ------------------------------------------------------------
def extract_localparams(root):
    params = {}

    def walk(node):
        if node is None:
            return

        # localparam lives here
        if isinstance(node, pyslang.ParameterDeclarationStatementSyntax):
            param_decl = node.parameter

            for decl in param_decl.declarators:
                if not isinstance(decl, pyslang.DeclaratorSyntax):
                    continue

                name = decl.name.valueText

                if decl.initializer:
                    # FIXED: Safe extraction that handles different node types
                    try:
                        raw_parts = []
                        expr = decl.initializer.expr
                        
                        # Handle different expression types
                        if hasattr(expr, '__iter__'):
                            # It's iterable (list of tokens)
                            for tok in expr:
                                if hasattr(tok, 'rawText'):
                                    raw_parts.append(tok.rawText)
                                elif hasattr(tok, 'valueText'):
                                    raw_parts.append(tok.valueText)
                                elif hasattr(tok, 'name') and hasattr(tok.name, 'valueText'):
                                    raw_parts.append(tok.name.valueText)
                        else:
                            # It's a single node
                            if hasattr(expr, 'rawText'):
                                raw_parts.append(expr.rawText)
                            elif hasattr(expr, 'valueText'):
                                raw_parts.append(expr.valueText)
                            elif hasattr(expr, 'name') and hasattr(expr.name, 'valueText'):
                                raw_parts.append(expr.name.valueText)
                        
                        raw = "".join(raw_parts)
                        val = parse_literal_token(raw)

                        if val is not None:
                            params[name] = val
                            if _PROD_VERBOSE:
                                print(f"[FOUND LOCALPARAM] {name} = {val}")

                    except Exception as e:
                        # If extraction fails, skip this parameter
                        if _PROD_VERBOSE:
                            print(f"[SKIP] Could not extract value for {name}: {e}")

        # recurse
        if hasattr(node, "members"):
            for m in node.members:
                walk(m)
        if hasattr(node, "items"):
            for i in node.items:
                walk(i)
        if hasattr(node, "statement"):
            walk(node.statement)

    walk(root)
    return params



# ------------------------------------------------------------
# Top-level driver
# ------------------------------------------------------------

def extract_fsm_encodings(rtl_file):
    tree = pyslang.SyntaxTree.fromFile(str(rtl_file))
    root = tree.root

    enums = extract_enums(root)
    localparams = extract_localparams(root)

    return {
        "enums": enums,
        "localparams": localparams
    }


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage:")
        print("  python extract_fsm_encodings.py design.sv")
        sys.exit(1)

    rtl = Path(sys.argv[1])
    out = rtl.stem + ".fsm_encodings.json"

    enc = extract_fsm_encodings(rtl)

    with open(out, "w") as f:
        json.dump(enc, f, indent=2)

    print(f"[OK] FSM encodings written to {out}")
    print(f"  enums       : {len(enc['enums'])}")
    print(f"  localparams : {len(enc['localparams'])}")