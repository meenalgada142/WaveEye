import pyslang
import json
import os
from pathlib import Path
from pyslang import SyntaxKind
import sys

from semantic_checks.memory_write_analysis import (
    detect_memory_write_semantic_mismatch,
    detect_lane_bijection_violation,
    detect_mask_conservation_violation,
    detect_width_conservation_violation,
)
from semantic_checks.invertibility import detect_invertibility_violation
from semantic_checks.transport_semantic_analysis import (
    detect_transport_semantic_mismatch,
    detect_address_monotonicity_violation,
)
from rca_core.semantic_datapath_analysis import detect_semantic_datapath_violations

# ----------------------------
# IR Builder
# ----------------------------
# Check for verbose flag
DEBUG = '--verbose' in sys.argv or '--trace' in sys.argv or '-v' in sys.argv
_PROD_VERBOSE: bool = os.environ.get("WAVEEYE_VERBOSE", "0") == "1"
STRICT_GUARD_EXCLUSION = os.getenv("WAVEEYE_STRICT_GUARD_EXCLUSION", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

import re

class GuardNormalizer:
    def normalize(self, guard: str) -> str:
        if guard is None:
            return guard

        g = guard.strip()

        # ----------------------------
        # 1. Remove leading "true &&"
        # ----------------------------
        g = re.sub(r'^true\s*&&\s*', '', g)

        # ----------------------------
        # 2. Remove trailing "&& true"
        # ----------------------------
        g = re.sub(r'\s*&&\s*true$', '', g)

        # ----------------------------
        # 3. Replace !(!X) -> X
        #    Repeat until stable
        # ----------------------------
        prev = None
        while prev != g:
            prev = g
            g = re.sub(r'!\(\s*!\s*([^)]+)\)', r'\1', g)

        # ----------------------------
        # 4. Remove redundant parentheses: (X) -> X
        #    Only if no operators inside
        # ----------------------------
        g = re.sub(r'\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', r'\1', g)

        # ----------------------------
        # 5. Normalize spacing
        # ----------------------------
        g = re.sub(r'\s+', ' ', g).strip()

        return g


def _strip_outer_parens_expr(text: str) -> str:
    s = (text or "").strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        whole = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    whole = False
                    break
                if depth == 0 and i != len(s) - 1:
                    whole = False
                    break
        if not whole or depth != 0:
            break
        s = s[1:-1].strip()
    return s


def _is_constant_like(token: str) -> bool:
    t = (token or "").strip()
    if not t:
        return False
    if re.match(r"^\d+$", t):
        return True
    if re.match(r"^\d+'[bBdDhHoO][0-9a-fA-FxXzZ_]+$", t):
        return True
    # Treat enum-style ALL_CAPS names as constants.
    if re.match(r"^[A-Z][A-Z0-9_]*$", t):
        return True
    return False


def _is_identifier_like(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_:\[\]\.']*$", (token or "").strip()))


_ATOM_CMP_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_:\[\]\.']*|\d+'[bBdDhHoO][0-9a-fA-FxXzZ_]+|\d+)\s*(==|!=)\s*([A-Za-z_][A-Za-z0-9_:\[\]\.']*|\d+'[bBdDhHoO][0-9a-fA-FxXzZ_]+|\d+)\s*$"
)


def _canonicalize_atom_text(atom_text: str) -> str:
    a = _strip_outer_parens_expr(atom_text)
    m = _ATOM_CMP_RE.match(a)
    if not m:
        return re.sub(r"\s+", " ", a).strip()

    lhs, op, rhs = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()

    # Keep identifiers on the left and constant-like terms on the right.
    if _is_constant_like(lhs) and not _is_constant_like(rhs):
        lhs, rhs = rhs, lhs
    elif _is_identifier_like(lhs) and _is_identifier_like(rhs):
        lhs_const = _is_constant_like(lhs)
        rhs_const = _is_constant_like(rhs)
        # Preserve identifier == CONST orientation when only one side is constant-like.
        if lhs_const and not rhs_const:
            lhs, rhs = rhs, lhs
        elif lhs_const == rhs_const:
            # Stable commutative ordering for stylistic variants.
            if lhs.lower() > rhs.lower():
                lhs, rhs = rhs, lhs

    return f"{lhs} {op} {rhs}"


def _canonicalize_ast(node):
    kind = node[0]
    if kind == "const":
        return node
    if kind == "atom":
        return ("atom", _canonicalize_atom_text(node[1]))
    if kind == "not":
        return ("not", _canonicalize_ast(node[1]))
    if kind in ("and", "or"):
        return (kind, _canonicalize_ast(node[1]), _canonicalize_ast(node[2]))
    return node


def _ast_to_text(node):
    kind = node[0]
    if kind == "const":
        return "true" if node[1] else "false"
    if kind == "atom":
        return node[1]
    if kind == "not":
        child = _ast_to_text(node[1])
        return f"!({child})"
    if kind == "and":
        return f"({_ast_to_text(node[1])}) && ({_ast_to_text(node[2])})"
    if kind == "or":
        return f"({_ast_to_text(node[1])}) || ({_ast_to_text(node[2])})"
    return str(node)


def canonicalize_boolean(expr: str) -> str:
    """
    Canonicalize predicate text:
      - normalize equality direction
      - collapse stylistic variants to stable forms
      - strip redundant outer parentheses and whitespace
    """
    s = re.sub(r"\s+", " ", (expr or "").strip()).strip()
    if not s:
        return s
    try:
        parser = _BoolExprParser(s)
        ast = parser.parse()
        ast = _canonicalize_ast(ast)
        out = _ast_to_text(ast)
        out = _strip_outer_parens_expr(out)
        return re.sub(r"\s+", " ", out).strip()
    except Exception:
        return _strip_outer_parens_expr(s)


class _BoolExprParser:
    """
    Minimal parser for guard exclusivity checks.
    Supports: !, &&, ||, parentheses, and opaque atomic predicates.
    """
    def __init__(self, expr: str):
        self.raw = expr or ""
        self.placeholder_map = {}
        self.tokens = self._tokenize(self._collapse_non_boolean_parens(self.raw))
        self.pos = 0

    def _collapse_non_boolean_parens(self, expr: str) -> str:
        """
        Replace parenthesized chunks that do not contain boolean operators with
        opaque placeholders so arithmetic/comparison parens don't confuse parsing.
        """
        s = expr
        counter = 0
        pat = re.compile(r"\(([^()]*)\)")
        changed = True
        while changed:
            changed = False

            def repl(m):
                nonlocal counter, changed
                inner = m.group(1)
                # Preserve explicit boolean structure (especially negation)
                # so patterns like !((A == B)) are parsed as NOT(atom),
                # not as a new opaque atom.
                if "&&" in inner or "||" in inner or "!" in inner:
                    return m.group(0)
                key = f"__ATOMP_{counter}__"
                counter += 1
                self.placeholder_map[key] = m.group(0)
                changed = True
                return key

            s = pat.sub(repl, s)
        return s

    def _expand_placeholders(self, text: str) -> str:
        out = text
        changed = True
        while changed:
            changed = False
            for k, v in self.placeholder_map.items():
                if k in out:
                    out = out.replace(k, v)
                    changed = True
        return out

    def _strip_outer_parens(self, text: str) -> str:
        s = text.strip()
        while s.startswith("(") and s.endswith(")"):
            depth = 0
            balanced_whole = True
            for i, ch in enumerate(s):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth < 0:
                        balanced_whole = False
                        break
                    if depth == 0 and i != len(s) - 1:
                        balanced_whole = False
                        break
            if not balanced_whole or depth != 0:
                break
            s = s[1:-1].strip()
        return s

    def _tokenize(self, expr: str):
        tokens = []
        i = 0
        n = len(expr)
        while i < n:
            ch = expr[i]
            if ch.isspace():
                i += 1
                continue
            if i + 1 < n and expr[i:i+2] in ("&&", "||"):
                tokens.append(expr[i:i+2])
                i += 2
                continue
            if ch in ("!", "(", ")"):
                tokens.append(ch)
                i += 1
                continue
            j = i
            while j < n:
                if expr[j] in ("!", "(", ")"):
                    break
                if j + 1 < n and expr[j:j+2] in ("&&", "||"):
                    break
                j += 1
            atom = expr[i:j].strip()
            if atom:
                tokens.append(atom)
            i = j
        return tokens

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self, expected=None):
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of boolean expression")
        if expected is not None and tok != expected:
            raise ValueError(f"expected '{expected}', got '{tok}'")
        self.pos += 1
        return tok

    def _parse_or(self):
        node = self._parse_and()
        while self._peek() == "||":
            self._consume("||")
            rhs = self._parse_and()
            node = ("or", node, rhs)
        return node

    def _parse_and(self):
        node = self._parse_unary()
        while self._peek() == "&&":
            self._consume("&&")
            rhs = self._parse_unary()
            node = ("and", node, rhs)
        return node

    def _parse_unary(self):
        tok = self._peek()
        if tok == "!":
            self._consume("!")
            return ("not", self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self):
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end in primary expression")
        if tok == "(":
            self._consume("(")
            node = self._parse_or()
            self._consume(")")
            return node

        atom = self._consume()
        atom_text = self._expand_placeholders(atom)
        atom_text = self._strip_outer_parens(atom_text)
        low = atom_text.lower()
        if low == "true":
            return ("const", True)
        if low == "false":
            return ("const", False)
        return ("atom", atom_text)

    def parse(self):
        if not self.tokens:
            return ("const", True)
        node = self._parse_or()
        if self._peek() is not None:
            raise ValueError(f"trailing token '{self._peek()}'")
        return node


def _collect_atoms(node, out=None):
    if out is None:
        out = set()
    kind = node[0]
    if kind == "atom":
        out.add(node[1])
    elif kind == "not":
        _collect_atoms(node[1], out)
    elif kind in ("and", "or"):
        _collect_atoms(node[1], out)
        _collect_atoms(node[2], out)
    return out


def _eval_partial(node, env):
    kind = node[0]
    if kind == "const":
        return bool(node[1])
    if kind == "atom":
        return env.get(node[1], None)
    if kind == "not":
        v = _eval_partial(node[1], env)
        return None if v is None else (not v)
    if kind == "and":
        a = _eval_partial(node[1], env)
        if a is False:
            return False
        b = _eval_partial(node[2], env)
        if b is False:
            return False
        if a is True and b is True:
            return True
        return None
    if kind == "or":
        a = _eval_partial(node[1], env)
        if a is True:
            return True
        b = _eval_partial(node[2], env)
        if b is True:
            return True
        if a is False and b is False:
            return False
        return None
    return None


_CMP_TOKEN = r"(?:[A-Za-z_][A-Za-z0-9_:\[\]\.']*|\d+'[bBdDhHoO][0-9a-fA-FxXzZ_]+|\d+)"
_CMP_RE = re.compile(
    rf"^\s*({_CMP_TOKEN})\s*(==|!=)\s*({_CMP_TOKEN})\s*$"
)
_SV_LIT_RE = re.compile(r"^\s*(\d+)'([bBdDhHoO])([0-9a-fA-FxXzZ_]+)\s*$")


def _normalize_compare_value(token: str) -> str:
    """
    Normalize literal-like RHS values so semantically identical encodings
    (e.g. 2'b00, 1'b0, 0) compare equal in consistency checks.
    """
    t = (token or "").strip()
    if not t:
        return t

    if re.match(r"^\d+$", t):
        try:
            return str(int(t, 10))
        except Exception:
            return t

    m = _SV_LIT_RE.match(t)
    if not m:
        return t

    base_ch = m.group(2).lower()
    digits = (m.group(3) or "").replace("_", "")
    if any(ch in digits.lower() for ch in ("x", "z")):
        # Unknown / high-impedance values are not safely numeric.
        return t

    base = {"b": 2, "o": 8, "d": 10, "h": 16}.get(base_ch, 10)
    try:
        return str(int(digits, base))
    except Exception:
        return t


def _comparison_atom_parts(atom_text: str):
    text = _canonicalize_atom_text(_strip_outer_parens_expr(atom_text or ""))
    m = _CMP_RE.match(text)
    if not m:
        return None
    lhs = m.group(1).strip()
    op = m.group(2).strip()
    rhs = _normalize_compare_value(m.group(3).strip())
    return lhs, op, rhs


def _env_is_consistent(env):
    """
    Lightweight propositional consistency for equality-style atoms:
      - (x==A) and (x==B) cannot both be true when A!=B
      - (x==A) and (x!=A) are logical complements
    """
    by_lhs = {}
    for atom, val in env.items():
        parts = _comparison_atom_parts(atom)
        if parts is None:
            continue
        lhs, op, rhs = parts
        ent = by_lhs.setdefault(lhs, {"eq": {}, "ne": {}})
        ent["eq" if op == "==" else "ne"][rhs] = bool(val)

    for lhs, ent in by_lhs.items():
        eq_map = ent["eq"]
        ne_map = ent["ne"]

        # Complement check: (x==A) and (x!=A) must have opposite truth values.
        for rhs in set(eq_map.keys()) & set(ne_map.keys()):
            if eq_map[rhs] == ne_map[rhs]:
                return False

        # Multiple true equalities to different rhs values are impossible.
        true_eq_rhs = [rhs for rhs, v in eq_map.items() if v]
        if len(set(true_eq_rhs)) > 1:
            return False

        # If x==A is true then x!=A cannot be true (already covered above),
        # and x!=B for B!=A may be either true or false depending on domain;
        # we intentionally keep this conservative.
    return True


def _is_satisfiable(node):
    atoms = sorted(_collect_atoms(node))

    def dfs(idx, env):
        if not _env_is_consistent(env):
            return False
        v = _eval_partial(node, env)
        if v is True:
            return True
        if v is False:
            return False
        if idx >= len(atoms):
            return False
        a = atoms[idx]
        env[a] = False
        if dfs(idx + 1, env):
            return True
        env[a] = True
        if dfs(idx + 1, env):
            return True
        del env[a]
        return False

    return dfs(0, {})


def _guards_can_overlap(guard_a: str, guard_b: str) -> bool:
    conj = f"({guard_a}) && ({guard_b})"
    parser = _BoolExprParser(conj)
    ast = parser.parse()
    return _is_satisfiable(ast)


def _guard_is_unsat(guard: str) -> bool:
    parser = _BoolExprParser(guard or "")
    ast = parser.parse()
    return not _is_satisfiable(ast)


def validate_guard_mutual_exclusion(ir_records):
    """
    Invariant:
      Within each if/else-if/else priority chain, assignments to the same signal
      must have mutually exclusive guards.
    Raises ValueError on overlap or on un-checkable guards.
    """
    grouped = {}
    for rec in ir_records:
        bid = rec.get("always_block_id")
        cid = rec.get("if_chain_id")
        if bid is None:
            continue
        if cid is None:
            continue
        sig = (rec.get("signal") or "").strip()
        if not sig:
            continue
        grouped.setdefault((bid, cid, sig), []).append(rec)

    for (bid, cid, sig), recs in grouped.items():
        if len(recs) <= 1:
            continue
        declared_exclusive = any(bool(r.get("declared_exclusive")) for r in recs)
        for rec in recs:
            g = (rec.get("guard") or "").strip()
            if not g:
                raise ValueError(
                    f"Extraction error: missing guard for always_block_id={bid}, if_chain_id={cid}, signal={sig}"
                )
            try:
                if _guard_is_unsat(g):
                    raise ValueError(
                        "Extraction error: contradictory guard inside priority chain "
                        f"always_block_id={bid}, if_chain_id={cid}, signal={sig}\n"
                        f"guard={g}"
                    )
            except ValueError:
                raise
            except Exception as e:
                raise ValueError(
                    "Extraction error: unable to validate guard satisfiability "
                    f"for always_block_id={bid}, if_chain_id={cid}, signal={sig}\n"
                    f"guard={g}\n"
                    f"reason={e}"
                )

        # Trust RTL-declared exclusivity (unique/priority) and skip overlap SAT checks.
        if declared_exclusive:
            continue

        for i in range(len(recs)):
            for j in range(i + 1, len(recs)):
                ga = (recs[i].get("guard") or "").strip()
                gb = (recs[j].get("guard") or "").strip()
                if ga.lower() == "true" or gb.lower() == "true":
                    raise ValueError(
                        "Extraction error: unconditional guard detected inside priority chain "
                        f"always_block_id={bid}, if_chain_id={cid}, signal={sig}\n"
                        f"guard_a={ga}\n"
                        f"guard_b={gb}"
                    )
                if not ga or not gb:
                    raise ValueError(
                        f"Extraction error: missing guard for always_block_id={bid}, if_chain_id={cid}, signal={sig}"
                    )
                try:
                    overlap = _guards_can_overlap(ga, gb)
                except Exception as e:
                    raise ValueError(
                        "Extraction error: unable to verify guard exclusivity "
                        f"for always_block_id={bid}, if_chain_id={cid}, signal={sig}\n"
                        f"guard_a={ga}\n"
                        f"guard_b={gb}\n"
                        f"reason={e}"
                    )
                if overlap:
                    msg = (
                        "Extraction error: non-mutually-exclusive guards "
                        f"for always_block_id={bid}, if_chain_id={cid}, signal={sig}\n"
                        f"guard_a={ga}\n"
                        f"guard_b={gb}"
                    )
                    if STRICT_GUARD_EXCLUSION:
                        raise ValueError(msg)
                    # Keep extraction resilient for common default+override RTL patterns.
                    print(f"[WARN] {msg}\n[WARN] Continuing; enable WAVEEYE_STRICT_GUARD_EXCLUSION=1 to hard-fail.")


def detect_cross_domain_reference(ir_records, chain_info):
    """
    Ensure synthesized exclusion terms inside a chain only reference
    that chain's local predicate domain.
    """
    chain_terms = {}
    for cid, info in (chain_info or {}).items():
        conds = info.get("conditions") or []
        chain_terms[cid] = set(conds)

    for rec in ir_records:
        cid = rec.get("if_chain_id")
        if cid is None:
            continue
        if rec.get("declared_exclusive"):
            continue
        own_terms = chain_terms.get(cid, set())
        ex_terms = rec.get("chain_exclusion_terms") or []
        for t in ex_terms:
            if t not in own_terms:
                raise ValueError(
                    "Extraction error: cross-domain exclusion reference detected "
                    f"for if_chain_id={cid}, parent_if_chain_id={rec.get('if_chain_parent_id')}, "
                    f"signal={rec.get('signal')}\n"
                    f"guard={rec.get('guard')}\n"
                    f"foreign_term={t}\n"
                    f"local_domain={sorted(own_terms)}"
                )


class IRBuilder:
    def __init__(self):
        self.ir = []
        self.cond_stack = []
        self.always_block_counter = 0  # NEW: Track always blocks
        self.guard_normalizer = GuardNormalizer()
        self.if_chain_counter = 0
        self.if_chain_stack = []
        self.if_chain_declared_exclusive_stack = []
        self.chain_exclusion_terms_stack = []
        self.chain_info = {}
        self.source_manager = None  # set per-tree in build()

    def _format_source_loc(self, asn):
        """Return (source_str, line_int) from a syntax node's sourceRange.

        Uses the pyslang SourceManager stored in self.source_manager.
        Falls back gracefully if the manager is unavailable.
        Returns ("filename.sv:42", 42) on success, ("", None) on failure.
        """
        try:
            sm = self.source_manager
            if sm is None:
                return "", None
            sr = asn.sourceRange
            loc = sr.start
            fname = sm.getFileName(loc)
            lineno = sm.getLineNumber(loc)
            short = Path(fname).name if fname else ""
            source_str = f"{short}:{lineno}" if short else (str(lineno) if lineno else "")
            return source_str, int(lineno) if lineno is not None else None
        except Exception:
            return "", None

    def node_text(self, node):
        if node is None:
            return ""
        try:
            return self.syntaxnode_to_text(node)
        except Exception:
            return str(node)


    # ---------- helpers ----------
    def cur_cond(self):
        return self.cond_stack[-1] if self.cond_stack else "true"

    def push_cond(self, c):
        self.cond_stack.append(c)

    def pop_cond(self):
        self.cond_stack.pop()

    def cur_if_chain_id(self):
        return self.if_chain_stack[-1] if self.if_chain_stack else None

    def cur_declared_exclusive(self):
        return self.if_chain_declared_exclusive_stack[-1] if self.if_chain_declared_exclusive_stack else False

    def cur_chain_exclusion_terms(self):
        return list(self.chain_exclusion_terms_stack[-1]) if self.chain_exclusion_terms_stack else []

    def cur_if_chain_parent_id(self):
        if not self.if_chain_stack:
            return None
        cid = self.if_chain_stack[-1]
        info = self.chain_info.get(cid, {})
        return info.get("parent_chain_id")

    def _normalize_and_canonicalize_guard(self, text: str) -> str:
        return canonicalize_boolean(self.guard_normalizer.normalize(text or ""))

    def _if_declared_exclusive(self, cond_stmt) -> bool:
        """
        Detect SystemVerilog unique/priority qualifiers.
        Pyslang commonly exposes this as 'uniqueOrPriority'.
        """
        if cond_stmt is None:
            return False

        cand_attrs = (
            "uniqueOrPriority",
            "ifQualifier",
            "qualifier",
            "uniqueOrPriorityKeyword",
        )
        for a in cand_attrs:
            if not hasattr(cond_stmt, a):
                continue
            q = getattr(cond_stmt, a)
            if q is None:
                continue
            qtxt = self.node_text(q).strip().lower()
            if not qtxt:
                qtxt = str(q).strip().lower()

            ktxt = ""
            if hasattr(q, "kind"):
                try:
                    ktxt = str(q.kind).strip().lower()
                except Exception:
                    ktxt = ""

            merged = f"{qtxt} {ktxt}".strip()
            if not merged:
                continue
            if "unknown" in merged or "none" in merged:
                continue
            if "unique" in merged or "priority" in merged:
                return True
        return False

    def token_text(self, tok):
        if tok is None:
            return ""
        if hasattr(tok, "rawText"):
            return tok.rawText
        if hasattr(tok, "valueText"):
            return tok.valueText
        return str(tok)
    
    def cond_to_string(self, predicate):
        return self.syntaxnode_to_text(predicate.conditions)
    
    def syntaxnode_to_text(self, node):
        if node is None:
            return ""
        try:
            return "".join(tok.rawText for tok in node).strip()
        except Exception:
            return str(node).strip()

    def extract_clock_and_reset(self, timing_stmt):
        clk = None
        clk_edge = None
        rst = None
        rst_edge = None

        tc = timing_stmt.timingControl
        if tc is None:
            return clk, clk_edge, rst, rst_edge

        # -----------------------------
        # CASE 1: always @(*)
        # -----------------------------
        if tc.__class__.__name__ == "ImplicitEventControlSyntax":
            # combinational block
            return None, None, None, None

        # -----------------------------
        # CASE 2: always @(posedge ... or negedge ...)
        # -----------------------------
        text = self.syntaxnode_to_text(tc.expr)
        text = text.strip().strip("()")

        parts = [p.strip() for p in text.split("or")]

        for p in parts:
            if p.startswith("posedge"):
                sig = p[len("posedge"):].strip()
                if clk is None:
                    clk = sig
                    clk_edge = "posedge"
                else:
                    rst = sig
                    rst_edge = "posedge"

            elif p.startswith("negedge"):
                sig = p[len("negedge"):].strip()
                if clk is None:
                    clk = sig
                    clk_edge = "negedge"
                else:
                    rst = sig
                    rst_edge = "negedge"

        return clk, clk_edge, rst, rst_edge


    def dump_predicate_api(self, pred):
        
        for name in dir(pred):
            if name.startswith("_"):
                continue
            try:
                val = getattr(pred, name)
                if callable(val):
                    print(f"{name}(): callable")
                else:
                    print(f"{name}: {type(val)} -> {val}")
            except Exception as e:
                print(f"{name}: ERROR -> {e}")

        print("\n--- SOURCE RANGE ---")
        try:
            sr = pred.sourceRange
            print("sourceRange:", sr)
            print("dir(sourceRange):", dir(sr))
        except Exception as e:
            print("NO sourceRange:", e)

        print("=== END DUMP ===\n")

    def emit_assign(self, asn, proc_meta):
        if proc_meta is None:
            return

        rec = {
            "signal": self.node_text(asn.left),
            "process": proc_meta["process"],
            "clock": proc_meta["clock"],
            "clock_edge": proc_meta["clock_edge"],
            "reset": proc_meta["reset"],
            "reset_edge": proc_meta["reset_edge"],
            "guard": self.cur_cond(),
            "rhs": self.node_text(asn.right),
            "timing": (
                "next_cycle"
                if asn.kind == SyntaxKind.NonblockingAssignmentExpression
                else "same_cycle"
            ),
            "always_block_id": proc_meta.get("always_block_id"),  # NEW: Add always block ID
            "if_chain_id": self.cur_if_chain_id(),
            "if_chain_parent_id": self.cur_if_chain_parent_id(),
            "declared_exclusive": bool(self.cur_declared_exclusive()),
            "chain_exclusion_terms": self.cur_chain_exclusion_terms(),
        }
        source_str, lineno = self._format_source_loc(asn)
        rec["source"] = source_str   # "filename.sv:42"
        rec["line"]   = lineno       # 42 (int) — consumed by violation detectors
        self.ir.append(rec)

    def dump_stmt_api(self, stmt):
        print("\n=== STMT API DUMP ===")
        print("CLASS:", stmt.__class__.__name__)
        print("KIND :", getattr(stmt, "kind", None))
        print("DIR  :", dir(stmt))
        print("=== END STMT DUMP ===\n")
        
    def dump_case_item_api(self, item):
        print("\n--- CASE ITEM DUMP ---")
        print("CLASS:", item.__class__.__name__)
        print("DIR  :", dir(item))
        for attr in ["expressions", "statement", "isDefault"]:
            if hasattr(item, attr):
                print(f"{attr} =", getattr(item, attr))
        print("--- END CASE ITEM ---\n")


    def _is_conditional_stmt(self, node):
        return getattr(node, "kind", None) == SyntaxKind.ConditionalStatement

    def _else_clause_stmt(self, else_clause):
        if else_clause is None:
            return None
        if else_clause.__class__.__name__ == "ElseClauseSyntax" and hasattr(else_clause, "clause"):
            return else_clause.clause
        return else_clause

    def _and_guard(self, parent, term):
        p = (parent or "true").strip()
        t = (term or "true").strip()
        if p == "true":
            return t
        if t == "true":
            return p
        return f"({p}) && ({t})"

    def visit_if_chain(self, stmt, proc_meta):
        """
        Flatten if / else-if / else priority ladder and synthesize cumulative
        exclusion masks:
          branch_i = parent && !(c1 || ... || c(i-1)) && ci
          default  = parent && !(c1 || ... || cn)
        """
        parent = self.cur_cond()
        taken_conditions = []
        current = stmt
        self.if_chain_counter += 1
        chain_id = self.if_chain_counter
        parent_chain_id = self.cur_if_chain_id()
        declared_exclusive = self._if_declared_exclusive(stmt)
        self.chain_info[chain_id] = {
            "parent_chain_id": parent_chain_id,
            "declared_exclusive": bool(declared_exclusive),
            "conditions": [],
        }
        self.if_chain_stack.append(chain_id)
        self.if_chain_declared_exclusive_stack.append(bool(declared_exclusive))
        # Isolate nested ladders to prevent condition-domain leakage.
        self.push_cond(parent)

        try:
            while current is not None and self._is_conditional_stmt(current):
                cond_i_raw = self.syntaxnode_to_text(current.predicate.conditions).strip()
                cond_i = self._normalize_and_canonicalize_guard(cond_i_raw)
                if not cond_i:
                    cond_i = "true"

                self.chain_info[chain_id]["conditions"].append(cond_i)

                branch_exclusion_terms = []
                if declared_exclusive:
                    branch_term = cond_i
                else:
                    if taken_conditions:
                        prior_or = " || ".join(f"({c})" for c in taken_conditions)
                        branch_term = f"!({prior_or}) && ({cond_i})"
                        branch_exclusion_terms = list(taken_conditions)
                    else:
                        branch_term = f"({cond_i})"

                full_guard = self._normalize_and_canonicalize_guard(
                    self._and_guard(parent, branch_term)
                )
                if DEBUG:
                    print("\n[IF-CHAIN BRANCH]")
                    print("CHAIN:", chain_id)
                    print("COND:", cond_i)
                    print("TAKEN:", taken_conditions)
                    print("DECLARED_EXCLUSIVE:", declared_exclusive)
                    print("GUARD:", full_guard)

                self.chain_exclusion_terms_stack.append(branch_exclusion_terms)
                self.push_cond(full_guard)
                try:
                    self.visit_stmt(current.statement, proc_meta)
                finally:
                    self.pop_cond()
                    self.chain_exclusion_terms_stack.pop()

                taken_conditions.append(cond_i)

                if not current.elseClause:
                    break

                else_stmt = self._else_clause_stmt(current.elseClause)
                if else_stmt is not None and self._is_conditional_stmt(else_stmt):
                    current = else_stmt
                    continue

                # Final else default branch.
                if declared_exclusive:
                    default_term = "true"
                    default_exclusion_terms = []
                else:
                    prior_or = " || ".join(f"({c})" for c in taken_conditions)
                    default_term = f"!({prior_or})" if prior_or else "true"
                    default_exclusion_terms = list(taken_conditions)
                default_guard = self._normalize_and_canonicalize_guard(
                    self._and_guard(parent, default_term)
                )

                if DEBUG:
                    print("\n[IF-CHAIN DEFAULT]")
                    print("CHAIN:", chain_id)
                    print("TAKEN:", taken_conditions)
                    print("DECLARED_EXCLUSIVE:", declared_exclusive)
                    print("GUARD:", default_guard)

                self.chain_exclusion_terms_stack.append(default_exclusion_terms)
                self.push_cond(default_guard)
                try:
                    self.visit_stmt(else_stmt, proc_meta)
                finally:
                    self.pop_cond()
                    self.chain_exclusion_terms_stack.pop()
                break
        finally:
            self.pop_cond()
            self.if_chain_declared_exclusive_stack.pop()
            self.if_chain_stack.pop()



    def visit_stmt(self, stmt, proc_meta):
        if stmt is None:
            return
        if DEBUG:
            self.dump_stmt_api(stmt)


        # -------------------------
        # FOR LOOP (Slang-correct)
        # -------------------------
        if stmt.__class__.__name__ == "ForLoopStatementSyntax":
            parent = self.cur_cond()

            # Slang API (confirmed by dump)
            init = " , ".join(self.syntaxnode_to_text(i) for i in stmt.initializers)
            cond = self.syntaxnode_to_text(stmt.stopExpr)
            step = " , ".join(self.syntaxnode_to_text(s) for s in stmt.steps)

            loop_guard = self._and_guard(parent, f"FOR({init}; {cond}; {step})")

            if DEBUG:
                print("\n[FOR LOOP]")
                print("INIT :", init)
                print("COND :", cond)
                print("STEP :", step)
                print("GUARD:", loop_guard)

            self.push_cond(loop_guard)
            self.visit_stmt(stmt.statement, proc_meta)
            self.pop_cond()
            return


        # ---------------------------------
        # ELSE CLAUSE WRAPPER
        # ---------------------------------
        if stmt.__class__.__name__ == "ElseClauseSyntax":
            self.visit_stmt(stmt.clause, proc_meta)
            return


        # -------------------------
        # IF / ELSE
        # -------------------------
        if stmt.kind == SyntaxKind.ConditionalStatement:
            self.visit_if_chain(stmt, proc_meta)
            return

        # -------------------------
        # CASE
        # -------------------------
        if stmt.__class__.__name__ == "CaseStatementSyntax":
            parent = self.cur_cond()
            case_expr = self.syntaxnode_to_text(stmt.expr)

            if DEBUG:
                print("\n[CASE STATEMENT]")
                print("CASE EXPR:", case_expr)
                print("PARENT:", parent)

            seen_conds = []

            for idx, item in enumerate(stmt.items):
                cls = item.__class__.__name__

                # -------------------------
                # DEFAULT CASE
                # -------------------------
                if cls == "DefaultCaseItemSyntax":
                    if seen_conds:
                        cond = f"!({' || '.join(seen_conds)})"
                    else:
                        cond = "true"

                    full_cond = self._normalize_and_canonicalize_guard(
                        self._and_guard(parent, cond)
                    )

                    if DEBUG:
                        print(f"[DEFAULT CASE {idx}] GUARD:", full_cond)

                    self.push_cond(full_cond)
                    self.visit_stmt(item.clause, proc_meta)
                    self.pop_cond()
                    continue

                # -------------------------
                # NORMAL CASE ITEM
                # -------------------------
                if cls == "StandardCaseItemSyntax":
                    item_conds = []
                    for expr in item.expressions:
                        c = f"{case_expr} == {self.syntaxnode_to_text(expr)}"
                        item_conds.append(c)
                        seen_conds.append(c)

                    cond = " || ".join(item_conds)
                    full_cond = self._normalize_and_canonicalize_guard(
                        self._and_guard(parent, cond)
                    )

                    if DEBUG:
                        print(f"[CASE ITEM {idx}] GUARD:", full_cond)

                    self.push_cond(full_cond)
                    self.visit_stmt(item.clause, proc_meta)
                    self.pop_cond()
                    continue



            return


        # -------------------------
        # GENERIC BLOCK (LAST)
        # -------------------------
        if hasattr(stmt, "items"):
            for s in stmt.items:
                self.visit_stmt(s, proc_meta)
            return

        # -------------------------
        # ASSIGNMENT
        # -------------------------
        if getattr(stmt, "kind", None) == SyntaxKind.ExpressionStatement:
            expr = stmt.expr
            if expr.kind in (
                SyntaxKind.AssignmentExpression,
                SyntaxKind.NonblockingAssignmentExpression,
            ):
                self.emit_assign(expr, proc_meta)
            return



    # ---------- syntax tree visitor ----------
    def visit_node(self, node):
        if node is None:
            return

        if DEBUG:
            print(
                "NODE:",
                node.__class__.__name__,
                "KIND:",
                getattr(node, "kind", None)
            )
        # -------------------------------------------------
        # PROCEDURAL BLOCK  (always / initial)
        # -------------------------------------------------
        if node.__class__.__name__ == "ProceduralBlockSyntax":

            stmt = node.statement

            if node.kind == SyntaxKind.InitialBlock:
                block_kind = "Initial"
            else:
                block_kind = "Always"

            if block_kind == "Always":
                self.always_block_counter += 1
                current_block_id = self.always_block_counter
            else:
                current_block_id = None

            proc_meta = {
                "process": "initial" if block_kind == "Initial" else "always",
                "clock": None,
                "clock_edge": None,
                "reset": None,
                "reset_edge": None,
                "always_block_id": current_block_id,
            }

            if stmt.__class__.__name__ == "TimingControlStatementSyntax":
                clk, clk_edge, rst, rst_edge = self.extract_clock_and_reset(stmt)
                proc_meta["clock"] = clk
                proc_meta["clock_edge"] = clk_edge
                proc_meta["reset"] = rst
                proc_meta["reset_edge"] = rst_edge

                self.visit_stmt(stmt.statement, proc_meta)
                return

            self.visit_stmt(stmt, proc_meta)
            return


        # -------------------------------------------------
        # CONTINUOUS ASSIGN  (MODULE LEVEL)
        # -------------------------------------------------
        if node.__class__.__name__ == "ContinuousAssignSyntax":
            for asn in node.assignments:
                rec = {
                    "signal": self.node_text(asn.left),
                    "process": "assign",
                    "clock": None,
                    "clock_edge": None,
                    "reset": None,
                    "reset_edge": None,
                    "guard": "true",
                    "rhs": self.node_text(asn.right),
                    "timing": "same_cycle",
                    "always_block_id": None,
                    "if_chain_id": None,
                    "if_chain_parent_id": None,
                    "declared_exclusive": False,
                    "chain_exclusion_terms": [],
                }
                source_str, lineno = self._format_source_loc(asn)
                rec["source"] = source_str
                rec["line"]   = lineno
                self.ir.append(rec)
            return




        # -------------------------------------------------
        # GENERIC RECURSION
        # -------------------------------------------------
        if hasattr(node, "members"):
            for m in node.members:
                self.visit_node(m)

        if hasattr(node, "statement"):
            self.visit_node(node.statement)

        if hasattr(node, "items"):
            for s in node.items:
                self.visit_node(s)



    # ---------- build ----------
    def build(self, rtl_files):
        comp = pyslang.Compilation()

        for f in rtl_files:
            fpath = Path(f).resolve()
            if DEBUG:
                print("ADDING FILE:", fpath)
            elif _PROD_VERBOSE:
                print(f"[INFO] Processing: {fpath.name}")
            comp.addSyntaxTree(pyslang.SyntaxTree.fromFile(str(fpath)))

        for d in comp.getSemanticDiagnostics():
            if DEBUG:
                print("SEMANTIC:", d)

        for tree in comp.getSyntaxTrees():
            self.source_manager = tree.sourceManager  # needed by _format_source_loc
            self.visit_node(tree.root)

        return self.ir

# ----------------------------
# CLI
# ----------------------------
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python ir_builder.py <rtl files> [--verbose]")
        sys.exit(1)

    # Filter out verbose flags from file list
    files = [str(Path(f)) for f in sys.argv[1:] 
             if f not in ('--verbose', '--trace', '-v')]

    if not files:
        print("[ERROR] No RTL files provided")
        print("Usage: python ir_builder.py <rtl files> [--verbose]")
        sys.exit(1)

    builder = IRBuilder()
    ir = builder.build(files)

    for rec in ir:
        rec["guard"] = canonicalize_boolean(GuardNormalizer().normalize(rec["guard"]))
        rec["chain_exclusion_terms"] = [
            canonicalize_boolean(GuardNormalizer().normalize(t))
            for t in (rec.get("chain_exclusion_terms") or [])
        ]

    validate_guard_mutual_exclusion(ir)
    detect_cross_domain_reference(ir, builder.chain_info)

    # ── STEP: Memory write semantic mismatch detection (pre-waveform) ──
    datapath_violations = detect_memory_write_semantic_mismatch(ir)
    if datapath_violations:
        print(f"[DATAPATH] Detected {len(datapath_violations)} memory write semantic mismatch(es):")
        for dv in datapath_violations:
            print(f"  [{dv['class']}] {dv['memory']}  block={dv.get('always_block_id')}")
            print(f"    expected: {dv['expected']}")
            print(f"    actual:   {dv['actual']}")
            print(f"    impact:   {dv['impact']}")

    # ── STEP: Lane bijection violation detection ──────────────────────────────
    lane_violations = detect_lane_bijection_violation(ir)
    if lane_violations:
        print(f"[LANE]     Detected {len(lane_violations)} lane bijection violation(s):")
        for lv in lane_violations:
            print(f"  [{lv['class']}] {lv['memory']}  block={lv.get('always_block_id')}")
            print(f"    {lv['impact'].splitlines()[0]}")
    datapath_violations = datapath_violations + lane_violations

    # ── STEP: Mask conservation violation detection ───────────────────────────
    mask_violations = detect_mask_conservation_violation(ir)
    if mask_violations:
        print(f"[MASK]     Detected {len(mask_violations)} mask conservation violation(s):")
        for mv in mask_violations:
            print(f"  [{mv['class']}] subtype={mv['subtype']}  block={mv.get('always_block_id')}")
            print(f"    {mv['impact'].splitlines()[0]}")
    datapath_violations = datapath_violations + mask_violations

    # ── STEP: Width conservation violation detection ──────────────────────────
    width_violations = detect_width_conservation_violation(ir)
    if width_violations:
        print(f"[WIDTH]    Detected {len(width_violations)} width conservation violation(s):")
        for wv in width_violations:
            print(f"  [{wv['class']}] subtype={wv['subtype']}  block={wv.get('always_block_id')}  line={wv.get('rtl_line')}")
            print(f"    {wv['impact'].splitlines()[0]}")
    datapath_violations = datapath_violations + width_violations

    # ── STEP: Invertibility violation detection ───────────────────────────────
    inv_violations = detect_invertibility_violation(ir)
    if inv_violations:
        print(f"[INVERT]   Detected {len(inv_violations)} invertibility violation(s):")
        for iv in inv_violations:
            print(f"  [{iv['class']}] subtype={iv['subtype']}  block={iv.get('always_block_id')}  line={iv.get('rtl_line')}")
            print(f"    lhs={iv['lhs']}  {iv['details'][:80]}")
    datapath_violations = datapath_violations + inv_violations

    # ── STEP: Semantic datapath validation (protocol-agnostic) ───────────────
    semantic_violations = detect_semantic_datapath_violations(ir)
    if semantic_violations:
        print(f"[SEMANTIC] Detected {len(semantic_violations)} semantic datapath violation(s):")
        for sv in semantic_violations:
            print(f"  [{sv['class']}] subtype={sv['subtype']}  severity={sv['severity']}")
            print(f"    {sv['storage_element']}: {sv['mathematical_reason'][:100]}")

    # ── STEP: Transport-path semantic mismatch detection (pre-waveform) ──
    transport_violations = detect_transport_semantic_mismatch(ir)
    if transport_violations:
        print(f"[TRANSPORT] Detected {len(transport_violations)} transport alignment violation(s):")
        for tv in transport_violations:
            print(f"  [{tv['class']}] subtype={tv['subtype']}  block={tv.get('always_block_id')}  line={tv.get('rtl_line')}")
            print(f"    {tv['bug_pattern']}")

    # ── STEP: Address monotonicity violation detection (pre-waveform) ────
    addr_mono_violations = detect_address_monotonicity_violation(ir)
    transport_violations = transport_violations + addr_mono_violations
    if addr_mono_violations:
        print(f"[ADDR_MONO] Detected {len(addr_mono_violations)} address monotonicity violation(s):")
        for av in addr_mono_violations:
            print(f"  [{av['class']}] subtype={av['subtype']}  block={av.get('always_block_id')}  line={av.get('rtl_line')}")
            print(f"    lhs={av['lhs']}  coeff={av['coefficient']}  offset={av['offset']}  risk={av['risk']}")

    first_rtl = Path(files[0])
    ir_name = first_rtl.stem + "_ir.json"

    with open(ir_name, "w") as f:
        json.dump(ir, f, indent=2)

    # Export datapath violations alongside IR
    if datapath_violations:
        dv_name = first_rtl.stem + "_datapath_violations.json"
        with open(dv_name, "w") as f:
            json.dump(datapath_violations, f, indent=2)
        print(f"[OK] Exported datapath violations to {dv_name}")

    # Export transport violations alongside IR
    if transport_violations:
        tv_name = first_rtl.stem + "_transport_violations.json"
        with open(tv_name, "w") as f:
            json.dump(transport_violations, f, indent=2)
        print(f"[OK] Exported transport violations to {tv_name}")

    # Export semantic violations alongside IR
    if semantic_violations:
        sv_name = first_rtl.stem + "_semantic_violations.json"
        with open(sv_name, "w") as f:
            json.dump(semantic_violations, f, indent=2)
        print(f"[OK] Exported semantic violations to {sv_name}")

    # Summary output
    always_blocks = len(set(rec.get("always_block_id") for rec in ir if rec.get("always_block_id") is not None))
    continuous_assigns = sum(1 for rec in ir if rec.get("always_block_id") is None)
    total_assignments = len(ir)
    
    print(f"[OK] Exported to {ir_name}")
    print(f"[OK] Extracted {total_assignments} assignments from {always_blocks} always blocks + {continuous_assigns} continuous assigns")
    
    if DEBUG:
        print("\n[VERBOSE] Run without --verbose flag for cleaner output")

def build_ir_to_json(rtl_files, out_json):
    builder = IRBuilder()
    ir = builder.build(rtl_files)

    for rec in ir:
        rec["guard"] = canonicalize_boolean(GuardNormalizer().normalize(rec["guard"]))
        rec["chain_exclusion_terms"] = [
            canonicalize_boolean(GuardNormalizer().normalize(t))
            for t in (rec.get("chain_exclusion_terms") or [])
        ]

    validate_guard_mutual_exclusion(ir)
    detect_cross_domain_reference(ir, builder.chain_info)

    # ── Memory write + lane bijection + mask + width conservation ────────────
    datapath_violations  = detect_memory_write_semantic_mismatch(ir)
    datapath_violations += detect_lane_bijection_violation(ir)
    datapath_violations += detect_mask_conservation_violation(ir)
    datapath_violations += detect_width_conservation_violation(ir)
    datapath_violations += detect_invertibility_violation(ir)

    # ── Semantic datapath validation (protocol-agnostic) ─────────────────────
    semantic_violations = detect_semantic_datapath_violations(ir)

    # ── Transport-path semantic mismatch detection (pre-waveform) ────────────
    transport_violations = detect_transport_semantic_mismatch(ir)
    transport_violations += detect_address_monotonicity_violation(ir)
    if transport_violations:
        print(f"[TRANSPORT] Detected {len(transport_violations)} transport alignment violation(s):")
        for tv in transport_violations:
            print(f"  [{tv['class']}] subtype={tv['subtype']}  block={tv.get('always_block_id')}  line={tv.get('rtl_line')}")

    import os
    with open(out_json, "w") as f:
        json.dump(ir, f, indent=2)

    if datapath_violations:
        dv_path = os.path.splitext(out_json)[0] + "_datapath_violations.json"
        with open(dv_path, "w") as f:
            json.dump(datapath_violations, f, indent=2)

    if transport_violations:
        tv_path = os.path.splitext(out_json)[0] + "_transport_violations.json"
        with open(tv_path, "w") as f:
            json.dump(transport_violations, f, indent=2)
        print(f"[OK] Exported transport violations to {tv_path}")

    if semantic_violations:
        sv_path = os.path.splitext(out_json)[0] + "_semantic_violations.json"
        with open(sv_path, "w") as f:
            json.dump(semantic_violations, f, indent=2)
        print(f"[OK] Exported semantic violations to {sv_path}")

    return ir, datapath_violations, transport_violations, semantic_violations