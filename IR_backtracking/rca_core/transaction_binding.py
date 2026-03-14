"""
transaction_binding.py
======================
TRANSACTION_TO_DATAPATH_BINDING pass.

Proves whether a violating RTL transform participated in an observed AXI
transaction, upgrading STRUCTURAL_UNBOUND → STRUCTURAL_CAUSAL when a
causal path is confirmed through waveform evidence.

Algorithm
---------
1. For each AXI read/write transaction:
     Extract type, address (from waveform at accept_cycle), and cycle window.

2. Resolve address decode by evaluating IR guard predicates:
     Find IR assignments where:
       a) LHS is the data bus (RDATA for reads, WDATA/mem[] for writes), AND
       b) guard contains an address comparison matching the transaction address
          (or has no explicit address comparison — relies on FSM state).

3. Identify which RTL assignment produced RDATA/WDATA for that transaction.

4. Match that assignment's source location against semantic violations
   (by source_location, rtl_line, always_block_id, or signal name).

5. If matched:
     binding = STRUCTURAL_CAUSAL
     Attach transaction_id, waveform cycle, decoded address.

6. If not matched:
     binding = LATENT (violation present but not exercised by observed transactions).

Output
------
causal_binding.json  (written to analysis directory)

Return value: dict with causal_bindings, latent_violations, upgraded_violations,
              and a summary {causal, latent, total_violations}.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# SystemVerilog integer literal parser
# ---------------------------------------------------------------------------

_HEX_LIT_RE = re.compile(r"\d+'h([0-9a-fA-F_]+)", re.IGNORECASE)
_BIN_LIT_RE = re.compile(r"\d+'b([01_]+)",         re.IGNORECASE)
_DEC_LIT_RE = re.compile(r"\d+'d(\d+)",             re.IGNORECASE)
_BARE_INT_RE = re.compile(r"^\s*(\d+)\s*$")


def _parse_sv_literal(s: str) -> Optional[int]:
    """Convert a SV/C integer literal string to int, or None if unparseable."""
    s = s.strip()
    m = _HEX_LIT_RE.fullmatch(s)
    if m:
        return int(m.group(1).replace("_", ""), 16)
    m = _BIN_LIT_RE.fullmatch(s)
    if m:
        return int(m.group(1).replace("_", ""), 2)
    m = _DEC_LIT_RE.fullmatch(s)
    if m:
        return int(m.group(1))
    m = _BARE_INT_RE.fullmatch(s)
    if m:
        return int(m.group(1))
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Guard address extraction
# ---------------------------------------------------------------------------

# Matches:  araddr == 8'h04   /   awaddr == 32'd8   /   addr == 0
_ADDR_EQ_RE = re.compile(
    r'\b(?:(?:ar|aw|w|r)?addr(?:_[A-Za-z0-9_]*)?)\s*==\s*'
    r"((?:\d+'[hbodHBOD][0-9a-fA-F_xXzZ]+)|\d+)",
    re.IGNORECASE,
)


def _extract_guard_address(guard: str) -> Optional[int]:
    """
    Extract the address constant from a guard expression.

    Examples:
      "(araddr == 8'h04)"                          → 4
      "ARVALID && (awaddr == 32'h0000_0008)"        → 8
      "ARVALID && ARREADY"                          → None  (no address compare)
    """
    m = _ADDR_EQ_RE.search(guard or "")
    if not m:
        return None
    return _parse_sv_literal(m.group(1))


# ---------------------------------------------------------------------------
# Rule / transaction type helpers
# ---------------------------------------------------------------------------

_READ_RULES = frozenset({
    "RULE_6", "RULE_7", "RULE_8", "RULE_9", "RULE_10", "RULE_12",
})

# Candidate waveform column names for address signals, in priority order.
_WAVEFORM_ADDR_SIGNALS: Dict[str, List[str]] = {
    "read":  ["ARADDR", "araddr", "s_axil_araddr", "m_axil_araddr"],
    "write": ["AWADDR", "awaddr", "s_axil_awaddr", "m_axil_awaddr"],
}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Unified attribute access for dict-like or object-like containers."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _txn_type(txn: Any) -> str:
    """Return 'read' or 'write' for a transaction object or dict."""
    t = str(_get(txn, "type") or _get(txn, "direction") or "").lower()
    if t in ("read", "write"):
        return t
    rule_id = str(_get(txn, "rule_id") or "").upper()
    return "read" if rule_id in _READ_RULES else "write"


def _is_data_signal(signal: str, txn_type: str) -> bool:
    """Return True if LHS signal is the data bus for this transaction type."""
    s = signal.lower().strip()
    if txn_type == "read":
        return "rdata" in s
    # write: WDATA bus, or memory write (mem[addr]) which contains '['
    return "wdata" in s or "[" in s


# ---------------------------------------------------------------------------
# Address extraction from waveform
# ---------------------------------------------------------------------------

def _resolve_address_from_waveform(
    txn:      Any,
    txn_type: str,
    view:     Any,   # WaveformView
) -> Optional[int]:
    """
    Read ARADDR / AWADDR from the waveform row at accept_cycle.
    Returns the address as int, or None if not available.
    """
    accept_cycle = _get(txn, "accept_cycle") or _get(txn, "cycle")
    if accept_cycle is None:
        return None
    try:
        accept_cycle = int(accept_cycle)
    except (TypeError, ValueError):
        return None

    try:
        resolved = view.resolve_cycle(accept_cycle)
        row = view.rows[resolved.row_idx]
    except Exception:
        return None

    for sig_name in _WAVEFORM_ADDR_SIGNALS.get(txn_type, []):
        raw = row.get(sig_name)
        if raw is not None and raw != "":
            addr = _parse_sv_literal(str(raw))
            if addr is not None:
                return addr
    return None


# ---------------------------------------------------------------------------
# Core binder
# ---------------------------------------------------------------------------

class TransactionToDatapathBinder:
    """
    Bind semantic datapath violations to observed AXI transactions.

    Constructor pre-indexes all violations by four keys so each match
    attempt is O(1) rather than O(N_violations).
    """

    def __init__(
        self,
        ir_records:         List[Dict[str, Any]],
        semantic_violations: List[Dict[str, Any]],
    ) -> None:
        self._ir         = ir_records
        self._violations = semantic_violations

        # Index violations by four lookup keys
        self._by_source: Dict[str, List[int]] = {}
        self._by_line:   Dict[int,  List[int]] = {}
        self._by_block:  Dict[Any,  List[int]] = {}
        self._by_signal: Dict[str,  List[int]] = {}

        for idx, v in enumerate(semantic_violations):
            src = str(v.get("source_location") or v.get("source") or "")
            if src:
                self._by_source.setdefault(src, []).append(idx)

            line = v.get("rtl_line")
            if line is not None:
                try:
                    self._by_line.setdefault(int(line), []).append(idx)
                except (TypeError, ValueError):
                    pass

            bid = v.get("always_block_id")
            if bid is not None:
                self._by_block.setdefault(bid, []).append(idx)

            dst = str(v.get("destination") or v.get("lhs_signal") or "").lower()
            if dst:
                self._by_signal.setdefault(dst, []).append(idx)

    # ------------------------------------------------------------------
    # Step 2: find IR candidates for a transaction
    # ------------------------------------------------------------------

    def _candidate_assignments(
        self,
        address:  Optional[int],
        txn_type: str,
    ) -> List[Dict[str, Any]]:
        """
        Return IR records whose:
          a) LHS is the data bus (RDATA / WDATA / mem[addr])
          b) guard address comparison matches *address* (if present)
        Guards without an explicit address comparison are included because
        they may be gated by FSM state rather than direct address decode.
        """
        out = []
        for rec in self._ir:
            sig = str(rec.get("signal") or "")
            if not _is_data_signal(sig, txn_type):
                continue
            guard     = str(rec.get("guard") or "")
            guard_addr = _extract_guard_address(guard)
            if address is not None and guard_addr is not None and guard_addr != address:
                continue   # address decode mismatch — skip
            out.append(rec)
        return out

    # ------------------------------------------------------------------
    # Step 3-4: match IR assignment → semantic violation
    # ------------------------------------------------------------------

    def _match_violations(
        self,
        asn: Dict[str, Any],
    ) -> List[Tuple[int, str]]:
        """
        Find violations that cover *asn* (the RTL assignment).
        Returns [(violation_index, match_reason), ...].
        Match priority: source_location > rtl_line > always_block_id > signal_name.
        """
        hits: List[Tuple[int, str]] = []
        seen: Set[int] = set()

        def _add(idx: int, reason: str) -> None:
            if idx not in seen:
                hits.append((idx, reason))
                seen.add(idx)

        # 1. source location file:line  (strongest — uniquely identifies a statement)
        src = str(asn.get("source") or "")
        for idx in self._by_source.get(src, []):
            _add(idx, "source_location")

        # 2. RTL line number  (same file, matching line)
        line = asn.get("line")
        if line is not None:
            try:
                for idx in self._by_line.get(int(line), []):
                    _add(idx, "rtl_line")
            except (TypeError, ValueError):
                pass

        # 3. always_block_id  (same always block, possibly different line)
        bid = asn.get("always_block_id")
        if bid is not None:
            for idx in self._by_block.get(bid, []):
                _add(idx, "always_block_id")

        # 4. LHS signal name  (weakest — allows false positives but catches renames)
        sig_lower = str(asn.get("signal") or "").lower()
        for idx in self._by_signal.get(sig_lower, []):
            _add(idx, "signal_name")

        return hits

    # ------------------------------------------------------------------
    # Main bind() entry
    # ------------------------------------------------------------------

    def bind(
        self,
        transactions: List[Any],
        view:         Any,   # WaveformView
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Run the binding pass over all transactions.

        Returns:
            causal_bindings  — STRUCTURAL_CAUSAL records (one per exercised violation per txn)
            latent           — violations not exercised by any transaction
        """
        causal_bindings:    List[Dict[str, Any]] = []
        exercised_viol_ids: Set[int]             = set()

        for txn in transactions:
            t_type    = _txn_type(txn)
            address   = _resolve_address_from_waveform(txn, t_type, view)
            accept_cy = int(_get(txn, "accept_cycle") or _get(txn, "cycle") or 0)
            rule_id   = str(_get(txn, "rule_id") or "")
            txn_id    = rule_id or f"txn@{accept_cy}"

            # Steps 1-2: resolve address and find candidate assignments
            candidates = self._candidate_assignments(address, t_type)

            # Steps 3-4: match each candidate against semantic violations
            for asn in candidates:
                for viol_idx, reason in self._match_violations(asn):
                    exercised_viol_ids.add(viol_idx)
                    causal_bindings.append({
                        "binding":           "STRUCTURAL_CAUSAL",
                        "transaction_id":    txn_id,
                        "transaction_type":  t_type,
                        "violation_index":   viol_idx,
                        "violation":         self._violations[viol_idx],
                        "match_reason":      reason,
                        "cycle":             accept_cy,
                        "address":           address,
                        "assignment_source": asn.get("source"),
                        "assignment_signal": asn.get("signal"),
                        "assignment_block":  asn.get("always_block_id"),
                    })

        # Step 6: violations not exercised by any transaction → LATENT
        latent: List[Dict[str, Any]] = []
        for idx, v in enumerate(self._violations):
            if idx not in exercised_viol_ids:
                latent.append({
                    "binding":         "LATENT",
                    "violation_index": idx,
                    "violation":       v,
                    "note": (
                        "Violation present in RTL but not exercised by "
                        "any observed transaction."
                    ),
                })

        return causal_bindings, latent


# ---------------------------------------------------------------------------
# Top-level function
# ---------------------------------------------------------------------------

def run_transaction_binding(
    transactions:        List[Any],
    ir_records:          List[Dict[str, Any]],
    semantic_violations: List[Dict[str, Any]],
    view:                Any,                    # WaveformView
    output_path:         Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Run the TRANSACTION_TO_DATAPATH_BINDING pass.

    Parameters
    ----------
    transactions        : list from adapter.detect_transactions(view)
    ir_records          : list of IR assignment dicts (from *_ir.json)
    semantic_violations : list of semantic violation dicts
    view                : WaveformView (used to read address values from waveform)
    output_path         : if given, write causal_binding.json here

    Returns
    -------
    dict with keys:
      pass                — "TRANSACTION_TO_DATAPATH_BINDING"
      causal_bindings     — one record per (transaction, violation) pair confirmed causal
      latent_violations   — violations not exercised by any transaction
      upgraded_violations — de-duplicated violation dicts with binding metadata
      summary             — {causal, latent, total_violations}
    """
    if not semantic_violations:
        result: Dict[str, Any] = {
            "pass":               "TRANSACTION_TO_DATAPATH_BINDING",
            "causal_bindings":    [],
            "latent_violations":  [],
            "upgraded_violations": [],
            "summary": {"causal": 0, "latent": 0, "total_violations": 0},
        }
        if output_path:
            output_path.write_text(json.dumps(result, indent=2))
        return result

    binder = TransactionToDatapathBinder(ir_records, semantic_violations)
    causal_bindings, latent = binder.bind(transactions, view)

    # Build de-duplicated upgraded violation list (one entry per unique violation)
    seen:     Set[int]             = set()
    upgraded: List[Dict[str, Any]] = []
    for cb in causal_bindings:
        idx = cb["violation_index"]
        if idx not in seen:
            seen.add(idx)
            v_copy = dict(cb["violation"])
            v_copy["binding"]        = "STRUCTURAL_CAUSAL"
            v_copy["transaction_id"] = cb["transaction_id"]
            v_copy["cycle"]          = cb["cycle"]
            v_copy["address"]        = cb.get("address")
            v_copy["match_reason"]   = cb["match_reason"]
            upgraded.append(v_copy)

    result = {
        "pass":               "TRANSACTION_TO_DATAPATH_BINDING",
        "causal_bindings":    causal_bindings,
        "latent_violations":  latent,
        "upgraded_violations": upgraded,
        "summary": {
            "causal":           len(seen),
            "latent":           len(latent),
            "total_violations": len(semantic_violations),
        },
    }

    if output_path:
        output_path.write_text(json.dumps(result, indent=2, default=str))

    return result
