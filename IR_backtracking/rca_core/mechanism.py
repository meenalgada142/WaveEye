from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .contracts import CausalContract, CausalResult, ContractStatus


_WS_RE = re.compile(r"\s+")


def _strip_outer_parens(expr: str) -> str:
    s = str(expr or "").strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        ok = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    ok = False
                    break
            if depth == 0 and i != len(s) - 1:
                ok = False
                break
        if not ok or depth != 0:
            break
        s = s[1:-1].strip()
    return s


def _split_top(expr: str, op: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    i = 0
    start = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            i += 1
            continue
        if depth == 0 and expr.startswith(op, i):
            parts.append(expr[start:i].strip())
            i += len(op)
            start = i
            continue
        i += 1
    if start <= n:
        parts.append(expr[start:].strip())
    return [p for p in parts if p]


def _normalize_bool_expr(expr: str) -> str:
    s = str(expr or "").strip()
    if not s:
        return ""
    s = s.replace("||", " || ").replace("&&", " && ")
    s = re.sub(r"\band\b", "&&", s, flags=re.IGNORECASE)
    s = re.sub(r"\bor\b", "||", s, flags=re.IGNORECASE)
    s = _WS_RE.sub(" ", s).strip()
    s = s.replace(" ", "")

    def norm(x: str) -> str:
        x = _strip_outer_parens(x)
        or_parts = _split_top(x, "||")
        if len(or_parts) > 1:
            return "||".join(sorted(norm(p) for p in or_parts))
        and_parts = _split_top(x, "&&")
        if len(and_parts) > 1:
            return "&&".join(sorted(norm(p) for p in and_parts))
        if x.startswith("!"):
            return "!" + norm(x[1:])
        return _strip_outer_parens(x)

    return norm(s)


def _graph_edge_signature(graph: Dict[str, Any]) -> str:
    if not isinstance(graph, dict):
        return ""
    nodes = list(graph.get("nodes", []) or [])
    edges = list(graph.get("edges", []) or [])
    if not edges:
        return ""

    id_to_label: Dict[str, str] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        nid = str(node.get("id", "")).strip()
        if not nid:
            continue
        sig = str(node.get("signal", "")).strip()
        lab = str(node.get("label", "")).strip()
        id_to_label[nid] = sig or lab or nid

    canon: List[Tuple[str, str, str]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source", edge.get("from", ""))).strip()
        dst = str(edge.get("target", edge.get("to", ""))).strip()
        typ = str(edge.get("type", "")).strip()
        src_l = id_to_label.get(src, src)
        dst_l = id_to_label.get(dst, dst)
        canon.append((src_l, typ, dst_l))
    canon = sorted(set(canon))
    return "|".join([f"{a}>{t}>{b}" for a, t, b in canon])


def _status_to_kind(status: ContractStatus) -> Optional[str]:
    if status == ContractStatus.CANCELLED:
        return "DRIVER_CONFLICT"
    if status == ContractStatus.CYCLIC:
        return "CYCLIC_ENABLE"
    if status == ContractStatus.BLOCKED:
        return "TEMPORAL_BLOCK"
    return None


def _status_from_kind(kind: str) -> ContractStatus:
    if kind == "DRIVER_CONFLICT":
        return ContractStatus.CANCELLED
    if kind == "CYCLIC_ENABLE":
        return ContractStatus.CYCLIC
    if kind == "TEMPORAL_BLOCK":
        return ContractStatus.BLOCKED
    return ContractStatus.UNDETERMINED


def _extract_conflict_conditions(evidence: Dict[str, Any]) -> List[str]:
    cancel = evidence.get("intra_cycle_cancellation", {}) if isinstance(evidence, dict) else {}
    if not isinstance(cancel, dict):
        return []
    items: List[str] = []
    for key in ("expected_driver_conditions", "final_overwrite_conditions"):
        vals = list(cancel.get(key, []) or [])
        for v in vals:
            nv = _normalize_bool_expr(str(v))
            if nv:
                items.append(nv)
    return sorted(set(items))


def _signal_from_result(result: CausalResult) -> str:
    sig = str(result.contract.expected_signal or "").strip()
    if sig:
        return sig
    ev = result.evidence or {}
    sig2 = str(ev.get("expected_signal", "")).strip()
    return sig2


def _predicate_from_result(result: CausalResult) -> str:
    pred = str(result.contract.enable_condition or "").strip()
    if pred:
        return _normalize_bool_expr(pred)
    ev = result.evidence or {}
    en = ev.get("enable_condition", {})
    if isinstance(en, dict):
        return _normalize_bool_expr(str(en.get("expr", "")))
    return ""


def _signature_components(result: CausalResult) -> Optional[Tuple[str, str, str, str, Tuple[str, ...]]]:
    kind = _status_to_kind(result.status)
    if not kind:
        return None
    signal = _signal_from_result(result).strip().lower()
    predicate = _predicate_from_result(result)
    evidence = result.evidence or {}
    graph_raw = _graph_edge_signature(evidence.get("dependency_graph", {}) if isinstance(evidence, dict) else {})
    graph_sig = hashlib.sha1(graph_raw.encode("utf-8")).hexdigest() if graph_raw else ""
    conflicts = tuple(_extract_conflict_conditions(evidence))
    return (kind, signal, predicate, graph_sig, conflicts)


@dataclass
class FailureMechanism:
    mechanism_id: str
    kind: str
    signal: Optional[str]
    predicate_signature: str
    graph_signature: str
    occurrence_count: int
    first_cycle: int
    sample_evidence: Dict[str, Any]
    related_contract_ids: List[str]
    # Compatibility shim: allows existing adapters that still expect CausalResult-like fields.
    status: ContractStatus = field(default=ContractStatus.UNDETERMINED, repr=False)
    contract: Optional[CausalContract] = field(default=None, repr=False)
    analysis_cycle: int = field(default=0, repr=False)
    detail: str = field(default="", repr=False)
    evidence: Dict[str, Any] = field(default_factory=dict, repr=False)


def synthesize_mechanisms(results: List[CausalResult]) -> List[FailureMechanism]:
    groups: Dict[str, Dict[str, Any]] = {}

    indexed: List[Tuple[Tuple[str, str, str, str, Tuple[str, ...]], CausalResult]] = []
    for result in list(results or []):
        sig = _signature_components(result)
        if sig is None:
            continue
        indexed.append((sig, result))

    # Deterministic processing order.
    indexed.sort(
        key=lambda it: (
            int(getattr(it[1], "analysis_cycle", 10**9)),
            str(getattr(getattr(it[1], "contract", None), "contract_id", "")),
            repr(it[0]),
        )
    )

    for sig, result in indexed:
        sig_blob = json.dumps(sig, sort_keys=False, separators=(",", ":"))
        mechanism_id = hashlib.sha1(sig_blob.encode("utf-8")).hexdigest()
        bucket = groups.get(mechanism_id)
        if bucket is None:
            bucket = {
                "signature": sig,
                "items": [],
            }
            groups[mechanism_id] = bucket
        bucket["items"].append(result)

    mechanisms: List[FailureMechanism] = []
    for mechanism_id in sorted(groups.keys()):
        items: List[CausalResult] = list(groups[mechanism_id]["items"])
        items.sort(
            key=lambda r: (
                int(getattr(r, "analysis_cycle", 10**9)),
                str(getattr(getattr(r, "contract", None), "contract_id", "")),
            )
        )
        sample = items[0]
        kind, signal, predicate, graph_sig, conflicts = groups[mechanism_id]["signature"]

        contract_ids = sorted(
            {
                str(getattr(getattr(r, "contract", None), "contract_id", ""))
                for r in items
                if str(getattr(getattr(r, "contract", None), "contract_id", ""))
            }
        )
        first_cycle = min(int(getattr(r, "analysis_cycle", 10**9)) for r in items)
        if first_cycle >= 10**9:
            first_cycle = int(getattr(sample, "analysis_cycle", 0))

        sample_evidence = dict(getattr(sample, "evidence", {}) or {})
        sample_evidence.setdefault("mechanism_signature_conflicts", list(conflicts))
        sample_evidence.setdefault("mechanism_occurrence_count", len(items))
        sample_evidence.setdefault("mechanism_related_contract_ids", list(contract_ids))

        mechanism = FailureMechanism(
            mechanism_id=mechanism_id,
            kind=kind,
            signal=signal or None,
            predicate_signature=predicate,
            graph_signature=graph_sig,
            occurrence_count=len(items),
            first_cycle=first_cycle,
            sample_evidence=sample_evidence,
            related_contract_ids=contract_ids,
            status=_status_from_kind(kind),
            contract=getattr(sample, "contract", None),
            analysis_cycle=int(getattr(sample, "analysis_cycle", first_cycle)),
            detail=str(getattr(sample, "detail", "") or f"Synthesized {kind} mechanism."),
            evidence=sample_evidence,
        )
        mechanisms.append(mechanism)

    mechanisms.sort(key=lambda m: (int(m.first_cycle), str(m.kind), str(m.mechanism_id)))
    return mechanisms
