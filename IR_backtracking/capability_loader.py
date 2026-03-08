#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capability_loader.py — Controlled Module Loader for AXI-Lite RCA
================================================================

Provides strict, fail-fast module loading that replaces silent try/except
import fallbacks.  Every engine required by the RCA orchestrator is loaded
through this module so that:

  • Missing modules raise immediately with clear diagnostics.
  • Each loaded module's version and file path are recorded for
    reproducibility (the "capability manifest").
  • The same loading path works in a normal Python environment AND inside
    a PyInstaller / cx_Freeze / Nuitka single-file executable.

Public API
----------
    require(module_name, symbols=None)
        Import *module_name*, optionally verify that *symbols* exist on it,
        and return the module object.  Raises ``RuntimeError`` on failure.

    validate_runtime_capabilities(required_engines)
        Bulk-check every module→symbols mapping.  Raises ``RuntimeError``
        listing ALL missing pieces if any are absent.

    generate_capability_manifest(required_engines, out_path=None)
        Emit a human-readable capability report to stdout and, optionally,
        write a ``rca_run_manifest.json`` file for audit trails.
"""

from __future__ import annotations

import importlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Optional, Sequence

__all__ = [
    "require",
    "validate_runtime_capabilities",
    "generate_capability_manifest",
]

# ---------------------------------------------------------------------------
# Internal registry — every module loaded through require() is tracked here
# so the manifest generator can report on it later.
# ---------------------------------------------------------------------------
_loaded_registry: Dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Helpers for exe-bundled environments
# ---------------------------------------------------------------------------

def _is_frozen() -> bool:
    """Return True when running inside a PyInstaller/cx_Freeze bundle."""
    return getattr(sys, "frozen", False)


def _bundle_root() -> Optional[str]:
    """Return the PyInstaller _MEIPASS temp dir, or None."""
    return getattr(sys, "_MEIPASS", None)


def _module_version(mod: ModuleType) -> str:
    """Best-effort version extraction from a module."""
    for attr in ("__version__", "VERSION", "version"):
        v = getattr(mod, attr, None)
        if v is not None:
            return str(v)
    return "unknown"


def _module_file(mod: ModuleType) -> str:
    """Best-effort file path extraction from a module."""
    f = getattr(mod, "__file__", None)
    if f:
        return str(f)
    spec = getattr(mod, "__spec__", None)
    if spec and spec.origin:
        return str(spec.origin)
    return "<built-in or namespace>"


# ============================================================================
# require()  —  the replacement for every try/except ImportError block
# ============================================================================

def require(
    module_name: str,
    symbols: Optional[Sequence[str]] = None,
) -> ModuleType:
    """
    Import *module_name* and return the module object.

    Parameters
    ----------
    module_name : str
        Dotted Python module name, e.g. ``"analyse_interactive"``.
    symbols : sequence of str, optional
        If provided, each name is verified to exist as an attribute on the
        loaded module.  A missing symbol is a hard failure.

    Returns
    -------
    ModuleType
        The imported module.

    Raises
    ------
    RuntimeError
        If the module cannot be imported or any listed symbol is absent.
        The message includes the file path that was (or would have been)
        loaded and, for exe bundles, the _MEIPASS root.
    """
    # ---- attempt import ------------------------------------------------
    try:
        mod = importlib.import_module(module_name)
    except ImportError as exc:
        bundle_hint = ""
        if _is_frozen():
            bundle_hint = (
                f"\n  (Running inside frozen bundle; _MEIPASS={_bundle_root()})"
                f"\n  Ensure '{module_name}' is included in your PyInstaller "
                f"--hidden-import or .spec file."
            )
        raise RuntimeError(
            f"Required analysis engine '{module_name}' could not be imported.\n"
            f"  Original error: {exc}{bundle_hint}"
        ) from exc

    # ---- verify symbols ------------------------------------------------
    missing_symbols: List[str] = []
    if symbols:
        for sym in symbols:
            if not hasattr(mod, sym):
                missing_symbols.append(sym)

    if missing_symbols:
        raise RuntimeError(
            f"Module '{module_name}' loaded from {_module_file(mod)},\n"
            f"but the following required symbols are missing:\n"
            + "".join(f"  - {s}\n" for s in missing_symbols)
            + "This may indicate a version mismatch or incomplete installation."
        )

    # ---- record for manifest -------------------------------------------
    ver = _module_version(mod)
    fpath = _module_file(mod)
    _loaded_registry[module_name] = {
        "version": ver,
        "file": fpath,
        "symbols_verified": list(symbols) if symbols else [],
        "loaded_at": datetime.now(timezone.utc).isoformat(),
    }

    # ---- traceability print --------------------------------------------
    print(f"  [ENGINE] {module_name} v{ver}  ({fpath})")

    return mod


# ============================================================================
# validate_runtime_capabilities()  —  bulk pre-flight check
# ============================================================================

def validate_runtime_capabilities(
    required_engines: Dict[str, List[str]],
) -> None:
    """
    Validate that every module listed in *required_engines* can be imported
    and exposes the symbols expected.

    Parameters
    ----------
    required_engines : dict
        Mapping of ``module_name`` → ``[symbol, ...]``.

    Raises
    ------
    RuntimeError
        If **any** module or symbol is missing.  The error message lists
        every failure so the user can fix all problems in one pass.
    """
    failures: List[str] = []

    for module_name, symbols in required_engines.items():
        # ---- try import ------------------------------------------------
        try:
            mod = importlib.import_module(module_name)
        except ImportError as exc:
            failures.append(f"  ✗ {module_name}: import failed — {exc}")
            continue

        # ---- check symbols ---------------------------------------------
        for sym in symbols:
            if not hasattr(mod, sym):
                failures.append(
                    f"  ✗ {module_name}.{sym}: symbol not found "
                    f"(loaded from {_module_file(mod)})"
                )

    if failures:
        formatted_list = "\n".join(failures)
        raise RuntimeError(
            "AXI-Lite RCA installation is incomplete.\n"
            "Missing required analysis engines:\n"
            + formatted_list
            + "\nThis tool cannot run in degraded mode."
        )


# ============================================================================
# generate_capability_manifest()  —  startup traceability report
# ============================================================================

def generate_capability_manifest(
    required_engines: Dict[str, List[str]],
    out_path: Optional[str] = None,
) -> dict:
    """
    Emit a human-readable capability report to stdout and optionally
    write a JSON manifest file.

    Parameters
    ----------
    required_engines : dict
        Same mapping passed to ``validate_runtime_capabilities``.
    out_path : str, optional
        If given, the manifest is also written as JSON to this path.
        Defaults to ``None`` (stdout only).

    Returns
    -------
    dict
        The manifest data structure (also written to *out_path* if set).
    """
    # ---- collect engine status -----------------------------------------
    engine_status: Dict[str, dict] = {}
    all_ok = True

    for module_name, symbols in required_engines.items():
        try:
            mod = importlib.import_module(module_name)
            ver = _module_version(mod)
            fpath = _module_file(mod)
            missing = [s for s in symbols if not hasattr(mod, s)]
            status = "OK" if not missing else "PARTIAL"
            if missing:
                all_ok = False
        except ImportError:
            ver = "N/A"
            fpath = "NOT FOUND"
            missing = list(symbols)
            status = "MISSING"
            all_ok = False

        engine_status[module_name] = {
            "status": status,
            "version": ver,
            "file": fpath,
            "missing_symbols": missing,
        }

    # ---- print human-readable ------------------------------------------
    print()
    print("AXI-Lite RCA Capability Manifest")
    print("─" * 48)

    max_name_len = max(len(n) for n in required_engines) if required_engines else 20
    for name, info in engine_status.items():
        dots = "." * (max_name_len - len(name) + 4)
        tag = info["status"]
        print(f"  {name} {dots} {tag}")
        if info["missing_symbols"]:
            for sym in info["missing_symbols"]:
                print(f"      ✗ {sym}")

    print("─" * 48)
    print(f"  Overall: {'ALL ENGINES READY' if all_ok else 'INCOMPLETE — SEE ABOVE'}")
    print()

    # ---- build manifest dict -------------------------------------------
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "frozen": _is_frozen(),
        "meipass": _bundle_root(),
        "engines": engine_status,
        "all_engines_ok": all_ok,
        "loaded_registry": dict(_loaded_registry),
    }

    # ---- write JSON if requested ---------------------------------------
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as fp:
                json.dump(manifest, fp, indent=2, ensure_ascii=False)
            print(f"  Manifest written to: {out_path}")
        except OSError as exc:
            print(f"  [WARN] Could not write manifest: {exc}")

    return manifest