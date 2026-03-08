from __future__ import annotations

import importlib
from typing import Any

from .base import ProtocolAdapter


def load_protocol(name: str, **kwargs: Any) -> ProtocolAdapter:
    module = importlib.import_module(f"protocols.{name}.adapter")
    if hasattr(module, "build_adapter"):
        adapter = module.build_adapter(**kwargs)
    elif hasattr(module, "Adapter"):
        adapter = module.Adapter(**kwargs)
    else:
        raise ImportError(f"Protocol module protocols.{name}.adapter has no Adapter/build_adapter")

    if not isinstance(adapter, ProtocolAdapter):
        raise TypeError(f"Loaded adapter for '{name}' does not implement ProtocolAdapter")
    return adapter

