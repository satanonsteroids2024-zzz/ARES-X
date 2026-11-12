"""
ARES X v10 — Global Registry
==============================

THE wiring simplifier. Every subsystem capability — tools, skills, LLM
clients, services — registers itself here ONCE. Callers look up by name;
they never import each other directly. This is what breaks the N×N
import tangle that made v9 fragile:

    domain A  ──X──> domain B          (v9: direct import, brittle)
    domain A  ──> registry.get("b.feature")   (v10: one wire)

Rules
-----
1. Domains register capabilities; they never import other domains.
2. Everything loads lazily — importing aresx.registry is cheap and pulls
   in no subsystem implementation code.
3. Registration errors are logged, never fatal — a broken plugin or
   optional subsystem can't take down the whole system.
4. The registry is the ONLY place where the legacy eager-import chains
   from v9 still live (compat loaders), kept for one release only.

Public API
----------
    from aresx.registry import registry

    registry.register_tool("nmap.scan", fn, schema={...}, domain="red")
    fn, meta = registry.get_tool("nmap.scan")

    registry.register_service("llm", llm_client)
    client = registry.get_service("llm")
"""
from __future__ import annotations

import importlib
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("aresx.registry")


# ===================================================================
# DATA SHAPES
# ===================================================================
@dataclass
class ToolMeta:
    """Metadata attached to a registered tool."""
    name: str
    fn: Callable[..., Any]
    domain: str = "core"
    description: str = ""
    schema: Optional[Dict[str, Any]] = None        # JSON-schema-ish arg spec (for LLM tool use)
    auth_required: bool = False                    # needs red-team authorization gate
    tags: List[str] = field(default_factory=list)

    def to_tool_def(self) -> Dict[str, Any]:
        """Emit the Gemini functionDeclaration-style definition used by the chat."""
        properties, required = {}, []
        schema = self.schema or {}
        for k, v in (schema.get("properties") or {}).items():
            properties[k] = {p: v[p] for p in ("type", "description", "enum", "default") if p in v}
            if v.get("required") or k in schema.get("required", []):
                required.append(k)
        return {
            "name": self.name,
            "description": self.description or f"Run {self.name}",
            "parameters": {
                "type": "OBJECT",
                "properties": properties,
                "required": required,
            },
        }


# ===================================================================
# REGISTRY
# ===================================================================
class Registry:
    """Thread-safe global capability registry."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolMeta] = {}
        self._services: Dict[str, Any] = {}
        self._locked = False
        self._mu = threading.Lock()

    # ── tools ──────────────────────────────────────────────────
    def register_tool(self, name: str, fn: Callable[..., Any], *,
                      domain: str = "core", description: str = "",
                      schema: Optional[Dict[str, Any]] = None,
                      auth_required: bool = False,
                      tags: Optional[List[str]] = None) -> ToolMeta:
        meta = ToolMeta(name=name, fn=fn, domain=domain, description=description,
                        schema=schema, auth_required=auth_required, tags=tags or [])
        with self._mu:
            self._tools[name] = meta
        logger.debug("Registered tool %s (domain=%s)", name, domain)
        return meta

    def unregister_tool(self, name: str) -> bool:
        with self._mu:
            return self._tools.pop(name, None) is not None

    def get_tool(self, name: str) -> Optional[Tuple[Callable[..., Any], ToolMeta]]:
        with self._mu:
            meta = self._tools.get(name)
        if meta is None:
            return None
        return meta.fn, meta

    def list_tools(self, domain: Optional[str] = None, tag: Optional[str] = None) -> List[ToolMeta]:
        with self._mu:
            tools = list(self._tools.values())
        if domain:
            tools = [t for t in tools if t.domain == domain]
        if tag:
            tools = [t for t in tools if tag in t.tags]
        return tools

    def tool_names(self) -> List[str]:
        with self._mu:
            return sorted(self._tools)

    # ── services (llm clients, storage facade, auth manager...) ──
    def register_service(self, name: str, service: Any) -> None:
        with self._mu:
            self._services[name] = service
        logger.debug("Registered service %s", name)

    def get_service(self, name: str) -> Optional[Any]:
        with self._mu:
            return self._services.get(name)

    # ── bulk definitions for LLM function calling ──────────────
    def tool_definitions(self, domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """All tools as Gemini functionDeclaration-style dicts."""
        tools = self.list_tools()
        if domains:
            tools = [t for t in tools if t.domain in domains]
        return [t.to_tool_def() for t in tools]

    # ── diagnostics ────────────────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        with self._mu:
            by_domain: Dict[str, int] = {}
            for t in self._tools.values():
                by_domain[t.domain] = by_domain.get(t.domain, 0) + 1
            return {"tools": len(self._tools), "by_domain": by_domain,
                    "services": list(self._services)}


# Global singleton — the one stop for all cross-domain capability lookups.
registry: Registry = Registry()

__all__ = ["Registry", "ToolMeta", "registry"]
