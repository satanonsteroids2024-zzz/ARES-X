#!/usr/bin/env python3
"""ARES-X v10 reachability map (road-network audit).

Three views, combined into the classification the road-network rules need:

  *runtime_live*   — modules actually imported when the real entry points
                     boot (ares_server / ares_native / ares_x / main).
  *static_reach*   — transitive closure of STATIC import edges from the
                     entry points (what could load without runtime
                     discovery).
  *classified*     — every .py file in aresx/:
      live        - runtime_live or static_reach
      static_only - reachable only via static edges (subsystem loaded
                    on first chat command that references it)
      dead_end    - zero inbound static edges from the live/static set
                    (rule 4: safe to delete, after supersession check)
      unwired     - low inbound (1 edge) but genuinely capable
                    (rule 4 other branch: build on-ramp, don't delete)

Usage: python3 reachability_map.py [--json out.json]
"""
from __future__ import annotations

import ast
import importlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARESX = ROOT / "aresx"

ENTRY_POINTS = ["ares_server", "ares_native", "ares_x", "main"]


def _file_imports(py: Path):
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
    return names


def _collect_all_modules():
    modules = {}
    for py in sorted(ARESX.rglob("*.py")):
        rel = py.relative_to(ARESX).with_suffix("")
        parts = rel.parts
        dotted = ".".join(parts) if parts[-1] != "__init__" else ".".join(parts[:-1])
        if not dotted:
            dotted = "aresx"
        else:
            dotted = "aresx." + dotted
        modules[dotted] = py
    return modules


def runtime_live():
    """Import each entry point in a fresh interpreter and record aresx.*."""
    live = set()
    probe_file = ROOT / "_live_probe.py"
    probe_file.write_text(
        "import sys, json, importlib\n"
        "entry = sys.argv[1]\n"
        "try:\n"
        "    importlib.import_module(entry)\n"
        "except Exception as exc:  # noqa: BLE001\n"
        "    sys.stderr.write('[probe ' + entry + '] failed: ' + str(exc) + '\\n')\n"
        "json.dump(sorted(m for m in sys.modules if m.startswith('aresx')),\n"
        "          open('/tmp/_aresx_live_probe_out.json', 'w'))\n"
    )
    env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
    for entry in ENTRY_POINTS:
        try:
            r = subprocess.run([sys.executable, str(probe_file), entry],
                               cwd=str(ROOT), env=env,
                               capture_output=True, text=True, timeout=120)
            if r.stderr.strip():
                print(f"  [warn] {entry}: {r.stderr.strip().splitlines()[-1]}",
                      file=sys.stderr)
            data = json.loads(Path("/tmp/_aresx_live_probe_out.json").read_text())
            live.update(data)
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] {entry} probe failed: {exc}", file=sys.stderr)
    probe_file.unlink(missing_ok=True)
    return sorted(live)


def static_reach(modules, live):
    """Static AST-edge closure starting from live set."""
    static_imports = {}
    for dotted, py in modules.items():
        static_imports[dotted] = _file_imports(py)

    def _targets_of(import_name):
        return [d for d in modules
                if d == import_name or d.startswith(import_name + ".")]

    closure = set(live)
    queue = list(live)
    while queue:
        cur = queue.pop(0)
        if cur not in static_imports:
            continue
        for imp in static_imports[cur]:
            for t in _targets_of(imp):
                if t not in closure:
                    closure.add(t)
                    queue.append(t)
    return closure


def inbound_counts(modules, static_imports, reachable):
    """Inbound edges only counting FROM reachable modules (real wires)."""
    inbound = {}
    for dotted in reachable:
        if dotted not in static_imports:
            continue
        for imp in static_imports[dotted]:
            for t in modules:
                if t == imp or t.startswith(imp + "."):
                    inbound.setdefault(t, set()).add(dotted)
    return inbound


def main():
    print("Step 1/3: runtime probes of entry points …")
    live = runtime_live()
    print(f"  runtime-live aresx modules: {len(live)}")

    print("Step 2/3: static edge closure …")
    modules = _collect_all_modules()
    static_imports = {d: _file_imports(py) for d, py in modules.items()}
    reachable = static_reach(modules, live)
    print(f"  static-reachable aresx modules: {len(reachable)} / {len(modules)}")

    print("Step 3/3: classifying …")
    inbound = inbound_counts(modules, static_imports, reachable)

    dead_ends, unwired, static_only = [], [], []
    rows = []
    for dotted in sorted(modules):
        if dotted == "aresx":
            continue
        size = modules[dotted].stat().st_size
        is_live = dotted in live
        is_reach = dotted in reachable
        edges = len(inbound.get(dotted, set()))
        if is_live:
            cls = "live"
        elif is_reach:
            cls = "static_only"
        elif edges == 0:
            cls = "dead_end"
            dead_ends.append((dotted, size))
        else:
            cls = "unwired"
            unwired.append((dotted, edges, size))
        rows.append((dotted, cls, edges, size))
        if cls == "static_only":
            static_only.append(dotted)

    print(f"\nCLASS SUMMARY")
    print(f"  live         (loaded at boot)       : {sum(1 for r in rows if r[1]=='live')}")
    print(f"  static_only  (loaded on chat cmd)   : {len(static_only)}")
    print(f"  dead_end     (zero inbound edges)   : {len(dead_ends)}")
    print(f"  unwired      (real capability, thin): {len(unwired)}")

    print("\n=== DEAD-END candidates (rule 4 — delete or confirm superseded) ===")
    for dotted, size in dead_ends:
        print(f"  {dotted:72s} {size:>7d}B")
    print("\n=== UNWIRED-BUT-REAL candidates (rule 4 other branch — on-ramp, don't delete) ===")
    for dotted, edges, size in sorted(unwired, key=lambda x: -x[2]):
        print(f"  {dotted:72s} inbound={edges:>2d} {size:>7d}B")
    print("\n=== STATIC-ONLY subsystems (thinly connected to highway — known substrate) ===")
    for dotted in static_only:
        print(f"  {dotted}")

    result = {
        "runtime_live": live,
        "static_only": static_only,
        "dead_ends": [{"module": d, "size_bytes": s} for d, s in dead_ends],
        "unwired": [{"module": d, "inbound_edges": e, "size_bytes": s}
                    for d, e, s in unwired],
        "all": rows,
    }
    if "--json" in sys.argv:
        with open(ROOT / "reachability_map.json", "w") as f:
            json.dump(result, f, indent=2)
        print("\nwrote reachability_map.json")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    main()
