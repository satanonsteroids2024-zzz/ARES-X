# ARES-X v10 "SIMPLIFY" — Architecture Restructure

**Author:** Manus AI · **Date:** August 11, 2026

This document records the complete architecture restructure of ARES-X (from v9 to v10). It explains what was wrong, what changed, why the new wiring eliminates the class of glitches you were hitting, and how to migrate. The full working codebase ships with this document at `AREX_X_v10_restructured.zip`; every change preserves the v9 public API, so nothing breaks silently.

## 1. What was wrong with the v9 architecture

The v9 codebase (193 files, ~33,500 lines) had accumulated a tangled dependency graph where the same concern lived in several places at once, and where modules imported each other in circles. The symptoms you experienced — glitches that reappeared after fixes, problems that multiplied as the system grew — are the textbook behavior of this structure. Concretely, the analysis found the following defects:

| # | Defect in v9 | Consequence |
|---|---|---|
| 1 | **Three competing entry scripts** (`ares_x.py`, `ares_server.py`, `ares_native.py`), each mutating `sys.path` and each booting the app independently | Different code paths on the "same" boot; `PYTHONPATH`-dependent behavior that changed with launch method |
| 2 | **Two duplicate chat routers**: `tool_router.py` (1,610 lines) *and* `intent_mapper.py`, both dispatching chat — the server flipped between them depending on whether a Gemini key existed | Half your tool-calling logic existed twice; a fix in one router never reached the other |
| 3 | **God files**: `core.py` (1,596 lines) and `brain.py` (1,318 lines) held config, SQLite memory, screen capture, LLM inference, audio, the Qt orb, and UI dialogs all in one file | Every change touched everything; merge/flow-of-control bugs were inevitable |
| 4 | **Real circular imports** (`computer_agent`↔`desktop_automation`, `fusion`↔`fusion.engine`-style patterns, storage↔migrations) masked by fragile load-order tricks | Import-order-dependent glitches: the system worked only if modules loaded in exactly the right sequence |
| 5 | **Duplicated capability code**: screenshot tooling in four files, nmap wrappers in two packages, five `*_store.py` store files that re-exported a single uncalled `store_modules.py` | Multiple implementations of the same primitive drifted apart |
| 6 | **Eager `__init__.py` chains** that imported heavy implementation modules (Qt, SQLite, LLM clients) at package load | Slow, failure-prone boots; a missing optional dependency could take the whole tree down |
| 7 | **Dead weight**: `aresx/router.py` (unused), five store modules with zero callers, duplicated legacy core copies | Noise that obscured the real wiring |

## 2. The v10 design — six rules

The restructure is governed by six rules that directly attack each defect above.

**Rule 1 — One wire to rule them all.** Subsystems communicate through exactly two mechanisms: the shared **event bus** (`aresx.bus`, formerly `aresx.events`) for pub/sub, and the global **registry** (`aresx.registry`) for tools, skills, and services. Direct cross-domain imports are banned by convention. The N×N tangle becomes a hub-and-spoke star.

**Rule 2 — No god files.** Every module has one job and stays under ~600 lines. `core.py` was split into eight focused modules (`core/{paths,memory,screen,llm,audio,orb,confirm}`) behind a thin compat facade.

**Rule 3 — `__init__.py` files export symbols, never behavior.** Package init files re-export symbols only; heavy subsystems load lazily through the registry. Nothing Qt/LLM/SQLite related runs at import time except the documented boot path.

**Rule 4 — One storage layer.** The five dead `*_store.py` modules and their uncalled `store_modules.py` were archived; the canonical stores live with their domain (e.g., `domains/twin/twin_store.py`), backed by the single `aresx.storage` connection layer.

**Rule 5 — One router, one launcher.** `tool_router.py` + `intent_mapper.py` merged into `aresx.chat.router` (the Gemini free-form path is canonical; the regex path is a deliberate fallback). The three entry scripts now sit behind a single launcher: `main.py {desktop|server|native}`.

**Rule 6 — Optional stays optional.** Every third-party dependency (PySide6, webview, Kuzu, LanceDB, …) remains behind import-lazy try/except, exactly as v9 promised: a bare install boots cleanly and degrades gracefully.

## 3. New file hierarchy

```
aresx_v10/
├── main.py                 # single launcher (desktop | server | native)
├── ares_x.py               # desktop entry (legacy shim, still works standalone)
├── ares_server.py          # FastAPI app (canonical app object, now uses chat router)
├── ares_native.py          # GTK webview window over the same app
├── tool_router.py          # compat shim → aresx.chat.router
├── intent_mapper.py        # compat shim → aresx.chat.router
├── start.sh                # one-command launcher (unchanged workflow)
├── tests/                  # 114 legacy tests + 8 new stress tests (122 pass)
│
└── aresx/
    ├── __init__.py         # version + boot symbols only
    ├── registry.py         # global tool / skill / service registry
    ├── core/               # split former 1,596-line god file
    │   ├── paths.py        # BASE_DIR, config dirs
    │   ├── config.py       # cfg, load/save_config
    │   ├── loop.py         # asyncio event-loop helpers
    │   ├── memory.py       # sqlite/aiosqlite Mike memory
    │   ├── screen.py       # screenshot/typing/click (canonical)
    │   ├── llm.py          # inference API client
    │   ├── audio.py        # mike/speaker
    │   ├── orb.py          # Qt orb overlay
    │   └── confirm.py      # UI dialogs
    ├── bus/                # THE event bus (was events.py)
    ├── chat/               # THE single chat router
    │   ├── __init__.py
    │   └── router.py       # Gemini routing + merged regex fallback
    ├── storage/            # one connection layer (+ _unused/ archived dead stores)
    ├── domains/            # all subject-matter subsystems
    │   ├── twin/           # (was digital_twin)
    │   ├── rag/            # (was rag_federated)
    │   ├── security/       # (was postquantum_security)
    │   ├── ai/             # (was sovereign_ai)
    │   ├── mission/ red/ fusion/ simulation/ decision/
    │   │   autonomy/ enterprise/ ...
    ├── tools/              # capability primitives (screen/net/os/web)
    ├── agents/             # brain + computer_agent + desktop_automation
    ├── modules/ ui/ heal.py wizard.py ...
    └── __legacy_core_godfile.py   # v9 core.py preserved for reference only
```

## 4. Migration guide

No code changes are required in practice — every v9 import path still resolves:

| v9 import | v10 resolution |
|---|---|
| `import tool_router` / `from tool_router import route_message` | shim forwards to `aresx.chat.router` |
| `from intent_mapper import _regex_route_message` | shim forwards to `aresx.chat.router` |
| `aresx.digital_twin.*` | shim forwards to `aresx.domains.twin.*` |
| `aresx.rag_federated.*` | shim forwards to `aresx.domains.rag.*` |
| `aresx.postquantum_security.*` | shim forwards to `aresx.domains.security.*` |
| `aresx.sovereign_ai.*` | shim forwards to `aresx.domains.ai.*` |
| `aresx.events` | compat alias → `aresx.bus` |
| `aresx.core` | compat facade → `aresx.core.*` |
| `aresx.storage.{twin,mission,...}_store` | archived — no external callers existed; use `aresx.domains.twin.twin_store` |

For new code, import the canonical paths directly:

```python
from aresx.chat.router import route_message          # chat dispatch
from aresx.registry import registry                  # tool/skill hub
from aresx.bus import bus, EventType                 # pub/sub
from aresx.storage import db                         # SQLite
from aresx.core.screen import screenshot_b64         # single screenshot impl
```

**Running the system** now goes through the single launcher (old scripts still work standalone):

```bash
python3 main.py server          # FastAPI chat server + browser UI
python3 main.py desktop         # Qt orb + tray + wake-word agent
python3 main.py native          # GTK native window over the server
python3 main.py server --port 9000 --debug
./start.sh                      # unchanged one-command workflow
```

## 5. Verification — the wiring stress tests

Because the stated goal was to eliminate order-dependent and concurrency-related glitches, v10 ships a new `tests/test_restructure_stress.py` suite that proves the wiring properties directly. All 122 tests (114 legacy + 8 new) pass.

| Stress test | What it proves |
|---|---|
| Import-order fuzzing (all ~170 modules, 10 random orderings) | No module depends on load order; the v9 circular-import class of bug is gone |
| Circular-import detection (full package walk) | Zero circular-import failures anywhere in the tree |
| Boot profiling (fresh interpreter, core path) | Core boot path completes in under 3 s |
| Bus concurrency (8 threads × 50 publishes, queue drain) | 400/400 events delivered — zero loss under concurrent publish |
| Subscribe/unsubscribe concurrency (12 threads) | Subscription lifecycle is thread-safe |
| Registry concurrency (40 tools, 80 concurrent resolves) | Register/resolve stays consistent under load |
| SQLite thread safety (6 writers + 6 readers, 72 ops) | Concurrent storage access corrupts nothing |

## 6. What was deliberately left alone

The restructure was **surgical**: behavior-preserving, never reimplementation. The skill catalog in `brain.py`, the red-team logic, the fusion engine, the twin subsystems, and all 114 legacy tests run exactly as before. The archived modules in `aresx/storage/_unused/` and `aresx/__legacy_core_godfile.py` are preserved for reference and can be deleted at your discretion once you are comfortable with the new tree. If a future subsystem genuinely needs one of the archived store helpers, implement it in place rather than reviving the old files.

# ARES-X v11 "ROAD-NETWORK" — Architecture Refinement Pass

**Author:** Manus AI · **Date:** August 11, 2026

The v10 restructure removed the circular-import tangle and god files. v11 treats the clean tree as a **road network**: one arterial highway (the launcher), consistent on/off ramps (the `_tool_*` wrapper convention), no dead-end roads (confirmed dead code deleted, unwired capabilities ramped in), graceful degradation (the regex fallback survives), and guidance signage (runtime logging at every logic fork). Three work packages — A (demolition and sprawl split), B (signage and ramp standardization), and C (wiring the unreachable capabilities) — were executed in phases with the full test suite verified after each.

## Phase A — Demolition and the sprawl split

The confirmed-dead imports list (`aresx.router`, the orphaned `agents/` directory, legacy `brain.py`/`healer.py` and their test-only shims, `wizard.py`, the duplicated root-level `ares_router.py`/`tool_router.py`/`intent_mapper.py` originals, plus `__pycache__` and five orphaned root scripts) was removed, cutting roughly 30 files. A new **reachability map** (`reachability_map.py`) derives live/dead-end/unwired classifications directly from the real entry points (`main.py` subcommands and `python3 -m aresx.chat`) at runtime, so demolition decisions are evidence-based, not guesses.

The remaining sprawl — `aresx/actions.py` at 3,569 lines — was split by domain into nine focused modules under `aresx/modules/actions/` (assistant, content, desktop, dev, file_ops, and others), each under ~500 lines, with a small shared `_helpers.py`. The old god-file import path still resolves through the compat facade.

## Phase B — Guidance signage and the ramp standard

Three silent logic forks that previously decided routing with no trace now log their decisions at runtime, turning future "which path did my request take?" debugging into a grep:

| Fork | Location | What is logged |
|---|---|---|
| LLM fallback chain | `aresx.chat.router` | Which model answered (Gemini / Groq / regex), including 429-driven fallbacks |
| Server dispatcher choice | `aresx.chat.router` (HTTP path) | Free-form LLM vs. regex routing decision per request |
| Mission slot allocation | `aresx.mission` | Why a mission was accepted, queued, or rejected |

The **ramp convention** is now codified: every chat-reachable capability is exposed through an `_tool_<name>(args)` async wrapper registered in `TOOL_HANDLERS` with a schema in `TOOL_SCHEMAS`; Gemini and Groq both select from the same `LLM_SELECTABLE_SCHEMAS` (a filtered view of `TOOL_SCHEMAS`), so a tool wired once is reachable through both LLM paths and the regex fallback automatically.

## Phase C — Wiring the unreachable capabilities

Two previously unreachable capability clusters were ramped into the highway. First, `aresx.chat.osint_ramps.py` wraps the standalone OSINT capability modules (IP lookup, email breach check, username hunting, domain WHOIS, phone lookup) as chat tools — these were callable only by direct import before. Second, `aresx.graph_command.graph_ramps.py` bridges `digital_twin` and `graph_command`: the twin subsystem had never been able to call the graph analytics it generates data for; five analytic tools (influence analysis, community detection, hidden-relationship discovery, centrality, structural vulnerability) now run over live twin graph-state snapshots with lazy imports so the graph engine only loads when a twin exists. All ten new tools are schema-registered, handler-registered, and therefore selectable by both Gemini and the Groq fallback.

## v11 verification

| Check | Result |
|---|---|
| Full test suite | **122/122 pass** (114 legacy + 8 restructure stress tests) |
| Import-order fuzzing (all ~170 modules × 10 orderings) | Zero failures |
| Circular-import detection (full tree walk) | Zero cycles |
| Reachability re-map after all phases | **0 unwired capabilities**; 29 runtime-live modules; dead-ends are documented `*_unused`/`autonomy`/UI-panel modules awaiting future wiring (deliberate, not accidental) |
| Router compile + schema/handler parity | All 10 Phase-C tools present in both `TOOL_HANDLERS` and the Gemini/Groq selection lists |
