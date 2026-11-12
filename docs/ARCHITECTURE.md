# ARES X — Architecture

## Principles

1. **One wire.** Subsystems communicate only through the **event bus** (`aresx.bus`) and the global **registry** (`aresx.registry`). No cross-domain imports — a hub-and-spoke star, not an N×N tangle.
2. **No god files.** Each module has one job and stays small.
3. **`__init__.py` exports symbols, never behavior.** Heavy subsystems load lazily through the registry.
4. **One storage layer.** A single SQLite connection layer (`aresx.storage`) with migrations, an audit chain, and an optional Kuzu graph.
5. **One router, one launcher.** `aresx.chat.router` turns natural language into tool calls; `main.py` is the single entry point.
6. **Optional stays optional.** Every third-party dependency is import-lazy, so a bare install boots and degrades gracefully.

## Layout

```
main.py                 launcher: server | native
ares_server.py          FastAPI app, SSE chat streaming, setup endpoints
frontend/index.html     single-file web UI
aresx/
  chat/                 LLM tool router + intent ramps
  core/                 config, paths, LLM client, memory, audio, screen
  bus/  registry.py     the event bus and the service registry
  storage/              SQLite layer, migrations, optional graph
  red/                  recon, vuln intel, threat actors, ROE, ATT&CK kill chain
  fusion/               confidence model, contradictions, correlators
  digital_twin/ + domains/twin     org / infra / human / adversary / supply-chain / terrain / timeline twins
  mission/              missions, objectives, branching, replay, live ops
  decision/             cost-benefit, risk, decision trees, scenarios
  simulation/           propagation, what-if, wargame, economic impact
  graph_command/        influence, communities, centrality, hidden links
  enterprise/           evidence vault, approval gates, watchlists, briefs, lineage
  domains/security/     hybrid vault, HSM, zero-trust, key rotation, SOC 2 / NIST CSF
  domains/rag/          ingestion, embeddings, vector store, federated search
  domains/ai/           model registry, inference API, cluster, offline mode
  plugins/              sandboxed plugin system
tests/                  122 tests across all layers
```

## Request flow

```
browser ──▶ /chat/stream ──▶ chat router ──▶ LLM function-calling (Gemini → Groq → OpenRouter → HF → Ollama)
                                  │                         └─ regex fallback when no model is reachable
                                  ▼
                              registry ──▶ tool (red / fusion / twin / mission / …) ──▶ event bus ──▶ storage + audit chain
```

## Human-in-the-loop controls

- **Rules of Engagement:** network-facing tools run only inside an operator-opened, time-boxed, case-labelled authorization window; otherwise each target needs a live confirmation.
- **Approval gates:** sensitive actions (e.g. human-twin building) block until a human resolves the gate.
- **Evidence vault:** hash-chained entries so tampering is detectable.
