"""
ARES X — async inference tests
===============================
sovereign_cluster.py's provider calls were synchronous httpx and were
invoked, unawaited, from the async chat router — every LLM fallback
froze the FastAPI event loop for the whole request. These tests lock
the async rewrite in:

  * every provider twin + generate_async is a coroutine function
  * no synchronous httpx (post / Client) survives in the module
  * generate_async runs over the shared pooled client and does NOT
    block the event loop even while a provider is slow
  * the synchronous generate() surface (4 non-async callers) still
    works and still audits (Order 21)
  * the router uses generate_async, not generate
"""
from __future__ import annotations

import asyncio
import inspect
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import importlib

# aresx.domains.ai.__init__ binds the name `sovereign_cluster` to the
# SovereignCluster *instance*, shadowing the submodule — go through
# importlib to get the actual module object.
sc = importlib.import_module("aresx.domains.ai.sovereign_cluster")


class AsyncSurfaceTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from tests._isolated_db import boot_isolated_db
        cls._tmp = boot_isolated_db("ares_x_infer_")

    @classmethod
    def tearDownClass(cls):
        from tests._isolated_db import teardown_isolated_db
        teardown_isolated_db(cls._tmp)

    def test_twins_and_generate_async_are_coroutines(self):
        for name in ("_try_ollama_async", "_try_gemini_async", "_try_groq_async",
                     "_try_huggingface_async", "_try_openrouter_free_async"):
            self.assertTrue(inspect.iscoroutinefunction(getattr(sc, name)), name)
        self.assertTrue(inspect.iscoroutinefunction(sc.InferenceAPI.generate_async))
        self.assertFalse(inspect.iscoroutinefunction(sc.InferenceAPI.generate))

    def test_no_sync_httpx_left_in_module(self):
        src = Path(sc.__file__).read_text()
        # strip comments so the "we used to do this" note doesn't trip it
        code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
        self.assertNotIn("httpx.post(", code)
        self.assertNotIn("httpx.Client(", code)

    def test_generate_async_does_not_block_event_loop(self):
        async def slow(prompt, model, system, max_tokens):
            await asyncio.sleep(0.4)
            return "SLOW-OK"

        orig = dict(sc._ASYNC_PROVIDERS)
        sc._ASYNC_PROVIDERS["gemini/"] = slow
        try:
            async def go():
                ticks = 0
                stop = asyncio.Event()

                async def ticker():
                    nonlocal ticks
                    while not stop.is_set():
                        ticks += 1
                        await asyncio.sleep(0.01)

                tk = asyncio.create_task(ticker())
                import os
                os.environ["GEMINI_API_KEY"] = "x"
                try:
                    r = await sc.inference_api.generate_async("hi", max_tokens=5)
                finally:
                    os.environ.pop("GEMINI_API_KEY", None)
                stop.set()
                await tk
                return r, ticks

            r, ticks = asyncio.run(go())
            self.assertEqual(r, "SLOW-OK")
            self.assertGreater(ticks, 20, "event loop was blocked during the call")
        finally:
            sc._ASYNC_PROVIDERS.clear()
            sc._ASYNC_PROVIDERS.update(orig)

    def test_sync_generate_still_works_and_audits(self):
        from aresx.storage import db
        out = sc.inference_api.generate("Say hello", task_type="general", max_tokens=10)
        self.assertIsInstance(out, str)  # "" is fine when no LLM is reachable
        row = db.query_one(
            "SELECT log_id FROM audit_log_v2 WHERE action = 'inference.generate' "
            "ORDER BY sequence_num DESC LIMIT 1"
        )
        self.assertIsNotNone(row, "inference.generate must still be audited (Order 21)")

    def test_providers_degrade_without_keys(self):
        async def go():
            for prefix, fn in sc._ASYNC_PROVIDERS.items():
                self.assertIsNone(await fn("hi", prefix + "m", None, 5), prefix)
        asyncio.run(go())

    def test_router_uses_generate_async(self):
        router_src = (PROJECT_ROOT / "aresx" / "chat" / "router.py").read_text()
        self.assertNotIn("inference_api.generate(", router_src)
        self.assertIn("inference_api.generate_async(", router_src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
