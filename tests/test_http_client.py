"""
ARES X — shared HTTP client tests
==================================
Every outbound call in the process (LLM providers, OSINT endpoints,
connectivity checks) must go through ONE pooled HTTP/2 client so a
multi-step Gemini/Groq tool turn reuses a keepalive connection per host
instead of paying a fresh TLS handshake per request.

These tests lock that architecture in:
  * ``aresx.core.paths`` is the single source of the client
  * ``aresx.core.llm`` re-exports it rather than owning a second pool
  * the router's Gemini/Groq paths and the OSINT ramps use it
  * the client is a per-event-loop singleton (so the CLI's background
    loop and the server's main loop don't cross-reuse a stale client)
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aresx.core import paths as core_paths
from aresx.core import llm as core_llm


class SharedHttpClientTests(unittest.TestCase):

    def test_llm_does_not_own_a_second_pool(self):
        # llm.py must delegate, not define its own _get_http / _async_*.
        self.assertIs(core_llm._get_http, core_paths.get_http_client)
        self.assertIs(core_llm._async_post, core_paths._async_post)
        self.assertIs(core_llm._async_get, core_paths._async_get)

    def test_singleton_within_one_loop(self):
        async def go():
            a = await core_paths.get_http_client()
            b = await core_paths.get_http_client()
            return a, b

        a, b = asyncio.run(go())
        self.assertIs(a, b)
        self.assertFalse(a.is_closed)

    def test_fresh_loop_gets_a_usable_client(self):
        # A client cached against a now-closed loop must not be handed
        # back — that was the "Event loop is closed" bug.
        c1 = asyncio.run(core_paths.get_http_client())
        c2 = asyncio.run(core_paths.get_http_client())
        self.assertFalse(c2.is_closed)
        # Different loops => different client objects.
        self.assertIsNot(c1, c2)

    def test_router_and_osint_use_the_shared_client(self):
        from aresx.chat import router, osint_ramps

        async def go():
            rc = await router._shared_http_client()
            pc = await core_paths.get_http_client()
            return rc, pc

        rc, pc = asyncio.run(go())
        self.assertIs(rc, pc)
        # osint_ramps imports get_http_client lazily inside _get_json —
        # assert the symbol it reaches for is the shared one.
        self.assertTrue(hasattr(core_paths, "get_http_client"))
        self.assertIn("get_http_client", osint_ramps._get_json.__code__.co_names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
