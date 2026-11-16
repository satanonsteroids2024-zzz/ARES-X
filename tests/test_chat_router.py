"""
ARES X v11 — Chat router (regex ring-road) tests
=================================================
Replaces the two v9-era standalone scripts at repo root
(test_tool_router.py / test_chat_auth.py), which referenced the
pre-restructure ``tool_router.TOOL_HANDLERS`` module surface and
required a live Gemini key to run at all.

This suite exercises the canonical router at ``aresx.chat.router``:

  * ``_match_intent``      — regex intent + argument extraction, incl.
                              the priority-ordering subtleties
  * ``_regex_route_message`` — end-to-end dispatch for the intents that
                              are safe to run fully offline
  * ``_llm_fallback``     — graceful-degradation string when no LLM
                              backend is reachable (no key, no Ollama)
  * handler-signature parity — every entry in ``_INTENT_HANDLERS`` is an
                              async ``(arg, message)`` callable, matching
                              the ramp convention in RESTRUCTURE.md §B

The Gemini free-form path (``route_message``) needs a real key and is
intentionally out of scope here.
"""
from __future__ import annotations

import asyncio
import inspect
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from aresx.chat import router
from tests._isolated_db import boot_isolated_db, teardown_isolated_db


class MatchIntentTests(unittest.TestCase):
    """The fast regex path: phrasing -> (intent, captured arg)."""

    def _match(self, msg):
        return router._match_intent(msg)

    def test_recon_phrasings(self):
        for msg in ("scan example.com", "run a recon scan on example.com",
                    "reconnaissance example.com"):
            got = self._match(msg)
            self.assertIsNotNone(got, msg)
            self.assertEqual(got[0], "recon", msg)
            self.assertEqual(got[1], "example.com", msg)

    def test_cve_lookup_vs_search(self):
        self.assertEqual(self._match("tell me about CVE-2021-44228"),
                         ("cve_lookup", "2021-44228"))
        intent, arg = self._match("cve search apache struts")
        self.assertEqual(intent, "cve_search")
        self.assertIn("apache struts", arg)

    def test_whois_domain_beats_threat_actor(self):
        # The specific WHOIS-with-TLD pattern must win over the generic
        # "profile/threat actor <name>" catch-all (priority ordering).
        self.assertEqual(self._match("whois example.com"),
                         ("osint_domain_whois", "example.com"))

    def test_zero_arg_intents(self):
        self.assertEqual(self._match("status")[0], "status")
        self.assertEqual(self._match("show my missions")[0], "list_missions")
        self.assertEqual(self._match("run a wargame")[0], "wargame")

    def test_osint_ip_and_breach(self):
        self.assertEqual(self._match("ip lookup 8.8.8.8"),
                         ("osint_ip_lookup", "8.8.8.8"))
        self.assertEqual(self._match("breach check alice@example.com"),
                         ("osint_email_breach_check", "alice@example.com"))

    def test_no_match_returns_none(self):
        self.assertIsNone(self._match("what's the weather like today"))


class RegexRouteMessageTests(unittest.TestCase):
    """End-to-end dispatch for intents that touch no network/LLM."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = boot_isolated_db("ares_x_router_")

    @classmethod
    def tearDownClass(cls):
        teardown_isolated_db(cls._tmp)

    def _route(self, msg):
        return asyncio.run(router._regex_route_message(msg))

    def test_status(self):
        self.assertIn("operational", self._route("status").lower())

    def test_wargame(self):
        self.assertIn("war-game", self._route("run a wargame").lower())

    def test_list_missions_dispatches_cleanly(self):
        # Regression: these three handlers previously had a 1-arg
        # signature while the dispatcher always calls handler(arg, msg),
        # so every call raised TypeError and fell back to the LLM.
        out = self._route("show my missions")
        self.assertNotIn("failed", out.lower())
        self.assertNotIn("takes 1 positional argument", out)


class LlmFallbackTests(unittest.TestCase):
    """No key + no local model => a clean string, never an exception."""

    def test_fallback_degrades_gracefully(self):
        out = asyncio.run(router._llm_fallback("hello there"))
        self.assertIsInstance(out, str)
        self.assertTrue(out)

    def test_unmatched_message_routes_to_fallback_without_error(self):
        out = asyncio.run(router._regex_route_message("ponder the void"))
        self.assertIsInstance(out, str)
        self.assertTrue(out)


class HandlerSignatureParityTests(unittest.TestCase):
    """Ramp convention (RESTRUCTURE.md Phase B): every intent handler is
    an async callable taking exactly (arg, message)."""

    def test_all_handlers_are_async_two_arg(self):
        for intent, handler in router._INTENT_HANDLERS.items():
            with self.subTest(intent=intent):
                self.assertTrue(inspect.iscoroutinefunction(handler),
                                f"{intent} handler is not async")
                params = list(inspect.signature(handler).parameters.values())
                positional = [p for p in params
                              if p.kind in (p.POSITIONAL_ONLY,
                                             p.POSITIONAL_OR_KEYWORD)]
                self.assertEqual(len(positional), 2,
                                 f"{intent} handler must take (arg, message)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
