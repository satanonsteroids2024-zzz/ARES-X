"""
ARES X — core module wiring tests
===================================
A static-analysis pass (ruff --select F821) found 64 undefined-name
bugs across aresx/core/* and aresx/modules/actions/* — names used but
never imported, left behind when core.py and actions.py were split
into focused modules. Most would only ever surface at runtime, inside
an `except:` branch or a rarely-hit code path, as a confusing NameError
masking the real error.

This suite locks in the two most severe fixes with real behavior
(the rest are covered structurally by `ruff check --select F821`
staying clean — see the repo's CI/dev workflow):

  * Mike memory (aresx.core.memory): every single operation crashed
    with "threads can only be started once" (aiosqlite.Connection was
    entered twice — once inside _ensure_db's own `await connect()`,
    again by the caller's `async with`) and, even ignoring the crash,
    leaked a connection + background thread on every call, forever.
  * aresx.core.llm's Gemini/Groq async backends referenced an undefined
    `logger` in their exception handlers — any real exception during a
    live call (timeout, connection error, bad JSON) crashed with
    NameError instead of gracefully falling through to the next
    provider.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class MikeMemoryTests(unittest.TestCase):
    """aresx.core.memory.mike — was 100% broken before this fix."""

    def test_remember_recall_roundtrip(self):
        from aresx.core.memory import Mike
        # Fresh instance + throwaway DB file so this test doesn't share
        # state with a real run of the app.
        import tempfile, os
        m = Mike()
        m._db_path = os.path.join(tempfile.mkdtemp(prefix="ares_mike_test_"), "mike.db")

        m.remember("k1", "v1")
        self.assertEqual(m.recall("k1"), "v1")
        self.assertIn("k1", m.all_keys())

    def test_repeated_operations_do_not_crash(self):
        # Regression for "threads can only be started once" — every
        # call used to open (and never close) its own aiosqlite
        # connection+thread and then immediately double-enter it.
        from aresx.core.memory import Mike
        import tempfile, os
        m = Mike()
        m._db_path = os.path.join(tempfile.mkdtemp(prefix="ares_mike_test_"), "mike.db")

        for i in range(5):
            m.add_note(f"note {i}")
            m.log_command(f"cmd {i}", "ok")
        summary = m.summary()
        self.assertIn("5 cmds", summary)
        self.assertIn("5 notes", summary)

    def test_connections_are_actually_closed(self):
        # The old _ensure_db never closed what it opened — each call
        # left its aiosqlite connection's worker thread running forever.
        # Each aiosqlite.Connection spawns exactly one worker thread, so
        # the live thread count must return to baseline once its `async
        # with` block (now backed by @asynccontextmanager) exits.
        import threading, time
        from aresx.core.memory import Mike
        import tempfile, os
        m = Mike()
        m._db_path = os.path.join(tempfile.mkdtemp(prefix="ares_mike_test_"), "mike.db")

        before = threading.active_count()
        for i in range(5):
            m.remember(f"k{i}", f"v{i}")
        time.sleep(0.2)  # let a closed connection's worker thread exit
        after = threading.active_count()
        self.assertEqual(after, before,
                          f"thread count grew from {before} to {after} — connections leaking")


class LlmLoggerTests(unittest.TestCase):
    """aresx.core.llm's provider exception handlers referenced an
    undefined `logger` — any real exception (not just a non-200 HTTP
    status) crashed with NameError instead of degrading gracefully."""

    def test_module_defines_logger(self):
        from aresx.core import llm
        import logging
        self.assertIsInstance(llm.logger, logging.Logger)

    def test_gemini_async_exception_path_does_not_nameerror(self):
        import asyncio
        from aresx.core import llm

        async def broken_post(*a, **kw):
            raise RuntimeError("simulated network failure")

        orig = llm._async_post
        llm._async_post = broken_post
        try:
            import os
            os.environ["GEMINI_API_KEY"] = "x"
            try:
                result = asyncio.run(llm._gemini_async("hi"))
            finally:
                os.environ.pop("GEMINI_API_KEY", None)
            self.assertIsNone(result)  # degrades to None, not a crash
        finally:
            llm._async_post = orig


class ActionsWiringTests(unittest.TestCase):
    """The actions.py -> aresx/modules/actions/* split left several
    cross-file references unimported (_HTTPX, _ps_async,
    browser_tabs_async, _run_git_async, git_advanced_async) plus a few
    missing stdlib imports (hashlib, sqlite3, datetime). All now
    resolve; this proves the git-command path is not just importable
    but functionally correct end-to-end."""

    def test_no_undefined_names_anywhere(self):
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "--select", "F821,F822,F823",
             "aresx/", "main.py", "ares_server.py", "ares_native.py",
             "tool_router.py", "intent_mapper.py", "api_keys.py"],
            cwd=PROJECT_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_git_advanced_async_returns_real_output_not_a_tuple(self):
        # _run_git_async returns (returncode, output); the pre-fix code
        # treated that tuple itself as the result string.
        import asyncio
        from aresx.modules.actions.web import git_advanced_async
        out = asyncio.run(git_advanced_async("log", repo_path=str(PROJECT_ROOT)))
        self.assertIsInstance(out, str)
        self.assertNotIn("(0,", out)  # would appear if a tuple got str()'d


if __name__ == "__main__":
    unittest.main(verbosity=2)
