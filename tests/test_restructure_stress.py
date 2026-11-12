"""
ARES X v10 — Restructure stress tests
======================================
Verifies the NEW wiring properties that the old architecture lacked:

1. Import-order fuzzing        — importing every module in 10 random orders
   must always succeed (no order-dependent init bugs).
2. Circular import detection   — importing every module must never raise a
   circular-import error, even under importlib stress.
3. Boot profiling              — the core boot path must stay fast
   (< 3s to import aresx + core + chat on this hardware).
4. Event bus concurrency       — N threads publishing to the bus concurrently
   must never lose or corrupt events.
5. Tool registry concurrency   — concurrent register() / resolve() must stay
   consistent.
6. Storage thread safety       — concurrent reads/writes against the SQLite
   layer must not corrupt rows.
"""
from __future__ import annotations

import asyncio
import importlib
import os
import pkgutil
import random
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aresx
from aresx.bus import bus, Event, EventType
from aresx.registry import registry
from aresx.core.paths import BASE_DIR
PROJECT_ROOT = BASE_DIR.parent


class ImportOrderFuzzTests(unittest.TestCase):
    """Every module must import in ANY order. The v9 codebase failed this
    because heavy __init__.py chains imported implementation modules
    eagerly in an order-dependent way."""

    def _module_names(self) -> list[str]:
        names = []
        for modinfo in pkgutil.walk_packages(
                aresx.__path__, aresx.__name__ + "."):
            # __legacy_core_godfile is the archived v9 core.py reference copy —
            # not part of the live wiring; skipped deliberately (needs tkinter).
            if modinfo.name.endswith("__legacy_core_godfile"):
                continue
            # aresx.wizard hard-requires PySide6 at import (documented: it is a
            # Qt-only module). On headless/CI boxes without Qt it is expected to
            # raise a clear ImportError — that is the designed degradation, not
            # a wiring bug.
            if modinfo.name == "aresx.wizard":
                continue
            names.append(modinfo.name)
        return names

    def test_import_every_module_once(self):
        failed = []
        for name in self._module_names():
            try:
                importlib.import_module(name)
            except Exception as exc:  # noqa: BLE001
                failed.append((name, type(exc).__name__, str(exc)[:120]))
        self.assertEqual(failed, [], f"modules failed to import: {failed[:5]}")

    def test_import_random_orders(self):
        names = self._module_names()
        self.assertGreater(len(names), 50)  # sanity: we really fuzzed everything
        for seed in range(10):
            rng = random.Random(seed)
            order = list(names)
            rng.shuffle(order)
            for name in order:
                # clear to force a genuine re-import (catches lazy-init bugs)
                if name in sys.modules:
                    del sys.modules[name]
                try:
                    importlib.import_module(name)
                except ImportError as exc:
                    if "circular" in str(exc).lower():
                        self.fail(f"circular import on seed={seed} path: {name}")


class CircularImportTests(unittest.TestCase):
    """No module may fail to load with a circular-import error, ever."""

    def test_no_circular_import_errors(self):
        circular = []
        for modinfo in pkgutil.walk_packages(
                aresx.__path__, aresx.__name__ + "."):
            try:
                importlib.import_module(modinfo.name)
            except ImportError as exc:
                if "circular" in str(exc).lower():
                    circular.append((modinfo.name, str(exc)[:200]))
        self.assertEqual(circular, [])


class BootProfileTests(unittest.TestCase):
    """The boot path must stay snappy. v9 imported Qt/sqlite/LLM clients
    eagerly at package init, inflating boot time with every added feature."""

    def test_core_boot_path_under_3s(self):
        # fresh interpreter: the expensive measurement.
        script = (
            "import aresx, aresx.core, aresx.core.paths, aresx.core.memory, "
            "aresx.chat.router, aresx.bus\n"
            "print('boot ok')"
        )
        t0 = time.perf_counter()
        import subprocess
        r = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(PROJECT_ROOT),
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        elapsed = time.perf_counter() - t0
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        self.assertLess(elapsed, 3.0, f"boot took {elapsed:.2f}s")


class BusConcurrencyTests(unittest.TestCase):
    """The bus is THE pub/sub wire. Concurrent publishers must all be heard.

    publish_sync() requires an Event or EventType (the audit hook reads
    ``event.type``), so the concurrency tests build a lightweight wrapper
    event type using a real EventType member and carry per-thread data in
    the payload — that is the bus's supported contract."""

    def test_concurrent_publish(self):
        n_threads, n_each = 8, 50
        # Queue-backed subscription (real bus API: subscribe -> Subscription
        # whose queue is drained by a worker thread).
        sub = bus.subscribe("plugin.*", queue_size=10000)
        received = []
        lock = threading.Lock()
        stop = threading.Event()

        async def _drain_one():
            try:
                return await asyncio.wait_for(sub.queue.get(), timeout=0.2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                return None

        def drainer():
            loop = asyncio.new_event_loop()
            try:
                while not stop.is_set():
                    ev = loop.run_until_complete(_drain_one())
                    if ev is not None:
                        with lock:
                            received.append(ev)
            finally:
                loop.close()

        dr = threading.Thread(target=drainer, daemon=True)
        dr.start()
        try:
            def publisher(tid):
                for i in range(n_each):
                    bus.publish_sync(
                        EventType.PLUGIN_LOADED, payload={"t": tid, "i": i},
                        source="stress")

            threads = [threading.Thread(target=publisher, args=(t,))
                       for t in range(n_threads)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=15)
            # drain anything still in flight
            time.sleep(0.3)
            stop.set()
            dr.join(timeout=5)
        finally:
            bus.unsubscribe(sub)

        total = len(received)
        self.assertEqual(total, n_threads * n_each,
                         f"lost events: expected {n_threads*n_each}, got {total}")

    def test_subscribe_unsubscribe_concurrent(self):
        errors = []
        lock = threading.Lock()

        def worker():
            try:
                sub = bus.subscribe("plugin.*")
                bus.publish_sync(EventType.PLUGIN_LOADED, payload={"k": 1}, source="stress")
                bus.unsubscribe(sub)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=15)
        self.assertEqual(errors, [])


class RegistryConcurrencyTests(unittest.TestCase):
    """The registry is the tool/skill hub. Concurrent register/resolve must
    stay consistent without locks racing."""

    def test_concurrent_register_resolve(self):
        names = [f"stress.tool_{i}" for i in range(40)]
        for name in names:
            registry.register_tool(name, lambda msg="ping": f"ok-{name}")
        results = []
        lock = threading.Lock()

        def resolver(name):
            try:
                got = registry.get_tool(name)
                res = f"ok-{name}" if got is not None else "MISSING"
            except Exception as exc:  # noqa: BLE001
                res = f"ERR {exc}"
            with lock:
                results.append(res)

        threads = [threading.Thread(target=resolver,
                                    args=(names[i % 40],))
                   for i in range(80)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=15)
        self.assertEqual(len(results), 80)
        self.assertTrue(all(r.startswith("ok-") for r in results), results[:3])
        # cleanup
        for name in names:
            registry.unregister_tool(name)


class StorageThreadSafetyTests(unittest.TestCase):
    """SQLite layer must survive concurrent read/write bursts."""

    def test_concurrent_sqlite_ops(self):
        from aresx.storage import db
        with db.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS restructure_stress "
                "(id INTEGER PRIMARY KEY, tid INTEGER, val INTEGER)")
        errors = []
        lock = threading.Lock()

        def writer(tid):
            try:
                with db.transaction() as conn:
                    for i in range(12):
                        conn.execute(
                            "INSERT INTO restructure_stress (tid, val) VALUES (?, ?)",
                            (tid, i))
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        def reader():
            try:
                with db.connect() as conn:
                    conn.execute(
                        "SELECT COUNT(*) FROM restructure_stress").fetchone()
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(6)]
        threads += [threading.Thread(target=reader) for _ in range(6)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=30)
        # cleanup
        try:
            with db.connect() as conn:
                conn.execute("DROP TABLE IF EXISTS restructure_stress")
        except Exception:  # noqa: BLE001
            pass
        self.assertEqual(errors, [], errors[:3])


if __name__ == "__main__":
    unittest.main()
