"""Shared test helper: boot the v8 substrate against a throwaway titan.db.

Tests that touch missions / audit logging need the schema to exist. A
fresh checkout has no titan.db (it's gitignored runtime state), so they
must not depend on one already being there or on another test file
having created it first. Same bootstrap pattern the phase tests use.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path


_saved: dict[Path, tuple] = {}


def boot_isolated_db(prefix: str = "ares_x_test_") -> Path:
    tmp = Path(tempfile.mkdtemp(prefix=prefix))
    from aresx.storage import db as db_mod
    from aresx.storage import graph as _g
    import aresx.v8_bootstrap as _bs
    # Remember global state so teardown can put it back — other test
    # files rely on whatever DB_PATH they (or the default) established.
    _saved[tmp] = (db_mod.DB_PATH, _g.GRAPH_PATH, _g._initialised,
                   _g._status, _bs._booted, _bs._boot_status)
    db_mod.DB_PATH = tmp / "titan.db"
    db_mod.close_thread_connection()

    from aresx.storage import graph as graph_mod
    graph_mod.GRAPH_PATH = tmp / "titan_graph.kuzu"
    graph_mod._initialised = False
    graph_mod._status = {"available": False, "message": "not initialised"}

    import aresx.v8_bootstrap as bs
    bs._booted = False
    bs._boot_status = None
    bs.boot()
    return tmp


def teardown_isolated_db(tmp: Path) -> None:
    from aresx.storage import db as db_mod
    from aresx.storage import graph as graph_mod
    import aresx.v8_bootstrap as bs
    db_mod.close_thread_connection()
    prev = _saved.pop(tmp, None)
    if prev is not None:
        (db_mod.DB_PATH, graph_mod.GRAPH_PATH, graph_mod._initialised,
         graph_mod._status, bs._booted, bs._boot_status) = prev
    shutil.rmtree(tmp, ignore_errors=True)
