"""ARES X v10 — compat shim forwarding to aresx.domains.twin.twin_builder."""
from __future__ import annotations
from aresx.domains.twin.twin_builder import logger
from aresx.domains.twin.twin_builder import _MAX_CONCURRENT
from aresx.domains.twin.twin_builder import _semaphore
from aresx.domains.twin.twin_builder import _get_semaphore
from aresx.domains.twin.twin_builder import build_twin
