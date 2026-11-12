"""ARES X v10 — compat shim for moved package aresx.rag_federated."""
from __future__ import annotations
# forwards 16 public symbols
from aresx.domains.rag.rag_system import EmbeddingManager  # noqa: F401
from aresx.domains.rag.rag_system import FederatedResult  # noqa: F401
from aresx.domains.rag.__init__ import PHASE_STATUS  # noqa: F401
from aresx.domains.rag.rag_system import RAGResult  # noqa: F401
from aresx.domains.rag.rag_system import VectorStore  # noqa: F401
from aresx.domains.rag.rag_system import auto_ingest_from_event  # noqa: F401
from aresx.domains.rag.rag_system import embedding_manager  # noqa: F401
from aresx.domains.rag.rag_system import federated_search  # noqa: F401
from aresx.domains.rag.rag_system import ingest_document  # noqa: F401
from aresx.domains.rag.rag_system import list_search_sessions  # noqa: F401
from aresx.domains.rag.rag_system import logger  # noqa: F401
from aresx.domains.rag.rag_system import map_entity_to_ontology  # noqa: F401
from aresx.domains.rag.rag_system import rag_query  # noqa: F401
from aresx.domains.rag.rag_system import resolve_entities  # noqa: F401
from aresx.domains.rag.rag_system import save_search_session  # noqa: F401
from aresx.domains.rag.rag_system import vector_store  # noqa: F401
