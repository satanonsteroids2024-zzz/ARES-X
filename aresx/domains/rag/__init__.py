"""aresx.rag_federated — Phase 10: Enterprise RAG + Federated Search (Orders 22 & 24)"""
from aresx.domains.rag.rag_system import (
    ingest_document, rag_query, federated_search,
    auto_ingest_from_event, resolve_entities,
    save_search_session, list_search_sessions,
    map_entity_to_ontology,
    embedding_manager, vector_store,
    RAGResult, FederatedResult,
)
PHASE_STATUS = "implemented"
__all__ = [
    "ingest_document","rag_query","federated_search",
    "auto_ingest_from_event","resolve_entities",
    "save_search_session","list_search_sessions",
    "map_entity_to_ontology",
    "embedding_manager","vector_store",
    "RAGResult","FederatedResult","PHASE_STATUS",
]
