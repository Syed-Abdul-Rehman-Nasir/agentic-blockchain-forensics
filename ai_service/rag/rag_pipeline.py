"""Retrieve-then-generate RAG pipeline grounded in ChromaDB evidence."""

from __future__ import annotations

from typing import Any, Dict

from ai_service.rag.vector_store import VectorStore


class RAGPipeline:
    """Top-k retrieval from VectorStore + grounded Ollama answer."""

    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store

    def answer(self, case_id: str, question: str, n_results: int = 8) -> Dict[str, Any]:
        from ai_service.llm.ollama_client import query_llm_with_tools
        result = query_llm_with_tools(case_id, question)
        return {
            "answer": result["answer"],
            "sources": result.get("sources") or [],
            "tools_used": result.get("tools_used") or [],
        }
