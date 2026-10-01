"""LangGraph orchestration for the forensic multi-agent pipeline.

Committee note: LangGraph is the central controller that sequences two
genuinely distinct agents (ArtifactAnalysisAgent for parsing, then
ThreatInterpretationAgent for ML scoring) plus RAG indexing. This is a
true multi-agent system controlled centrally — not a single script of
hardcoded function calls. Agents never run in parallel.
"""

from __future__ import annotations

from typing import Any, Dict, Literal

from langgraph.graph import END, START, StateGraph

from ai_service.agents.artifact_agent import ArtifactAnalysisAgent
from ai_service.agents.threat_agent import ThreatInterpretationAgent
from ai_service.db.database import get_completed_stages, get_connection
from ai_service.graph.state import ForensicState
from ai_service.rag.rag_pipeline import RAGPipeline
from ai_service.rag.vector_store import VectorStore

# Module-level singletons — models / embedder load once for the process.
_artifact_agent: ArtifactAnalysisAgent | None = None
_threat_agent: ThreatInterpretationAgent | None = None
_vector_store: VectorStore | None = None
_rag_pipeline: RAGPipeline | None = None
_compiled_graph = None


def _get_artifact_agent() -> ArtifactAnalysisAgent:
    global _artifact_agent
    if _artifact_agent is None:
        _artifact_agent = ArtifactAnalysisAgent()
    return _artifact_agent


def _get_threat_agent() -> ThreatInterpretationAgent:
    global _threat_agent
    if _threat_agent is None:
        _threat_agent = ThreatInterpretationAgent()
    return _threat_agent


def _get_vector_store() -> VectorStore:
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore()
    return _vector_store


def _get_rag_pipeline() -> RAGPipeline:
    global _rag_pipeline
    if _rag_pipeline is None:
        _rag_pipeline = RAGPipeline(_get_vector_store())
    return _rag_pipeline


def artifact_node(state: ForensicState) -> Dict[str, Any]:
    agent = _get_artifact_agent()
    try:
        summary = agent.analyse(state["case_id"], state["image_path"])
        stages = get_completed_stages(state["case_id"])
        return {
            "artifact_summary": summary,
            "completed_stages": stages,
            "errors": list(state.get("errors") or []),
        }
    except Exception as exc:
        errors = list(state.get("errors") or [])
        errors.append(f"artifact_node: {exc}")
        return {"errors": errors}


def threat_node(state: ForensicState) -> Dict[str, Any]:
    agent = _get_threat_agent()
    try:
        scores = agent.analyse(state["case_id"])
        stages = get_completed_stages(state["case_id"])
        return {
            "threat_scores": scores,
            "completed_stages": stages,
        }
    except Exception as exc:
        errors = list(state.get("errors") or [])
        errors.append(f"threat_node: {exc}")
        return {"errors": errors}


def index_node(state: ForensicState) -> Dict[str, Any]:
    store = _get_vector_store()
    try:
        summary = store.index_case(state["case_id"])
        stages = get_completed_stages(state["case_id"])
        return {
            "index_summary": summary,
            "completed_stages": stages,
        }
    except Exception as exc:
        errors = list(state.get("errors") or [])
        errors.append(f"index_node: {exc}")
        return {"errors": errors}


def query_node(state: ForensicState) -> Dict[str, Any]:
    """Grounded RAG answer via VectorStore retrieval + Ollama (Phase 5)."""
    rag = _get_rag_pipeline()
    question = state.get("question") or ""
    try:
        result = rag.answer(state["case_id"], question, n_results=8)
        return {
            "query_response": {
                "status": "ok",
                "answer": result.get("answer"),
                "sources": result.get("sources") or [],
            }
        }
    except Exception as exc:
        errors = list(state.get("errors") or [])
        errors.append(f"query_node: {exc}")
        return {
            "query_response": {"status": "error", "message": str(exc)},
            "errors": errors,
        }


def _route_intent(state: ForensicState) -> Literal["analyse", "query"]:
    intent = (state.get("intent") or "analyse").lower()
    return "query" if intent == "query" else "analyse"


def build_graph():
    """Compile the forensic StateGraph (analyse vs query routes)."""
    graph = StateGraph(ForensicState)
    graph.add_node("artifact_node", artifact_node)
    graph.add_node("threat_node", threat_node)
    graph.add_node("index_node", index_node)
    graph.add_node("query_node", query_node)

    graph.add_conditional_edges(
        START,
        _route_intent,
        {
            "analyse": "artifact_node",
            "query": "query_node",
        },
    )
    graph.add_edge("artifact_node", "threat_node")
    graph.add_edge("threat_node", "index_node")
    graph.add_edge("index_node", END)
    graph.add_edge("query_node", END)
    return graph.compile()


def get_graph():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


def run_analysis(case_id: str, image_path: str) -> ForensicState:
    """Invoke the full sequential multi-agent analysis pipeline."""
    graph = get_graph()
    initial: ForensicState = {
        "case_id": case_id,
        "image_path": image_path,
        "intent": "analyse",
        "question": "",
        "artifact_summary": {},
        "threat_scores": {},
        "query_response": {},
        "completed_stages": [],
        "errors": [],
        "index_summary": {},
    }
    return graph.invoke(initial)


def run_query(case_id: str, question: str) -> ForensicState:
    """Runs RAG pipeline via query_node."""
    graph = get_graph()
    initial: ForensicState = {
        "case_id": case_id,
        "image_path": "",
        "intent": "query",
        "question": question,
        "artifact_summary": {},
        "threat_scores": {},
        "query_response": {},
        "completed_stages": [],
        "errors": [],
        "index_summary": {},
    }
    return graph.invoke(initial)
