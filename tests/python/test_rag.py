"""Phase 5 RAG / LLM / report tests against TEST_NIST (requires live Ollama)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import requests

from ai_service.llm.ollama_client import (
    MODEL,
    NO_EVIDENCE_REPLY,
    OLLAMA_HOST,
    TEMPERATURE,
    query_llm,
)
from ai_service.rag.rag_pipeline import RAGPipeline
from ai_service.rag.vector_store import VectorStore
from ai_service.reports.html_generator import generate_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASE_ID = "TEST_NIST"
CHROMA = PROJECT_ROOT / "data" / "chromadb"

DEMO_QUESTIONS = [
    "Show all USB device connections",
    "Were there failed login attempts after midnight?",
    "List programs that were executed",
    "Were any suspicious scheduled tasks created?",
    "Provide an investigation summary",
]


def _ollama_up() -> bool:
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        return r.status_code == 200
    except requests.RequestException:
        return False


pytestmark = [
    pytest.mark.skipif(not CHROMA.exists(), reason="ChromaDB data missing"),
    pytest.mark.skipif(not _ollama_up(), reason=f"Ollama not reachable at {OLLAMA_HOST}"),
]


@pytest.fixture(scope="module")
def rag():
    os.environ.setdefault("OLLAMA_HOST", OLLAMA_HOST)
    return RAGPipeline(VectorStore())


def test_temperature_is_factual():
    assert TEMPERATURE == 0.1
    assert MODEL == "qwen2.5:3b"


def test_query_llm_returns_text():
    ans = query_llm(
        "What device is listed?",
        ["Registry entry: Compaq WL110 PCMCIA wireless card"],
    )
    assert isinstance(ans, str)
    assert len(ans.strip()) > 0
    assert "Unable to reach Ollama" not in ans
    assert "timed out" not in ans.lower()


@pytest.mark.parametrize("question", DEMO_QUESTIONS)
def test_demo_question_returns_answer_with_sources(rag, question):
    result = rag.answer(CASE_ID, question)
    assert result["answer"] and len(result["answer"].strip()) > 0
    assert isinstance(result["sources"], list)
    assert len(result["sources"]) > 0
    for src in result["sources"]:
        assert "text" in src and "type" in src


def test_no_evidence_question(rag):
    result = rag.answer(
        CASE_ID,
        "What is the capital of the purple elephant planet Zorp?",
    )
    assert NO_EVIDENCE_REPLY in result["answer"]


def test_generate_report_has_sections(rag):
    path = generate_report(CASE_ID, rag=rag)
    assert Path(path).exists()
    html = Path(path).read_text(encoding="utf-8")
    for marker in (
        "Evidence Integrity",
        "Statistics",
        "Threat Assessment",
        "Event Timeline",
        "USB / PCMCIA",
        "AI Narrative Summary",
        "Offline mode",
        MODEL,
    ):
        assert marker in html
