"""Shared LangGraph state for the forensic multi-agent pipeline."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class ForensicState(TypedDict, total=False):
    case_id: str
    image_path: str
    intent: str  # "analyse" or "query"
    question: str
    artifact_summary: Dict[str, Any]
    threat_scores: Dict[str, Any]
    query_response: Dict[str, Any]
    completed_stages: List[str]
    errors: List[str]
    index_summary: Dict[str, Any]
