"""FastAPI AI service — forensic analysis, RAG chat, reports, hash verify.

Run from project root:
  uvicorn ai_service.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field

from ai_service.db.database import (
    create_case,
    get_artifacts_for_case,
    get_case,
    get_completed_stages,
    get_threats_for_case,
    initialise_db,
    list_cases,
    update_case_status,
)
from ai_service.graph.forensic_graph import run_analysis
from ai_service.parsers.disk_mount import compute_system_hash, mount_image
from ai_service.rag.rag_pipeline import RAGPipeline
from ai_service.rag.vector_store import EMBEDDING_MODEL, VectorStore
from ai_service.reports.html_generator import generate_report
from ai_service.llm.ollama_client import MODEL, TEMPERATURE

logger = logging.getLogger("ai_service")

app = FastAPI(title="Forensic AI Service", version="0.7.0")

# Expected sequential stages for progress reporting (matches agents/index).
EXPECTED_STAGES: List[str] = [
    "disk_mount",
    "registry",
    "events",
    "browser",
    "prefetch",
    "threat_analysis",
    "rag_indexing",
]

_vector_store: Optional[VectorStore] = None
_rag: Optional[RAGPipeline] = None
# case_id -> True while a background analysis is running
_running: Dict[str, bool] = {}


def _get_rag() -> RAGPipeline:
    global _vector_store, _rag
    if _rag is None:
        _vector_store = VectorStore()
        _rag = RAGPipeline(_vector_store)
    return _rag


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateCaseRequest(BaseModel):
    name: str = Field(..., description="Human-readable case name")
    image_path: str = Field(..., description="Path to disk image (E01 or raw/split)")
    case_id: Optional[str] = Field(None, description="Optional case id; auto-generated if omitted")


class AnalyseRequest(BaseModel):
    case_id: str
    image_path: str


class ChatRequest(BaseModel):
    case_id: str = Field(..., description="Case identifier")
    question: str = Field(..., description="Investigator question")


class VerifyHashRequest(BaseModel):
    image_path: str = Field(..., description="Path to disk image to re-hash")


# ---------------------------------------------------------------------------
# Background analysis
# ---------------------------------------------------------------------------


def _run_analysis_job(case_id: str, image_path: str) -> None:
    """Background worker: LangGraph analyse pipeline; updates case status."""
    try:
        update_case_status(case_id, "analysing")
        result = run_analysis(case_id, image_path)
        errors = result.get("errors") or []
        if errors:
            logger.error("Analysis errors for %s: %s", case_id, errors)
            update_case_status(case_id, "error")
        else:
            update_case_status(case_id, "complete")
    except Exception as exc:
        logger.exception("Analysis failed for %s: %s", case_id, exc)
        try:
            update_case_status(case_id, "error")
        except Exception:
            logger.warning("Could not set case %s status to error after failure", case_id)
    finally:
        _running.pop(case_id, None)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def _check_dependencies() -> None:
    missing = []
    try:
        import pytsk3  # noqa: F401
    except ImportError:
        missing.append("pytsk3 (needs: sudo apt install libewf-dev && pip install pytsk3)")
    try:
        from ai_service.parsers.ewf_bindings import available as ewf_available

        if not ewf_available():
            missing.append(
                "libewf (needs: sudo apt install libewf2 libewf-dev ewf-tools)"
            )
    except Exception:
        missing.append(
            "libewf (needs: sudo apt install libewf2 libewf-dev ewf-tools)"
        )
    if missing:
        for m in missing:
            logger.error("MISSING DEPENDENCY: %s", m)
        logger.error(
            "Fix the above and restart. "
            "See README.md Troubleshooting section for full install commands."
        )


@app.on_event("startup")
def on_startup() -> None:
    initialise_db()
    _check_dependencies()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "model": MODEL,
        "temperature": TEMPERATURE,
        "embedding_model": EMBEDDING_MODEL,
        "vector_db": "ChromaDB",
    }


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


@app.post("/cases")
def post_case(body: CreateCaseRequest) -> Dict[str, Any]:
    """Create a case row in SQLite; returns case_id."""
    initialise_db()
    case_id = (body.case_id or "").strip() or f"CASE_{uuid.uuid4().hex[:12].upper()}"
    if get_case(case_id) is not None:
        raise HTTPException(status_code=409, detail=f"Case {case_id} already exists")
    image_path = body.image_path
    # Resolve relative paths against project root
    if not Path(image_path).is_absolute():
        root = Path(__file__).resolve().parents[1]
        image_path = str((root / image_path).resolve())
    create_case(case_id, body.name, image_path)
    case = get_case(case_id)
    return {"case_id": case_id, "case": case}


@app.get("/cases")
def get_cases() -> Dict[str, Any]:
    return {"cases": list_cases()}


@app.get("/cases/{case_id}")
def get_case_endpoint(case_id: str) -> Dict[str, Any]:
    case = get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@app.post("/analyse")
def analyse(body: AnalyseRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Start LangGraph analysis as a background task; return immediately."""
    case = get_case(body.case_id)
    if case is None:
        # Allow analyse without prior POST /cases (agent also ensures case)
        create_case(body.case_id, body.case_id, body.image_path)
        case = get_case(body.case_id)

    if _running.get(body.case_id):
        return {
            "status": "already_running",
            "case_id": body.case_id,
            "message": "Analysis already in progress",
        }

    image_path = body.image_path or (case or {}).get("image_path") or ""
    if not image_path:
        raise HTTPException(status_code=400, detail="image_path is required")

    _running[body.case_id] = True
    update_case_status(body.case_id, "queued")
    background_tasks.add_task(_run_analysis_job, body.case_id, image_path)
    return {
        "status": "started",
        "case_id": body.case_id,
        "message": "Analysis started in background",
    }


@app.get("/status/{case_id}")
def status(case_id: str) -> Dict[str, Any]:
    """Return current stage list + progress from analysis_stages."""
    case = get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    stages = get_completed_stages(case_id)
    done = len([s for s in EXPECTED_STAGES if s in stages])
    total = len(EXPECTED_STAGES)
    case_status = case.get("status") or "pending"
    if _running.get(case_id) and case_status not in ("complete", "error"):
        case_status = "analysing"

    return {
        "case_id": case_id,
        "status": case_status,
        "stages": stages,
        "progress": f"{done}/{total}",
        "progress_pct": round(100.0 * done / total, 1) if total else 0.0,
        "acquisition_hash": case.get("acquisition_hash"),
        "system_hash": case.get("system_hash"),
        "image_path": case.get("image_path"),
        "name": case.get("name"),
        "running": bool(_running.get(case_id)),
    }


# ---------------------------------------------------------------------------
# Artifacts / threats / chat / report / verify
# ---------------------------------------------------------------------------


@app.get("/artifacts/{case_id}")
def artifacts(case_id: str) -> Dict[str, Any]:
    if get_case(case_id) is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    data = get_artifacts_for_case(case_id)
    return {"case_id": case_id, **data}


@app.get("/threats/{case_id}")
def threats(case_id: str) -> Dict[str, Any]:
    if get_case(case_id) is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    rows = get_threats_for_case(case_id)
    flagged = [r for r in rows if r.get("flagged")]
    return {
        "case_id": case_id,
        "threats": rows,
        "flagged": flagged,
        "flagged_count": len(flagged),
        "total": len(rows),
    }


@app.post("/chat")
def chat(body: ChatRequest) -> Dict[str, Any]:
    """Answer an investigator question via RAG + Ollama."""
    try:
        result = _get_rag().answer(body.case_id, body.question)
        # Log tool usage to local audit — non-fatal
        try:
            tools_used = result.get("tools_used") or []
            if tools_used:
                from ai_service.db.database import log_audit
                tool_names = ", ".join(t["tool"] for t in tools_used)
                log_audit(
                    body.case_id,
                    "TOOL_CALL",
                    f"Q: {body.question[:200]} | Tools: {tool_names}",
                )
        except Exception:
            pass  # audit failure must never break chat
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/report/{case_id}")
def report(case_id: str) -> Dict[str, Any]:
    """Generate HTML report; return path and file content."""
    try:
        path = generate_report(case_id, rag=_get_rag())
        html = Path(path).read_text(encoding="utf-8")
        return {"path": path, "html": html}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/verify_hash")
def verify_hash(body: VerifyHashRequest) -> Dict[str, Any]:
    """Recompute system SHA-256 by streaming the image (64MB chunks)."""
    image_path = body.image_path
    if not Path(image_path).is_absolute():
        root = Path(__file__).resolve().parents[1]
        image_path = str((root / image_path).resolve())
    if not Path(image_path).exists():
        raise HTTPException(status_code=404, detail=f"Image not found: {image_path}")
    try:
        img_info, _fs = mount_image(image_path)
        try:
            system_hash = compute_system_hash(img_info)
        finally:
            close = getattr(img_info, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    logger.debug("Error closing image after /hash request")
        return {"image_path": image_path, "system_hash": system_hash}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
