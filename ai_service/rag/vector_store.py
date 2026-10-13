"""ChromaDB vector store for forensic artifact RAG.

Indexes parsed artifacts (events, registry, browser, prefetch) and
file metadata for indexed extensions — to keep per-case documents under ~150,000.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings
import torch
from sentence_transformers import SentenceTransformer

from ai_service.db.database import get_connection, mark_stage_complete

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CHROMA_PATH = str(_PROJECT_ROOT / "data" / "chromadb")
COLLECTION_NAME = "forensic_evidence"
BATCH_SIZE = 500
MAX_DOCS_PER_CASE = 150_000
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


def file_document_id(case_id: str, path: str) -> str:
    """Stable Chroma document ID for a file path (independent of PYTHONHASHSEED)."""
    digest = hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{case_id}_file_{digest}"

INDEXABLE_EXTENSIONS = {
    # Documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt",
    # Images
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "heic",
    # Executables / scripts
    "exe", "dll", "bat", "ps1", "vbs", "py", "sh",
    # Archives
    "zip", "rar", "7z", "tar", "gz",
    # Email / database
    "pst", "ost", "mbox", "db", "sqlite",
}


class VectorStore:
    """Persistent ChromaDB evidence index with MiniLM embeddings."""

    def __init__(self, chroma_path: str = DEFAULT_CHROMA_PATH):
        Path(chroma_path).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=chroma_path,
            settings=Settings(anonymized_telemetry=False),
        )
        # Cosine space for semantic similarity over evidence text.
        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.embedder = SentenceTransformer(EMBEDDING_MODEL, device=device)
        self.device = device

    def _delete_case_docs(self, case_id: str) -> None:
        """Remove prior embeddings for this case so re-index is idempotent."""
        try:
            existing = self.collection.get(where={"case_id": case_id})
            ids = existing.get("ids") or []
            if ids:
                # Chroma delete in chunks to avoid oversized requests
                for i in range(0, len(ids), BATCH_SIZE):
                    self.collection.delete(ids=ids[i : i + BATCH_SIZE])
        except Exception as exc:
            logger.warning("Failed to delete prior Chroma docs for case %s: %s", case_id, exc)

    def _gather_documents(self, case_id: str, conn) -> List[Dict[str, Any]]:
        docs: List[Dict[str, Any]] = []

        for row in conn.execute(
            """
            SELECT id, event_id, user_name, computer, timestamp, description
            FROM event_logs WHERE case_id = ?
            """,
            (case_id,),
        ):
            text = (
                f"Security Event {row['event_id']}: User {row['user_name']} "
                f"on {row['computer']} at {row['timestamp']} — {row['description']}"
            )
            docs.append(
                {
                    "id": f"{case_id}_event_{row['id']}",
                    "text": text,
                    "type": "event_log",
                }
            )

        for row in conn.execute(
            """
            SELECT id, hive, key_path, value_name, value_data, timestamp
            FROM registry_entries WHERE case_id = ?
            """,
            (case_id,),
        ):
            text = (
                f"Registry: {row['hive']} hive, key {row['key_path']}, "
                f"value {row['value_name']}: {row['value_data']} at {row['timestamp']}"
            )
            docs.append(
                {
                    "id": f"{case_id}_registry_{row['id']}",
                    "text": text,
                    "type": "registry",
                }
            )

        for row in conn.execute(
            """
            SELECT id, browser, url, title, visit_count, visit_time
            FROM browser_history WHERE case_id = ?
            """,
            (case_id,),
        ):
            text = (
                f"Browser visit ({row['browser']}): {row['url']} "
                f"titled '{row['title']}' — {row['visit_count']} visits, "
                f"last {row['visit_time']}"
            )
            docs.append(
                {
                    "id": f"{case_id}_browser_{row['id']}",
                    "text": text,
                    "type": "browser",
                }
            )

        for row in conn.execute(
            """
            SELECT id, executable, run_count, last_run
            FROM prefetch_entries WHERE case_id = ?
            """,
            (case_id,),
        ):
            text = (
                f"Program executed: {row['executable']} ran {row['run_count']} "
                f"times, last at {row['last_run']}"
            )
            docs.append(
                {
                    "id": f"{case_id}_prefetch_{row['id']}",
                    "text": text,
                    "type": "prefetch",
                }
            )

        for row in conn.execute(
            """
            SELECT path, size, extension, created, modified, accessed
            FROM files
            WHERE case_id = ?
              AND LOWER(extension) IN ({})
            ORDER BY modified DESC
            LIMIT 50000
            """.format(",".join("?" * len(INDEXABLE_EXTENSIONS))),
            (case_id, *INDEXABLE_EXTENSIONS),
        ):
            ext = (row["extension"] or "").lower()
            fname = row["path"].split("/")[-1] if row["path"] else "unknown"
            text = (
                f"File on disk: {fname} "
                f"(type: {ext}, size: {row['size']} bytes, "
                f"modified: {row['modified']}, path: {row['path']})"
            )
            docs.append(
                {
                    "id": file_document_id(case_id, row["path"] or ""),
                    "text": text,
                    "type": "file_metadata",
                }
            )

        if len(docs) > MAX_DOCS_PER_CASE:
            docs = docs[:MAX_DOCS_PER_CASE]
        return docs

    def index_case(self, case_id: str, conn=None) -> Dict[str, Any]:
        """Embed and upsert forensic artifacts for a case; mark rag_indexing."""
        owns = conn is None
        if owns:
            conn = get_connection()
        try:
            self._delete_case_docs(case_id)
            docs = self._gather_documents(case_id, conn)
            total = 0
            for i in range(0, len(docs), BATCH_SIZE):
                batch = docs[i : i + BATCH_SIZE]
                texts = [d["text"] for d in batch]
                embeddings = self.embedder.encode(
                    texts,
                    batch_size=64,
                    show_progress_bar=False,
                    convert_to_numpy=True,
                ).tolist()
                self.collection.add(
                    ids=[d["id"] for d in batch],
                    documents=texts,
                    embeddings=embeddings,
                    metadatas=[
                        {"case_id": case_id, "type": d["type"]} for d in batch
                    ],
                )
                total += len(batch)

            mark_stage_complete(case_id, "rag_indexing", conn=conn)
            return {"indexed": total, "device": self.device}
        finally:
            if owns:
                conn.close()

    def query(
        self,
        case_id: str,
        question: str,
        n_results: int = 8,
    ) -> Dict[str, Any]:
        """Return top-n evidence documents for a natural-language question."""
        embedding = self.embedder.encode(
            [question], convert_to_numpy=True
        ).tolist()
        result = self.collection.query(
            query_embeddings=embedding,
            n_results=n_results,
            where={"case_id": case_id},
            include=["documents", "metadatas", "distances"],
        )
        documents = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]
        ids = (result.get("ids") or [[]])[0]
        hits = []
        for i, doc in enumerate(documents):
            hits.append(
                {
                    "id": ids[i] if i < len(ids) else None,
                    "document": doc,
                    "metadata": metadatas[i] if i < len(metadatas) else {},
                    "distance": distances[i] if i < len(distances) else None,
                }
            )
        return {"question": question, "results": hits}
