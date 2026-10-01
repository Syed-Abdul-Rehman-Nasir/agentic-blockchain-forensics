"""Eight deterministic tool functions for the forensic tool-calling loop.

Each function queries SQLite directly and returns
  {"rows": [...], "total": int, "source": str}
so the LLM always knows the true record count even when rows are capped.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ai_service.db.database import get_connection

_CAP = 25  # max rows returned per tool call


def _rows(conn, sql: str, params: tuple) -> List[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _count(conn, table: str, where: str, params: tuple) -> int:
    row = conn.execute(
        f"SELECT COUNT(*) AS c FROM {table} WHERE {where}", params
    ).fetchone()
    return int(row["c"])


# ── Tool 1 ─────────────────────────────────────────────────────────────────

def query_programs_executed(
    case_id: str,
    limit: int = _CAP,
    order: str = "recent",
) -> Dict[str, Any]:
    """Return prefetch entries (programs executed). order: 'recent' or 'frequent'."""
    conn = get_connection()
    try:
        order_clause = (
            "last_run DESC" if order == "recent" else "run_count DESC"
        )
        rows = _rows(
            conn,
            f"SELECT executable, run_count, last_run, volume_path "
            f"FROM prefetch_entries WHERE case_id = ? "
            f"ORDER BY {order_clause} LIMIT ?",
            (case_id, min(limit, _CAP)),
        )
        total = _count(conn, "prefetch_entries", "case_id = ?", (case_id,))
        return {"rows": rows, "total": total, "source": "prefetch"}
    finally:
        conn.close()


# ── Tool 2 ─────────────────────────────────────────────────────────────────

def query_security_events(
    case_id: str,
    event_id: Optional[int] = None,
    user_name: Optional[str] = None,
    channel: Optional[str] = None,
    limit: int = _CAP,
) -> Dict[str, Any]:
    """Return event log entries, optionally filtered by event_id, user, or channel."""
    conn = get_connection()
    try:
        clauses = ["case_id = ?"]
        params: list = [case_id]
        if event_id is not None:
            clauses.append("event_id = ?")
            params.append(event_id)
        if user_name:
            clauses.append("LOWER(user_name) LIKE ?")
            params.append(f"%{user_name.lower()}%")
        if channel:
            clauses.append("LOWER(channel) LIKE ?")
            params.append(f"%{channel.lower()}%")
        where = " AND ".join(clauses)
        rows = _rows(
            conn,
            f"SELECT event_id, channel, timestamp, user_name, computer, description "
            f"FROM event_logs WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            tuple(params) + (min(limit, _CAP),),
        )
        total = _count(conn, "event_logs", where, tuple(params))
        return {"rows": rows, "total": total, "source": "event_logs"}
    finally:
        conn.close()


# ── Tool 3 ─────────────────────────────────────────────────────────────────

def query_registry(
    case_id: str,
    key_pattern: Optional[str] = None,
    value_pattern: Optional[str] = None,
    limit: int = _CAP,
) -> Dict[str, Any]:
    """Return registry entries matching hive/key or value patterns (SQL LIKE)."""
    conn = get_connection()
    try:
        clauses = ["case_id = ?"]
        params: list = [case_id]
        if key_pattern:
            clauses.append("(LOWER(hive) LIKE ? OR LOWER(key_path) LIKE ?)")
            pat = f"%{key_pattern.lower()}%"
            params.extend([pat, pat])
        if value_pattern:
            clauses.append("(LOWER(value_name) LIKE ? OR LOWER(value_data) LIKE ?)")
            params.extend([f"%{value_pattern.lower()}%", f"%{value_pattern.lower()}%"])
        where = " AND ".join(clauses)
        rows = _rows(
            conn,
            f"SELECT hive, key_path, value_name, value_data, timestamp "
            f"FROM registry_entries WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            tuple(params) + (min(limit, _CAP),),
        )
        total = _count(conn, "registry_entries", where, tuple(params))
        return {"rows": rows, "total": total, "source": "registry"}
    finally:
        conn.close()


# ── Tool 4 ─────────────────────────────────────────────────────────────────

def query_usb_devices(case_id: str, limit: int = _CAP) -> Dict[str, Any]:
    """Return USB/removable device registry entries (USBSTOR and USB hives)."""
    conn = get_connection()
    try:
        rows = _rows(
            conn,
            "SELECT hive, key_path, value_name, value_data, timestamp "
            "FROM registry_entries "
            "WHERE case_id = ? AND (key_path LIKE '%USBSTOR%' OR key_path LIKE '%USB%') "
            "ORDER BY timestamp DESC LIMIT ?",
            (case_id, min(limit, _CAP)),
        )
        total = _count(
            conn,
            "registry_entries",
            "case_id = ? AND (key_path LIKE '%USBSTOR%' OR key_path LIKE '%USB%')",
            (case_id,),
        )
        return {"rows": rows, "total": total, "source": "registry_usb"}
    finally:
        conn.close()


# ── Tool 5 ─────────────────────────────────────────────────────────────────

def query_browser_history(
    case_id: str,
    url_pattern: Optional[str] = None,
    limit: int = _CAP,
) -> Dict[str, Any]:
    """Return browser history, optionally filtered by URL pattern."""
    conn = get_connection()
    try:
        clauses = ["case_id = ?"]
        params: list = [case_id]
        if url_pattern:
            clauses.append("(LOWER(url) LIKE ? OR LOWER(title) LIKE ?)")
            params.extend([f"%{url_pattern.lower()}%", f"%{url_pattern.lower()}%"])
        where = " AND ".join(clauses)
        rows = _rows(
            conn,
            f"SELECT browser, url, title, visit_count, visit_time "
            f"FROM browser_history WHERE {where} ORDER BY visit_time DESC LIMIT ?",
            tuple(params) + (min(limit, _CAP),),
        )
        total = _count(conn, "browser_history", where, tuple(params))
        return {"rows": rows, "total": total, "source": "browser_history"}
    finally:
        conn.close()


# ── Tool 6 ─────────────────────────────────────────────────────────────────

def query_files(
    case_id: str,
    extension: Optional[str] = None,
    path_pattern: Optional[str] = None,
    limit: int = _CAP,
) -> Dict[str, Any]:
    """Return file metadata from the disk image, filtered by extension or path."""
    conn = get_connection()
    try:
        clauses = ["case_id = ?"]
        params: list = [case_id]
        if extension:
            ext = extension.lstrip(".").lower()
            clauses.append("LOWER(extension) = ?")
            params.append(ext)
        if path_pattern:
            clauses.append("LOWER(path) LIKE ?")
            params.append(f"%{path_pattern.lower()}%")
        where = " AND ".join(clauses)
        rows = _rows(
            conn,
            f"SELECT path, size, extension, created, modified, accessed "
            f"FROM files WHERE {where} ORDER BY modified DESC LIMIT ?",
            tuple(params) + (min(limit, _CAP),),
        )
        total = _count(conn, "files", where, tuple(params))
        return {"rows": rows, "total": total, "source": "file_metadata"}
    finally:
        conn.close()


# ── Tool 7 ─────────────────────────────────────────────────────────────────

def query_case_summary(case_id: str) -> Dict[str, Any]:
    """Return counts of all artifact types for a case — use for overview questions."""
    conn = get_connection()
    try:
        def c(table: str) -> int:
            return int(
                conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE case_id = ?",
                    (case_id,),
                ).fetchone()["n"]
            )

        summary = {
            "files": c("files"),
            "registry_entries": c("registry_entries"),
            "event_logs": c("event_logs"),
            "browser_history": c("browser_history"),
            "prefetch_entries": c("prefetch_entries"),
            "flagged_threats": int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM artifacts WHERE case_id = ? AND flagged = 1",
                    (case_id,),
                ).fetchone()["n"]
            ),
        }
        return {"rows": [summary], "total": 1, "source": "case_summary"}
    finally:
        conn.close()


# ── Tool 8 ─────────────────────────────────────────────────────────────────

def semantic_search(
    case_id: str,
    query: str,
    n_results: int = 8,
) -> Dict[str, Any]:
    """Semantic similarity search across all indexed artifacts via ChromaDB.
    Use only when no specific tool matches the question."""
    from ai_service.rag.vector_store import VectorStore

    store = VectorStore()
    result = store.query(case_id, query, n_results=n_results)
    hits = result.get("results") or []
    rows = [{"document": h["document"], "type": h["metadata"].get("type")} for h in hits]
    return {"rows": rows, "total": len(rows), "source": "semantic_search"}


# ── Ollama tool schema ──────────────────────────────────────────────────────

TOOL_REGISTRY = {
    "query_programs_executed": query_programs_executed,
    "query_security_events": query_security_events,
    "query_registry": query_registry,
    "query_usb_devices": query_usb_devices,
    "query_browser_history": query_browser_history,
    "query_files": query_files,
    "query_case_summary": query_case_summary,
    "semantic_search": semantic_search,
}

OLLAMA_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_programs_executed",
            "description": "Get programs and executables that ran on this Windows machine from Prefetch (.pf files). Use for: recently executed programs, execution history, application usage. order='recent' for most recent, order='frequent' for most run.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 20},
                    "order": {"type": "string", "enum": ["recent", "frequent"], "default": "recent"},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_security_events",
            "description": "Get Windows Security and System event log entries. Use for: logins (4624 success, 4625 failed), new accounts (4720), process creation (4688), scheduled tasks (4698), privilege use (4672), audit log cleared (1102).",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "event_id": {"type": "integer", "description": "Filter by specific Windows event ID e.g. 4624=login 4625=failed-login"},
                    "user_name": {"type": "string", "description": "Filter by username (partial match)"},
                    "channel": {"type": "string", "description": "Filter by channel e.g. Security, System, Application"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_registry",
            "description": "Get Windows registry entries. Filter by key path or value. Use for: installed software (key_pattern='Uninstall'), startup items (key_pattern='Run'), services (key_pattern='Services'), scheduled tasks (key_pattern='TASKS'), recently accessed files (key_pattern='LNK'), deleted files (key_pattern='RECYCLEBIN'), typed URLs (key_pattern='TypedURLs'), USB devices via registry.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "key_pattern": {"type": "string", "description": "Partial hive or key path e.g. 'TASKS', 'Run', 'Services', 'Uninstall', 'LNK', 'RECYCLEBIN'"},
                    "value_pattern": {"type": "string", "description": "Partial value name or data to search"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_usb_devices",
            "description": "Get USB and removable storage devices connected to this Windows machine from USBSTOR registry entries. Use for any question about USB drives, external storage, removable media.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_browser_history",
            "description": "Get web browser history (Chrome, Firefox, Internet Explorer). Use for: websites visited, URLs accessed, browsing activity. Pass url_pattern to search specific domains or titles.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "url_pattern": {"type": "string", "description": "Partial URL or title to search"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_files",
            "description": "Search file metadata on the Windows disk image. Use for: finding documents (extension='pdf','docx'), executables ('exe','dll'), images ('jpg','png'), archives ('zip','rar'), or files in specific locations (path_pattern='Desktop', 'Downloads','Documents','AppData'). Does not read file contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "extension": {"type": "string", "description": "File extension without dot e.g. 'pdf', 'docx', 'exe', 'jpg'"},
                    "path_pattern": {"type": "string", "description": "Partial file path to search e.g. 'Desktop', 'Documents', 'Downloads'"},
                    "limit": {"type": "integer", "default": 20},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_case_summary",
            "description": "Get counts of all artifact types for this case. Use first for any overview, summary, or 'what do we have' question.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                },
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "semantic_search",
            "description": "Semantic similarity search across all indexed Windows artifacts. Use only when no specific tool matches — for open-ended or cross-artifact questions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "query": {"type": "string", "description": "Natural language search query"},
                    "n_results": {"type": "integer", "default": 8},
                },
                "required": ["case_id", "query"],
            },
        },
    },
]


def dispatch(tool_name: str, arguments: dict) -> Dict[str, Any]:
    """Execute a tool by name with the given arguments. Returns tool result dict."""
    fn = TOOL_REGISTRY.get(tool_name)
    if fn is None:
        return {"rows": [], "total": 0, "source": "error", "error": f"Unknown tool: {tool_name}"}
    try:
        return fn(**arguments)
    except Exception as exc:
        return {"rows": [], "total": 0, "source": "error", "error": str(exc)}
