"""Shared helpers for extracting artifact files from a mounted disk image.

Parsers locate targets via the files table, stream bytes to /tmp, parse, then
delete the temp file. Never load an entire artifact into memory when streaming
is possible.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence

CHUNK_SIZE = 4 * 1024 * 1024  # 4MB extract chunks


def extract_file(fs_info, image_path: str, temp_path: str) -> int:
    """Stream a file from the mounted image to temp_path. Returns bytes written."""
    # Normalise leading slash for pytsk3 open()
    path = image_path if image_path.startswith("/") else f"/{image_path}"
    file_obj = fs_info.open(path)
    meta = file_obj.info.meta
    size = int(meta.size) if meta and meta.size is not None else 0

    Path(temp_path).parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(temp_path, "wb") as out:
        offset = 0
        while offset < size:
            to_read = min(CHUNK_SIZE, size - offset)
            data = file_obj.read_random(offset, to_read)
            if not data:
                break
            out.write(data)
            written += len(data)
            offset += len(data)
    return written


def find_files(
    conn,
    case_id: str,
    like_patterns: Sequence[str],
    *,
    exclude_substrings: Optional[Sequence[str]] = None,
) -> List[str]:
    """Case-insensitive path lookup against the files table."""
    if not like_patterns:
        return []

    clauses = " OR ".join(["LOWER(path) LIKE LOWER(?)"] * len(like_patterns))
    sql = f"SELECT DISTINCT path FROM files WHERE case_id = ? AND ({clauses})"
    rows = conn.execute(sql, (case_id, *like_patterns)).fetchall()

    paths = []
    excludes = [e.lower() for e in (exclude_substrings or [])]
    for row in rows:
        path = row["path"] if hasattr(row, "keys") else row[0]
        lower = path.lower()
        if any(ex in lower for ex in excludes):
            continue
        paths.append(path)
    return sorted(paths)


def safe_unlink(path: str) -> None:
    """Delete a temp file without raising if it is already gone."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def temp_path_for(prefix: str, suffix: str = "") -> str:
    """Build a unique temp path under /tmp for extracted artifacts."""
    import uuid

    name = f"forensic_{prefix}_{uuid.uuid4().hex}{suffix}"
    return str(Path("/tmp") / name)
