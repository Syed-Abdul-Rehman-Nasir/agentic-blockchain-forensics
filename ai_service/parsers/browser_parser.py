"""Browser history parser — Chrome, Firefox, and IE (index.dat via libmsiecf).

NIST SCHARDT has Internet Explorer History.IE5 index.dat only (no Chrome/Firefox).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from urllib.parse import unquote

from ai_service.db.database import mark_stage_complete
from ai_service.parsers.extract_utils import (
    extract_file,
    find_files,
    safe_unlink,
    temp_path_for,
)

# Chrome WebKit epoch: microseconds since 1601-01-01 UTC
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _webkit_to_iso(value) -> Optional[str]:
    if value is None:
        return None
    try:
        micros = int(value)
        if micros <= 0:
            return None
        return (_WEBKIT_EPOCH + timedelta(microseconds=micros)).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _dt_iso(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _insert_history(
    conn,
    case_id: str,
    browser: str,
    url: str,
    title: Optional[str],
    visit_time: Optional[str],
    visit_count: Optional[int],
) -> None:
    conn.execute(
        """
        INSERT INTO browser_history
            (case_id, browser, url, title, visit_time, visit_count)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, browser, url, title, visit_time, visit_count),
    )


def _parse_chrome_db(temp_path: str, case_id: str, conn) -> int:
    db = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
    try:
        rows = db.execute(
            """
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT 1000
            """
        ).fetchall()
    except sqlite3.Error:
        db.close()
        return 0

    for url, title, visit_count, last_visit_time in rows:
        _insert_history(
            conn,
            case_id,
            "chrome",
            url or "",
            title,
            _webkit_to_iso(last_visit_time),
            visit_count,
        )
    db.close()
    return len(rows)


def _parse_firefox_db(temp_path: str, case_id: str, conn) -> int:
    db = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
    try:
        rows = db.execute(
            """
            SELECT url, title, visit_count, last_visit_date
            FROM moz_places
            WHERE url IS NOT NULL
            ORDER BY last_visit_date DESC
            LIMIT 1000
            """
        ).fetchall()
    except sqlite3.Error:
        db.close()
        return 0

    # Firefox last_visit_date is microseconds since Unix epoch
    count = 0
    for url, title, visit_count, last_visit_date in rows:
        visit_time = None
        if last_visit_date:
            try:
                visit_time = datetime.fromtimestamp(
                    int(last_visit_date) / 1_000_000, tz=timezone.utc
                ).isoformat()
            except (OSError, OverflowError, ValueError):
                visit_time = None
        _insert_history(
            conn, case_id, "firefox", url or "", title, visit_time, visit_count
        )
        count += 1
    db.close()
    return count


def _clean_ie_location(location: str) -> str:
    """Strip IE 'Visited: user@' prefix when present."""
    if not location:
        return ""
    if "@" in location and location.lower().startswith("visited:"):
        return location.split("@", 1)[1]
    return location


def _parse_ie_index_dat(temp_path: str, case_id: str, conn) -> int:
    import pymsiecf

    inserted = 0
    msie = pymsiecf.file()
    msie.open(temp_path)
    try:
        n = msie.get_number_of_items()
        for i in range(n):
            try:
                item = msie.get_item(i)
            except Exception:
                continue
            try:
                location = item.get_location()
            except Exception:
                location = None
            if not location:
                continue
            url = _clean_ie_location(location)
            # Prefer decoded URL for readability
            url = unquote(url)
            try:
                hits = item.get_number_of_hits()
            except Exception:
                hits = None
            try:
                visit_time = _dt_iso(item.get_primary_time() or item.get_last_checked_time())
            except Exception:
                visit_time = None
            try:
                title = item.get_filename()
            except Exception:
                title = None
            _insert_history(conn, case_id, "ie", url, title, visit_time, hits)
            inserted += 1
    finally:
        msie.close()
    return inserted


def _extract_and_parse(
    fs_info,
    image_path: str,
    case_id: str,
    conn,
    parser_fn,
    suffix: str,
) -> int:
    temp = temp_path_for("browser", suffix)
    try:
        extract_file(fs_info, image_path, temp)
        n = parser_fn(temp, case_id, conn)
        conn.commit()
        return n
    except Exception:
        return 0
    finally:
        safe_unlink(temp)


def parse_chrome_history(fs_info, case_id: str, conn) -> Dict[str, int]:
    """Detect and parse whichever browser history is present; mark stage 'browser'.

    Detection order: Chrome History → Firefox places.sqlite → IE index.dat.
    """
    counts: Dict[str, int] = {"chrome": 0, "firefox": 0, "ie": 0}

    chrome_paths = find_files(
        conn,
        case_id,
        [
            "%/Google/Chrome/%/History",
            "%Chrome%History",
        ],
        exclude_substrings=["journal", "tmp", "cache", "code cache"],
    )
    # Keep files that end with /History (Chrome SQLite DB name)
    chrome_paths = [p for p in chrome_paths if p.rstrip("/").lower().endswith("history")]

    for path in chrome_paths:
        counts["chrome"] += _extract_and_parse(
            fs_info, path, case_id, conn, _parse_chrome_db, ".sqlite"
        )

    if counts["chrome"] == 0:
        firefox_paths = find_files(
            conn,
            case_id,
            ["%/places.sqlite", "%places.sqlite"],
        )
        for path in firefox_paths:
            counts["firefox"] += _extract_and_parse(
                fs_info, path, case_id, conn, _parse_firefox_db, ".sqlite"
            )

    if counts["chrome"] == 0 and counts["firefox"] == 0:
        # Prefer Mr. Evil History.IE5 index.dat files on NIST image
        ie_paths = find_files(
            conn,
            case_id,
            [
                "%/History.IE5%/index.dat",
                "%/History.IE5/index.dat",
                "%History.IE5%index.dat",
            ],
            exclude_substrings=["content.ie5", "cookies", "temporary internet"],
        )
        # Prefer interactive user histories first
        ie_paths.sort(
            key=lambda p: (
                0 if "mr. evil" in p.lower() else 1,
                0 if "/history.ie5/index.dat" in p.lower() else 1,
                p.lower(),
            )
        )
        for path in ie_paths:
            counts["ie"] += _extract_and_parse(
                fs_info, path, case_id, conn, _parse_ie_index_dat, ".dat"
            )

    mark_stage_complete(case_id, "browser", conn=conn)
    return counts
