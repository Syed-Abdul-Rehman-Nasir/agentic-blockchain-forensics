"""Windows Event Log parser — EVTX (Vista+) and classic EVT (XP).

Streams record-by-record; never loads a full log into memory.
NIST SCHARDT Security log is empty; System/Application EVT hold usable events.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Optional, Set

from ai_service.db.database import mark_stage_complete
from ai_service.parsers.extract_utils import (
    extract_file,
    find_files,
    safe_unlink,
    temp_path_for,
)

logger = logging.getLogger(__name__)

# Vista+ Security/System Event IDs (prompt)
EVTX_TARGET_IDS: Set[int] = {
    4624,
    4625,
    4634,
    4648,  # Logon attempt with explicit credentials
    4663,
    4672,  # Special privileges assigned to new logon
    4688,  # New process created
    4689,  # Process exited
    4698,  # Scheduled task created
    4699,  # Scheduled task deleted
    4700,  # Scheduled task enabled
    4702,  # Scheduled task updated
    4720,  # User account created
    4726,  # User account deleted
    4732,  # Member added to security-enabled local group
    4733,  # Member removed from group
    4776,
    7045,  # New service installed (System log)
    1102,  # Audit log cleared
}

# XP classic Security + System IDs (SCHARDT uses System 7035/7036; Security often empty)
EVT_TARGET_IDS: Set[int] = {
    528,  # Successful logon
    529,  # Failed logon
    538,  # Logoff
    540,  # Network logon
    560,  # Object open
    576,
    577,
    578,
    680,  # Account logon
    7035,  # Service sent control
    7036,  # Service state change
    7040,  # Service start type changed
    7045,  # New service (also used on newer systems)
}

TARGET_EVENT_IDS = EVTX_TARGET_IDS | EVT_TARGET_IDS


def _channel_from_path(path: str) -> str:
    name = path.replace("\\", "/").split("/")[-1].lower()
    if "sec" in name:
        return "Security"
    if "sys" in name:
        return "System"
    if "app" in name:
        return "Application"
    return name


def _insert_event(
    conn,
    case_id: str,
    event_id: int,
    channel: str,
    timestamp: Optional[str],
    user_name: Optional[str],
    computer: Optional[str],
    description: Optional[str],
    raw_xml: Optional[str],
) -> None:
    conn.execute(
        """
        INSERT INTO event_logs
            (case_id, event_id, channel, timestamp, user_name, computer, description, raw_xml)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            event_id,
            channel,
            timestamp,
            user_name,
            computer,
            description,
            (raw_xml or "")[:500],
        ),
    )


def _dt_iso(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _parse_evtx_xml(xml_str: str) -> Dict[str, Optional[str]]:
    """Pull EventID, TimeCreated, Computer, Security UserID from EVTX XML."""
    out: Dict[str, Optional[str]] = {
        "event_id": None,
        "timestamp": None,
        "computer": None,
        "user_name": None,
        "channel": None,
    }
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return out

    # EVTX XML often uses namespaces — match by localname.
    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for elem in root.iter():
        name = local(elem.tag)
        if name == "EventID" and elem.text and out["event_id"] is None:
            out["event_id"] = elem.text.strip()
        elif name == "TimeCreated":
            out["timestamp"] = elem.attrib.get("SystemTime") or out["timestamp"]
        elif name == "Computer" and elem.text:
            out["computer"] = elem.text.strip()
        elif name == "Security":
            out["user_name"] = elem.attrib.get("UserID") or out["user_name"]
        elif name == "Channel" and elem.text:
            out["channel"] = elem.text.strip()
    return out


def _parse_evtx_stream(temp_path: str, case_id: str, channel: str, conn) -> int:
    """Stream-parse a modern .evtx file with python-evtx."""
    import Evtx.Evtx as evtx

    inserted = 0
    with evtx.Evtx(temp_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
            except Exception:
                continue
            meta = _parse_evtx_xml(xml_str)
            try:
                event_id = int(meta["event_id"]) if meta["event_id"] else None
            except (TypeError, ValueError):
                continue
            if event_id not in TARGET_EVENT_IDS:
                continue
            _insert_event(
                conn,
                case_id,
                event_id,
                meta.get("channel") or channel,
                meta.get("timestamp"),
                meta.get("user_name"),
                meta.get("computer"),
                None,
                xml_str,
            )
            inserted += 1
    return inserted


def _parse_evt_stream(temp_path: str, case_id: str, channel: str, conn) -> int:
    """Stream-parse a classic XP .evt file with libevt (pyevt)."""
    import pyevt

    inserted = 0
    evt_file = pyevt.file()
    evt_file.open(temp_path)
    try:
        n = evt_file.get_number_of_records()
        for i in range(n):
            try:
                record = evt_file.get_record(i)
            except Exception:
                continue
            # Lower 16 bits are the Windows Event ID; high bits encode severity.
            full_id = record.get_event_identifier()
            event_id = int(full_id) & 0xFFFF
            if event_id not in TARGET_EVENT_IDS:
                continue

            strings = []
            try:
                for j in range(record.get_number_of_strings()):
                    s = record.get_string(j)
                    if s:
                        strings.append(s)
            except Exception as exc:
                logger.debug("EVT string extraction failed for event %s: %s", event_id, exc)

            summary = (
                f"source={record.get_source_name()}; strings={';'.join(strings)}"
            )
            _insert_event(
                conn,
                case_id,
                event_id,
                channel,
                _dt_iso(record.get_written_time() or record.get_creation_time()),
                record.get_user_security_identifier(),
                record.get_computer_name(),
                record.get_source_name(),
                summary,
            )
            inserted += 1
    finally:
        evt_file.close()
    return inserted


def parse_evtx_file(fs_info, evtx_path: str, case_id: str, conn) -> int:
    """Extract one event log from the image, stream-parse, filter, insert."""
    lower = evtx_path.lower()
    channel = _channel_from_path(evtx_path)
    suffix = ".evtx" if lower.endswith(".evtx") else ".evt"
    temp = temp_path_for("eventlog", suffix)
    inserted = 0
    try:
        extract_file(fs_info, evtx_path, temp)
        if lower.endswith(".evtx"):
            inserted = _parse_evtx_stream(temp, case_id, channel, conn)
        else:
            inserted = _parse_evt_stream(temp, case_id, channel, conn)
        conn.commit()
    except Exception:
        # One bad log must not abort the events stage.
        inserted = 0
    finally:
        safe_unlink(temp)
    return inserted


def parse_all_evtx(fs_info, case_id: str, conn) -> Dict[str, int]:
    """Find .evtx/.evt logs via files table, parse each, mark stage 'events'."""
    paths = find_files(
        conn,
        case_id,
        [
            "%.evtx",
            "%.evt",
            "%.Evt",
            "%/winevt/Logs/%.evtx",
            "%/system32/config/%Event.Evt",
            "%/system32/config/%Event.evt",
        ],
        exclude_substrings=[".dll", "dllcache", "eventlog.dll"],
    )
    # Deduplicate while preferring Security/System/Application named logs
    seen = set()
    ordered = []
    for p in paths:
        key = p.lower()
        if key in seen:
            continue
        if not (key.endswith(".evtx") or key.endswith(".evt")):
            continue
        seen.add(key)
        ordered.append(p)

    counts: Dict[str, int] = {}
    for path in ordered:
        counts[path] = parse_evtx_file(fs_info, path, case_id, conn)

    mark_stage_complete(case_id, "events", conn=conn)
    return counts
