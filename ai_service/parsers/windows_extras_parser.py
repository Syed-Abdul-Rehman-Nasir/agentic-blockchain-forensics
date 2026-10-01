"""Windows extra artifact parsers — scheduled tasks, LNK recent files, Recycle Bin.

All output goes into registry_entries (hive TASKS / LNK / RECYCLEBIN) so the
existing tool layer works without schema changes.
"""

from __future__ import annotations

import datetime
import logging
import shutil
import struct
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import pytsk3

from ai_service.parsers.extract_utils import extract_file, safe_unlink, temp_path_for

logger = logging.getLogger(__name__)

_RECYCLE_CAP = 5000


def _probe_paths(fs_info, *candidates):
    """Return the first path that opens successfully, or None."""
    for path in candidates:
        try:
            fs_info.open_dir(path=path)
            return path
        except Exception:
            continue
    return None


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_text(root: ET.Element, *names: str) -> str:
    """Return first matching element's text by localname (namespace-tolerant)."""
    wanted = {n.lower() for n in names}
    for elem in root.iter():
        if _localname(elem.tag).lower() in wanted and elem.text:
            return elem.text.strip()
    return ""


def _entry_name(entry) -> Optional[str]:
    if not entry.info or not entry.info.name:
        return None
    name_bytes = entry.info.name.name
    name = (
        name_bytes.decode("utf-8", errors="replace")
        if isinstance(name_bytes, bytes)
        else str(name_bytes)
    )
    if name in (".", ".."):
        return None
    return name


def _is_dir(entry) -> bool:
    try:
        meta = entry.info.meta
        if meta is None:
            return False
        # pytsk3: TSK_FS_META_TYPE_DIR == 2
        return int(getattr(meta, "type", 0) or 0) == 2
    except Exception:
        return False


def _walk_task_files(fs_info, root_path: str):
    """Yield (full_path, task_name) for task XML files under root (one subdir level)."""
    try:
        d = fs_info.open_dir(path=root_path)
    except Exception:
        return
    for entry in d:
        name = _entry_name(entry)
        if not name:
            continue
        full = f"{root_path}/{name}"
        if _is_dir(entry):
            try:
                sub = fs_info.open_dir(path=full)
            except Exception:
                continue
            for sub_entry in sub:
                sub_name = _entry_name(sub_entry)
                if not sub_name or _is_dir(sub_entry):
                    continue
                yield f"{full}/{sub_name}", sub_name
        else:
            yield full, name


def parse_scheduled_tasks(fs_info: pytsk3.FS_Info, case_id: str, conn) -> int:
    """Parse Windows Task Scheduler XML files into registry_entries (hive=TASKS)."""
    inserted = 0
    roots = []
    for candidate in (
        "/Windows/System32/Tasks",
        "/WINDOWS/system32/Tasks",
        "/Windows/SysWOW64/Tasks",
        "/WINDOWS/SysWOW64/Tasks",
    ):
        try:
            fs_info.open_dir(path=candidate)
            if candidate not in roots:
                roots.append(candidate)
        except Exception:
            continue

    tmp = tempfile.mkdtemp(prefix="abf_tasks_")
    try:
        for root_path in roots:
            for full_path, task_name in _walk_task_files(fs_info, root_path):
                tmp_file = str(Path(tmp) / f"{inserted}_{task_name}")
                try:
                    written = extract_file(fs_info, full_path, tmp_file)
                except Exception as exc:
                    logger.debug("Task extract failed %s: %s", full_path, exc)
                    continue
                if not written:
                    continue
                try:
                    tree = ET.parse(tmp_file)
                    root = tree.getroot()
                except Exception as exc:
                    logger.debug("Task XML parse failed %s: %s", full_path, exc)
                    continue
                command = _xml_text(root, "Command")
                author = _xml_text(root, "Author")
                date = _xml_text(root, "Date")
                # Triggers summary — concatenate Trigger child localnames / text
                triggers = []
                for elem in root.iter():
                    if _localname(elem.tag).lower() == "triggers":
                        for child in list(elem):
                            triggers.append(_localname(child.tag))
                trigger_desc = ",".join(triggers) if triggers else ""
                value_data = (
                    f"Command: {command} | Author: {author} | Registered: {date}"
                )
                if trigger_desc:
                    value_data += f" | Triggers: {trigger_desc}"
                try:
                    conn.execute(
                        """INSERT INTO registry_entries
                           (case_id, hive, key_path, value_name, value_data, timestamp)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            case_id,
                            "TASKS",
                            full_path,
                            task_name,
                            value_data[:2000],
                            date or "",
                        ),
                    )
                    inserted += 1
                except Exception as exc:
                    logger.debug("Task insert failed %s: %s", full_path, exc)
        conn.commit()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    logger.info("Scheduled tasks: %d entries for %s", inserted, case_id)
    return inserted


def parse_lnk_files(conn, case_id: str) -> int:
    """Index .lnk paths from the files table into registry_entries (hive=LNK).

    Uses filename-derived targets and files-table timestamps (no image extract).
    """
    inserted = 0
    try:
        rows = conn.execute(
            """
            SELECT path, created, modified, accessed
            FROM files
            WHERE case_id = ? AND LOWER(extension) = 'lnk'
            """,
            (case_id,),
        ).fetchall()
    except Exception as exc:
        logger.debug("LNK files query failed: %s", exc)
        return 0

    for row in rows:
        try:
            path = row["path"] if hasattr(row, "keys") else row[0]
            created = (row["created"] if hasattr(row, "keys") else row[1]) or ""
            modified = (row["modified"] if hasattr(row, "keys") else row[2]) or ""
            accessed = (row["accessed"] if hasattr(row, "keys") else row[3]) or ""
            basename = path.replace("\\", "/").split("/")[-1]
            target = (
                basename[:-4]
                if basename.lower().endswith(".lnk")
                else basename
            )
            timestamp = created or modified or accessed or ""
            value_data = f"Target: {target} | LNK path: {path}"
            conn.execute(
                """INSERT INTO registry_entries
                   (case_id, hive, key_path, value_name, value_data, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    case_id,
                    "LNK",
                    path,
                    "recently_accessed",
                    value_data[:2000],
                    timestamp,
                ),
            )
            inserted += 1
        except Exception as exc:
            logger.debug("LNK insert failed: %s", exc)
            continue
    try:
        conn.commit()
    except Exception:
        pass
    logger.info("LNK files: %d entries for %s", inserted, case_id)
    return inserted


def _parse_i_file(data: bytes) -> Optional[tuple]:
    """Parse $I recycle metadata. Returns (original_path, file_size, iso_ts) or None."""
    if len(data) < 28:
        return None
    try:
        # header unused; Vista+ layout per project spec
        file_size = struct.unpack_from("<Q", data, 8)[0]
        filetime = struct.unpack_from("<Q", data, 16)[0]
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(
            microseconds=filetime // 10
        )
        # Win7+: often uint32 path length at offset 24, then UTF-16LE
        # Spec: path starts at offset 24 as UTF-16LE
        original_path = (
            data[24:].decode("utf-16-le", errors="replace").rstrip("\x00")
        )
        # Strip embedded NULs / garbage after first path
        if "\x00" in original_path:
            original_path = original_path.split("\x00")[0]
        return original_path, file_size, dt.isoformat()
    except Exception:
        return None


def parse_recycle_bin(fs_info: pytsk3.FS_Info, case_id: str, conn) -> int:
    """Parse $Recycle.Bin $I files into registry_entries (hive=RECYCLEBIN)."""
    inserted = 0
    recycle_root = _probe_paths(
        fs_info,
        "/$Recycle.Bin",
        "/RECYCLER",
        "/Recycled",
    )
    if not recycle_root:
        logger.info("Recycle Bin: no root found for %s", case_id)
        return 0

    tmp = tempfile.mkdtemp(prefix="abf_recycle_")
    try:
        try:
            sid_dirs = fs_info.open_dir(path=recycle_root)
        except Exception as exc:
            logger.debug("Recycle Bin open failed: %s", exc)
            return 0

        for sid_entry in sid_dirs:
            if inserted >= _RECYCLE_CAP:
                break
            sid_name = _entry_name(sid_entry)
            if not sid_name:
                continue
            sid_path = f"{recycle_root}/{sid_name}"
            if not _is_dir(sid_entry):
                # Flat $I at root (rare)
                if not sid_name.upper().startswith("$I"):
                    continue
                candidates = [(sid_path, sid_name)]
            else:
                candidates = []
                try:
                    inner = fs_info.open_dir(path=sid_path)
                except Exception:
                    continue
                for f_entry in inner:
                    fname = _entry_name(f_entry)
                    if not fname or _is_dir(f_entry):
                        continue
                    if not fname.upper().startswith("$I"):
                        continue
                    candidates.append((f"{sid_path}/{fname}", fname))

            for full_path, fname in candidates:
                if inserted >= _RECYCLE_CAP:
                    break
                tmp_file = temp_path_for("recycle", ".i")
                try:
                    written = extract_file(fs_info, full_path, tmp_file)
                    if not written:
                        continue
                    with open(tmp_file, "rb") as fh:
                        data = fh.read()
                    parsed = _parse_i_file(data)
                    if not parsed:
                        continue
                    original_path, file_size, ts = parsed
                    value_data = (
                        f"Original: {original_path} | Size: {file_size} bytes"
                    )
                    conn.execute(
                        """INSERT INTO registry_entries
                           (case_id, hive, key_path, value_name, value_data, timestamp)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            case_id,
                            "RECYCLEBIN",
                            recycle_root,
                            "deleted_file",
                            value_data[:2000],
                            ts,
                        ),
                    )
                    inserted += 1
                except Exception as exc:
                    logger.debug("Recycle $I failed %s: %s", full_path, exc)
                finally:
                    safe_unlink(tmp_file)
        conn.commit()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    logger.info("Recycle Bin: %d entries for %s", inserted, case_id)
    return inserted
