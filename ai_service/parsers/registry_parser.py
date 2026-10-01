"""Windows Registry hive parser — USBSTOR, services, uninstall, Run keys, RecentDocs.

Validates against NIST SCHARDT (XP): SYSTEM/SOFTWARE under WINDOWS/system32/config
and NTUSER.DAT under Documents and Settings/Mr. Evil.
"""

from __future__ import annotations

import logging
from datetime import timezone
from typing import Dict, List, Optional, Sequence, Tuple

from Registry import Registry
from Registry.RegistryParse import ParseException

from ai_service.db.database import mark_stage_complete
from ai_service.parsers.extract_utils import (
    extract_file,
    find_files,
    safe_unlink,
    temp_path_for,
)

logger = logging.getLogger(__name__)

# Target keys per hive (prompt). Subkeys are walked for USBSTOR / Services / Uninstall.
# NIST SCHARDT (XP) has Enum\USB + PCMCIA, not USBSTOR — include those for device history.
SYSTEM_KEYS = [
    r"ControlSet001\Enum\USBSTOR",
    r"ControlSet001\Enum\USB",
    r"ControlSet001\Enum\PCMCIA",
    r"ControlSet001\Services",
    # Timezone — important for timestamp correlation
    r"ControlSet001\Control\TimeZoneInformation",
    # Shutdown time
    r"ControlSet001\Control\Windows",
]
SOFTWARE_KEYS = [
    r"Microsoft\Windows\CurrentVersion\Uninstall",
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
]
NTUSER_KEYS = [
    # RecentDocs by extension — files opened per extension
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    # UserAssist — GUI program execution with run count and timestamp
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    # RunMRU — commands typed in Run dialog
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    # TypedURLs — URLs typed in IE/Edge address bar
    r"Software\Microsoft\Internet Explorer\TypedURLs",
    # Last visited MRU — dialog box history
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
]

# Limit Services value explosion — ImagePath/DisplayName/Start are persistence-relevant.
SERVICE_VALUE_NAMES = {
    "imagepath",
    "displayname",
    "description",
    "objectname",
    "start",
    "type",
    "group",
}


def extract_hive(fs_info, hive_path: str, temp_path: str) -> int:
    """Extract hive bytes from the mounted image to temp_path."""
    return extract_file(fs_info, hive_path, temp_path)


def _ts_iso(dt) -> Optional[str]:
    if dt is None:
        return None
    try:
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def _value_to_str(value) -> str:
    raw = value.value()
    try:
        if isinstance(raw, bytes):
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return str(raw)
    except Exception:
        return repr(raw)


def _insert_value(
    conn,
    case_id: str,
    hive: str,
    key_path: str,
    value_name: str,
    value_data: str,
    timestamp: Optional[str],
) -> None:
    conn.execute(
        """
        INSERT INTO registry_entries
            (case_id, hive, key_path, value_name, value_data, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (case_id, hive, key_path, value_name, value_data, timestamp),
    )


def _walk_key_values(
    conn,
    case_id: str,
    hive: str,
    key,
    key_path: str,
    *,
    value_filter: Optional[set] = None,
    max_depth: int = 0,
    depth: int = 0,
) -> int:
    """Insert values for this key; optionally recurse into subkeys."""
    count = 0
    ts = _ts_iso(key.timestamp())
    try:
        for value in key.values():
            name = value.name() or "(default)"
            if value_filter is not None and name.lower() not in value_filter:
                # Always keep (default) when filtering services? Skip unless named.
                continue
            _insert_value(conn, case_id, hive, key_path, name, _value_to_str(value), ts)
            count += 1
    except Exception as exc:
        logger.debug("Skipping registry values under %s\\%s: %s", hive, key_path, exc)

    if depth >= max_depth:
        return count

    try:
        for sub in key.subkeys():
            sub_name = sub.name()
            sub_path = f"{key_path}\\{sub_name}" if key_path else sub_name
            # For deep trees (USBSTOR/Uninstall), insert a marker for the subkey itself
            _insert_value(
                conn,
                case_id,
                hive,
                sub_path,
                "(key)",
                sub_name,
                _ts_iso(sub.timestamp()),
            )
            count += 1
            count += _walk_key_values(
                conn,
                case_id,
                hive,
                sub,
                sub_path,
                value_filter=value_filter,
                max_depth=max_depth,
                depth=depth + 1,
            )
    except Exception as exc:
        logger.debug("Skipping registry subkeys under %s\\%s: %s", hive, key_path, exc)
    return count


def parse_hive(
    temp_path: str,
    hive_name: str,
    target_keys: Sequence[str],
    case_id: str,
    conn,
) -> int:
    """Parse a hive with python-registry and insert targeted key values."""
    reg = Registry.Registry(temp_path)
    inserted = 0

    for key_path in target_keys:
        try:
            key = reg.open(key_path)
        except (Registry.RegistryKeyNotFoundException, ParseException, Exception):
            continue

        # USBSTOR / Uninstall: walk device/product subkeys (depth 3).
        # Services: one level of service names + filtered values.
        # Run / RunOnce / RecentDocs: values on the key (+ RecentDocs subkeys).
        lower = key_path.lower()
        if (
            "usbstor" in lower
            or lower.endswith(r"\usb")
            or lower.endswith(r"\pcmcia")
            or "uninstall" in lower
        ):
            inserted += _walk_key_values(
                conn, case_id, hive_name, key, key_path, max_depth=3
            )
        elif lower.endswith(r"\services") or lower.endswith("services"):
            inserted += _walk_key_values(
                conn,
                case_id,
                hive_name,
                key,
                key_path,
                value_filter=SERVICE_VALUE_NAMES,
                max_depth=1,
            )
        elif (
            "recentdocs" in lower
            or "userassist" in lower
            or "runmru" in lower
            or "typedurls" in lower
            or "lastvisited" in lower
        ):
            inserted += _walk_key_values(
                conn, case_id, hive_name, key, key_path, max_depth=2
            )
        else:
            inserted += _walk_key_values(
                conn, case_id, hive_name, key, key_path, max_depth=0
            )

    conn.commit()
    return inserted


def _resolve_hive_path(conn, case_id: str, candidates: Sequence[str]) -> Optional[str]:
    """Pick the best matching hive path from the files table."""
    for pattern in candidates:
        hits = find_files(
            conn,
            case_id,
            [pattern],
            exclude_substrings=["/repair/", "\\repair\\", "pchealth", "common files"],
        )
        # Prefer exact basename match when possible
        for hit in hits:
            base = hit.rstrip("/").split("/")[-1].lower()
            wanted = pattern.rstrip("%").rstrip("/").split("/")[-1].lower()
            if base == wanted or base == wanted.replace("%", ""):
                return hit
        if hits:
            return hits[0]
    return None


def _find_ntuser_paths(conn, case_id: str) -> List[Tuple[str, str]]:
    """Return (label, path) for user NTUSER.DAT hives, preferring interactive users."""
    hits = find_files(conn, case_id, ["%/NTUSER.DAT", "%/ntuser.dat"])
    results: List[Tuple[str, str]] = []
    skip = {"default user", "localservice", "networkservice", "systemprofile"}
    for path in hits:
        if "/repair/" in path.lower():
            continue
        # Label = parent folder name
        parts = path.replace("\\", "/").split("/")
        user = parts[-2] if len(parts) >= 2 else "unknown"
        if user.lower() in skip:
            continue
        results.append((user, path))
    # Prefer Mr. Evil first on NIST image
    results.sort(key=lambda t: (0 if "evil" in t[0].lower() else 1, t[0].lower()))
    return results


def parse_all_registry(fs_info, case_id: str, conn) -> Dict[str, int]:
    """Extract and parse SYSTEM, SOFTWARE, and user NTUSER hives; mark stage complete."""
    counts: Dict[str, int] = {"SYSTEM": 0, "SOFTWARE": 0, "NTUSER": 0}

    hive_specs = [
        (
            "SYSTEM",
            [
                "%/system32/config/SYSTEM",
                "%/system32/config/system",
            ],
            SYSTEM_KEYS,
        ),
        (
            "SOFTWARE",
            [
                "%/system32/config/SOFTWARE",
                "%/system32/config/software",
            ],
            SOFTWARE_KEYS,
        ),
    ]

    for hive_name, patterns, keys in hive_specs:
        hive_path = _resolve_hive_path(conn, case_id, patterns)
        if not hive_path:
            continue
        temp = temp_path_for(hive_name.lower(), ".hive")
        try:
            extract_hive(fs_info, hive_path, temp)
            counts[hive_name] = parse_hive(temp, hive_name, keys, case_id, conn)
        except Exception:
            # One bad hive must not abort the whole registry stage.
            continue
        finally:
            safe_unlink(temp)

    for user_label, ntuser_path in _find_ntuser_paths(conn, case_id):
        temp = temp_path_for("ntuser", ".hive")
        try:
            extract_hive(fs_info, ntuser_path, temp)
            n = parse_hive(
                temp, f"NTUSER:{user_label}", NTUSER_KEYS, case_id, conn
            )
            counts["NTUSER"] += n
        except Exception:
            continue
        finally:
            safe_unlink(temp)

    mark_stage_complete(case_id, "registry", conn=conn)
    return counts
