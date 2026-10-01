"""Engineer a fixed 12-feature threat vector from parsed forensic artifacts.

Column order is defined by FEATURE_NAMES and must stay consistent across
training, XGBoost, and the autoencoder.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, Mapping

import numpy as np

FEATURE_NAMES = [
    "failed_logon_count",
    "logon_outside_hours",
    "new_service_installed",
    "scheduled_task_created",
    "process_creation_count",
    "unique_usb_devices",
    "autorun_entries",
    "tor_visits",
    "total_urls",
    "known_malware_executed",
    "total_executions",
    "sensitive_file_access",
]

# Offensive / hacking / malware tools (lowercase). Includes NIST SCHARDT tools.
KNOWN_MALWARE = frozenset(
    {
        "mimikatz.exe",
        "mimikatz64.exe",
        "psexec.exe",
        "procdump.exe",
        "procdump64.exe",
        "wce.exe",
        "cobaltstrike.exe",
        "beacon.exe",
        "meterpreter.exe",
        "pwdump.exe",
        "fgdump.exe",
        "nc.exe",
        "ncat.exe",
        "netcat.exe",
        "nmap.exe",
        "lazagne.exe",
        "crackmapexec.exe",
        "bloodhound.exe",
        "sharphound.exe",
        "rubeus.exe",
        "seatbelt.exe",
        "winpeas.exe",
        "winpeasx64.exe",
        "ghostpack.exe",
        "impacket.exe",
        "smbexec.exe",
        "wmiexec.exe",
        "atexec.exe",
        "secretsdump.exe",
        "hashcat.exe",
        "john.exe",
        "hydra.exe",
        "medusa.exe",
        "responder.exe",
        "empire.exe",
        "powershell_empire.exe",
        "covenant.exe",
        "sliver.exe",
        "merlin.exe",
        "chisel.exe",
        "plink.exe",
        "stunnel.exe",
        "tor.exe",
        "torbrowser.exe",
        "anydesk.exe",
        "teamviewer.exe",
        # NIST Hacking Case / wardriving toolkit
        "cain.exe",
        "cain25b45.exe",
        "ethereal.exe",
        "ethereal-setup-0.10.6.exe",
        "netstumbler.exe",
        "netstumblerinstaller.exe",
        "anonymizer.exe",
        "123wasp_setup.exe",
        "cute3032.exe",
        "look@lan.exe",
        "irsetup.exe",
        "agent.exe",
        "agentsvr.exe",
    }
)

# Vista+ and XP equivalents so SCHARDT and modern demo images both work.
_FAILED_LOGON_IDS = (4625, 529)
_LOGON_IDS = (4624, 528, 540)
_SERVICE_IDS = (7045, 7035, 7036)
_TASK_IDS = (4698, 4702)
_PROCESS_IDS = (4688,)


def _scalar(row) -> Any:
    if row is None:
        return 0
    if hasattr(row, "keys"):
        return row[0]
    return row[0] if row else 0


def _parse_hour(timestamp: str) -> int | None:
    if not timestamp:
        return None
    text = timestamp.strip()
    # ISO-8601 or common SQLite forms
    for fmt in (
        None,  # fromisoformat first
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            if fmt is None:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                dt = datetime.strptime(text[:19], fmt)
            return dt.hour
        except (ValueError, TypeError):
            continue
    return None


def extract_features(case_id: str, conn) -> OrderedDict:
    """Return an OrderedDict of the 12 engineered features for a case."""
    features: OrderedDict[str, float] = OrderedDict()

    features["failed_logon_count"] = int(
        _scalar(
            conn.execute(
                f"""
                SELECT COUNT(*) FROM event_logs
                WHERE case_id = ? AND event_id IN ({",".join("?" * len(_FAILED_LOGON_IDS))})
                """,
                (case_id, *_FAILED_LOGON_IDS),
            ).fetchone()
        )
    )

    # Outside-hours logons: 22:00–06:00
    logon_rows = conn.execute(
        f"""
        SELECT timestamp FROM event_logs
        WHERE case_id = ? AND event_id IN ({",".join("?" * len(_LOGON_IDS))})
        """,
        (case_id, *_LOGON_IDS),
    ).fetchall()
    outside = 0
    for row in logon_rows:
        ts = row["timestamp"] if hasattr(row, "keys") else row[0]
        hour = _parse_hour(ts)
        if hour is not None and (hour >= 22 or hour < 6):
            outside = 1
            break
    features["logon_outside_hours"] = outside

    features["new_service_installed"] = int(
        _scalar(
            conn.execute(
                f"""
                SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END
                FROM event_logs
                WHERE case_id = ? AND event_id IN ({",".join("?" * len(_SERVICE_IDS))})
                """,
                (case_id, *_SERVICE_IDS),
            ).fetchone()
        )
    )

    features["scheduled_task_created"] = int(
        _scalar(
            conn.execute(
                f"""
                SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END
                FROM event_logs
                WHERE case_id = ? AND event_id IN ({",".join("?" * len(_TASK_IDS))})
                """,
                (case_id, *_TASK_IDS),
            ).fetchone()
        )
    )

    features["process_creation_count"] = int(
        _scalar(
            conn.execute(
                f"""
                SELECT COUNT(*) FROM event_logs
                WHERE case_id = ? AND event_id IN ({",".join("?" * len(_PROCESS_IDS))})
                """,
                (case_id, *_PROCESS_IDS),
            ).fetchone()
        )
    )

    # USBSTOR device keys, Enum\USB instances, or PCMCIA device keys (NIST XP).
    features["unique_usb_devices"] = int(
        _scalar(
            conn.execute(
                """
                SELECT COUNT(DISTINCT key_path) FROM registry_entries
                WHERE case_id = ?
                  AND (
                    UPPER(key_path) LIKE '%USBSTOR%'
                    OR key_path LIKE 'ControlSet001\\Enum\\USB\\%\\%'
                    OR key_path LIKE 'ControlSet001\\Enum\\PCMCIA\\%'
                  )
                  AND value_name = '(key)'
                """,
                (case_id,),
            ).fetchone()
        )
    )

    features["autorun_entries"] = int(
        _scalar(
            conn.execute(
                """
                SELECT COUNT(*) FROM registry_entries
                WHERE case_id = ?
                  AND (
                    UPPER(key_path) LIKE '%\\RUN'
                    OR UPPER(key_path) LIKE '%\\RUNONCE'
                    OR UPPER(key_path) LIKE '%CURRENTVERSION\\RUN'
                    OR UPPER(key_path) LIKE '%CURRENTVERSION\\RUNONCE'
                  )
                  AND value_name != '(key)'
                """,
                (case_id,),
            ).fetchone()
        )
    )

    features["tor_visits"] = int(
        _scalar(
            conn.execute(
                """
                SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END
                FROM browser_history
                WHERE case_id = ? AND LOWER(url) LIKE '%.onion%'
                """,
                (case_id,),
            ).fetchone()
        )
    )

    features["total_urls"] = int(
        _scalar(
            conn.execute(
                "SELECT COUNT(*) FROM browser_history WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        )
    )

    prefetch_rows = conn.execute(
        "SELECT executable FROM prefetch_entries WHERE case_id = ?",
        (case_id,),
    ).fetchall()
    malware_hit = 0
    for row in prefetch_rows:
        exe = row["executable"] if hasattr(row, "keys") else row[0]
        if exe and exe.lower() in KNOWN_MALWARE:
            malware_hit = 1
            break
    features["known_malware_executed"] = malware_hit
    features["total_executions"] = len(prefetch_rows)

    features["sensitive_file_access"] = int(
        _scalar(
            conn.execute(
                """
                SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END
                FROM files
                WHERE case_id = ?
                  AND (
                    UPPER(path) LIKE '%/SAM'
                    OR UPPER(path) LIKE '%\\SAM'
                    OR UPPER(path) LIKE '%/SYSTEM'
                    OR UPPER(path) LIKE '%/system'
                    OR UPPER(path) LIKE '%NTDS.DIT%'
                    OR UPPER(path) LIKE '%/SECURITY'
                    OR UPPER(path) LIKE '%/security'
                  )
                  AND (
                    UPPER(path) LIKE '%/CONFIG/%'
                    OR UPPER(path) LIKE '%\\CONFIG\\%'
                    OR UPPER(path) LIKE '%NTDS%'
                  )
                """,
                (case_id,),
            ).fetchone()
        )
    )

    # Ensure all keys present as floats for ML
    for name in FEATURE_NAMES:
        features[name] = float(features.get(name, 0))
    return features


def features_to_vector(feature_dict: Mapping[str, Any]) -> np.ndarray:
    """Convert a feature dict to a numpy vector in FEATURE_NAMES order."""
    return np.asarray(
        [float(feature_dict[name]) for name in FEATURE_NAMES],
        dtype=np.float64,
    )


def vector_to_dict(vector: np.ndarray) -> Dict[str, float]:
    """Inverse of features_to_vector (for debugging)."""
    return {name: float(vector[i]) for i, name in enumerate(FEATURE_NAMES)}
