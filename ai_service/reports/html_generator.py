"""HTML forensic report generator — f-string + inline CSS, no template engine."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai_service.db.database import get_connection
from ai_service.llm.ollama_client import MODEL
from ai_service.rag.rag_pipeline import RAGPipeline
from ai_service.rag.vector_store import VectorStore

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = _PROJECT_ROOT / "data" / "reports"

# Vista+ and XP event IDs for timeline section
_TIMELINE_IDS = (4624, 4625, 4688, 7045, 528, 529, 7035, 7036)


def _esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _risk_color(score: float) -> str:
    if score > 0.8:
        return "#b91c1c"  # red
    if score >= 0.4:
        return "#b45309"  # amber
    return "#15803d"  # green


def generate_report(
    case_id: str,
    conn=None,
    rag: Optional[RAGPipeline] = None,
) -> str:
    """Build report_{case_id}.html under data/reports/ and return its path."""
    owns = conn is None
    if owns:
        conn = get_connection()

    try:
        case = conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if case is None:
            raise ValueError(f"Unknown case_id: {case_id}")

        stats = {
            "files": conn.execute(
                "SELECT COUNT(*) AS c FROM files WHERE case_id = ?", (case_id,)
            ).fetchone()["c"],
            "events": conn.execute(
                "SELECT COUNT(*) AS c FROM event_logs WHERE case_id = ?", (case_id,)
            ).fetchone()["c"],
            "registry": conn.execute(
                "SELECT COUNT(*) AS c FROM registry_entries WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
            "browser": conn.execute(
                "SELECT COUNT(*) AS c FROM browser_history WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
            "prefetch": conn.execute(
                "SELECT COUNT(*) AS c FROM prefetch_entries WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
            "flagged": conn.execute(
                "SELECT COUNT(*) AS c FROM artifacts WHERE case_id = ? AND flagged = 1",
                (case_id,),
            ).fetchone()["c"],
        }

        threat = conn.execute(
            """
            SELECT * FROM artifacts
            WHERE case_id = ? AND artifact_type = 'threat_assessment'
            ORDER BY id DESC LIMIT 1
            """,
            (case_id,),
        ).fetchone()

        xgb = float(threat["xgboost_score"]) if threat and threat["xgboost_score"] is not None else 0.0
        ae = float(threat["autoencoder_score"]) if threat and threat["autoencoder_score"] is not None else 0.0
        flagged = bool(threat["flagged"]) if threat else False
        risk = "HIGH" if flagged else "LOW"
        bar_pct = max(0, min(100, int(round(xgb * 100))))

        features: Dict[str, Any] = {}
        if threat and threat["data_json"]:
            try:
                features = json.loads(threat["data_json"])
            except json.JSONDecodeError:
                features = {}

        events = conn.execute(
            f"""
            SELECT event_id, channel, timestamp, user_name, computer, description
            FROM event_logs
            WHERE case_id = ? AND event_id IN ({",".join("?" * len(_TIMELINE_IDS))})
            ORDER BY timestamp ASC
            LIMIT 100
            """,
            (case_id, *_TIMELINE_IDS),
        ).fetchall()

        usb_rows = conn.execute(
            """
            SELECT key_path, value_name, value_data, timestamp
            FROM registry_entries
            WHERE case_id = ?
              AND (
                UPPER(key_path) LIKE '%USBSTOR%'
                OR key_path LIKE 'ControlSet001\\Enum\\USB%'
                OR UPPER(key_path) LIKE '%PCMCIA%'
              )
            ORDER BY key_path, value_name
            LIMIT 80
            """,
            (case_id,),
        ).fetchall()

        if rag is None:
            rag = RAGPipeline(VectorStore())
        narrative = rag.answer(
            case_id,
            "Provide a concise forensic investigation summary covering key findings, "
            "suspicious activity, and timeline",
        )["answer"]

        event_rows_html = "".join(
            f"<tr><td>{_esc(e['timestamp'])}</td><td>{_esc(e['event_id'])}</td>"
            f"<td>{_esc(e['channel'])}</td><td>{_esc(e['computer'])}</td>"
            f"<td>{_esc(e['description'])}</td></tr>"
            for e in events
        ) or "<tr><td colspan='5'>No matching timeline events.</td></tr>"

        usb_rows_html = "".join(
            f"<tr><td>{_esc(u['key_path'])}</td><td>{_esc(u['value_name'])}</td>"
            f"<td>{_esc(u['value_data'])}</td><td>{_esc(u['timestamp'])}</td></tr>"
            for u in usb_rows
        ) or "<tr><td colspan='4'>No USB/PCMCIA registry entries.</td></tr>"

        feature_rows = "".join(
            f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
            for k, v in features.items()
        ) or "<tr><td colspan='2'>No feature vector stored.</td></tr>"

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        score_color = _risk_color(xgb)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Forensic Report — {_esc(case_id)}</title>
<style>
  :root {{
    --ink: #1a2332;
    --muted: #5b6b7c;
    --line: #d7dee7;
    --bg: #f4f6f8;
    --card: #ffffff;
    --accent: #0f3d5e;
  }}
  body {{
    margin: 0; padding: 0;
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    color: var(--ink); background: var(--bg); line-height: 1.45;
  }}
  header {{
    background: linear-gradient(135deg, #0f3d5e, #1f5f82);
    color: #fff; padding: 2rem 2.5rem;
  }}
  header h1 {{ margin: 0 0 0.4rem 0; font-size: 1.8rem; letter-spacing: 0.02em; }}
  header p {{ margin: 0.2rem 0; opacity: 0.92; }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 1.5rem; }}
  section {{
    background: var(--card); border: 1px solid var(--line);
    border-radius: 6px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
  }}
  h2 {{
    margin: 0 0 0.85rem 0; font-size: 1.15rem; color: var(--accent);
    border-bottom: 2px solid var(--line); padding-bottom: 0.4rem;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th, td {{ border-bottom: 1px solid var(--line); padding: 0.45rem 0.5rem; text-align: left; vertical-align: top; }}
  th {{ background: #eef3f7; color: var(--muted); font-weight: 600; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; }}
  .stat {{ background: #eef3f7; border-radius: 4px; padding: 0.75rem; }}
  .stat .n {{ font-size: 1.4rem; font-weight: 700; color: var(--accent); }}
  .stat .l {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; }}
  .hash {{ font-family: ui-monospace, Consolas, monospace; font-size: 0.85rem; word-break: break-all; }}
  .bar {{
    height: 18px; background: #e5e7eb; border-radius: 9px; overflow: hidden; max-width: 360px;
  }}
  .bar > span {{ display: block; height: 100%; background: {score_color}; width: {bar_pct}%; }}
  .risk-high {{ color: #b91c1c; font-weight: 700; }}
  .risk-low {{ color: #15803d; font-weight: 700; }}
  .narrative {{ white-space: pre-wrap; background: #f8fafc; border-left: 4px solid var(--accent); padding: 0.9rem 1rem; }}
  footer {{
    text-align: center; color: var(--muted); font-size: 0.85rem;
    padding: 1.5rem; border-top: 1px solid var(--line); margin-top: 1rem;
  }}
</style>
</head>
<body>
<header>
  <h1>Digital Forensic Investigation Report</h1>
  <p><strong>Case:</strong> {_esc(case['name'] or case_id)} ({_esc(case_id)})</p>
  <p><strong>Created:</strong> {_esc(case['created_at'])} &nbsp;|&nbsp; <strong>Status:</strong> {_esc(case['status'])}</p>
  <p><strong>Image:</strong> {_esc(case['image_path'])}</p>
</header>
<main>

<section>
  <h2>1. Evidence Integrity</h2>
  <p><strong>Acquisition hash</strong> (acquisition-time / ewfinfo or streamed MD5):</p>
  <p class="hash">{_esc(case['acquisition_hash'])}</p>
  <p><strong>System hash</strong> (independent SHA-256 of raw disk content):</p>
  <p class="hash">{_esc(case['system_hash'])}</p>
</section>

<section>
  <h2>2. Statistics</h2>
  <div class="stats">
    <div class="stat"><div class="n">{stats['files']}</div><div class="l">Files</div></div>
    <div class="stat"><div class="n">{stats['events']}</div><div class="l">Events</div></div>
    <div class="stat"><div class="n">{stats['registry']}</div><div class="l">Registry</div></div>
    <div class="stat"><div class="n">{stats['browser']}</div><div class="l">Browser</div></div>
    <div class="stat"><div class="n">{stats['prefetch']}</div><div class="l">Prefetch</div></div>
    <div class="stat"><div class="n">{stats['flagged']}</div><div class="l">Flagged</div></div>
  </div>
</section>

<section>
  <h2>3. Threat Assessment</h2>
  <p>XGBoost threat probability: <strong style="color:{score_color}">{xgb:.2%}</strong></p>
  <div class="bar"><span></span></div>
  <p>Autoencoder reconstruction error: <strong>{ae:.6f}</strong></p>
  <p>Combined risk level:
    <span class="{'risk-high' if flagged else 'risk-low'}">{risk}</span>
    ({'flagged' if flagged else 'not flagged'})
  </p>
</section>

<section>
  <h2>4. Flagged Artifacts / Feature Vector</h2>
  <table>
    <thead><tr><th>Feature</th><th>Value</th></tr></thead>
    <tbody>{feature_rows}</tbody>
  </table>
</section>

<section>
  <h2>5. Event Timeline</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Event ID</th><th>Channel</th><th>Computer</th><th>Description</th></tr></thead>
    <tbody>{event_rows_html}</tbody>
  </table>
</section>

<section>
  <h2>6. USB / PCMCIA Device History</h2>
  <table>
    <thead><tr><th>Key Path</th><th>Value</th><th>Data</th><th>Timestamp</th></tr></thead>
    <tbody>{usb_rows_html}</tbody>
  </table>
</section>

<section>
  <h2>7. AI Narrative Summary</h2>
  <div class="narrative">{_esc(narrative)}</div>
</section>

</main>
<footer>
  Generated {_esc(generated_at)} &nbsp;·&nbsp; Model: {_esc(MODEL)} &nbsp;·&nbsp; Offline mode
</footer>
</body>
</html>
"""

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = REPORTS_DIR / f"report_{case_id}.html"
        out_path.write_text(html_doc, encoding="utf-8")
        return str(out_path)
    finally:
        if owns:
            conn.close()
