"""Offline Ollama LLM client for grounded forensic Q&A.

Temperature is always 0.1 — forensic answers must be factual, never creative.
The LLM may only answer from provided evidence context (project rule).
"""

from __future__ import annotations

import json
import os
from typing import List, Sequence, Union

import requests

from ai_service.llm.tools import OLLAMA_TOOLS, dispatch

# Portable defaults; override OLLAMA_HOST when Ollama runs on the Windows host.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
TEMPERATURE = 0.1
REQUEST_TIMEOUT = 180  # Cold-start of qwen2.5:3b on the Windows host can exceed 60s.

SYSTEM_PROMPT = """You are a digital forensics AI assistant
with access to tools that query a parsed Windows disk image.

TOOL SELECTION RULES:
- Programs executed → query_programs_executed
  (Windows Prefetch; order='recent' for most recent)
- Login attempts / account events → query_security_events
  (4624 success, 4625 failed, 4688 process, 4720 account
   created, 4698 scheduled task, 4672 privileges, 1102 log cleared)
- USB / removable devices → query_usb_devices
- Browser history → query_browser_history
- Files by type or location → query_files
  (extension: 'pdf','docx','exe','jpg','zip';
   path_pattern: 'Desktop','Downloads','AppData')
- Scheduled tasks → query_registry key_pattern='TASKS'
- Recently accessed files → query_registry key_pattern='LNK'
- Deleted files → query_registry key_pattern='RECYCLEBIN'
- Installed software → query_registry key_pattern='Uninstall'
- Startup programs → query_registry key_pattern='Run'
- User assist / GUI execution → query_registry key_pattern='UserAssist'
- Typed URLs → query_registry key_pattern='TypedURLs'
- Run dialog history → query_registry key_pattern='RunMRU'
- Case overview → query_case_summary first
- Open-ended or cross-artifact → semantic_search last

RESPONSE RULES:
- Always use the most specific tool for the question.
- Call query_case_summary first for overview questions.
- When total > len(rows), state the total and note you are
  showing the top N. Never understate record counts.
- Zero rows → 'No matching records found in [source].'
  Never say 'no evidence exists.'
- Never fabricate records not returned by a tool.
- Format timestamps consistently.
- Use numbered lists for event sequences.
- Be concise and factual.
"""

NO_EVIDENCE_REPLY = "The evidence does not contain information about this query."


def _chunk_text(chunk: Union[str, dict]) -> str:
    if isinstance(chunk, dict):
        return str(chunk.get("document") or chunk.get("text") or chunk)
    return str(chunk)


def query_llm(question: str, context_chunks: Sequence[Union[str, dict]]) -> str:
    """Ask qwen2.5:3b with numbered evidence context. Returns response text."""
    lines = []
    for i, chunk in enumerate(context_chunks, start=1):
        lines.append(f"[{i}] {_chunk_text(chunk)}")
    context_block = "\n".join(lines) if lines else "(no evidence chunks provided)"

    user_content = (
        "Evidence context:\n"
        f"{context_block}\n\n"
        f"Investigator question: {question}"
    )

    payload = {
        "model": MODEL,
        "stream": False,
        "options": {"temperature": TEMPERATURE},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }

    url = f"{OLLAMA_HOST}/api/chat"
    try:
        response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        message = data.get("message") or {}
        content = (message.get("content") or "").strip()
        if not content:
            return "The LLM returned an empty response."
        return content
    except requests.exceptions.ConnectionError:
        return (
            f"Unable to reach Ollama at {OLLAMA_HOST}. "
            "Ensure Ollama is running on Windows and OLLAMA_HOST is set."
        )
    except requests.exceptions.Timeout:
        return f"Ollama request timed out after {REQUEST_TIMEOUT}s."
    except requests.exceptions.RequestException as exc:
        return f"Ollama request failed: {exc}"


MAX_TOOL_ITERATIONS = 5


def query_llm_with_tools(case_id: str, question: str) -> dict:
    """Tool-calling chat loop. Returns {"answer": str, "sources": list, "tools_used": list}."""
    from ai_service.llm.tools import OLLAMA_TOOLS, dispatch

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": question},
    ]
    tools_used = []
    sources = []

    url = f"{OLLAMA_HOST}/api/chat"

    for iteration in range(MAX_TOOL_ITERATIONS):
        payload = {
            "model": MODEL,
            "stream": False,
            "options": {"temperature": TEMPERATURE},
            "messages": messages,
            "tools": OLLAMA_TOOLS,
        }
        try:
            response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.ConnectionError:
            return {
                "answer": f"Unable to reach Ollama at {OLLAMA_HOST}. Ensure Ollama is running.",
                "sources": [],
                "tools_used": tools_used,
            }
        except requests.exceptions.Timeout:
            return {
                "answer": f"Ollama request timed out after {REQUEST_TIMEOUT}s.",
                "sources": [],
                "tools_used": tools_used,
            }
        except requests.exceptions.RequestException as exc:
            return {
                "answer": f"Ollama request failed: {exc}",
                "sources": [],
                "tools_used": tools_used,
            }

        message = data.get("message") or {}
        tool_calls = message.get("tool_calls") or []

        # No tool calls — model returned final answer
        if not tool_calls:
            content = (message.get("content") or "").strip()
            if not content:
                content = "The model returned an empty response."
            return {
                "answer": content,
                "sources": sources,
                "tools_used": tools_used,
            }

        # Append assistant message with tool calls
        messages.append({"role": "assistant", "content": "", "tool_calls": tool_calls})

        # Execute each tool call and append results
        for tc in tool_calls:
            fn_info = tc.get("function") or {}
            tool_name = fn_info.get("name") or ""
            raw_args = fn_info.get("arguments") or {}
            # Ollama may return arguments as a JSON string
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args)
                except Exception:
                    raw_args = {}

            # Always inject case_id
            raw_args["case_id"] = case_id

            result = dispatch(tool_name, raw_args)
            tools_used.append({"tool": tool_name, "args": raw_args, "total": result.get("total", 0)})

            # Build source entries for UI
            for row in result.get("rows") or []:
                sources.append({
                    "text": str(row)[:100],
                    "type": result.get("source", tool_name),
                })

            # Append tool result as a tool-role message
            messages.append({
                "role": "tool",
                "content": json.dumps(result),
            })

    # Exhausted iterations — return what we have
    return {
        "answer": "Investigation complete. See tool results above.",
        "sources": sources,
        "tools_used": tools_used,
    }


def summarise(text_blob: str) -> str:
    """Ask the LLM to summarise a blob of findings (used by report generator)."""
    return query_llm(
        "Summarise the following forensic findings concisely for an investigation report.",
        [text_blob],
    )
