#!/usr/bin/env python3
"""
hook_runner.py — Claude Code PreToolUse hook.

Registered in ~/.claude/settings.json for Write, Edit, and Bash tool events.
Reads the hook payload from stdin, runs the security monitor, and:
  - Returns a systemMessage to warn Claude if a vulnerability is detected
  - Appends a structured alert to ~/.wotcha/alerts.jsonl

Exits 0 always (warn-only mode). Never blocks tool execution in v1.
Fails silently on LLM errors to avoid disrupting Claude's session.
"""

import asyncio
import json
import sys
from pathlib import Path

from monitor.llm import OllamaClient
from monitor.monitor import SecurityMonitor
from monitor.sources import normalise_cc_payload
from monitor.store import JSONLStore

WATCHED_TOOLS = {"Write", "Edit", "Bash"}
ALERTS_PATH = Path.home() / ".wotcha" / "alerts.jsonl"
CONTEXT_WINDOW = 10

_store = JSONLStore()
_monitor = SecurityMonitor(llm=OllamaClient())


async def run(raw_text: str) -> None:
    payload = json.loads(raw_text)

    if payload.get("tool_name") not in WATCHED_TOOLS:
        return

    event = normalise_cc_payload(payload)
    _store.append(event, raw=payload)
    context = _store.get_session(event.session_id, last_n=CONTEXT_WINDOW)

    try:
        result = await _monitor.check(context)
    except Exception as exc:
        # LLM unavailable, timeout, etc. — don't disrupt the session.
        sys.stderr.write(f"wotcha: monitor error: {exc}\n")
        return

    if result.vulnerable:
        ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with ALERTS_PATH.open("a") as f:
            f.write(result.model_dump_json() + "\n")

        cwe = result.cwe or "unknown"
        pct = f"{result.confidence:.0%}"
        print(json.dumps({
            "systemMessage": (
                f"[wotcha] Security warning {cwe} ({pct} confidence): "
                f"{result.explanation}"
                + (f"\n  Snippet: {result.snippet}" if result.snippet else "")
            )
        }))


if __name__ == "__main__":
    raw = sys.stdin.read().strip()
    if raw:
        asyncio.run(run(raw))
