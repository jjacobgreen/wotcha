"""
EventSource — agent-agnostic event ingestion.

Each source normalises raw agent events into AgentEvent objects.
The hook runner and capture pipeline depend only on the protocol.

Adding a new agent (Cursor, Codex, opencode, etc.) means implementing
a new EventSource — the rest of the stack is unchanged.
"""

import json
import sys
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import AgentEvent


@runtime_checkable
class EventSource(Protocol):
    def events(self) -> AsyncIterator[AgentEvent]: ...


class ClaudeCodeHookSource:
    """
    Reads a single Claude Code hook payload from stdin and yields one AgentEvent.

    Claude Code delivers one JSON object per hook invocation.
    Normalises the CC-specific payload into the agent-agnostic AgentEvent model.
    """

    def __init__(self, raw: str | None = None):
        # Accept raw JSON string directly (useful for testing); otherwise read stdin.
        self._raw = raw

    async def events(self) -> AsyncIterator[AgentEvent]:
        text = self._raw if self._raw is not None else sys.stdin.read()
        payload = json.loads(text)
        yield normalise_cc_payload(payload)


class TranscriptReplaySource:
    """
    Replays AgentEvents from a wotcha session JSONL file.

    Each line is a JSON object with an "event" key containing a serialised AgentEvent,
    as written by JSONLStore. Used by capture.py and for offline debugging.
    """

    def __init__(self, path: Path):
        self._path = path

    async def events(self) -> AsyncIterator[AgentEvent]:
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            yield AgentEvent.model_validate(data["event"])


def normalise_cc_payload(payload: dict) -> AgentEvent:
    """Map a raw Claude Code hook payload to an AgentEvent."""
    return AgentEvent(
        session_id=payload["session_id"],
        tool_name=payload["tool_name"],
        tool_input=payload.get("tool_input", {}),
        tool_response=payload.get("tool_response"),
        cwd=payload.get("cwd", ""),
        timestamp=datetime.now(),  # TODO: should we use the timestamp from the payload instead, OR as well? 
    )
