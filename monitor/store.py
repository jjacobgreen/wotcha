"""
EventStore — swappable persistence for agent events.

Switching from JSONL to SQLite (or anything else) is a one-line config change:
replace JSONLStore(...) with SQLiteStore(...) wherever the store is constructed.
The rest of the stack depends only on the EventStore protocol.
"""

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import AgentEvent


@runtime_checkable
class EventStore(Protocol):
    def append(self, event: AgentEvent, raw: dict) -> None: ...
    def get_session(self, session_id: str, last_n: int = 10) -> list[AgentEvent]: ...


class JSONLStore:
    """
    Append-only JSONL files under base_dir/<session_id>.jsonl.

    Each line: {"event": <AgentEvent as dict>, "raw": <original hook payload>}
    Doubles as the capture output consumed by capture.py and TranscriptReplaySource.
    """

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or Path.home() / ".wotcha" / "sessions"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _session_path(self, session_id: str) -> Path:
        return self.base_dir / f"{session_id}.jsonl"

    def append(self, event: AgentEvent, raw: dict) -> None:
        entry = {"event": event.model_dump(mode="json"), "raw": raw}
        with self._session_path(event.session_id).open("a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_session(self, session_id: str, last_n: int = 10) -> list[AgentEvent]:
        path = self._session_path(session_id)
        if not path.exists():
            return []
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        events = []
        for line in lines[-last_n:]:
            data = json.loads(line)
            events.append(AgentEvent.model_validate(data["event"]))
        return events


class SQLiteStore:
    """
    SQLite-backed store. Drop-in replacement for JSONLStore.
    Not yet implemented — raises NotImplementedError on all calls.
    """

    def __init__(self, db_path: Path | None = None):
        raise NotImplementedError("SQLiteStore is not yet implemented")

    def append(self, event: AgentEvent, raw: dict) -> None:  # pragma: no cover
        raise NotImplementedError

    def get_session(self, session_id: str, last_n: int = 10) -> list[AgentEvent]:  # pragma: no cover
        raise NotImplementedError
