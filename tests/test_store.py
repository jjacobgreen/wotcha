import json
from pathlib import Path

import pytest

from monitor.models import AgentEvent
from monitor.store import JSONLStore


@pytest.fixture
def store(tmp_path):
    return JSONLStore(base_dir=tmp_path)


def make_event(session_id: str = "sess1", tool: str = "Write") -> AgentEvent:
    return AgentEvent(
        session_id=session_id,
        tool_name=tool,
        tool_input={"file_path": "/tmp/foo.py", "content": "x = 1"},
        cwd="/project",
    )


def test_append_creates_file(store, tmp_path):
    event = make_event()
    store.append(event, raw={"original": "payload"})
    assert (tmp_path / "sess1.jsonl").exists()


def test_get_session_empty(store):
    assert store.get_session("nonexistent") == []


def test_round_trip(store):
    event = make_event()
    store.append(event, raw={})
    retrieved = store.get_session("sess1")
    assert len(retrieved) == 1
    assert retrieved[0].session_id == "sess1"
    assert retrieved[0].tool_name == "Write"
    assert retrieved[0].tool_input == event.tool_input


def test_get_session_last_n(store):
    for i in range(15):
        store.append(make_event(tool=f"Tool{i}"), raw={})
    result = store.get_session("sess1", last_n=5)
    assert len(result) == 5
    assert result[-1].tool_name == "Tool14"


def test_raw_stored_alongside_event(store, tmp_path):
    raw = {"session_id": "sess1", "tool_name": "Write", "extra_cc_field": "abc"}
    store.append(make_event(), raw=raw)
    line = (tmp_path / "sess1.jsonl").read_text().strip()
    data = json.loads(line)
    assert data["raw"]["extra_cc_field"] == "abc"


def test_multiple_sessions_isolated(store, tmp_path):
    store.append(make_event(session_id="a"), raw={})
    store.append(make_event(session_id="b"), raw={})
    assert len(store.get_session("a")) == 1
    assert len(store.get_session("b")) == 1
    assert (tmp_path / "a.jsonl").exists()
    assert (tmp_path / "b.jsonl").exists()
