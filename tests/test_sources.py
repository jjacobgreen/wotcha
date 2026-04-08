import json
from pathlib import Path

import pytest

from monitor.models import AgentEvent
from monitor.sources import ClaudeCodeHookSource, TranscriptReplaySource
from monitor.store import JSONLStore


CC_PAYLOAD = {
    "session_id": "abc123",
    "transcript_path": "/tmp/transcript.jsonl",
    "cwd": "/project",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Write",
    "tool_input": {"file_path": "/tmp/foo.py", "content": "x = 1"},
    "tool_use_id": "toolu_01ABC",
}


async def collect(source) -> list[AgentEvent]:
    return [e async for e in source.events()]


async def test_cc_hook_source_normalises_payload():
    source = ClaudeCodeHookSource(raw=json.dumps(CC_PAYLOAD))
    events = await collect(source)
    assert len(events) == 1
    e = events[0]
    assert e.session_id == "abc123"
    assert e.tool_name == "Write"
    assert e.tool_input == CC_PAYLOAD["tool_input"]
    assert e.cwd == "/project"
    assert e.tool_response is None


async def test_cc_hook_source_yields_exactly_one_event():
    source = ClaudeCodeHookSource(raw=json.dumps(CC_PAYLOAD))
    events = await collect(source)
    assert len(events) == 1


async def test_transcript_replay_source(tmp_path):
    # Write two events to a store, then replay them
    store = JSONLStore(base_dir=tmp_path)
    for i in range(3):
        event = AgentEvent(
            session_id="sess1",
            tool_name=f"Tool{i}",
            tool_input={},
            cwd="/project",
        )
        store.append(event, raw={})

    session_file = tmp_path / "sess1.jsonl"
    source = TranscriptReplaySource(session_file)
    events = await collect(source)
    assert len(events) == 3
    assert [e.tool_name for e in events] == ["Tool0", "Tool1", "Tool2"]
