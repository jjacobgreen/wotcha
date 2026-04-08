"""
Tests for SecurityMonitor using a stub LLMClient — no Ollama required.
"""

import pytest

from monitor.models import AgentEvent, MonitorResult, TriageResult
from monitor.monitor import SecurityMonitor


def make_event(tool: str = "Write", content: str = "x = 1", command: str = "") -> AgentEvent:
    if tool == "Bash":
        tool_input = {"command": command}
    else:
        tool_input = {"file_path": "/project/app.py", "content": content}
    return AgentEvent(session_id="s1", tool_name=tool, tool_input=tool_input, cwd="/project")


class StubLLM:
    """Always returns a fixed result; records calls for assertions."""

    def __init__(self, result: MonitorResult):
        self.calls: list[tuple] = []
        self._result = result

    async def analyse(self, events, triage, session_id, event_index) -> MonitorResult:
        self.calls.append((events, triage, session_id, event_index))
        return self._result


def vuln_result(session_id: str = "s1") -> MonitorResult:
    return MonitorResult(
        session_id=session_id, event_index=0, vulnerable=True,
        cwe="CWE-78", confidence=0.9, explanation="injection detected",
        snippet="os.system(cmd)",
    )


def clean_result(session_id: str = "s1") -> MonitorResult:
    return MonitorResult(
        session_id=session_id, event_index=0, vulnerable=False,
        confidence=0.05, explanation="no issue found",
    )


async def test_clean_event_skips_llm():
    llm = StubLLM(clean_result())
    monitor = SecurityMonitor(llm=llm)
    event = make_event(content="def add(a, b): return a + b")
    result = await monitor.check([event])
    assert not result.vulnerable
    assert llm.calls == []  # triage short-circuits — LLM never called


async def test_suspicious_event_calls_llm():
    stub_result = vuln_result()
    llm = StubLLM(stub_result)
    monitor = SecurityMonitor(llm=llm)
    event = make_event(content="import os\nos.system(user_cmd)\n")
    result = await monitor.check([event])
    assert len(llm.calls) == 1
    assert result.vulnerable
    assert result.cwe == "CWE-78"


async def test_llm_receives_full_context_window():
    llm = StubLLM(clean_result())
    monitor = SecurityMonitor(llm=llm)
    events = [
        make_event(content="x = 1"),
        make_event(content="import os\nos.system(cmd)\n"),  # triggers triage
    ]
    await monitor.check(events)
    assert len(llm.calls) == 1
    passed_events, _, _, event_index = llm.calls[0]
    assert len(passed_events) == 2
    assert event_index == 1  # last event in the window


async def test_empty_events_raises():
    monitor = SecurityMonitor(llm=StubLLM(clean_result()))
    with pytest.raises(ValueError):
        await monitor.check([])


async def test_llm_clean_verdict_returned():
    llm = StubLLM(clean_result())
    monitor = SecurityMonitor(llm=llm)
    event = make_event(content="import os\nos.system(cmd)\n")
    result = await monitor.check([event])
    # LLM was called (triage escalated) but returned clean
    assert len(llm.calls) == 1
    assert not result.vulnerable
