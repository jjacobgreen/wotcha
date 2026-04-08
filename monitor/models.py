from datetime import datetime
from pydantic import BaseModel, Field


class AgentEvent(BaseModel):
    """A normalised, agent-agnostic representation of a single tool-use event."""

    session_id: str
    tool_name: str
    tool_input: dict
    tool_response: dict | None = None
    cwd: str
    timestamp: datetime = Field(default_factory=datetime.now)


class TriageResult(BaseModel):
    """Output of the fast first-pass triage layer (no LLM call)."""

    should_escalate: bool
    cwe_candidates: list[str]  # e.g. ["CWE-78"]
    reason: str


class MonitorResult(BaseModel):
    """Structured output from the LLM monitor for a single event (or context window)."""

    session_id: str
    event_index: int
    vulnerable: bool
    cwe: str | None = None
    confidence: float  # 0.0–1.0
    explanation: str
    snippet: str | None = None
    # Populated by capture.py from Bandit; empty in live monitoring mode.
    bandit_labels: list[str] | None = Field(default_factory=list)
