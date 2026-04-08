"""
SecurityMonitor — orchestrates triage → LLM → MonitorResult.

This is the single entry point the hook runner and Inspect solver both call.
It has no dependency on Claude Code, Inspect, or Ollama directly — those are
injected via the LLMClient protocol.
"""

from .llm import LLMClient
from .models import AgentEvent, MonitorResult
from .triage import triage_event


class SecurityMonitor:
    def __init__(self, llm: LLMClient):
        self._llm = llm

    async def check(self, events: list[AgentEvent]) -> MonitorResult:
        """
        Analyse a context window of events and return a MonitorResult.

        `events` should be ordered oldest-first; the last entry is the current
        event being assessed. The full window is passed to the LLM for context,
        but triage runs only on the current event.
        """
        if not events:
            raise ValueError("events list must not be empty")

        current = events[-1]
        event_index = len(events) - 1

        triage = triage_event(current)  # TODO: inject triage func for different levels of triage?

        if not triage.should_escalate:
            return MonitorResult(
                session_id=current.session_id,
                event_index=event_index,
                vulnerable=False,
                confidence=0.0,
                explanation=f"Triage: {triage.reason}",
            )

        return await self._llm.analyse(
            events=events,
            triage=triage,
            session_id=current.session_id,
            event_index=event_index,
        )
