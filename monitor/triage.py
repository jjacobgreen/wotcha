"""
Triage — fast first-pass filter that gates LLM calls.

Uses regex/keyword matching only (no subprocess, no LLM). Must stay cheap
since it runs on every watched tool event in the PreToolUse hook.

High recall is the goal here: we'd rather escalate a false positive to the LLM
than silently drop a real vulnerability. The LLM is the precision layer.
"""

import re
from pathlib import Path

from .models import AgentEvent, TriageResult

PYTHON_EXTENSIONS = {".py", ".pyw"}

# ── CWE-78: Command injection ─────────────────────────────────────────────────

# Bash tool: patterns that suggest user-controlled data may reach a shell
_BASH_CWE78 = re.compile(
    r"""
    \$\{[^}]+\}                 # ${variable}
    | \$\([^)]+\)               # $(subshell)
    | `[^`]+`                   # `backtick`
    | \$[A-Za-z_][A-Za-z0-9_]* # $BARE_VARIABLE
    | \beval\b                  # eval
    | shell=True                # python subprocess shell=True in a bash one-liner
    """,
    re.VERBOSE,
)

# Python source: subprocess/os calls that might accept unsanitised input
_PYTHON_CWE78 = re.compile(
    r"""
    \bos\.system\s*\(
    | \bos\.popen\s*\(
    | \bsubprocess\.\w+\s*\(      # subprocess.call/run/Popen etc.
    | \beval\s*\(
    | \bexec\s*\(
    """,
    re.VERBOSE,
)

# ── CWE-89: SQL injection ─────────────────────────────────────────────────────

_PYTHON_CWE89 = re.compile(
    r"""
    (?:
        # f-string whose content contains a SQL keyword
        \bf["\'].*?(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)
        |
        # SQL keyword followed by string concatenation or % / .format() interpolation
        (?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).{0,120}(?:[+%]|\bformat\b)
    )
    """,
    re.VERBOSE | re.IGNORECASE | re.DOTALL,
)

# ── CWE-798: Hardcoded credentials ───────────────────────────────────────────

_PYTHON_CWE798 = re.compile(
    r"""
    (?:password|passwd|api_key|apikey|secret|token|private_key)
    \s*=\s*
    (?:["'][^"']{4,}["'])   # assigned a non-trivial string literal
    """,
    re.VERBOSE | re.IGNORECASE,
)


def triage_event(event: AgentEvent) -> TriageResult:
    """
    Run all triage patterns against a single event.

    Returns a TriageResult with should_escalate=True if any pattern fires,
    along with the candidate CWEs for the LLM to focus on.
    """
    tool = event.tool_name
    candidates: list[str] = []
    reasons: list[str] = []

    if tool == "Bash":
        command = event.tool_input.get("command", "")
        if _BASH_CWE78.search(command):
            candidates.append("CWE-78")
            reasons.append("bash command contains shell interpolation or eval")

    elif tool in ("Write", "Edit"):
        content = event.tool_input.get("content", "")
        file_path = event.tool_input.get("file_path", "")
        is_python = Path(file_path).suffix in PYTHON_EXTENSIONS

        if is_python and _PYTHON_CWE78.search(content):
            candidates.append("CWE-78")
            reasons.append("Python code contains subprocess/os/eval call")

        if is_python and _PYTHON_CWE89.search(content):
            candidates.append("CWE-89")
            reasons.append("Python code contains SQL keyword near string formatting")

        if _PYTHON_CWE798.search(content):
            candidates.append("CWE-798")
            reasons.append("file contains credential-like string assignment")

    return TriageResult(
        should_escalate=bool(candidates),
        cwe_candidates=candidates,
        reason="; ".join(reasons) if reasons else "no suspicious patterns",
    )
