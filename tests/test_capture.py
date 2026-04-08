import json
from pathlib import Path

import pytest

from capture import _label_payload
from evaluation.dataset import DatasetStore, LabeledEvent

COMMAND_INJECTION_PY = """
import subprocess
user_input = input("cmd: ")
subprocess.call(user_input, shell=True)
"""

CLEAN_PY = """
def add(a, b):
    return a + b
"""


def make_write_payload(content: str, file_path: str = "/project/app.py") -> dict:
    return {
        "session_id": "sess1",
        "tool_name": "Write",
        "tool_input": {"file_path": file_path, "content": content},
        "tool_response": {"success": True},
        "cwd": "/project",
        "hook_event_name": "PostToolUse",
    }


def make_bash_payload(command: str) -> dict:
    return {
        "session_id": "sess1",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"output": ""},
        "cwd": "/project",
        "hook_event_name": "PostToolUse",
    }


def test_write_python_with_injection_gets_label():
    labeled = _label_payload(make_write_payload(COMMAND_INJECTION_PY))
    assert "CWE-78" in labeled.bandit_labels


def test_write_clean_python_no_labels():
    labeled = _label_payload(make_write_payload(CLEAN_PY))
    assert labeled.bandit_labels == []


def test_write_non_python_file_no_labels():
    labeled = _label_payload(make_write_payload("SELECT * FROM users", "/project/query.sql"))
    assert labeled.bandit_labels == []


def test_bash_event_no_bandit_labels():
    # Bandit can't analyse shell commands; label is empty even for suspicious cmds.
    labeled = _label_payload(make_bash_payload("rm -rf / --no-preserve-root"))
    assert labeled.bandit_labels == []


def test_raw_payload_preserved():
    payload = make_write_payload(CLEAN_PY)
    labeled = _label_payload(payload)
    assert labeled.raw == payload


def test_dataset_store_round_trip(tmp_path):
    payload = make_write_payload(COMMAND_INJECTION_PY)
    labeled = _label_payload(payload)
    store = DatasetStore(tmp_path)
    store.append(labeled)

    rows = list(store.iter_all())
    assert len(rows) == 1
    assert rows[0].event.session_id == "sess1"
    assert "CWE-78" in rows[0].bandit_labels


def test_dataset_store_iter_all_multiple_sessions(tmp_path):
    store = DatasetStore(tmp_path)
    for session_id in ("a", "b", "c"):
        payload = {**make_write_payload(CLEAN_PY), "session_id": session_id}
        store.append(_label_payload(payload))

    rows = list(store.iter_all())
    assert len(rows) == 3
    assert {r.event.session_id for r in rows} == {"a", "b", "c"}
