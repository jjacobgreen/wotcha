#!/usr/bin/env python3
"""
capture.py — Captures and labels Claude Code agent events for the eval dataset.

Registered as a PostToolUse hook alongside hook_runner.py. Runs after tool
execution so tool_response is available for context.

Two subcommands:
  hook    Read one PostToolUse event from stdin (CC hook mode)
  batch   Label all events from a wotcha session JSONL file
"""

import json
import sys
from pathlib import Path

import typer

from evaluation.bandit import findings_to_cwe_labels, run_bandit
from evaluation.dataset import DatasetStore, LabeledEvent
from monitor.sources import normalise_cc_payload

app = typer.Typer(help=__doc__, no_args_is_help=True)

PYTHON_EXTENSIONS = {".py", ".pyw"}
WATCHED_TOOLS = {"Write", "Edit", "Bash"}


def _label_payload(payload: dict) -> LabeledEvent:
    """Normalise a raw CC hook payload and attach Bandit labels."""
    event = normalise_cc_payload(payload)
    bandit_labels: list[str] = []

    tool_name = payload.get("tool_name", "")
    if tool_name in ("Write", "Edit"):
        tool_input = payload.get("tool_input", {})
        content = tool_input.get("content", "")
        file_path = tool_input.get("file_path", "")
        if content and Path(file_path).suffix in PYTHON_EXTENSIONS:
            findings = run_bandit(content, filename=Path(file_path).name)
            bandit_labels = findings_to_cwe_labels(findings)
    # Bash events are captured but Bandit can't analyse shell commands,
    # so bandit_labels remains empty for those.

    return LabeledEvent(event=event, bandit_labels=bandit_labels, raw=payload)


@app.command()
def hook(
    dataset_dir: Path = typer.Option(
        None,
        help="Directory to write labeled JSONL rows (default: evaluation/dataset/)",
    ),
) -> None:
    """Hook mode: read one PostToolUse event from stdin and append to dataset."""
    raw_text = sys.stdin.read().strip()
    if not raw_text:
        return

    payload = json.loads(raw_text)
    if payload.get("tool_name") not in WATCHED_TOOLS:
        return

    store = DatasetStore(dataset_dir)
    store.append(_label_payload(payload))


@app.command()
def batch(
    session_file: Path = typer.Argument(..., help="Wotcha session JSONL to process"),
    dataset_dir: Path = typer.Option(
        None,
        help="Directory to write labeled JSONL rows (default: evaluation/dataset/)",
    ),
) -> None:
    """Batch mode: label all events from a wotcha session JSONL file."""
    lines = [l for l in session_file.read_text().splitlines() if l.strip()]
    store = DatasetStore(dataset_dir)

    for line in lines:
        data = json.loads(line)
        store.append(_label_payload(data["raw"]))

    typer.echo(f"Labeled {len(lines)} events → {store.dataset_dir}")


if __name__ == "__main__":
    app()
