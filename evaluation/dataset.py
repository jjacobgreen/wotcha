"""
Dataset storage for labeled agent events.

LabeledEvent is the unit of the eval dataset: an agent event paired with
Bandit-derived ground truth CWE labels. DatasetStore writes and reads these
as JSONL, one file per session.
"""

from collections.abc import Iterator
from pathlib import Path

from pydantic import BaseModel, Field

from monitor.models import AgentEvent

DATASET_DIR = Path(__file__).parent / "dataset"


class LabeledEvent(BaseModel):
    event: AgentEvent
    # CWE strings from Bandit (e.g. ["CWE-78"]). Empty means Bandit found nothing
    # in scope — not a confirmed clean label, just no positive signal.
    bandit_labels: list[str] = Field(default_factory=list)
    # Original raw hook payload preserved for debugging and future re-labeling.
    raw: dict = Field(default_factory=dict)


class DatasetStore:
    def __init__(self, dataset_dir: Path | None = None):
        self.dataset_dir = dataset_dir or DATASET_DIR
        self.dataset_dir.mkdir(parents=True, exist_ok=True)

    def append(self, labeled: LabeledEvent) -> None:
        path = self.dataset_dir / f"{labeled.event.session_id}.jsonl"
        with path.open("a") as f:
            f.write(labeled.model_dump_json() + "\n")

    def iter_all(self) -> Iterator[LabeledEvent]:
        for path in sorted(self.dataset_dir.glob("*.jsonl")):
            for line in path.read_text().splitlines():
                if line.strip():
                    yield LabeledEvent.model_validate_json(line)
