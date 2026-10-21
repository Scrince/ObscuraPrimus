from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from .runtime import portable_data_dir


@dataclass
class JobRecord:
    id: str
    kind: str
    target: str
    status: str
    created: float
    updated: float
    message: str = ""


class JobQueue:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else portable_data_dir() / "jobs.json"
        self.jobs = self._load()

    def create(self, kind: str, target: str) -> JobRecord:
        now = time.time()
        record = JobRecord(str(uuid.uuid4()), kind, target, "queued", now, now)
        self.jobs.append(record)
        self.save()
        return record

    def update(self, job_id: str, status: str, message: str = "") -> None:
        for job in self.jobs:
            if job.id == job_id:
                job.status = status
                job.message = message
                job.updated = time.time()
                self.save()
                return

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([asdict(job) for job in self.jobs], indent=2)
        fd, temp_name = tempfile.mkstemp(prefix=".jobs.", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _load(self) -> list[JobRecord]:
        if not self.path.exists():
            return []
        try:
            return [JobRecord(**item) for item in json.loads(self.path.read_text(encoding="utf-8"))]
        except Exception:
            return []
