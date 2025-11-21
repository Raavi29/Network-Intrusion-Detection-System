from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Dict


class EventStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = Lock()
        self.path.touch(exist_ok=True)

    def append(self, event: Dict[str, object]) -> None:
        line = json.dumps(event, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as fp:
            fp.write(line + "\n")

