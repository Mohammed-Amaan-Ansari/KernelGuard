import json
from pathlib import Path

from .model import SecurityEvent


class EventLogger:
    def __init__(self, log_file="logs/kernelguard.jsonl"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def log(self, event: SecurityEvent):
        with self.log_file.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write(
                json.dumps(event.to_dict())
                + "\n"
            )

    def print_event(self, event: SecurityEvent):
        print(
            f"[{event.event_type}] "
            f"PID={event.pid} "
            f"UID={event.uid} "
            f"COMM={event.comm}"
        )
