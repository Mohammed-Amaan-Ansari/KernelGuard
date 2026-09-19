from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SecurityEvent:
    event_type: str
    pid: int
    uid: int
    comm: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "pid": self.pid,
            "uid": self.uid,
            "comm": self.comm,
            "data": self.data,
        }
