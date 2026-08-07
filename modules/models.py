from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

@dataclass
class ToolResult:
    tool: str
    identifier: str
    success: bool
    data: dict = field(default_factory=dict)
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class Report:
    identifiers: dict = field(default_factory=dict)
    generated_at: str = ""
    results: list = field(default_factory=list)

    def to_dict(self):
        return {
            "identifiers": self.identifiers,
            "generated_at": self.generated_at,
            "results": [asdict(r) for r in self.results],
        }
