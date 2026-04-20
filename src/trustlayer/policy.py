from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PolicyConfig:
    ingress_oversized_threshold: int = 600
    egress_oversized_threshold: int = 500
    allowed_destination_hosts: set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            ingress_oversized_threshold=payload.get("ingress_oversized_threshold", 600),
            egress_oversized_threshold=payload.get("egress_oversized_threshold", 500),
            allowed_destination_hosts={
                host.lower() for host in payload.get("allowed_destination_hosts", [])
            },
        )
