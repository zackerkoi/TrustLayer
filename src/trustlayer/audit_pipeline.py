from __future__ import annotations

from dataclasses import replace

from .audit import AuditStore


class AuditForwarder:
    def __init__(
        self,
        source_store: AuditStore,
        central_store: AuditStore,
        *,
        consumer_name: str = "central_audit",
        gateway_instance_id: str = "gw-local",
    ) -> None:
        self.source_store = source_store
        self.central_store = central_store
        self.consumer_name = consumer_name
        self.gateway_instance_id = gateway_instance_id

    def forward_once(self, batch_size: int = 500) -> dict[str, int]:
        last_sequence = self.source_store.get_checkpoint(self.consumer_name)
        events = self.source_store.events_after(last_sequence, limit=batch_size)
        for event in events:
            metadata = dict(event.metadata)
            metadata.setdefault("source_gateway_instance_id", self.gateway_instance_id)
            imported = replace(event, metadata=metadata)
            self.central_store.import_event(imported)
        if events:
            self.source_store.save_checkpoint(self.consumer_name, events[-1].sequence)
        return {
            "forwarded_count": len(events),
            "last_sequence": events[-1].sequence if events else last_sequence,
        }
