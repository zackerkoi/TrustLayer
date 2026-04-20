from __future__ import annotations

from dataclasses import replace

from .audit import AuditStore
from .audit_bus import AuditBus


class AuditForwarder:
    def __init__(
        self,
        source_store: AuditStore,
        audit_bus: AuditBus,
        *,
        checkpoint_name: str = "audit_bus_forwarder",
        gateway_instance_id: str = "gw-local",
    ) -> None:
        self.source_store = source_store
        self.audit_bus = audit_bus
        self.checkpoint_name = checkpoint_name
        self.gateway_instance_id = gateway_instance_id

    def forward_once(self, batch_size: int = 500) -> dict[str, int]:
        last_sequence = self.source_store.get_checkpoint(self.checkpoint_name)
        events = self.source_store.events_after(last_sequence, limit=batch_size)
        outbound = []
        for event in events:
            metadata = dict(event.metadata)
            metadata.setdefault("source_gateway_instance_id", self.gateway_instance_id)
            outbound.append(replace(event, metadata=metadata))
        published_count = self.audit_bus.publish_events(outbound)
        if events:
            self.source_store.save_checkpoint(self.checkpoint_name, events[-1].sequence)
        return {
            "forwarded_count": published_count,
            "last_sequence": events[-1].sequence if events else last_sequence,
        }


class AuditConsumer:
    def __init__(
        self,
        audit_bus: AuditBus,
        central_store: AuditStore,
        *,
        consumer_name: str = "central_audit_consumer",
    ) -> None:
        self.audit_bus = audit_bus
        self.central_store = central_store
        self.consumer_name = consumer_name

    def consume_once(self, batch_size: int = 500) -> dict[str, int]:
        envelopes = self.audit_bus.consume_events(self.consumer_name, limit=batch_size)
        for envelope in envelopes:
            self.central_store.import_event(envelope.event)
        self.audit_bus.acknowledge(self.consumer_name, envelopes)
        return {
            "consumed_count": len(envelopes),
        }
