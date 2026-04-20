from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from .audit import AuditEvent

try:
    from kafka import KafkaConsumer, KafkaProducer, TopicPartition  # type: ignore[import-not-found]
    from kafka.structs import OffsetAndMetadata  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    KafkaConsumer = None
    KafkaProducer = None
    TopicPartition = None
    OffsetAndMetadata = None


def _is_kafka_target(location: str) -> bool:
    return location.startswith("kafka://")


@dataclass(frozen=True)
class BusEnvelope:
    ack_token: Any
    event: AuditEvent


class _Backend(Protocol):
    backend_kind: str

    def publish_events(self, events: list[AuditEvent]) -> int:
        ...

    def consume_events(self, consumer_name: str, limit: int = 500) -> list[BusEnvelope]:
        ...

    def acknowledge(self, consumer_name: str, envelopes: list[BusEnvelope]) -> None:
        ...


class _SQLiteAuditBusBackend:
    backend_kind = "sqlite"

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._memory_conn: sqlite3.Connection | None = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(self.db_path)
                self._memory_conn.row_factory = sqlite3.Row
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bus_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bus_checkpoints (
                    consumer_name TEXT PRIMARY KEY,
                    last_message_id INTEGER NOT NULL
                )
                """
            )

    def publish_events(self, events: list[AuditEvent]) -> int:
        if not events:
            return 0
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO bus_messages (event_json) VALUES (?)",
                [(
                    json.dumps(
                        {
                            "sequence": event.sequence,
                            "event_id": event.event_id,
                            "session_id": event.session_id,
                            "request_id": event.request_id,
                            "tenant_id": event.tenant_id,
                            "event_type": event.event_type,
                            "decision": event.decision,
                            "policy_id": event.policy_id,
                            "summary": event.summary,
                            "metadata": event.metadata,
                            "created_at": event.created_at,
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                    ),
                ) for event in events],
            )
        return len(events)

    def consume_events(self, consumer_name: str, limit: int = 500) -> list[BusEnvelope]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_message_id FROM bus_checkpoints WHERE consumer_name = ?",
                (consumer_name,),
            ).fetchone()
            last_message_id = int(row["last_message_id"]) if row else 0
            rows = conn.execute(
                """
                SELECT id, event_json
                FROM bus_messages
                WHERE id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (last_message_id, limit),
            ).fetchall()
        envelopes: list[BusEnvelope] = []
        for row in rows:
            payload = json.loads(row["event_json"])
            envelopes.append(
                BusEnvelope(
                    ack_token=int(row["id"]),
                    event=AuditEvent(
                        sequence=int(payload.get("sequence", 0)),
                        event_id=payload["event_id"],
                        session_id=payload["session_id"],
                        request_id=payload["request_id"],
                        tenant_id=payload["tenant_id"],
                        event_type=payload["event_type"],
                        decision=payload.get("decision"),
                        policy_id=payload.get("policy_id"),
                        summary=payload.get("summary"),
                        metadata=payload.get("metadata", {}),
                        created_at=payload.get("created_at", ""),
                    ),
                )
            )
        return envelopes

    def acknowledge(self, consumer_name: str, envelopes: list[BusEnvelope]) -> None:
        if not envelopes:
            return
        last_message_id = int(envelopes[-1].ack_token)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO bus_checkpoints (consumer_name, last_message_id)
                VALUES (?, ?)
                ON CONFLICT(consumer_name) DO UPDATE SET last_message_id = excluded.last_message_id
                """,
                (consumer_name, last_message_id),
            )


class _KafkaAuditBusBackend:
    backend_kind = "kafka"

    def __init__(self, url: str) -> None:
        if KafkaProducer is None or KafkaConsumer is None or TopicPartition is None or OffsetAndMetadata is None:
            raise RuntimeError(
                "Kafka audit bus requires kafka-python. Install with `pip install '.[kafka]'`."
            )
        parsed = urlparse(url)
        self.brokers = parsed.netloc.split(",")
        self.topic = parsed.path.lstrip("/") or "trustlayer.audit"
        self._producer = KafkaProducer(
            bootstrap_servers=self.brokers,
            value_serializer=lambda value: json.dumps(value, ensure_ascii=True, sort_keys=True).encode("utf-8"),
        )
        self._consumers: dict[str, Any] = {}

    def _consumer(self, consumer_name: str):
        consumer = self._consumers.get(consumer_name)
        if consumer is None:
            consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.brokers,
                group_id=consumer_name,
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
            )
            self._consumers[consumer_name] = consumer
        return consumer

    def publish_events(self, events: list[AuditEvent]) -> int:
        count = 0
        for event in events:
            self._producer.send(
                self.topic,
                {
                    "sequence": event.sequence,
                    "event_id": event.event_id,
                    "session_id": event.session_id,
                    "request_id": event.request_id,
                    "tenant_id": event.tenant_id,
                    "event_type": event.event_type,
                    "decision": event.decision,
                    "policy_id": event.policy_id,
                    "summary": event.summary,
                    "metadata": event.metadata,
                    "created_at": event.created_at,
                },
            )
            count += 1
        self._producer.flush()
        return count

    def consume_events(self, consumer_name: str, limit: int = 500) -> list[BusEnvelope]:
        consumer = self._consumer(consumer_name)
        records = consumer.poll(timeout_ms=500, max_records=limit)
        envelopes: list[BusEnvelope] = []
        for partition, messages in records.items():
            for message in messages:
                payload = message.value
                envelopes.append(
                    BusEnvelope(
                        ack_token=(partition.topic, partition.partition, message.offset + 1),
                        event=AuditEvent(
                            sequence=int(payload.get("sequence", 0)),
                            event_id=payload["event_id"],
                            session_id=payload["session_id"],
                            request_id=payload["request_id"],
                            tenant_id=payload["tenant_id"],
                            event_type=payload["event_type"],
                            decision=payload.get("decision"),
                            policy_id=payload.get("policy_id"),
                            summary=payload.get("summary"),
                            metadata=payload.get("metadata", {}),
                            created_at=payload.get("created_at", ""),
                        ),
                    )
                )
        return envelopes

    def acknowledge(self, consumer_name: str, envelopes: list[BusEnvelope]) -> None:
        if not envelopes:
            return
        consumer = self._consumer(consumer_name)
        offsets: dict[Any, Any] = {}
        for topic, partition, offset in [envelope.ack_token for envelope in envelopes]:
            tp = TopicPartition(topic, partition)
            current = offsets.get(tp)
            if current is None or offset > current.offset:
                offsets[tp] = OffsetAndMetadata(offset, None)
        consumer.commit(offsets=offsets)


class AuditBus:
    def __init__(self, location: str | Path) -> None:
        self.location = str(location)
        self._backend: _Backend = self._build_backend(self.location)

    @property
    def backend_kind(self) -> str:
        return self._backend.backend_kind

    def _build_backend(self, location: str) -> _Backend:
        if _is_kafka_target(location):
            return _KafkaAuditBusBackend(location)
        return _SQLiteAuditBusBackend(location)

    def publish_events(self, events: list[AuditEvent]) -> int:
        return self._backend.publish_events(events)

    def consume_events(self, consumer_name: str, limit: int = 500) -> list[BusEnvelope]:
        return self._backend.consume_events(consumer_name, limit=limit)

    def acknowledge(self, consumer_name: str, envelopes: list[BusEnvelope]) -> None:
        self._backend.acknowledge(consumer_name, envelopes)
