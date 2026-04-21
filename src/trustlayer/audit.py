from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_id: str
    session_id: str
    request_id: str
    tenant_id: str
    event_type: str
    decision: str | None
    policy_id: str | None
    summary: str | None
    metadata: dict[str, Any]
    created_at: str


class AuditStore:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._memory_conn: sqlite3.Connection | None = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(self.db_path, check_same_thread=False)
                self._memory_conn.row_factory = sqlite3.Row
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    decision TEXT,
                    policy_id TEXT,
                    summary TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS forwarder_checkpoints (
                    consumer_name TEXT PRIMARY KEY,
                    last_sequence INTEGER NOT NULL
                )
                """
            )

    def append_event(
        self,
        *,
        session_id: str,
        request_id: str,
        tenant_id: str,
        event_type: str,
        decision: str | None = None,
        policy_id: str | None = None,
        summary: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        self.import_event(
            AuditEvent(
                sequence=0,
                event_id=event_id,
                session_id=session_id,
                request_id=request_id,
                tenant_id=tenant_id,
                event_type=event_type,
                decision=decision,
                policy_id=policy_id,
                summary=summary,
                metadata=metadata or {},
                created_at="",
            )
        )
        return event_id

    def import_event(self, event: AuditEvent) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events (
                    event_id, session_id, request_id, tenant_id, event_type,
                    decision, policy_id, summary, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(NULLIF(?, ''), CURRENT_TIMESTAMP))
                """,
                (
                    event.event_id,
                    event.session_id,
                    event.request_id,
                    event.tenant_id,
                    event.event_type,
                    event.decision,
                    event.policy_id,
                    event.summary,
                    json.dumps(event.metadata or {}, ensure_ascii=True, sort_keys=True),
                    event.created_at,
                ),
            )

    def timeline(self, session_id: str) -> list[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rowid AS sequence, event_id, session_id, request_id, tenant_id, event_type,
                       decision, policy_id, summary, metadata_json, created_at
                FROM events
                WHERE session_id = ?
                ORDER BY rowid ASC
                """,
                (session_id,),
            ).fetchall()
        return [
            AuditEvent(
                sequence=int(row["sequence"]),
                event_id=row["event_id"],
                session_id=row["session_id"],
                request_id=row["request_id"],
                tenant_id=row["tenant_id"],
                event_type=row["event_type"],
                decision=row["decision"],
                policy_id=row["policy_id"],
                summary=row["summary"],
                metadata=json.loads(row["metadata_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def events_after(self, last_sequence: int, limit: int = 500) -> list[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rowid AS sequence, event_id, session_id, request_id, tenant_id, event_type,
                       decision, policy_id, summary, metadata_json, created_at
                FROM events
                WHERE rowid > ?
                ORDER BY rowid ASC
                LIMIT ?
                """,
                (last_sequence, limit),
            ).fetchall()
        return [
            AuditEvent(
                sequence=int(row["sequence"]),
                event_id=row["event_id"],
                session_id=row["session_id"],
                request_id=row["request_id"],
                tenant_id=row["tenant_id"],
                event_type=row["event_type"],
                decision=row["decision"],
                policy_id=row["policy_id"],
                summary=row["summary"],
                metadata=json.loads(row["metadata_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def get_checkpoint(self, consumer_name: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_sequence FROM forwarder_checkpoints WHERE consumer_name = ?",
                (consumer_name,),
            ).fetchone()
        if row is None:
            return 0
        return int(row["last_sequence"])

    def save_checkpoint(self, consumer_name: str, last_sequence: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO forwarder_checkpoints (consumer_name, last_sequence)
                VALUES (?, ?)
                ON CONFLICT(consumer_name) DO UPDATE SET last_sequence = excluded.last_sequence
                """,
                (consumer_name, last_sequence),
            )

    def has_seen_destination(
        self,
        tenant_id: str,
        destination_host: str,
        event_types: list[str],
    ) -> bool:
        if not event_types:
            return False
        placeholders = ", ".join("?" for _ in event_types)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT metadata_json
                FROM events
                WHERE tenant_id = ?
                  AND event_type IN ({placeholders})
                """,
                (tenant_id, *event_types),
            ).fetchall()
        for row in rows:
            metadata = json.loads(row["metadata_json"])
            if metadata.get("destination_host") == destination_host:
                return True
        return False

    def approval_queue(
        self,
        tenant_id: str,
        *,
        event_types: list[str],
        priority: dict[str, int],
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if not event_types:
            return []
        placeholders = ", ".join("?" for _ in event_types)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT session_id, request_id, event_type, decision, summary, metadata_json, created_at
                FROM events
                WHERE tenant_id = ?
                  AND event_type IN ({placeholders})
                ORDER BY rowid DESC
                """,
                (tenant_id, *event_types),
            ).fetchall()
            resolved_rows = conn.execute(
                """
                SELECT request_id
                FROM events
                WHERE tenant_id = ?
                  AND event_type = 'approval_resolved'
                """,
                (tenant_id,),
            ).fetchall()

        resolved_request_ids = {str(row["request_id"]) for row in resolved_rows}

        items: list[dict[str, Any]] = []
        for row in rows:
            if row["request_id"] in resolved_request_ids:
                continue
            metadata = json.loads(row["metadata_json"])
            items.append(
                {
                    "session_id": row["session_id"],
                    "request_id": row["request_id"],
                    "event_type": row["event_type"],
                    "decision": row["decision"],
                    "summary": row["summary"],
                    "approval_summary": metadata.get("approval_summary"),
                    "approval_request_excerpt": metadata.get("approval_request_excerpt"),
                    "risk_flags": metadata.get("risk_flags", []),
                    "destination_host": metadata.get("destination_host"),
                    "created_at": row["created_at"],
                }
            )

        items.sort(key=lambda item: (priority.get(item["decision"], 99), item["created_at"], item["request_id"]))
        return items[:limit]

    def latest_event_for_request(self, tenant_id: str, request_id: str) -> AuditEvent | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT rowid AS sequence, event_id, session_id, request_id, tenant_id, event_type,
                       decision, policy_id, summary, metadata_json, created_at
                FROM events
                WHERE tenant_id = ?
                  AND request_id = ?
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (tenant_id, request_id),
            ).fetchone()
        if row is None:
            return None
        return AuditEvent(
            sequence=int(row["sequence"]),
            event_id=row["event_id"],
            session_id=row["session_id"],
            request_id=row["request_id"],
            tenant_id=row["tenant_id"],
            event_type=row["event_type"],
            decision=row["decision"],
            policy_id=row["policy_id"],
            summary=row["summary"],
            metadata=json.loads(row["metadata_json"]),
            created_at=row["created_at"],
        )

    def search_events(
        self,
        *,
        tenant_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        event_type: str | None = None,
        destination_host: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        conditions: list[str] = []
        params: list[Any] = []
        if tenant_id:
            conditions.append("tenant_id = ?")
            params.append(tenant_id)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if request_id:
            conditions.append("request_id = ?")
            params.append(request_id)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)

        query = """
            SELECT rowid AS sequence, event_id, session_id, request_id, tenant_id, event_type,
                   decision, policy_id, summary, metadata_json, created_at
            FROM events
        """
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY rowid DESC LIMIT ?"
        params.append(limit * 5 if destination_host else limit)

        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        items: list[AuditEvent] = []
        for row in rows:
            metadata = json.loads(row["metadata_json"])
            if destination_host and metadata.get("destination_host") != destination_host:
                continue
            items.append(
                AuditEvent(
                    sequence=int(row["sequence"]),
                    event_id=row["event_id"],
                    session_id=row["session_id"],
                    request_id=row["request_id"],
                    tenant_id=row["tenant_id"],
                    event_type=row["event_type"],
                    decision=row["decision"],
                    policy_id=row["policy_id"],
                    summary=row["summary"],
                    metadata=metadata,
                    created_at=row["created_at"],
                )
            )
            if len(items) >= limit:
                break
        return items

    def dashboard_stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(DISTINCT session_id) AS total_sessions
                FROM events
                """
            ).fetchone()
            decision_rows = conn.execute(
                """
                SELECT decision, COUNT(*) AS count
                FROM events
                WHERE decision IS NOT NULL
                GROUP BY decision
                """
            ).fetchall()
            event_rows = conn.execute(
                """
                SELECT event_type, COUNT(*) AS count
                FROM events
                GROUP BY event_type
                """
            ).fetchall()

        decisions = {
            str(row["decision"]): int(row["count"])
            for row in decision_rows
            if row["decision"] is not None
        }
        event_counts = {str(row["event_type"]): int(row["count"]) for row in event_rows}
        return {
            "total_events": int(totals["total_events"]) if totals else 0,
            "total_sessions": int(totals["total_sessions"]) if totals else 0,
            "decision_counts": decisions,
            "event_counts": event_counts,
        }
