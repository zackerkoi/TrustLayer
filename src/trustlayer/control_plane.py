from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import PolicyStore


@dataclass(frozen=True)
class PolicyBundle:
    bundle_version: str
    document: dict[str, Any]
    created_by: str
    change_summary: str
    created_at: str


class ControlPlaneStore:
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
                CREATE TABLE IF NOT EXISTS policy_bundles (
                    bundle_version TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    change_summary TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_policy_bindings (
                    tenant_id TEXT PRIMARY KEY,
                    bundle_version TEXT NOT NULL,
                    rollout_state TEXT NOT NULL DEFAULT 'active',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS distribution_status (
                    instance_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    bundle_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (instance_id, tenant_id)
                )
                """
            )

    def create_bundle(
        self,
        *,
        document: dict[str, Any],
        created_by: str,
        change_summary: str,
    ) -> str:
        bundle_version = f"bundle_{uuid.uuid4().hex[:12]}"
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO policy_bundles (bundle_version, document_json, created_by, change_summary)
                VALUES (?, ?, ?, ?)
                """,
                (
                    bundle_version,
                    json.dumps(document, ensure_ascii=True, sort_keys=True),
                    created_by,
                    change_summary,
                ),
            )
        return bundle_version

    def get_bundle(self, bundle_version: str) -> PolicyBundle:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT bundle_version, document_json, created_by, change_summary, created_at
                FROM policy_bundles
                WHERE bundle_version = ?
                """,
                (bundle_version,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown_bundle:{bundle_version}")
        return PolicyBundle(
            bundle_version=row["bundle_version"],
            document=json.loads(row["document_json"]),
            created_by=row["created_by"],
            change_summary=row["change_summary"],
            created_at=row["created_at"],
        )

    def bind_tenant(self, tenant_id: str, bundle_version: str, rollout_state: str = "active") -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tenant_policy_bindings (tenant_id, bundle_version, rollout_state)
                VALUES (?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    bundle_version = excluded.bundle_version,
                    rollout_state = excluded.rollout_state,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (tenant_id, bundle_version, rollout_state),
            )

    def resolve_bundle_for_tenant(self, tenant_id: str) -> PolicyBundle:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT bundle_version FROM tenant_policy_bindings WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"tenant_not_bound:{tenant_id}")
        return self.get_bundle(row["bundle_version"])

    def record_distribution(
        self,
        *,
        instance_id: str,
        tenant_id: str,
        bundle_version: str,
        status: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO distribution_status (instance_id, tenant_id, bundle_version, status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(instance_id, tenant_id) DO UPDATE SET
                    bundle_version = excluded.bundle_version,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (instance_id, tenant_id, bundle_version, status),
            )

    def distribution_state(self, instance_id: str, tenant_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT instance_id, tenant_id, bundle_version, status, updated_at
                FROM distribution_status
                WHERE instance_id = ? AND tenant_id = ?
                """,
                (instance_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        return dict(row)


class RuleManagementService:
    def __init__(self, control_store: ControlPlaneStore) -> None:
        self.control_store = control_store

    def publish_bundle(
        self,
        *,
        document: dict[str, Any],
        created_by: str,
        change_summary: str,
    ) -> dict[str, Any]:
        payload = json.loads(json.dumps(document))
        settings = payload.setdefault("settings", {})
        bundle_version = self.control_store.create_bundle(
            document=payload,
            created_by=created_by,
            change_summary=change_summary,
        )
        settings["policy_bundle_version"] = bundle_version
        # Persist again with bundle version embedded.
        with self.control_store._connect() as conn:
            conn.execute(
                "UPDATE policy_bundles SET document_json = ? WHERE bundle_version = ?",
                (json.dumps(payload, ensure_ascii=True, sort_keys=True), bundle_version),
            )
        return {
            "bundle_version": bundle_version,
            "created_by": created_by,
            "change_summary": change_summary,
        }

    def bind_tenant(self, tenant_id: str, bundle_version: str) -> dict[str, Any]:
        self.control_store.bind_tenant(tenant_id, bundle_version)
        return {"tenant_id": tenant_id, "bundle_version": bundle_version, "status": "bound"}


class PolicyDistributionService:
    def __init__(
        self,
        control_store: ControlPlaneStore,
        local_policy_store: PolicyStore,
    ) -> None:
        self.control_store = control_store
        self.local_policy_store = local_policy_store

    def sync_tenant_bundle(self, *, tenant_id: str, instance_id: str) -> dict[str, Any]:
        bundle = self.control_store.resolve_bundle_for_tenant(tenant_id)
        local_snapshot = self.local_policy_store.snapshot()
        local_version = str(local_snapshot.setting("policy_bundle_version", ""))
        updated = local_version != bundle.bundle_version
        if updated:
            self.local_policy_store.import_document(bundle.document)
        self.control_store.record_distribution(
            instance_id=instance_id,
            tenant_id=tenant_id,
            bundle_version=bundle.bundle_version,
            status="applied" if updated else "unchanged",
        )
        return {
            "tenant_id": tenant_id,
            "instance_id": instance_id,
            "bundle_version": bundle.bundle_version,
            "updated": updated,
            "local_version_before": local_version or None,
            "local_version_after": bundle.bundle_version,
        }
