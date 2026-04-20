from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    import psycopg  # type: ignore[import-not-found]
    from psycopg.rows import dict_row  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - covered via runtime fallback test
    psycopg = None
    dict_row = None


def _is_postgres_target(location: str) -> bool:
    return location.startswith("postgresql://") or location.startswith("postgres://")


@dataclass(frozen=True)
class PolicyBundle:
    bundle_version: str
    document: dict[str, Any]
    created_by: str
    change_summary: str
    created_at: str


class _Backend(Protocol):
    backend_kind: str

    def create_bundle(self, document: dict[str, Any], created_by: str, change_summary: str) -> str:
        ...

    def update_bundle_document(self, bundle_version: str, document: dict[str, Any]) -> None:
        ...

    def get_bundle(self, bundle_version: str) -> PolicyBundle:
        ...

    def bind_tenant(self, tenant_id: str, bundle_version: str, rollout_state: str) -> None:
        ...

    def resolve_bundle_for_tenant(self, tenant_id: str) -> PolicyBundle:
        ...

    def record_distribution(self, instance_id: str, tenant_id: str, bundle_version: str, status: str) -> None:
        ...

    def distribution_state(self, instance_id: str, tenant_id: str) -> dict[str, Any] | None:
        ...

    def list_bundles(self, limit: int = 50) -> list[dict[str, Any]]:
        ...

    def list_tenant_bindings(self, limit: int = 100) -> list[dict[str, Any]]:
        ...

    def list_distribution_status(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        ...


class _SQLiteControlPlaneBackend:
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

    def create_bundle(self, document: dict[str, Any], created_by: str, change_summary: str) -> str:
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

    def update_bundle_document(self, bundle_version: str, document: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE policy_bundles SET document_json = ? WHERE bundle_version = ?",
                (json.dumps(document, ensure_ascii=True, sort_keys=True), bundle_version),
            )

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

    def bind_tenant(self, tenant_id: str, bundle_version: str, rollout_state: str) -> None:
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

    def record_distribution(self, instance_id: str, tenant_id: str, bundle_version: str, status: str) -> None:
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

    def list_bundles(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT bundle_version, created_by, change_summary, created_at
                FROM policy_bundles
                ORDER BY created_at DESC, bundle_version DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_tenant_bindings(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT tenant_id, bundle_version, rollout_state, updated_at
                FROM tenant_policy_bindings
                ORDER BY updated_at DESC, tenant_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_distribution_status(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT instance_id, tenant_id, bundle_version, status, updated_at
            FROM distribution_status
        """
        params: list[Any] = []
        if tenant_id is not None:
            query += " WHERE tenant_id = ?"
            params.append(tenant_id)
        query += " ORDER BY updated_at DESC, instance_id ASC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]


class _PostgresControlPlaneBackend:
    backend_kind = "postgresql"

    def __init__(self, dsn: str) -> None:
        if psycopg is None:
            raise RuntimeError(
                "PostgreSQL control plane store requires psycopg. "
                "Install with `pip install 'psycopg[binary]'`."
            )
        self.dsn = dsn
        self._init_db()

    def _connect(self):
        assert psycopg is not None
        assert dict_row is not None
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def _init_db(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policy_bundles (
                        bundle_version TEXT PRIMARY KEY,
                        document_json JSONB NOT NULL,
                        created_by TEXT NOT NULL,
                        change_summary TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tenant_policy_bindings (
                        tenant_id TEXT PRIMARY KEY,
                        bundle_version TEXT NOT NULL,
                        rollout_state TEXT NOT NULL DEFAULT 'active',
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS distribution_status (
                        instance_id TEXT NOT NULL,
                        tenant_id TEXT NOT NULL,
                        bundle_version TEXT NOT NULL,
                        status TEXT NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (instance_id, tenant_id)
                    )
                    """
                )
            conn.commit()

    def create_bundle(self, document: dict[str, Any], created_by: str, change_summary: str) -> str:
        bundle_version = f"bundle_{uuid.uuid4().hex[:12]}"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO policy_bundles (bundle_version, document_json, created_by, change_summary)
                    VALUES (%s, %s::jsonb, %s, %s)
                    """,
                    (
                        bundle_version,
                        json.dumps(document, ensure_ascii=True, sort_keys=True),
                        created_by,
                        change_summary,
                    ),
                )
            conn.commit()
        return bundle_version

    def update_bundle_document(self, bundle_version: str, document: dict[str, Any]) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE policy_bundles SET document_json = %s::jsonb WHERE bundle_version = %s",
                    (json.dumps(document, ensure_ascii=True, sort_keys=True), bundle_version),
                )
            conn.commit()

    def get_bundle(self, bundle_version: str) -> PolicyBundle:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT bundle_version, document_json, created_by, change_summary, created_at
                    FROM policy_bundles
                    WHERE bundle_version = %s
                    """,
                    (bundle_version,),
                )
                row = cur.fetchone()
        if row is None:
            raise KeyError(f"unknown_bundle:{bundle_version}")
        document = row["document_json"]
        if isinstance(document, str):
            document = json.loads(document)
        return PolicyBundle(
            bundle_version=row["bundle_version"],
            document=document,
            created_by=row["created_by"],
            change_summary=row["change_summary"],
            created_at=str(row["created_at"]),
        )

    def bind_tenant(self, tenant_id: str, bundle_version: str, rollout_state: str) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tenant_policy_bindings (tenant_id, bundle_version, rollout_state)
                    VALUES (%s, %s, %s)
                    ON CONFLICT(tenant_id) DO UPDATE SET
                        bundle_version = EXCLUDED.bundle_version,
                        rollout_state = EXCLUDED.rollout_state,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (tenant_id, bundle_version, rollout_state),
                )
            conn.commit()

    def resolve_bundle_for_tenant(self, tenant_id: str) -> PolicyBundle:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT bundle_version FROM tenant_policy_bindings WHERE tenant_id = %s",
                    (tenant_id,),
                )
                row = cur.fetchone()
        if row is None:
            raise KeyError(f"tenant_not_bound:{tenant_id}")
        return self.get_bundle(row["bundle_version"])

    def record_distribution(self, instance_id: str, tenant_id: str, bundle_version: str, status: str) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO distribution_status (instance_id, tenant_id, bundle_version, status)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT(instance_id, tenant_id) DO UPDATE SET
                        bundle_version = EXCLUDED.bundle_version,
                        status = EXCLUDED.status,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (instance_id, tenant_id, bundle_version, status),
                )
            conn.commit()

    def distribution_state(self, instance_id: str, tenant_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT instance_id, tenant_id, bundle_version, status, updated_at
                    FROM distribution_status
                    WHERE instance_id = %s AND tenant_id = %s
                    """,
                    (instance_id, tenant_id),
                )
                row = cur.fetchone()
        if row is None:
            return None
        result = dict(row)
        if "updated_at" in result:
            result["updated_at"] = str(result["updated_at"])
        return result

    def list_bundles(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT bundle_version, created_by, change_summary, created_at
                    FROM policy_bundles
                    ORDER BY created_at DESC, bundle_version DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return [
            {
                "bundle_version": row["bundle_version"],
                "created_by": row["created_by"],
                "change_summary": row["change_summary"],
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    def list_tenant_bindings(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tenant_id, bundle_version, rollout_state, updated_at
                    FROM tenant_policy_bindings
                    ORDER BY updated_at DESC, tenant_id ASC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return [
            {
                "tenant_id": row["tenant_id"],
                "bundle_version": row["bundle_version"],
                "rollout_state": row["rollout_state"],
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def list_distribution_status(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT instance_id, tenant_id, bundle_version, status, updated_at
            FROM distribution_status
        """
        params: list[Any] = []
        if tenant_id is not None:
            query += " WHERE tenant_id = %s"
            params.append(tenant_id)
        query += " ORDER BY updated_at DESC, instance_id ASC LIMIT %s"
        params.append(limit)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, tuple(params))
                rows = cur.fetchall()
        return [
            {
                "instance_id": row["instance_id"],
                "tenant_id": row["tenant_id"],
                "bundle_version": row["bundle_version"],
                "status": row["status"],
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]


class ControlPlaneStore:
    def __init__(self, location: str | Path) -> None:
        self.location = str(location)
        self._backend: _Backend = self._build_backend(self.location)

    @property
    def backend_kind(self) -> str:
        return self._backend.backend_kind

    def _build_backend(self, location: str) -> _Backend:
        if _is_postgres_target(location):
            return _PostgresControlPlaneBackend(location)
        return _SQLiteControlPlaneBackend(location)

    def create_bundle(
        self,
        *,
        document: dict[str, Any],
        created_by: str,
        change_summary: str,
    ) -> str:
        return self._backend.create_bundle(document, created_by, change_summary)

    def update_bundle_document(self, bundle_version: str, document: dict[str, Any]) -> None:
        self._backend.update_bundle_document(bundle_version, document)

    def get_bundle(self, bundle_version: str) -> PolicyBundle:
        return self._backend.get_bundle(bundle_version)

    def bind_tenant(self, tenant_id: str, bundle_version: str, rollout_state: str = "active") -> None:
        self._backend.bind_tenant(tenant_id, bundle_version, rollout_state)

    def resolve_bundle_for_tenant(self, tenant_id: str) -> PolicyBundle:
        return self._backend.resolve_bundle_for_tenant(tenant_id)

    def record_distribution(
        self,
        *,
        instance_id: str,
        tenant_id: str,
        bundle_version: str,
        status: str,
    ) -> None:
        self._backend.record_distribution(instance_id, tenant_id, bundle_version, status)

    def distribution_state(self, instance_id: str, tenant_id: str) -> dict[str, Any] | None:
        return self._backend.distribution_state(instance_id, tenant_id)

    def list_bundles(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._backend.list_bundles(limit)

    def list_tenant_bindings(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._backend.list_tenant_bindings(limit)

    def list_distribution_status(
        self,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._backend.list_distribution_status(limit, tenant_id)


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
        self.control_store.update_bundle_document(bundle_version, payload)
        return {
            "bundle_version": bundle_version,
            "created_by": created_by,
            "change_summary": change_summary,
            "backend_kind": self.control_store.backend_kind,
        }

    def bind_tenant(self, tenant_id: str, bundle_version: str) -> dict[str, Any]:
        self.control_store.bind_tenant(tenant_id, bundle_version)
        return {
            "tenant_id": tenant_id,
            "bundle_version": bundle_version,
            "status": "bound",
            "backend_kind": self.control_store.backend_kind,
        }


class PolicyDistributionService:
    def __init__(
        self,
        control_store: ControlPlaneStore,
        local_policy_store: Any,
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
            "backend_kind": self.control_store.backend_kind,
        }
