from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from trustlayer.app import create_app
from trustlayer.audit import AuditStore
from trustlayer.audit_bus import AuditBus
from trustlayer.audit_pipeline import AuditConsumer, AuditForwarder
from trustlayer import control_plane
from trustlayer.control_plane import ControlPlaneStore, PolicyDistributionService, RuleManagementService
from trustlayer.policy import PolicyStore
from trustlayer.service import DefenseGatewayService


def call_wsgi(app, method: str, path: str, body: dict | None = None):
    payload = json.dumps(body or {}).encode("utf-8")
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
    }
    response = b"".join(app(environ, start_response))
    return captured["status"], json.loads(response.decode("utf-8"))


def call_wsgi_text(app, method: str, path: str):
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": path.partition("?")[2],
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(b""),
    }
    if "?" in path:
        environ["PATH_INFO"] = path.partition("?")[0]
    response = b"".join(app(environ, start_response))
    return captured["status"], response.decode("utf-8")


class ControlPlaneIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        base = Path(self.temp_dir.name)
        self.local_db = base / "local.sqlite3"
        self.control_db = base / "control.sqlite3"
        self.central_db = base / "central.sqlite3"
        self.bus_db = base / "audit-bus.sqlite3"
        self.local_audit = AuditStore(self.local_db)
        self.local_policy = PolicyStore(self.local_db)
        self.central_audit = AuditStore(self.central_db)
        self.audit_bus = AuditBus(self.bus_db)
        self.service = DefenseGatewayService(
            self.local_audit,
            policy_store=self.local_policy,
            gateway_instance_id="gw-test-1",
            gateway_version="1.2.3",
        )
        self.control_store = ControlPlaneStore(self.control_db)
        self.rule_management = RuleManagementService(self.control_store)
        self.distribution = PolicyDistributionService(self.control_store, self.local_policy)
        self.forwarder = AuditForwarder(
            self.local_audit,
            self.audit_bus,
            gateway_instance_id="gw-test-1",
        )
        self.consumer = AuditConsumer(self.audit_bus, self.central_audit)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_publish_bind_and_sync_updates_local_policy_bundle(self) -> None:
        self.assertEqual(self.control_store.backend_kind, "sqlite")
        config_path = Path(__file__).resolve().parents[1] / "config" / "policy.example.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["settings"]["allowed_destination_hosts"] = ["post-sync.example"]

        published = self.rule_management.publish_bundle(
            document=document,
            created_by="security@example.com",
            change_summary="Allow a controlled rollout host.",
        )
        self.rule_management.bind_tenant("tenant-a", published["bundle_version"])

        before = self.local_policy.snapshot()
        self.assertNotEqual(before.setting("policy_bundle_version"), published["bundle_version"])
        self.assertNotIn("post-sync.example", before.setting("allowed_destination_hosts", []))

        sync_result = self.distribution.sync_tenant_bundle(
            tenant_id="tenant-a",
            instance_id="gw-test-1",
        )

        after = self.local_policy.snapshot()
        self.assertTrue(sync_result["updated"])
        self.assertEqual(after.setting("policy_bundle_version"), published["bundle_version"])
        self.assertIn("post-sync.example", after.setting("allowed_destination_hosts", []))

        decision = self.service.check_egress(
            tenant_id="tenant-a",
            session_id="sess_sync_allow",
            destination="https://post-sync.example/api",
            destination_type="webhook",
            payload="benign body",
        )
        self.assertEqual(decision.decision, "allow")

        distribution_state = self.control_store.distribution_state("gw-test-1", "tenant-a")
        self.assertEqual(distribution_state["bundle_version"], published["bundle_version"])

    def test_audit_forwarder_moves_local_events_through_bus_to_central_store(self) -> None:
        self.service.check_egress(
            tenant_id="tenant-b",
            session_id="sess_forward",
            destination="https://review.example/api",
            destination_type="webhook",
            payload="contact alice@example.com",
        )

        forwarded = self.forwarder.forward_once()
        consumed = self.consumer.consume_once()
        self.assertGreater(forwarded["forwarded_count"], 0)
        self.assertGreater(consumed["consumed_count"], 0)
        self.assertGreater(self.local_audit.get_checkpoint("audit_bus_forwarder"), 0)

        central_timeline = self.central_audit.timeline("sess_forward")
        self.assertTrue(central_timeline)
        self.assertEqual(central_timeline[0].metadata["gateway_instance_id"], "gw-test-1")
        self.assertEqual(central_timeline[0].metadata["source_gateway_instance_id"], "gw-test-1")
        self.assertEqual(central_timeline[0].metadata["policy_bundle_version"], "default-bundle")

    def test_control_plane_http_endpoints_publish_bind_and_sync(self) -> None:
        app = create_app(
            self.service,
            rule_management=self.rule_management,
            policy_distribution=self.distribution,
            control_store=self.control_store,
            audit_forwarder=self.forwarder,
            audit_consumer=self.consumer,
        )
        config_path = Path(__file__).resolve().parents[1] / "config" / "policy.example.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["settings"]["allowed_destination_hosts"] = ["api.rollout.example"]

        _, published = call_wsgi(
            app,
            "POST",
            "/v1/control/policies/publish",
            {
                "created_by": "secops@example.com",
                "change_summary": "Rollout host binding.",
                "document": document,
            },
        )
        _, binding = call_wsgi(
            app,
            "POST",
            "/v1/control/tenants/bind",
            {
                "tenant_id": "tenant-http",
                "bundle_version": published["bundle_version"],
            },
        )
        _, synced = call_wsgi(
            app,
            "POST",
            "/v1/control/distribution/sync",
            {
                "tenant_id": "tenant-http",
                "instance_id": "gw-test-1",
            },
        )

        self.assertEqual(binding["status"], "bound")
        self.assertEqual(synced["bundle_version"], published["bundle_version"])
        self.assertTrue(synced["updated"])

    def test_control_plane_http_endpoints_forward_and_consume_audit_events(self) -> None:
        app = create_app(
            self.service,
            rule_management=self.rule_management,
            policy_distribution=self.distribution,
            control_store=self.control_store,
            audit_forwarder=self.forwarder,
            audit_consumer=self.consumer,
        )
        self.service.check_egress(
            tenant_id="tenant-audit-http",
            session_id="sess_audit_http",
            destination="https://audit-http.example/api",
            destination_type="webhook",
            payload="contact alice@example.com",
        )

        _, forward = call_wsgi(app, "POST", "/v1/control/audit/forward", {"batch_size": 100})
        _, consume = call_wsgi(app, "POST", "/v1/control/audit/consume", {"batch_size": 100})

        self.assertGreater(forward["forwarded_count"], 0)
        self.assertGreater(consume["consumed_count"], 0)
        self.assertTrue(self.central_audit.timeline("sess_audit_http"))

    def test_console_dashboard_page_renders_live_stats(self) -> None:
        app = create_app(
            self.service,
            rule_management=self.rule_management,
            policy_distribution=self.distribution,
            control_store=self.control_store,
            audit_forwarder=self.forwarder,
            audit_consumer=self.consumer,
        )
        config_path = Path(__file__).resolve().parents[1] / "config" / "policy.example.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        published = self.rule_management.publish_bundle(
            document=document,
            created_by="secops@example.com",
            change_summary="Dashboard seed bundle.",
        )
        self.rule_management.bind_tenant("tenant-dashboard", published["bundle_version"])
        self.distribution.sync_tenant_bundle(tenant_id="tenant-dashboard", instance_id="gw-test-1")
        self.service.check_egress(
            tenant_id="tenant-dashboard",
            session_id="sess_dashboard",
            destination="https://review.example/api",
            destination_type="webhook",
            payload="contact alice@example.com",
        )

        status, html = call_wsgi_text(app, "GET", "/console/dashboard")
        self.assertEqual(status, "200 OK")
        self.assertIn("TrustLayer Control Console", html)
        self.assertIn("Review Required", html)
        self.assertIn("tenant-dashboard", html)
        self.assertIn("gw-test-1", html)

    def test_console_policies_page_lists_bundles_and_bindings(self) -> None:
        app = create_app(
            self.service,
            rule_management=self.rule_management,
            policy_distribution=self.distribution,
            control_store=self.control_store,
        )
        config_path = Path(__file__).resolve().parents[1] / "config" / "policy.example.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        published = self.rule_management.publish_bundle(
            document=document,
            created_by="policy-admin@example.com",
            change_summary="Policy page seed bundle.",
        )
        self.rule_management.bind_tenant("tenant-policy", published["bundle_version"])

        status, html = call_wsgi_text(app, "GET", "/console/policies")
        self.assertEqual(status, "200 OK")
        self.assertIn("Policy Bundles", html)
        self.assertIn("policy-admin@example.com", html)
        self.assertIn("tenant-policy", html)
        self.assertIn(published["bundle_version"], html)

    def test_console_distribution_page_filters_by_tenant(self) -> None:
        app = create_app(
            self.service,
            rule_management=self.rule_management,
            policy_distribution=self.distribution,
            control_store=self.control_store,
        )
        config_path = Path(__file__).resolve().parents[1] / "config" / "policy.example.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        published = self.rule_management.publish_bundle(
            document=document,
            created_by="dist-admin@example.com",
            change_summary="Distribution page seed bundle.",
        )
        self.rule_management.bind_tenant("tenant-dist-a", published["bundle_version"])
        self.rule_management.bind_tenant("tenant-dist-b", published["bundle_version"])
        self.distribution.sync_tenant_bundle(tenant_id="tenant-dist-a", instance_id="gw-test-1")
        self.distribution.sync_tenant_bundle(tenant_id="tenant-dist-b", instance_id="gw-test-2")

        status, html = call_wsgi_text(app, "GET", "/console/distribution?tenant_id=tenant-dist-a")
        self.assertEqual(status, "200 OK")
        self.assertIn("Distribution", html)
        self.assertIn("tenant-dist-a", html)
        self.assertIn("gw-test-1", html)
        self.assertNotIn("tenant-dist-b</td>", html)

    def test_console_audit_page_renders_search_results(self) -> None:
        app = create_app(
            self.service,
            rule_management=self.rule_management,
            policy_distribution=self.distribution,
            control_store=self.control_store,
        )
        self.service.check_egress(
            tenant_id="tenant-audit-search",
            session_id="sess_audit_search",
            destination="https://audit-search.example/api",
            destination_type="webhook",
            payload="token AKIAIOSFODNN7EXAMPLE",
        )

        status, html = call_wsgi_text(
            app,
            "GET",
            "/console/audit?tenant_id=tenant-audit-search&destination_host=audit-search.example",
        )
        self.assertEqual(status, "200 OK")
        self.assertIn("Audit Search", html)
        self.assertIn("tenant-audit-search", html)
        self.assertIn("audit-search.example", html)
        self.assertIn("secret_detected", html)

    def test_postgres_control_plane_target_requires_psycopg_or_uses_postgres_backend(self) -> None:
        dsn = "postgresql://trustlayer:secret@localhost:5432/trustlayer"
        if control_plane.psycopg is None:
            with self.assertRaises(RuntimeError):
                ControlPlaneStore(dsn)
            return

        class FakePostgresBackend:
            backend_kind = "postgresql"

            def __init__(self, location: str) -> None:
                self.location = location

            def create_bundle(self, document, created_by, change_summary):
                return "bundle_fake"

            def update_bundle_document(self, bundle_version, document):
                return None

            def get_bundle(self, bundle_version):
                raise AssertionError("not used")

            def bind_tenant(self, tenant_id, bundle_version, rollout_state):
                return None

            def resolve_bundle_for_tenant(self, tenant_id):
                raise AssertionError("not used")

            def record_distribution(self, instance_id, tenant_id, bundle_version, status):
                return None

            def distribution_state(self, instance_id, tenant_id):
                return None

        original = control_plane._PostgresControlPlaneBackend
        control_plane._PostgresControlPlaneBackend = FakePostgresBackend
        try:
            store = ControlPlaneStore(dsn)
        finally:
            control_plane._PostgresControlPlaneBackend = original

        self.assertEqual(store.backend_kind, "postgresql")


@unittest.skipUnless(
    os.environ.get("TRUSTLAYER_TEST_POSTGRES_DSN"),
    "Set TRUSTLAYER_TEST_POSTGRES_DSN to run live PostgreSQL control plane tests.",
)
class ControlPlanePostgresIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        if control_plane.psycopg is None:
            self.skipTest("psycopg is not installed")
        dsn = os.environ["TRUSTLAYER_TEST_POSTGRES_DSN"]
        self.temp_dir = tempfile.TemporaryDirectory()
        base = Path(self.temp_dir.name)
        self.local_db = base / "local.sqlite3"
        self.local_audit = AuditStore(self.local_db)
        self.local_policy = PolicyStore(self.local_db)
        self.control_store = ControlPlaneStore(dsn)
        self.rule_management = RuleManagementService(self.control_store)
        self.distribution = PolicyDistributionService(self.control_store, self.local_policy)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_live_postgres_publish_bind_and_sync(self) -> None:
        config_path = Path(__file__).resolve().parents[1] / "config" / "policy.example.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["settings"]["allowed_destination_hosts"] = ["postgres-live.example"]

        published = self.rule_management.publish_bundle(
            document=document,
            created_by="postgres-test@example.com",
            change_summary="Live PostgreSQL integration test.",
        )
        tenant_id = f"tenant-pg-{published['bundle_version'][-6:]}"
        instance_id = f"gw-pg-{published['bundle_version'][-6:]}"

        self.rule_management.bind_tenant(tenant_id, published["bundle_version"])
        synced = self.distribution.sync_tenant_bundle(
            tenant_id=tenant_id,
            instance_id=instance_id,
        )

        snapshot = self.local_policy.snapshot()
        self.assertEqual(self.control_store.backend_kind, "postgresql")
        self.assertEqual(synced["bundle_version"], published["bundle_version"])
        self.assertEqual(snapshot.setting("policy_bundle_version"), published["bundle_version"])
        self.assertIn("postgres-live.example", snapshot.setting("allowed_destination_hosts", []))

        distribution_state = self.control_store.distribution_state(instance_id, tenant_id)
        self.assertEqual(distribution_state["bundle_version"], published["bundle_version"])


if __name__ == "__main__":
    unittest.main()
