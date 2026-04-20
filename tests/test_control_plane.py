from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from trustlayer.app import create_app
from trustlayer.audit import AuditStore
from trustlayer.audit_pipeline import AuditForwarder
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


class ControlPlaneIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        base = Path(self.temp_dir.name)
        self.local_db = base / "local.sqlite3"
        self.control_db = base / "control.sqlite3"
        self.central_db = base / "central.sqlite3"
        self.local_audit = AuditStore(self.local_db)
        self.local_policy = PolicyStore(self.local_db)
        self.central_audit = AuditStore(self.central_db)
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
            self.central_audit,
            gateway_instance_id="gw-test-1",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_publish_bind_and_sync_updates_local_policy_bundle(self) -> None:
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

    def test_audit_forwarder_moves_local_events_to_central_store(self) -> None:
        self.service.check_egress(
            tenant_id="tenant-b",
            session_id="sess_forward",
            destination="https://review.example/api",
            destination_type="webhook",
            payload="contact alice@example.com",
        )

        result = self.forwarder.forward_once()
        self.assertGreater(result["forwarded_count"], 0)
        self.assertGreater(self.local_audit.get_checkpoint("central_audit"), 0)

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


if __name__ == "__main__":
    unittest.main()
