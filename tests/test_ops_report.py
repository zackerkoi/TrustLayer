from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trustlayer.audit import AuditStore
from trustlayer.ops_report import build_ops_report, format_ops_report
from trustlayer.service import DefenseGatewayService


class OpsReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "audit.sqlite3"
        self.service = DefenseGatewayService(AuditStore(self.db_path))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_build_ops_report_aggregates_core_operational_counts(self) -> None:
        self.service.sanitize_ingress(
            tenant_id="demo",
            session_id="sess_ops_ingress",
            source_type="web_page",
            origin="https://example.com",
            content="<html><body><div style='display:none'>hide</div><p>Visible</p></body></html>",
        )
        self.service.check_egress(
            tenant_id="demo",
            session_id="sess_ops_review",
            destination="https://new-destination.example/api",
            destination_type="webhook",
            payload="Contact alice@example.com for the next update.",
        )
        self.service.check_egress(
            tenant_id="demo",
            session_id="sess_ops_block",
            destination="https://block.example/api",
            destination_type="webhook",
            payload="Leak ghp_ABCDEF1234567890",
        )

        report = build_ops_report(self.db_path)

        self.assertEqual(report["summary"]["total_sessions"], 3)
        self.assertEqual(report["summary"]["source_sanitized_count"], 1)
        self.assertEqual(report["summary"]["egress_review_required_count"], 1)
        self.assertEqual(report["summary"]["egress_blocked_count"], 1)
        self.assertIn(("hidden_content", 1), report["top_risk_flags"])
        self.assertIn(("new_domain", 2), report["top_risk_flags"])
        self.assertEqual(report["decision_counts"]["allow_sanitized"], 1)
        self.assertEqual(report["decision_counts"]["review_required"], 1)
        self.assertEqual(report["decision_counts"]["block"], 1)

    def test_format_ops_report_renders_readable_sections(self) -> None:
        report = {
            "summary": {
                "total_events": 8,
                "total_sessions": 2,
                "source_sanitized_count": 1,
                "egress_blocked_count": 1,
                "egress_review_required_count": 1,
                "policy_matched_count": 3,
            },
            "top_risk_flags": [("hidden_content", 1), ("secret_detected", 1)],
            "top_destination_hosts": [("block.example", 1)],
            "event_counts": {"source_sanitized": 1},
            "decision_counts": {"block": 1, "review_required": 1},
        }

        rendered = format_ops_report(report)

        self.assertIn("TrustLayer Ops Report", rendered)
        self.assertIn("total_events=8", rendered)
        self.assertIn("- hidden_content: 1", rendered)
        self.assertIn("- block.example: 1", rendered)
        self.assertIn("- block: 1", rendered)


if __name__ == "__main__":
    unittest.main()
