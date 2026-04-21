from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trustlayer.audit import AuditStore
from trustlayer.scenarios import (
    run_approval_assistant_scenario,
    run_approval_fatigue_scenario,
    run_approval_social_engineering_scenario,
    run_false_safe_wording_scenario,
    run_batch_export_scenario,
    run_document_export_scenario,
    run_email_thread_forward_scenario,
    run_hidden_web_supplier_scenario,
    run_im_collaboration_scenario,
    run_mcp_secret_exfil_scenario,
    run_rag_memory_sync_scenario,
    run_slow_drift_export_scenario,
    run_ticket_env_snapshot_scenario,
)
from trustlayer.service import DefenseGatewayService


class RealisticScenarioComparisonTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = DefenseGatewayService(AuditStore(Path(self.temp_dir.name) / "audit.sqlite3"))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_hidden_supplier_webpage_exfiltration_is_neutralized_by_ingress_sanitization(self) -> None:
        baseline, controlled = run_hidden_web_supplier_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_hidden_web",
        )

        self.assertTrue(baseline.attempted_egress)
        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("attacker-controlled webhook", baseline.harm)

        self.assertFalse(controlled.attempted_egress)
        self.assertIsNone(controlled.egress_decision)
        self.assertIn("hidden instructions never reach the agent", controlled.harm)
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertIn("source_sanitized", event_types)
        sanitized_event = next(
            event for event in controlled.audit_events if event["event_type"] == "source_sanitized"
        )
        self.assertIn("hidden_content", sanitized_event["metadata"]["risk_flags"])

    def test_mcp_secret_exfiltration_is_blocked_and_audited(self) -> None:
        baseline, controlled = run_mcp_secret_exfil_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_mcp_secret",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("Secret token is exfiltrated", baseline.harm)

        self.assertEqual(controlled.egress_decision, "block")
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertIn("source_sanitized", event_types)
        self.assertIn("egress_blocked", event_types)
        self.assertIn("policy_matched", event_types)

    def test_rag_memory_sync_is_held_for_review_with_visible_signals(self) -> None:
        baseline, controlled = run_rag_memory_sync_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_rag_memory",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("PII reaches a new external endpoint", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertIn("destination_new_domain", event_types)
        self.assertIn("egress_review_required", event_types)
        scanned_event = next(
            event for event in controlled.audit_events if event["event_type"] == "egress_scanned"
        )
        self.assertIn("pii_detected", scanned_event["metadata"]["risk_flags"])
        self.assertIn("new_domain", scanned_event["metadata"]["risk_flags"])

    def test_hidden_email_footer_forwarding_is_neutralized_before_outbound_mail(self) -> None:
        baseline, controlled = run_email_thread_forward_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_email_forward",
        )

        self.assertTrue(baseline.attempted_egress)
        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("attacker-controlled inbox", baseline.harm)

        self.assertFalse(controlled.attempted_egress)
        self.assertIsNone(controlled.egress_decision)
        self.assertIn("malicious footer never reaches the agent", controlled.harm)
        sanitized_event = next(
            event for event in controlled.audit_events if event["event_type"] == "source_sanitized"
        )
        self.assertIn("hidden_content", sanitized_event["metadata"]["risk_flags"])

    def test_document_export_to_new_share_endpoint_is_held_for_review(self) -> None:
        baseline, controlled = run_document_export_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_document_export",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("unapproved share endpoint", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertIn("destination_new_domain", event_types)
        self.assertIn("egress_review_required", event_types)
        scanned_event = next(
            event for event in controlled.audit_events if event["event_type"] == "egress_scanned"
        )
        self.assertIn("payload_oversized", scanned_event["metadata"]["risk_flags"])
        self.assertIn("new_domain", scanned_event["metadata"]["risk_flags"])

    def test_ticket_env_snapshot_secret_leak_is_hard_blocked(self) -> None:
        baseline, controlled = run_ticket_env_snapshot_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_ticket_snapshot",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("Secrets embedded in the environment snapshot", baseline.harm)

        self.assertEqual(controlled.egress_decision, "block")
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertIn("egress_blocked", event_types)
        self.assertIn("source_sanitized", event_types)

    def test_im_collaboration_roster_post_is_held_for_review(self) -> None:
        baseline, controlled = run_im_collaboration_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_im_collab",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("external Slack-style webhook", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertIn("source_sanitized", event_types)
        self.assertIn("egress_review_required", event_types)
        scanned_event = next(
            event for event in controlled.audit_events if event["event_type"] == "egress_scanned"
        )
        self.assertIn("pii_detected", scanned_event["metadata"]["risk_flags"])
        self.assertIn("new_domain", scanned_event["metadata"]["risk_flags"])

    def test_batch_export_to_known_collector_is_still_reviewed_for_large_pii_payload(self) -> None:
        baseline, controlled = run_batch_export_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_batch_export",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("high-volume PII export", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        scanned_events = [
            event for event in controlled.audit_events if event["event_type"] == "egress_scanned"
        ]
        self.assertGreaterEqual(len(scanned_events), 2)
        final_scanned = scanned_events[-1]
        self.assertIn("pii_detected", final_scanned["metadata"]["risk_flags"])
        self.assertIn("payload_oversized", final_scanned["metadata"]["risk_flags"])
        self.assertNotIn("new_domain", final_scanned["metadata"]["risk_flags"])

    def test_slow_drift_workflow_leaves_a_visible_path_before_final_review_gate(self) -> None:
        baseline, controlled = run_slow_drift_export_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_slow_drift",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("drifts gradually", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertEqual(event_types.count("source_sanitized"), 3)
        self.assertIn("destination_new_domain", event_types)
        self.assertIn("egress_review_required", event_types)
        scanned_event = next(
            event for event in reversed(controlled.audit_events)
            if event["event_type"] == "egress_scanned"
        )
        self.assertIn("pii_detected", scanned_event["metadata"]["risk_flags"])
        self.assertIn("new_domain", scanned_event["metadata"]["risk_flags"])

    def test_approval_assistant_turns_a_noisy_request_into_a_clear_review_signal(self) -> None:
        baseline, controlled = run_approval_assistant_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_approval_assistant",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("looks operationally routine", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        self.assertIn("new destination", controlled.summary.lower())
        self.assertIn("pii", controlled.summary.lower())
        self.assertIn("egress_review_required", [event["event_type"] for event in controlled.audit_events])

    def test_approval_fatigue_scenario_highlights_the_final_risky_request(self) -> None:
        baseline, controlled = run_approval_fatigue_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_approval_fatigue",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("approves the final malicious export", baseline.harm)

        self.assertEqual(controlled.egress_decision, "review_required")
        self.assertIn("new destination", controlled.summary.lower())
        self.assertIn("pii", controlled.summary.lower())
        event_types = [event["event_type"] for event in controlled.audit_events]
        self.assertGreaterEqual(event_types.count("egress_review_required"), 2)

    def test_approval_social_engineering_summary_overrides_reassuring_request_wording(self) -> None:
        baseline, controlled = run_approval_social_engineering_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_approval_social",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("already approved", baseline.harm.lower())

        self.assertEqual(controlled.egress_decision, "review_required")
        self.assertIn("new destination", controlled.summary.lower())
        self.assertIn("pii", controlled.summary.lower())
        self.assertNotIn("already approved", controlled.summary.lower())
        self.assertNotIn("low risk", controlled.summary.lower())
        self.assertTrue(
            any(
                "already approved" in str(event["metadata"].get("approval_request_excerpt", "")).lower()
                for event in controlled.audit_events
            )
        )

    def test_false_safe_wording_cannot_mask_secret_block_reason(self) -> None:
        baseline, controlled = run_false_safe_wording_scenario(
            service=self.service,
            tenant_id="demo",
            session_id="sess_false_safe",
        )

        self.assertEqual(baseline.egress_decision, "allow")
        self.assertIn("routine maintenance", baseline.harm.lower())

        self.assertEqual(controlled.egress_decision, "block")
        self.assertIn("secret", controlled.summary.lower())
        self.assertNotIn("safe to send", controlled.summary.lower())
        self.assertNotIn("routine maintenance", controlled.summary.lower())
        self.assertTrue(
            any(
                "safe to send" in str(event["metadata"].get("approval_request_excerpt", "")).lower()
                for event in controlled.audit_events
            )
        )


if __name__ == "__main__":
    unittest.main()
