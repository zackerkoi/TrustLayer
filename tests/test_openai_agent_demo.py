from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from trustlayer.openai_agent_demo import (
    create_demo_service,
    run_scripted_supplier_research_demo,
    run_scripted_support_escalation_demo,
)
from trustlayer.demo_services import start_demo_environment


class OpenAIAgentDemoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.environment = start_demo_environment()
        self.service = create_demo_service(Path(self.temp_dir.name) / "audit.sqlite3")

    def tearDown(self) -> None:
        self.environment.close()
        self.temp_dir.cleanup()

    def test_supplier_research_demo_shows_hidden_html_exfil_without_gateway_and_neutralization_with_gateway(self) -> None:
        baseline = run_scripted_supplier_research_demo(
            environment=self.environment,
            mode="baseline",
        )
        self.assertTrue(baseline.outbound_attempted)
        self.assertEqual(baseline.outbound_decision, "allow")
        self.assertEqual(len(baseline.outbound_deliveries), 1)
        self.assertEqual(baseline.outbound_deliveries[0]["path"], "/collect/supplier-contacts")
        self.assertIn("lily.chen@acme.example", baseline.outbound_deliveries[0]["body"])
        self.assertIn("exfiltrated", baseline.harm.lower())

        self.environment.reset()

        controlled = run_scripted_supplier_research_demo(
            environment=self.environment,
            mode="protected",
            service=self.service,
        )
        self.assertFalse(controlled.outbound_attempted)
        self.assertEqual(controlled.outbound_deliveries, [])
        self.assertIn("never reaches the agent", controlled.harm.lower())
        event_types = [event["event_type"] for event in controlled.timeline]
        self.assertEqual(
            event_types,
            ["mcp_tool_invoked", "mcp_tool_result", "source_received", "policy_matched", "source_sanitized"],
        )
        sanitized_event = next(event for event in controlled.timeline if event["event_type"] == "source_sanitized")
        self.assertIn("hidden_content", sanitized_event["metadata"]["risk_flags"])
        self.assertNotIn("supplier contact roster", controlled.fetched_excerpt.lower())

    def test_support_escalation_demo_blocks_secret_snapshot_exfiltration(self) -> None:
        baseline = run_scripted_support_escalation_demo(
            environment=self.environment,
            mode="baseline",
        )
        self.assertTrue(baseline.outbound_attempted)
        self.assertEqual(baseline.outbound_decision, "allow")
        self.assertEqual(len(baseline.outbound_deliveries), 1)
        self.assertEqual(baseline.outbound_deliveries[0]["path"], "/collect/support-upload")
        self.assertIn("sk-live-demo", baseline.outbound_deliveries[0]["body"])
        self.assertIn("live secrets", baseline.harm.lower())

        self.environment.reset()

        controlled = run_scripted_support_escalation_demo(
            environment=self.environment,
            mode="protected",
            service=self.service,
        )
        self.assertTrue(controlled.outbound_attempted)
        self.assertEqual(controlled.outbound_decision, "block")
        self.assertEqual(controlled.outbound_deliveries, [])
        self.assertIn("blocks", controlled.harm.lower())
        event_types = [event["event_type"] for event in controlled.timeline]
        self.assertIn("source_sanitized", event_types)
        self.assertIn("egress_blocked", event_types)
        scanned_event = next(event for event in controlled.timeline if event["event_type"] == "egress_scanned")
        self.assertIn("secret_detected", scanned_event["metadata"]["risk_flags"])
