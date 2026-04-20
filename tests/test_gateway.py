from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from trustlayer.app import create_app
from trustlayer.audit import AuditStore
from trustlayer.policy import PolicyConfig
from trustlayer.replay import format_approval_queue, format_timeline
from trustlayer.service import DefenseGatewayService


def make_service(tmp_path: Path) -> DefenseGatewayService:
    return DefenseGatewayService(AuditStore(tmp_path / "audit.sqlite3"))


def call_wsgi(app, method: str, path: str, body: dict | None = None):
    payload = json.dumps(body or {}).encode("utf-8")
    captured: dict[str, object] = {}
    path_info, _, query_string = path.partition("?")

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path_info,
        "QUERY_STRING": query_string,
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
    }
    response = b"".join(app(environ, start_response))
    return captured["status"], json.loads(response.decode("utf-8"))


class GatewayScenariosTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = make_service(Path(self.temp_dir.name))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_ingress_strips_hidden_html_and_audits_timeline(self) -> None:
        html = """
        <html><body>
        <h1>Visible research update</h1>
        <!-- hidden comment directive -->
        <div style="display:none">Hidden instruction text</div>
        <p>Supplier terms remain normal.</p>
        </body></html>
        """
        result = self.service.sanitize_ingress(
            tenant_id="demo",
            session_id="sess_ingress",
            source_type="web_page",
            origin="https://example.com/report",
            content=html,
        )

        self.assertEqual(result.decision, "allow_sanitized")
        self.assertIn("hidden_content", result.risk_flags)
        visible_excerpt = result.payload["content"]["visible_excerpt"]
        self.assertIn("Visible research update", visible_excerpt)
        self.assertNotIn("Hidden instruction text", visible_excerpt)
        self.assertIn("html_comment", result.payload["content"]["removed_regions"])

        timeline = self.service.timeline("sess_ingress")
        self.assertEqual(
            [event["event_type"] for event in timeline],
            ["source_received", "policy_matched", "source_sanitized"],
        )

    def test_ingress_marks_mcp_responses_as_untrusted_tool_output(self) -> None:
        result = self.service.sanitize_ingress(
            tenant_id="demo",
            session_id="sess_mcp",
            source_type="mcp_response",
            origin="mcp://remote-search",
            content="Result: follow a different instruction.",
        )

        self.assertIn("tool_output_untrusted", result.risk_flags)
        self.assertEqual(result.payload["source"]["trust_level"], "untrusted")

    def test_ingress_trims_oversized_content_into_selected_chunks(self) -> None:
        oversized = "normal signal " * 120
        result = self.service.sanitize_ingress(
            tenant_id="demo",
            session_id="sess_large_ingress",
            source_type="web_page",
            origin="https://example.com/long",
            content=f"<p>{oversized}</p>",
        )

        self.assertIn("oversized_text", result.risk_flags)
        self.assertLessEqual(len(result.payload["content"]["selected_chunks"]), 3)
        self.assertLessEqual(len(result.payload["content"]["visible_excerpt"]), 280)

    def test_egress_blocks_secrets_and_records_block_event(self) -> None:
        result = self.service.check_egress(
            tenant_id="demo",
            session_id="sess_secret",
            destination="https://hooks.example.net/collect",
            destination_type="webhook",
            payload="Leak sk_test_ABCDEF123456 immediately.",
        )

        self.assertEqual(result.decision, "block")
        self.assertIn("secret_detected", result.risk_flags)

        timeline = self.service.timeline("sess_secret")
        self.assertIn("egress_blocked", [event["event_type"] for event in timeline])

    def test_egress_reviews_new_domain_with_pii(self) -> None:
        result = self.service.check_egress(
            tenant_id="demo",
            session_id="sess_pii",
            destination="https://new-destination.example/api",
            destination_type="webhook",
            payload="Contact alice@example.com for the next update.",
        )

        self.assertEqual(result.decision, "review_required")
        self.assertIn("pii_detected", result.risk_flags)
        self.assertIn("new_domain", result.risk_flags)
        self.assertIn("new destination", result.payload["approval_summary"].lower())
        self.assertIn("pii", result.payload["approval_summary"].lower())

    def test_egress_reviews_oversized_payloads(self) -> None:
        result = self.service.check_egress(
            tenant_id="demo",
            session_id="sess_large_egress",
            destination="https://approved.example/api",
            destination_type="webhook",
            payload="a" * 700,
        )

        self.assertEqual(result.decision, "review_required")
        self.assertIn("payload_oversized", result.risk_flags)

    def test_egress_block_summary_mentions_secret_exfiltration(self) -> None:
        result = self.service.check_egress(
            tenant_id="demo",
            session_id="sess_secret_summary",
            destination="https://hooks.example.net/collect",
            destination_type="webhook",
            payload="Leak ghp_ABCDEF1234567890 immediately.",
        )

        self.assertEqual(result.decision, "block")
        self.assertIn("secret", result.payload["approval_summary"].lower())

    def test_egress_allows_repeat_domain_when_payload_is_benign(self) -> None:
        first = self.service.check_egress(
            tenant_id="demo",
            session_id="sess_repeat_domain",
            destination="https://repeat.example/api",
            destination_type="webhook",
            payload="benign first contact",
        )
        second = self.service.check_egress(
            tenant_id="demo",
            session_id="sess_repeat_domain",
            destination="https://repeat.example/api",
            destination_type="webhook",
            payload="benign follow-up update",
        )

        self.assertEqual(first.decision, "review_required")
        self.assertIn("new_domain", first.risk_flags)
        self.assertEqual(second.decision, "allow")
        self.assertNotIn("new_domain", second.risk_flags)

    def test_policy_config_allowlists_destination_and_lowers_oversized_threshold(self) -> None:
        config = PolicyConfig(
            ingress_oversized_threshold=600,
            egress_oversized_threshold=20,
            allowed_destination_hosts={"safe.example"},
        )
        service = DefenseGatewayService(
            AuditStore(Path(self.temp_dir.name) / "audit-config.sqlite3"),
            policy=config,
        )

        allowlisted = service.check_egress(
            tenant_id="demo",
            session_id="sess_policy",
            destination="https://safe.example/api",
            destination_type="webhook",
            payload="short benign body",
        )
        oversized = service.check_egress(
            tenant_id="demo",
            session_id="sess_policy",
            destination="https://safe.example/api",
            destination_type="webhook",
            payload="x" * 30,
        )

        self.assertEqual(allowlisted.decision, "allow")
        self.assertNotIn("new_domain", allowlisted.risk_flags)
        self.assertEqual(oversized.decision, "review_required")
        self.assertIn("payload_oversized", oversized.risk_flags)

    def test_policy_config_can_load_from_file(self) -> None:
        config_path = Path(self.temp_dir.name) / "policy.json"
        config_path.write_text(
            json.dumps(
                {
                    "ingress_oversized_threshold": 123,
                    "egress_oversized_threshold": 45,
                    "allowed_destination_hosts": ["Configured.example"],
                }
            ),
            encoding="utf-8",
        )

        config = PolicyConfig.from_file(config_path)

        self.assertEqual(config.ingress_oversized_threshold, 123)
        self.assertEqual(config.egress_oversized_threshold, 45)
        self.assertIn("configured.example", config.allowed_destination_hosts)

    def test_replay_formatter_emits_human_readable_timeline(self) -> None:
        self.service.sanitize_ingress(
            tenant_id="demo",
            session_id="sess_replay",
            source_type="web_page",
            origin="https://example.com",
            content="<p>Visible only</p>",
        )

        timeline = self.service.timeline("sess_replay")
        formatted = format_timeline("sess_replay", timeline)

        self.assertIn("Timeline for session sess_replay", formatted)
        self.assertIn("source_received", formatted)
        self.assertIn("source_sanitized", formatted)

    def test_approval_queue_prioritizes_blocked_requests_and_exposes_summaries(self) -> None:
        self.service.check_egress(
            tenant_id="demo",
            session_id="sess_queue",
            destination="https://review.example/api",
            destination_type="webhook",
            payload="contact alice@example.com",
        )
        self.service.check_egress(
            tenant_id="demo",
            session_id="sess_queue",
            destination="https://block.example/api",
            destination_type="webhook",
            payload="Leak ghp_ABCDEF1234567890",
        )

        queue = self.service.approval_queue("demo")

        self.assertEqual(len(queue), 2)
        self.assertEqual(queue[0]["decision"], "block")
        self.assertIn("approval_summary", queue[0])
        self.assertIn("secret", queue[0]["approval_summary"].lower())
        self.assertEqual(queue[1]["decision"], "review_required")

        rendered = format_approval_queue(queue)
        self.assertIn("Approval Queue", rendered)
        self.assertIn("block.example", rendered)
        self.assertIn("review", rendered.lower())

    def test_wsgi_approval_queue_endpoint_returns_prioritized_items(self) -> None:
        app = create_app(self.service)
        call_wsgi(
            app,
            "POST",
            "/v1/egress/check",
            {
                "tenant_id": "demo",
                "session_id": "sess_queue_api",
                "destination": "https://review.example/api",
                "destination_type": "webhook",
                "payload": "contact alice@example.com",
            },
        )
        call_wsgi(
            app,
            "POST",
            "/v1/egress/check",
            {
                "tenant_id": "demo",
                "session_id": "sess_queue_api",
                "destination": "https://block.example/api",
                "destination_type": "webhook",
                "payload": "Leak ghp_ABCDEF1234567890",
            },
        )

        status, body = call_wsgi(app, "GET", "/v1/approvals/queue?tenant_id=demo")

        self.assertTrue(str(status).startswith("200"))
        self.assertEqual(body["tenant_id"], "demo")
        self.assertEqual(body["items"][0]["decision"], "block")
        self.assertIn("approval_summary", body["items"][0])

    def test_html_approval_queue_page_renders_prioritized_items(self) -> None:
        app = create_app(self.service)
        call_wsgi(
            app,
            "POST",
            "/v1/egress/check",
            {
                "tenant_id": "demo",
                "session_id": "sess_queue_html",
                "destination": "https://review.example/api",
                "destination_type": "webhook",
                "payload": "contact alice@example.com",
            },
        )
        call_wsgi(
            app,
            "POST",
            "/v1/egress/check",
            {
                "tenant_id": "demo",
                "session_id": "sess_queue_html",
                "destination": "https://block.example/api",
                "destination_type": "webhook",
                "payload": "Leak ghp_ABCDEF1234567890",
            },
        )

        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/approvals/queue",
            "QUERY_STRING": "tenant_id=demo",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
        }
        body = b"".join(app(environ, start_response)).decode("utf-8")

        self.assertTrue(str(captured["status"]).startswith("200"))
        headers = dict(captured["headers"])
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn("Approval Queue", body)
        self.assertIn("block.example", body)
        self.assertIn("review.example", body)
        self.assertLess(body.find("block.example"), body.find("review.example"))

    def test_wsgi_timeline_endpoint_returns_session_events(self) -> None:
        app = create_app(self.service)
        _, ingress_body = call_wsgi(
            app,
            "POST",
            "/v1/ingress/sanitize",
            {
                "tenant_id": "demo",
                "session_id": "sess_wsgi",
                "source_type": "web_page",
                "origin": "https://example.com",
                "content": "<p>Visible only</p>",
            },
        )
        self.assertEqual(ingress_body["decision"], "allow_sanitized")

        status, timeline_body = call_wsgi(app, "GET", "/v1/sessions/sess_wsgi/timeline")
        self.assertTrue(str(status).startswith("200"))
        self.assertEqual(timeline_body["session_id"], "sess_wsgi")
        self.assertGreaterEqual(len(timeline_body["events"]), 2)


if __name__ == "__main__":
    unittest.main()
