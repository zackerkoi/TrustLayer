from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trustlayer.audit import AuditStore
from trustlayer.evaluation import (
    evaluate_samples,
    format_evaluation_report,
    load_samples,
)
from trustlayer.policy import PolicyConfig
from trustlayer.service import DefenseGatewayService


class EvaluationFrameworkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_load_samples_reads_fixture_file(self) -> None:
        path = Path(self.temp_dir.name) / "samples.json"
        path.write_text(
            json.dumps(
                {
                    "samples": [
                        {
                            "id": "s1",
                            "kind": "egress",
                            "label": "benign",
                            "tenant_id": "demo",
                            "session_id": "sess1",
                            "destination": "https://safe.example/api",
                            "destination_type": "webhook",
                            "payload": "ok",
                            "expected_decision": "allow",
                            "required_flags": [],
                            "forbidden_flags": ["new_domain"]
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        samples = load_samples(path)

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].id, "s1")
        self.assertEqual(samples[0].payload["destination"], "https://safe.example/api")

    def test_evaluate_samples_computes_summary_metrics(self) -> None:
        samples_path = Path(__file__).resolve().parents[1] / "config" / "eval_samples.json"
        samples = load_samples(samples_path)
        service = DefenseGatewayService(
            AuditStore(Path(self.temp_dir.name) / "eval.sqlite3"),
            policy=PolicyConfig(allowed_destination_hosts={"safe.example"}),
        )

        report = evaluate_samples(samples, service)

        self.assertEqual(report["summary"]["false_positive_count"], 0)
        self.assertEqual(report["summary"]["false_negative_count"], 0)
        self.assertGreaterEqual(report["summary"]["benign_retention"], 1.0)
        self.assertGreaterEqual(report["summary"]["detection_recall"], 1.0)
        self.assertGreater(report["summary"]["average_latency_ms"], 0.0)

    def test_format_evaluation_report_contains_summary_and_results(self) -> None:
        report = {
            "summary": {
                "total_samples": 2,
                "false_positive_count": 0,
                "false_negative_count": 1,
                "benign_retention": 1.0,
                "detection_recall": 0.5,
                "average_latency_ms": 1.234,
            },
            "results": [
                {"id": "a", "pass": True, "decision": "allow", "risk_flags": [], "latency_ms": 1.2},
                {"id": "b", "pass": False, "decision": "allow", "risk_flags": ["new_domain"], "latency_ms": 1.3},
            ],
        }

        rendered = format_evaluation_report(report)

        self.assertIn("Evaluation Summary", rendered)
        self.assertIn("false_negative_count=1", rendered)
        self.assertIn("- a:", rendered)
        self.assertIn("- b:", rendered)


if __name__ == "__main__":
    unittest.main()
