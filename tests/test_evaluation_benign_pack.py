from __future__ import annotations

import unittest
from pathlib import Path

from trustlayer.audit import AuditStore
from trustlayer.evaluation import evaluate_samples, load_samples
from trustlayer.policy import PolicyConfig
from trustlayer.service import DefenseGatewayService


class BenignPackEvaluationTest(unittest.TestCase):
    def test_benign_extended_pack_has_zero_false_positives(self) -> None:
        samples_path = Path(__file__).resolve().parents[1] / "config" / "eval_samples_benign_extended.json"
        samples = load_samples(samples_path)
        service = DefenseGatewayService(
            AuditStore(":memory:"),
            policy=PolicyConfig(allowed_destination_hosts={"safe.example"}),
        )

        report = evaluate_samples(samples, service)

        self.assertEqual(report["summary"]["total_samples"], 6)
        self.assertEqual(report["summary"]["false_positive_count"], 0)
        self.assertEqual(report["summary"]["false_negative_count"], 0)
        self.assertEqual(report["summary"]["benign_retention"], 1.0)


if __name__ == "__main__":
    unittest.main()
