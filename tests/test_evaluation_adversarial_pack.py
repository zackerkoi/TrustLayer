from __future__ import annotations

import json
import unittest
from pathlib import Path

from trustlayer.audit import AuditStore
from trustlayer.evaluation import load_samples
from trustlayer.policy import PolicyConfig
from trustlayer.service import DefenseGatewayService


class AdversarialPackEvaluationTest(unittest.TestCase):
    def test_adversarial_pack_contains_known_gaps_and_detected_cases(self) -> None:
        samples_path = Path(__file__).resolve().parents[1] / "config" / "eval_samples_adversarial.json"
        payload = json.loads(samples_path.read_text(encoding="utf-8"))

        expectations = {sample["expectation"] for sample in payload["samples"]}

        self.assertIn("should_detect", expectations)
        self.assertIn("known_gap", expectations)

    def test_adversarial_pack_surfaces_known_gaps_without_failing_the_suite(self) -> None:
        samples_path = Path(__file__).resolve().parents[1] / "config" / "eval_samples_adversarial.json"
        samples = load_samples(samples_path)
        raw_payload = json.loads(samples_path.read_text(encoding="utf-8"))["samples"]
        expectations = {item["id"]: item["expectation"] for item in raw_payload}

        service = DefenseGatewayService(
            AuditStore(":memory:"),
            policy=PolicyConfig(allowed_destination_hosts={"safe.example"}),
        )

        detected = []
        gaps = []
        for sample in samples:
            result = service.check_egress(
                tenant_id=sample.tenant_id,
                session_id=sample.session_id,
                destination=sample.payload["destination"],
                destination_type=sample.payload["destination_type"],
                payload=sample.payload["payload"],
            )
            if expectations[sample.id] == "should_detect":
                detected.append((sample.id, result.decision, result.risk_flags))
            else:
                gaps.append((sample.id, result.decision, result.risk_flags))

        self.assertEqual(detected[0][1], "block")
        self.assertIn("secret_detected", detected[0][2])
        self.assertTrue(all(decision == "allow" for _, decision, _ in gaps))


if __name__ == "__main__":
    unittest.main()
