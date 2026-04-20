from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditStore
from .policy import PolicyConfig
from .service import DefenseGatewayService


@dataclass(frozen=True)
class EvalSample:
    id: str
    kind: str
    label: str
    tenant_id: str
    session_id: str
    expected_decision: str
    required_flags: list[str]
    forbidden_flags: list[str]
    payload: dict[str, Any]


def load_samples(path: str | Path) -> list[EvalSample]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    samples: list[EvalSample] = []
    for item in raw["samples"]:
        payload = {k: v for k, v in item.items() if k not in {
            "id", "kind", "label", "tenant_id", "session_id",
            "expected_decision", "required_flags", "forbidden_flags"
        }}
        samples.append(
            EvalSample(
                id=item["id"],
                kind=item["kind"],
                label=item["label"],
                tenant_id=item["tenant_id"],
                session_id=item["session_id"],
                expected_decision=item["expected_decision"],
                required_flags=item.get("required_flags", []),
                forbidden_flags=item.get("forbidden_flags", []),
                payload=payload,
            )
        )
    return samples


def evaluate_samples(samples: list[EvalSample], service: DefenseGatewayService) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    fp = fn = benign_total = benign_ok = risky_total = risky_detected = 0
    latencies: list[float] = []

    for sample in samples:
        started = time.perf_counter()
        if sample.kind == "ingress":
            result = service.sanitize_ingress(
                tenant_id=sample.tenant_id,
                session_id=sample.session_id,
                source_type=sample.payload["source_type"],
                origin=sample.payload["origin"],
                content=sample.payload["content"],
            )
        else:
            result = service.check_egress(
                tenant_id=sample.tenant_id,
                session_id=sample.session_id,
                destination=sample.payload["destination"],
                destination_type=sample.payload["destination_type"],
                payload=sample.payload["payload"],
            )
        latency_ms = (time.perf_counter() - started) * 1000
        latencies.append(latency_ms)

        flags = set(result.risk_flags)
        decision_ok = result.decision == sample.expected_decision
        required_ok = set(sample.required_flags).issubset(flags)
        forbidden_ok = not (set(sample.forbidden_flags) & flags)
        sample_ok = decision_ok and required_ok and forbidden_ok

        if sample.label == "benign":
            benign_total += 1
            if sample_ok:
                benign_ok += 1
            else:
                fp += 1
        else:
            risky_total += 1
            detected = decision_ok and required_ok
            if detected:
                risky_detected += 1
            else:
                fn += 1

        results.append(
            {
                "id": sample.id,
                "label": sample.label,
                "kind": sample.kind,
                "decision": result.decision,
                "risk_flags": result.risk_flags,
                "latency_ms": round(latency_ms, 3),
                "pass": sample_ok if sample.label == "benign" else (decision_ok and required_ok),
            }
        )

    total = len(samples)
    avg_latency = sum(latencies) / total if total else 0.0
    return {
        "summary": {
            "total_samples": total,
            "false_positive_count": fp,
            "false_negative_count": fn,
            "benign_retention": benign_ok / benign_total if benign_total else 0.0,
            "detection_recall": risky_detected / risky_total if risky_total else 0.0,
            "average_latency_ms": round(avg_latency, 3),
        },
        "results": results,
    }


def format_evaluation_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "Evaluation Summary",
        f"total_samples={summary['total_samples']}",
        f"false_positive_count={summary['false_positive_count']}",
        f"false_negative_count={summary['false_negative_count']}",
        f"benign_retention={summary['benign_retention']:.3f}",
        f"detection_recall={summary['detection_recall']:.3f}",
        f"average_latency_ms={summary['average_latency_ms']:.3f}",
        "",
        "Per-sample Results",
    ]
    for result in report["results"]:
        lines.append(
            f"- {result['id']}: pass={result['pass']} decision={result['decision']} "
            f"flags={','.join(result['risk_flags'])} latency_ms={result['latency_ms']}"
        )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--samples-file",
        default=str(Path(__file__).resolve().parents[2] / "config" / "eval_samples.json"),
        help="Path to evaluation samples JSON",
    )
    parser.add_argument(
        "--db-path",
        default=":memory:",
        help="SQLite path for audit storage during evaluation",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = PolicyConfig(allowed_destination_hosts={"safe.example"})
    service = DefenseGatewayService(AuditStore(args.db_path), policy=policy)
    samples = load_samples(args.samples_file)
    report = evaluate_samples(samples, service)
    print(format_evaluation_report(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
