from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from .policy import PolicyStore


def build_ops_report(db_path: str | Path) -> dict[str, Any]:
    snapshot = PolicyStore(db_path).snapshot()
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT session_id, request_id, event_type, decision, metadata_json, created_at
        FROM events
        ORDER BY rowid ASC
        """
    ).fetchall()
    conn.close()

    risk_flags = Counter()
    destination_hosts = Counter()
    event_counts = Counter()
    decision_counts = Counter()
    sessions = set()
    signal_event_types = {str(item) for item in snapshot.setting("ops_signal_event_types", [])}
    destination_event_types = {str(item) for item in snapshot.setting("ops_destination_event_types", [])}

    for row in rows:
        event_counts[row["event_type"]] += 1
        sessions.add(row["session_id"])
        metadata = json.loads(row["metadata_json"])
        if row["event_type"] in signal_event_types:
            if row["decision"]:
                decision_counts[row["decision"]] += 1
            for flag in metadata.get("risk_flags", []):
                risk_flags[str(flag)] += 1
        if row["event_type"] in destination_event_types and metadata.get("destination_host"):
            destination_hosts[str(metadata["destination_host"])] += 1

    return {
        "summary": {
            "total_events": len(rows),
            "total_sessions": len(sessions),
            "source_sanitized_count": event_counts["source_sanitized"],
            "egress_blocked_count": event_counts["egress_blocked"],
            "egress_review_required_count": event_counts["egress_review_required"],
            "policy_matched_count": event_counts["policy_matched"],
        },
        "top_risk_flags": risk_flags.most_common(10),
        "top_destination_hosts": destination_hosts.most_common(10),
        "event_counts": dict(event_counts),
        "decision_counts": dict(decision_counts),
    }


def format_ops_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "TrustLayer Ops Report",
        (
            "summary: "
            f"total_events={summary['total_events']} "
            f"total_sessions={summary['total_sessions']} "
            f"source_sanitized={summary['source_sanitized_count']} "
            f"egress_review_required={summary['egress_review_required_count']} "
            f"egress_blocked={summary['egress_blocked_count']} "
            f"policy_matched={summary['policy_matched_count']}"
        ),
        "top risk flags:",
    ]
    for flag, count in report["top_risk_flags"]:
        lines.append(f"- {flag}: {count}")
    if not report["top_risk_flags"]:
        lines.append("- none")

    lines.append("top destination hosts:")
    for host, count in report["top_destination_hosts"]:
        lines.append(f"- {host}: {count}")
    if not report["top_destination_hosts"]:
        lines.append("- none")

    lines.append("decision counts:")
    for decision, count in sorted(report["decision_counts"].items()):
        lines.append(f"- {decision}: {count}")
    if not report["decision_counts"]:
        lines.append("- none")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", required=True, help="SQLite audit database path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_ops_report(args.db_path)
    print(format_ops_report(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
