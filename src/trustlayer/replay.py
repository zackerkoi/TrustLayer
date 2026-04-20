from __future__ import annotations

import argparse
from pathlib import Path

from .audit import AuditStore
from .service import DefenseGatewayService


def format_timeline(session_id: str, events: list[dict]) -> str:
    lines = [f"Timeline for session {session_id}"]
    for index, event in enumerate(events, start=1):
        decision = f" decision={event['decision']}" if event.get("decision") else ""
        policy = f" policy={event['policy_id']}" if event.get("policy_id") else ""
        lines.append(
            f"{index}. {event['event_type']}{decision}{policy} :: {event.get('summary') or ''}"
        )
    return "\n".join(lines)


def format_approval_queue(items: list[dict]) -> str:
    lines = ["Approval Queue"]
    for index, item in enumerate(items, start=1):
        lines.append(
            f"{index}. {item['decision']} -> {item.get('destination_host') or 'unknown'} :: "
            f"{item.get('approval_summary') or item.get('summary') or ''}"
        )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", required=True, help="SQLite audit database path")
    parser.add_argument("--session-id", required=True, help="Session id to replay")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    service = DefenseGatewayService(AuditStore(Path(args.db_path)))
    timeline = service.timeline(args.session_id)
    print(format_timeline(args.session_id, timeline), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
