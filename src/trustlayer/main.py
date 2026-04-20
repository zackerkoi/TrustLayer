from __future__ import annotations

import argparse
from pathlib import Path
from wsgiref.simple_server import make_server

from .app import create_app
from .audit import AuditStore
from .mcp_gateway import build_default_mcp_gateway
from .policy import PolicyConfig
from .service import DefenseGatewayService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080, help="HTTP service port")
    parser.add_argument(
        "--db-path",
        default=str(Path("audit.sqlite3").resolve()),
        help="SQLite file for audit events",
    )
    parser.add_argument(
        "--policy-file",
        help="Optional policy JSON file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    audit = AuditStore(args.db_path)
    policy = PolicyConfig.from_file(args.policy_file) if args.policy_file else None
    service = DefenseGatewayService(audit, policy=policy)
    mcp_gateway = build_default_mcp_gateway(service)
    app = create_app(service, mcp_gateway=mcp_gateway)

    with make_server("127.0.0.1", args.port, app) as server:
        print(f"TrustLayer gateway listening on http://127.0.0.1:{args.port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
