from __future__ import annotations

import argparse
from pathlib import Path
from wsgiref.simple_server import make_server

from .app import create_app
from .audit import AuditStore
from .audit_pipeline import AuditForwarder
from .control_plane import ControlPlaneStore, PolicyDistributionService, RuleManagementService
from .mcp_gateway import build_default_mcp_gateway
from .policy import PolicyConfig, PolicyStore
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
    parser.add_argument(
        "--control-db-path",
        default=str(Path("control-plane.sqlite3").resolve()),
        help="SQLite file for control plane metadata",
    )
    parser.add_argument(
        "--central-audit-db-path",
        default=str(Path("central-audit.sqlite3").resolve()),
        help="SQLite file for centralized audit storage",
    )
    parser.add_argument(
        "--gateway-instance-id",
        default="gw-local",
        help="Gateway instance identifier for policy distribution and audit forwarding",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    audit = AuditStore(args.db_path)
    local_policy_store = PolicyStore(args.db_path)
    policy = PolicyConfig.from_file(args.policy_file) if args.policy_file else None
    service = DefenseGatewayService(
        audit,
        policy=policy,
        policy_store=local_policy_store,
        gateway_instance_id=args.gateway_instance_id,
    )
    mcp_gateway = build_default_mcp_gateway(service)
    control_store = ControlPlaneStore(args.control_db_path)
    rule_management = RuleManagementService(control_store)
    policy_distribution = PolicyDistributionService(control_store, local_policy_store)
    central_audit = AuditStore(args.central_audit_db_path)
    audit_forwarder = AuditForwarder(
        audit,
        central_audit,
        gateway_instance_id=args.gateway_instance_id,
    )
    app = create_app(
        service,
        mcp_gateway=mcp_gateway,
        rule_management=rule_management,
        policy_distribution=policy_distribution,
        control_store=control_store,
        audit_forwarder=audit_forwarder,
    )

    with make_server("127.0.0.1", args.port, app) as server:
        print(f"TrustLayer gateway listening on http://127.0.0.1:{args.port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
