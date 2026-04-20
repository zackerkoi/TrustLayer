from __future__ import annotations

import argparse
from pathlib import Path
from wsgiref.simple_server import make_server

from .app import create_app
from .audit import AuditStore
from .audit_bus import AuditBus
from .audit_pipeline import AuditConsumer, AuditForwarder
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
        help="Control plane SQLite path or PostgreSQL DSN",
    )
    parser.add_argument(
        "--central-audit-db-path",
        default=str(Path("central-audit.sqlite3").resolve()),
        help="SQLite file for centralized audit storage",
    )
    parser.add_argument(
        "--audit-bus-url",
        default=str(Path("audit-bus.sqlite3").resolve()),
        help="Audit bus SQLite path or kafka://broker/topic URL",
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
    audit_bus = AuditBus(args.audit_bus_url)
    audit_forwarder = AuditForwarder(
        audit,
        audit_bus,
        gateway_instance_id=args.gateway_instance_id,
    )
    audit_consumer = AuditConsumer(audit_bus, central_audit)
    app = create_app(
        service,
        mcp_gateway=mcp_gateway,
        rule_management=rule_management,
        policy_distribution=policy_distribution,
        control_store=control_store,
        audit_forwarder=audit_forwarder,
        audit_consumer=audit_consumer,
    )

    with make_server("127.0.0.1", args.port, app) as server:
        print(f"TrustLayer gateway listening on http://127.0.0.1:{args.port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
