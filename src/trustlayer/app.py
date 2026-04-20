from __future__ import annotations

import json
from html import escape
from urllib.parse import parse_qs
from typing import Any, Callable, Iterable

from .audit_pipeline import AuditForwarder
from .control_plane import ControlPlaneStore, PolicyDistributionService, RuleManagementService
from .mcp_gateway import (
    MCPGatewayService,
    ToolDirectionNotSupportedError,
    ToolNotFoundError,
)
from .service import DefenseGatewayService


StartResponse = Callable[[str, list[tuple[str, str]]], None]


def create_app(
    service: DefenseGatewayService,
    mcp_gateway: MCPGatewayService | None = None,
    rule_management: RuleManagementService | None = None,
    policy_distribution: PolicyDistributionService | None = None,
    control_store: ControlPlaneStore | None = None,
    audit_forwarder: AuditForwarder | None = None,
):
    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        query = parse_qs(environ.get("QUERY_STRING", ""))

        try:
            if method == "GET" and path == "/healthz":
                return _json_response(start_response, 200, {"status": "ok"})

            if method == "POST" and path == "/v1/ingress/sanitize":
                body = _read_json_body(environ)
                if mcp_gateway is not None and "tool_name" in body:
                    result = mcp_gateway.sanitize_supplied_tool_result(
                        tenant_id=body["tenant_id"],
                        session_id=body["session_id"],
                        tool_name=body["tool_name"],
                        source_type=body["source_type"],
                        origin=body["origin"],
                        content=body["content"],
                        result_metadata=body.get("result_metadata"),
                    )
                    return _json_response(
                        start_response,
                        200,
                        {
                            "request_id": result["request_id"],
                            "tool_name": result["tool_name"],
                            "tool": result["tool"],
                            "decision": result["decision"],
                            "risk_flags": result["risk_flags"],
                            "matched_policies": result["matched_policies"],
                            "sanitized_content": result["sanitized_content"],
                        },
                    )

                result = service.sanitize_ingress(
                    tenant_id=body["tenant_id"],
                    session_id=body["session_id"],
                    source_type=body["source_type"],
                    origin=body["origin"],
                    content=body["content"],
                )
                return _json_response(
                    start_response,
                    200,
                    {
                        "request_id": result.request_id,
                        "decision": result.decision,
                        "risk_flags": result.risk_flags,
                        "matched_policies": result.matched_policies,
                        "sanitized_content": result.payload,
                    },
                )

            if method == "POST" and path == "/v1/egress/check":
                body = _read_json_body(environ)
                if mcp_gateway is not None:
                    spec = mcp_gateway.resolve_egress_tool(body["destination_type"])
                else:
                    spec = None

                if spec is not None:
                    payload = mcp_gateway.invoke_tool(
                        tenant_id=body["tenant_id"],
                        session_id=body["session_id"],
                        tool_name=spec.name,
                        direction="egress",
                        arguments={
                            "destination": body["destination"],
                            "destination_type": body["destination_type"],
                            "payload": body["payload"],
                        },
                    )
                    return _json_response(
                        start_response,
                        200,
                        {
                            "request_id": payload["request_id"],
                            "decision": payload["decision"],
                            "risk_flags": payload["risk_flags"],
                            "matched_policies": payload["matched_policies"],
                            "egress": payload.get("egress"),
                        },
                    )

                result = service.check_egress(
                    tenant_id=body["tenant_id"],
                    session_id=body["session_id"],
                    destination=body["destination"],
                    destination_type=body["destination_type"],
                    payload=body["payload"],
                )
                return _json_response(
                    start_response,
                    200,
                    {
                        "request_id": result.request_id,
                        "decision": result.decision,
                        "risk_flags": result.risk_flags,
                        "matched_policies": result.matched_policies,
                        "egress": result.payload,
                    },
                )

            if method == "GET" and path.startswith("/v1/sessions/") and path.endswith("/timeline"):
                session_id = path.split("/")[3]
                return _json_response(
                    start_response,
                    200,
                    {"session_id": session_id, "events": service.timeline(session_id)},
                )

            if method == "GET" and path == "/v1/approvals/queue":
                tenant_id = query["tenant_id"][0]
                limit = int(query.get("limit", ["20"])[0])
                return _json_response(
                    start_response,
                    200,
                    {
                        "tenant_id": tenant_id,
                        "items": service.approval_queue(tenant_id, limit=limit),
                    },
                )

            if method == "GET" and path == "/approvals/queue":
                tenant_id = query["tenant_id"][0]
                limit = int(query.get("limit", ["20"])[0])
                items = service.approval_queue(tenant_id, limit=limit)
                return _html_response(
                    start_response,
                    200,
                    _render_approval_queue_page(tenant_id, items),
                )

            if method == "GET" and path == "/v1/mcp/tools":
                if mcp_gateway is None:
                    return _json_response(start_response, 404, {"error": "mcp_gateway_disabled"})
                return _json_response(
                    start_response,
                    200,
                    {"items": mcp_gateway.list_tools()},
                )

            if method == "POST" and path == "/v1/mcp/tools/fetch":
                if mcp_gateway is None:
                    return _json_response(start_response, 404, {"error": "mcp_gateway_disabled"})
                body = _read_json_body(environ)
                result = mcp_gateway.fetch_tool(
                    tenant_id=body["tenant_id"],
                    session_id=body["session_id"],
                    tool_name=body["tool_name"],
                    arguments=body.get("arguments", {}),
                )
                return _json_response(start_response, 200, result)

            if method == "POST" and path == "/v1/mcp/invoke":
                if mcp_gateway is None:
                    return _json_response(start_response, 404, {"error": "mcp_gateway_disabled"})
                body = _read_json_body(environ)
                result = mcp_gateway.invoke_tool(
                    tenant_id=body["tenant_id"],
                    session_id=body["session_id"],
                    tool_name=body["tool_name"],
                    direction=body["direction"],
                    arguments=body.get("arguments", {}),
                )
                return _json_response(start_response, 200, result)

            if method == "POST" and path == "/v1/control/policies/publish":
                if rule_management is None:
                    return _json_response(start_response, 404, {"error": "control_plane_disabled"})
                body = _read_json_body(environ)
                result = rule_management.publish_bundle(
                    document=body["document"],
                    created_by=body["created_by"],
                    change_summary=body["change_summary"],
                )
                return _json_response(start_response, 200, result)

            if method == "POST" and path == "/v1/control/tenants/bind":
                if rule_management is None:
                    return _json_response(start_response, 404, {"error": "control_plane_disabled"})
                body = _read_json_body(environ)
                result = rule_management.bind_tenant(
                    tenant_id=body["tenant_id"],
                    bundle_version=body["bundle_version"],
                )
                return _json_response(start_response, 200, result)

            if method == "GET" and path.startswith("/v1/control/tenants/") and path.endswith("/policy"):
                if control_store is None:
                    return _json_response(start_response, 404, {"error": "control_plane_disabled"})
                tenant_id = path.split("/")[4]
                bundle = control_store.resolve_bundle_for_tenant(tenant_id)
                return _json_response(
                    start_response,
                    200,
                    {
                        "tenant_id": tenant_id,
                        "bundle_version": bundle.bundle_version,
                        "created_by": bundle.created_by,
                        "change_summary": bundle.change_summary,
                        "document": bundle.document,
                    },
                )

            if method == "POST" and path == "/v1/control/distribution/sync":
                if policy_distribution is None:
                    return _json_response(start_response, 404, {"error": "control_plane_disabled"})
                body = _read_json_body(environ)
                result = policy_distribution.sync_tenant_bundle(
                    tenant_id=body["tenant_id"],
                    instance_id=body["instance_id"],
                )
                return _json_response(start_response, 200, result)

            if method == "POST" and path == "/v1/control/audit/forward":
                if audit_forwarder is None:
                    return _json_response(start_response, 404, {"error": "control_plane_disabled"})
                body = _read_json_body(environ) if environ.get("CONTENT_LENGTH") not in (None, "", "0") else {}
                result = audit_forwarder.forward_once(batch_size=int(body.get("batch_size", 500)))
                return _json_response(start_response, 200, result)

            return _json_response(start_response, 404, {"error": "not_found"})
        except KeyError as exc:
            return _json_response(
                start_response,
                400,
                {"error": "missing_field", "field": str(exc)},
            )
        except json.JSONDecodeError:
            return _json_response(start_response, 400, {"error": "invalid_json"})
        except ToolNotFoundError as exc:
            return _json_response(start_response, 404, {"error": "unknown_tool", "tool_name": str(exc)})
        except ToolDirectionNotSupportedError as exc:
            tool_name, _, direction = str(exc).partition(":")
            return _json_response(
                start_response,
                400,
                {
                    "error": "unsupported_tool_direction",
                    "tool_name": tool_name,
                    "direction": direction or "unknown",
                },
            )

    return app


def _read_json_body(environ: dict[str, Any]) -> dict[str, Any]:
    length = int(environ.get("CONTENT_LENGTH") or "0")
    raw = environ["wsgi.input"].read(length) if length else b"{}"
    return json.loads(raw.decode("utf-8"))


def _json_response(start_response: StartResponse, status_code: int, payload: dict[str, Any]):
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    start_response(
        f"{status_code} {'OK' if status_code < 400 else 'ERROR'}",
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def _html_response(start_response: StartResponse, status_code: int, body: str):
    payload = body.encode("utf-8")
    start_response(
        f"{status_code} {'OK' if status_code < 400 else 'ERROR'}",
        [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(payload)))],
    )
    return [payload]


def _render_approval_queue_page(tenant_id: str, items: list[dict[str, Any]]) -> str:
    rows = []
    for item in items:
        risk_flags = ", ".join(item.get("risk_flags") or []) or "none"
        rows.append(
            "<tr>"
            f"<td>{escape(item.get('decision') or '')}</td>"
            f"<td>{escape(item.get('destination_host') or '')}</td>"
            f"<td>{escape(item.get('approval_summary') or item.get('summary') or '')}</td>"
            f"<td>{escape(risk_flags)}</td>"
            f"<td>{escape(item.get('session_id') or '')}</td>"
            "</tr>"
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='5'>No pending approvals.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Approval Queue</title>
    <style>
      body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 32px; color: #111827; }}
      h1 {{ margin-bottom: 8px; }}
      p {{ color: #4b5563; }}
      table {{ width: 100%; border-collapse: collapse; margin-top: 24px; }}
      th, td {{ border: 1px solid #d1d5db; padding: 10px 12px; text-align: left; vertical-align: top; }}
      th {{ background: #f3f4f6; }}
      .decision-block {{ color: #991b1b; font-weight: 700; }}
      .decision-review_required {{ color: #92400e; font-weight: 700; }}
    </style>
  </head>
  <body>
    <h1>Approval Queue</h1>
    <p>Tenant: {escape(tenant_id)}</p>
    <table>
      <thead>
        <tr>
          <th>Decision</th>
          <th>Destination</th>
          <th>Approval Summary</th>
          <th>Risk Flags</th>
          <th>Session</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </body>
</html>"""
