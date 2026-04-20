from __future__ import annotations

import json
from html import escape
from urllib.parse import parse_qs
from typing import Any, Callable, Iterable

from .audit_pipeline import AuditConsumer, AuditForwarder
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
    audit_consumer: AuditConsumer | None = None,
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

            if method == "GET" and path in {"/console", "/console/"}:
                return _html_response(
                    start_response,
                    200,
                    _render_console_dashboard_page(service, control_store),
                )

            if method == "GET" and path == "/console/dashboard":
                return _html_response(
                    start_response,
                    200,
                    _render_console_dashboard_page(service, control_store),
                )

            if method == "GET" and path == "/console/policies":
                return _html_response(
                    start_response,
                    200,
                    _render_console_policies_page(control_store, query),
                )

            if method == "GET" and path == "/console/distribution":
                return _html_response(
                    start_response,
                    200,
                    _render_console_distribution_page(control_store, query),
                )

            if method == "GET" and path == "/console/audit":
                return _html_response(
                    start_response,
                    200,
                    _render_console_audit_page(service, query),
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

            if method == "POST" and path == "/v1/control/audit/consume":
                if audit_consumer is None:
                    return _json_response(start_response, 404, {"error": "control_plane_disabled"})
                body = _read_json_body(environ) if environ.get("CONTENT_LENGTH") not in (None, "", "0") else {}
                result = audit_consumer.consume_once(batch_size=int(body.get("batch_size", 500)))
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


def _render_console_dashboard_page(
    service: DefenseGatewayService,
    control_store: ControlPlaneStore | None,
) -> str:
    stats = service.audit.dashboard_stats()
    decision_counts = stats.get("decision_counts", {})
    event_counts = stats.get("event_counts", {})
    bindings = control_store.list_tenant_bindings(limit=5) if control_store is not None else []
    distributions = control_store.list_distribution_status(limit=5) if control_store is not None else []

    cards = [
        ("Total Events", str(stats.get("total_events", 0))),
        ("Sessions", str(stats.get("total_sessions", 0))),
        ("Blocked", str(decision_counts.get("block", 0))),
        ("Review Required", str(decision_counts.get("review_required", 0))),
        ("Sanitized Inputs", str(event_counts.get("source_sanitized", 0))),
        ("Allowed", str(decision_counts.get("allow", 0))),
    ]
    card_html = "".join(
        f"<div class='card'><div class='card-label'>{escape(label)}</div><div class='card-value'>{escape(value)}</div></div>"
        for label, value in cards
    )
    bindings_html = _rows_or_empty(
        [
            (
                item.get("tenant_id", ""),
                item.get("bundle_version", ""),
                item.get("rollout_state", ""),
                item.get("updated_at", ""),
            )
            for item in bindings
        ],
        columns=4,
    )
    distributions_html = _rows_or_empty(
        [
            (
                item.get("instance_id", ""),
                item.get("tenant_id", ""),
                item.get("bundle_version", ""),
                item.get("status", ""),
            )
            for item in distributions
        ],
        columns=4,
    )
    body = f"""
    <section class='hero'>
      <h1>TrustLayer Control Console</h1>
      <p>运营视角看执行面、规则绑定和最近分发状态。</p>
    </section>
    <section class='cards'>{card_html}</section>
    <section class='grid two-up'>
      <div class='panel'>
        <h2>Recent Tenant Bindings</h2>
        <table>
          <thead><tr><th>Tenant</th><th>Bundle</th><th>State</th><th>Updated</th></tr></thead>
          <tbody>{bindings_html}</tbody>
        </table>
      </div>
      <div class='panel'>
        <h2>Recent Distribution Status</h2>
        <table>
          <thead><tr><th>Instance</th><th>Tenant</th><th>Bundle</th><th>Status</th></tr></thead>
          <tbody>{distributions_html}</tbody>
        </table>
      </div>
    </section>
    """
    return _render_console_layout("Dashboard", body)


def _render_console_policies_page(
    control_store: ControlPlaneStore | None,
    query: dict[str, list[str]],
) -> str:
    bundles = control_store.list_bundles(limit=20) if control_store is not None else []
    bindings = control_store.list_tenant_bindings(limit=50) if control_store is not None else []
    selected_tenant = query.get("tenant_id", [""])[0] or ""
    bundle_detail: dict[str, Any] | None = None
    detail_error: str | None = None
    if control_store is not None:
        if not selected_tenant and bindings:
            selected_tenant = str(bindings[0].get("tenant_id") or "")
        if selected_tenant:
            try:
                resolved = control_store.resolve_bundle_for_tenant(selected_tenant)
                bundle_detail = resolved.document
            except KeyError:
                detail_error = f"Tenant {selected_tenant} is not bound to a policy bundle."
    bundle_rows = _rows_or_empty(
        [
            (
                item.get("bundle_version", ""),
                item.get("created_by", ""),
                item.get("change_summary", ""),
                item.get("created_at", ""),
            )
            for item in bundles
        ],
        columns=4,
    )
    binding_rows = _rows_or_empty(
        [
            (
                item.get("tenant_id", ""),
                item.get("bundle_version", ""),
                item.get("rollout_state", ""),
                item.get("updated_at", ""),
            )
            for item in bindings
        ],
        columns=4,
    )
    tenant_options = "".join(
        f"<option value='{escape(str(item.get('tenant_id') or ''))}'"
        f"{' selected' if str(item.get('tenant_id') or '') == selected_tenant else ''}>"
        f"{escape(str(item.get('tenant_id') or ''))}</option>"
        for item in bindings
    )
    detail_html = _render_policy_bundle_detail(selected_tenant, bundle_detail, detail_error)
    body = f"""
    <section class='hero'>
      <h1>Policies</h1>
      <p>查看 bundle 版本、租户绑定，以及某个租户当前生效的实际规则。</p>
    </section>
    <section class='panel'>
      <h2>Policy Bundles</h2>
      <table>
        <thead><tr><th>Bundle</th><th>Created By</th><th>Change Summary</th><th>Created</th></tr></thead>
        <tbody>{bundle_rows}</tbody>
      </table>
    </section>
    <section class='panel'>
      <h2>Tenant Bindings</h2>
      <table>
        <thead><tr><th>Tenant</th><th>Bundle</th><th>State</th><th>Updated</th></tr></thead>
        <tbody>{binding_rows}</tbody>
      </table>
    </section>
    <section class='panel'>
      <h2>Effective Rules</h2>
      <form class='filters' method='get' action='/console/policies'>
        <label>Tenant
          <select name='tenant_id'>
            {tenant_options}
          </select>
        </label>
        <button type='submit'>Load Rules</button>
      </form>
      {detail_html}
    </section>
    """
    return _render_console_layout("Policies", body)


def _render_console_distribution_page(
    control_store: ControlPlaneStore | None,
    query: dict[str, list[str]],
) -> str:
    tenant_id = query.get("tenant_id", [""])[0] or None
    items = control_store.list_distribution_status(limit=100, tenant_id=tenant_id) if control_store is not None else []
    rows = _rows_or_empty(
        [
            (
                item.get("instance_id", ""),
                item.get("tenant_id", ""),
                item.get("bundle_version", ""),
                item.get("status", ""),
                item.get("updated_at", ""),
            )
            for item in items
        ],
        columns=5,
    )
    tenant_value = escape(tenant_id or "")
    body = f"""
    <section class='hero'>
      <h1>Distribution</h1>
      <p>查看规则分发是否已经同步到各个 gateway 实例。</p>
    </section>
    <section class='panel'>
      <form class='filters' method='get' action='/console/distribution'>
        <label>Tenant <input type='text' name='tenant_id' value='{tenant_value}' placeholder='tenant-a' /></label>
        <button type='submit'>Filter</button>
      </form>
      <table>
        <thead><tr><th>Instance</th><th>Tenant</th><th>Bundle</th><th>Status</th><th>Updated</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    """
    return _render_console_layout("Distribution", body)


def _render_console_audit_page(
    service: DefenseGatewayService,
    query: dict[str, list[str]],
) -> str:
    tenant_id = query.get("tenant_id", [""])[0] or None
    session_id = query.get("session_id", [""])[0] or None
    request_id = query.get("request_id", [""])[0] or None
    event_type = query.get("event_type", [""])[0] or None
    destination_host = query.get("destination_host", [""])[0] or None
    items = service.audit.search_events(
        tenant_id=tenant_id,
        session_id=session_id,
        request_id=request_id,
        event_type=event_type,
        destination_host=destination_host,
        limit=100,
    )
    rows = []
    for item in items:
        risk_flags = ", ".join(item.metadata.get("risk_flags") or []) or "none"
        rows.append(
            "<tr>"
            f"<td>{escape(item.created_at)}</td>"
            f"<td>{escape(item.tenant_id)}</td>"
            f"<td>{escape(item.session_id)}</td>"
            f"<td>{escape(item.request_id)}</td>"
            f"<td>{escape(item.event_type)}</td>"
            f"<td>{escape(item.decision or '')}</td>"
            f"<td>{escape(item.metadata.get('destination_host') or item.metadata.get('origin') or '')}</td>"
            f"<td>{escape(risk_flags)}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='8'>No matching events.</td></tr>"
    body = f"""
    <section class='hero'>
      <h1>Audit Search</h1>
      <p>按 tenant、session、request、event type 和 destination 检索事件链。</p>
    </section>
    <section class='panel'>
      <form class='filters audit-filters' method='get' action='/console/audit'>
        <label>Tenant <input type='text' name='tenant_id' value='{escape(tenant_id or '')}' /></label>
        <label>Session <input type='text' name='session_id' value='{escape(session_id or '')}' /></label>
        <label>Request <input type='text' name='request_id' value='{escape(request_id or '')}' /></label>
        <label>Event <input type='text' name='event_type' value='{escape(event_type or '')}' /></label>
        <label>Destination <input type='text' name='destination_host' value='{escape(destination_host or '')}' /></label>
        <button type='submit'>Search</button>
      </form>
      <table>
        <thead><tr><th>Created</th><th>Tenant</th><th>Session</th><th>Request</th><th>Event</th><th>Decision</th><th>Origin / Destination</th><th>Risk Flags</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </section>
    """
    return _render_console_layout("Audit Search", body)


def _render_console_layout(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>{escape(title)} · TrustLayer</title>
    <style>
      :root {{
        --bg: #f6efe3;
        --surface: #fffaf4;
        --ink: #1e293b;
        --muted: #64748b;
        --line: #d8c9ae;
        --accent: #1d4ed8;
        --accent-soft: #dbeafe;
        --danger: #991b1b;
        --warn: #92400e;
      }}
      * {{ box-sizing: border-box; }}
      body {{ margin: 0; background: linear-gradient(180deg, #f3ead9 0%, var(--bg) 100%); color: var(--ink); font-family: Georgia, "Times New Roman", serif; }}
      a {{ color: var(--accent); text-decoration: none; }}
      .shell {{ max-width: 1320px; margin: 0 auto; padding: 24px; }}
      .topbar {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 24px; }}
      .brand {{ font-size: 28px; font-weight: 700; letter-spacing: 0.02em; }}
      .subtitle {{ color: var(--muted); font-size: 14px; }}
      .nav {{ display: flex; gap: 10px; flex-wrap: wrap; }}
      .nav a {{ padding: 10px 14px; border: 1px solid var(--line); border-radius: 999px; background: rgba(255,255,255,0.65); }}
      .hero {{ margin-bottom: 18px; }}
      .hero h1 {{ margin: 0 0 8px; font-size: 36px; }}
      .hero p {{ margin: 0; color: var(--muted); max-width: 760px; line-height: 1.5; }}
      .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin: 20px 0 28px; }}
      .card, .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 18px; box-shadow: 0 8px 20px rgba(85, 67, 24, 0.06); }}
      .card {{ padding: 18px; }}
      .card-label {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; }}
      .card-value {{ margin-top: 10px; font-size: 30px; font-weight: 700; }}
      .panel {{ padding: 20px; margin-bottom: 20px; }}
      .grid.two-up {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
      h2 {{ margin: 0 0 14px; font-size: 22px; }}
      table {{ width: 100%; border-collapse: collapse; }}
      th, td {{ border-top: 1px solid var(--line); padding: 10px 12px; text-align: left; vertical-align: top; font-size: 14px; }}
      th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }}
      .filters {{ display: flex; gap: 12px; flex-wrap: wrap; align-items: end; margin-bottom: 16px; }}
      .filters label {{ display: grid; gap: 6px; font-size: 13px; color: var(--muted); }}
      .filters input, .filters select {{ min-width: 170px; padding: 10px 12px; border: 1px solid var(--line); border-radius: 12px; background: white; }}
      button {{ padding: 10px 14px; border: 1px solid #a7c3ff; border-radius: 12px; background: var(--accent-soft); color: #1e3a8a; cursor: pointer; }}
      .audit-filters input {{ min-width: 140px; }}
      .rule-stack {{ display: grid; gap: 18px; }}
      .rule-subgrid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
      .hint {{ color: var(--muted); font-size: 14px; }}
      code {{ background: #f2eadc; padding: 2px 6px; border-radius: 8px; }}
      @media (max-width: 900px) {{
        .grid.two-up {{ grid-template-columns: 1fr; }}
        .rule-subgrid {{ grid-template-columns: 1fr; }}
        .topbar {{ align-items: start; flex-direction: column; }}
      }}
    </style>
  </head>
  <body>
    <div class="shell">
      <div class="topbar">
        <div>
          <div class="brand">TrustLayer</div>
          <div class="subtitle">Control plane view for gateway, policy distribution, and audit evidence.</div>
        </div>
        <nav class="nav">
          <a href="/console/dashboard">Dashboard</a>
          <a href="/console/policies">Policies</a>
          <a href="/console/distribution">Distribution</a>
          <a href="/console/audit">Audit Search</a>
          <a href="/approvals/queue?tenant_id=demo">Approval Queue</a>
        </nav>
      </div>
      {body}
    </div>
  </body>
</html>"""


def _rows_or_empty(rows: list[tuple[Any, ...]], *, columns: int) -> str:
    if not rows:
        return f"<tr><td colspan='{columns}'>No data yet.</td></tr>"
    return "\n".join(
        "<tr>" + "".join(f"<td>{escape(str(value or ''))}</td>" for value in row) + "</tr>"
        for row in rows
    )


def _render_policy_bundle_detail(
    tenant_id: str,
    document: dict[str, Any] | None,
    error: str | None,
) -> str:
    if error:
        return f"<p class='hint'>{escape(error)}</p>"
    if not document:
        return "<p class='hint'>Pick a tenant to view its currently effective rule bundle.</p>"

    settings = document.get("settings", {})
    source_policies = document.get("source_policies", [])
    detector_rules = document.get("detector_rules", [])
    decision_rules = document.get("decision_rules", [])
    approval_summary_rules = document.get("approval_summary_rules", {})

    settings_rows = _rows_or_empty(
        [(key, json.dumps(value, ensure_ascii=True, sort_keys=True)) for key, value in sorted(settings.items())],
        columns=2,
    )
    source_rows = _rows_or_empty(
        [
            (
                item.get("source_type", ""),
                item.get("trust_level", ""),
                item.get("extractor_kind", ""),
                ", ".join(item.get("static_risk_flags", []) or []),
            )
            for item in source_policies
        ],
        columns=4,
    )
    detector_rows = _rows_or_empty(
        [
            (
                item.get("rule_id", ""),
                item.get("direction", ""),
                item.get("detector_kind", ""),
                item.get("flag_name", ""),
                item.get("policy_id", ""),
                item.get("decision", ""),
            )
            for item in detector_rules
        ],
        columns=6,
    )
    decision_rows = _rows_or_empty(
        [
            (
                item.get("rule_id", ""),
                item.get("direction", ""),
                item.get("decision", ""),
                ", ".join(item.get("when_any_flags", []) or []),
                item.get("event_type", ""),
                item.get("priority", ""),
            )
            for item in decision_rules
        ],
        columns=6,
    )
    summary_rows = _rows_or_empty(
        [(flag, text) for flag, text in sorted(approval_summary_rules.items())],
        columns=2,
    )
    bundle_version = settings.get("policy_bundle_version", "unknown")
    return f"""
    <div class='rule-stack'>
      <p class='hint'>Tenant <code>{escape(tenant_id)}</code> is currently running bundle <code>{escape(str(bundle_version))}</code>.</p>
      <div class='rule-subgrid'>
        <div>
          <h3>Settings</h3>
          <table>
            <thead><tr><th>Key</th><th>Value</th></tr></thead>
            <tbody>{settings_rows}</tbody>
          </table>
        </div>
        <div>
          <h3>Approval Summary Rules</h3>
          <table>
            <thead><tr><th>Flag</th><th>Summary</th></tr></thead>
            <tbody>{summary_rows}</tbody>
          </table>
        </div>
      </div>
      <div>
        <h3>Source Policies</h3>
        <table>
          <thead><tr><th>Source Type</th><th>Trust Level</th><th>Extractor</th><th>Static Flags</th></tr></thead>
          <tbody>{source_rows}</tbody>
        </table>
      </div>
      <div>
        <h3>Detector Rules</h3>
        <table>
          <thead><tr><th>Rule ID</th><th>Direction</th><th>Kind</th><th>Flag</th><th>Policy ID</th><th>Decision</th></tr></thead>
          <tbody>{detector_rows}</tbody>
        </table>
      </div>
      <div>
        <h3>Decision Rules</h3>
        <table>
          <thead><tr><th>Rule ID</th><th>Direction</th><th>Decision</th><th>When Any Flags</th><th>Event Type</th><th>Priority</th></tr></thead>
          <tbody>{decision_rows}</tbody>
        </table>
      </div>
    </div>
    """
