from __future__ import annotations

import json
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .service import DefenseGatewayService


class MCPGatewayError(Exception):
    pass


class ToolNotFoundError(MCPGatewayError):
    pass


class ToolDirectionNotSupportedError(MCPGatewayError):
    pass


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    description: str
    direction: str = "ingress"
    trust_tier: str = "untrusted"
    source_type: str | None = None
    destination_type: str | None = None
    tags: tuple[str, ...] = ()


MCPToolSpec = ToolDescriptor


@dataclass(frozen=True)
class MCPToolResult:
    source_type: str
    origin: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class MCPToolAdapter(Protocol):
    def spec(self) -> ToolDescriptor:
        ...

    def fetch(self, arguments: dict[str, Any]) -> MCPToolResult:
        ...


class CallableMCPToolAdapter:
    def __init__(
        self,
        *,
        name: str,
        description: str,
        source_type: str | None,
        handler: Callable[[dict[str, Any]], MCPToolResult],
        direction: str = "ingress",
        trust_tier: str = "untrusted",
        destination_type: str | None = None,
        tags: tuple[str, ...] = (),
    ) -> None:
        self._spec = ToolDescriptor(
            name=name,
            description=description,
            direction=direction,
            trust_tier=trust_tier,
            source_type=source_type,
            destination_type=destination_type,
            tags=tags,
        )
        self._handler = handler

    def spec(self) -> ToolDescriptor:
        return self._spec

    def fetch(self, arguments: dict[str, Any]) -> MCPToolResult:
        result = self._handler(arguments)
        if self._spec.source_type and result.source_type != self._spec.source_type:
            return MCPToolResult(
                source_type=self._spec.source_type,
                origin=result.origin,
                content=result.content,
                metadata=result.metadata,
            )
        return result


class RemoteWebFetchAdapter:
    def __init__(
        self,
        *,
        name: str = "remote_web_fetch",
        description: str = "Fetches a remote web page through TrustLayer MCP Gateway.",
        timeout_seconds: int = 10,
        max_bytes: int = 200_000,
    ) -> None:
        self._spec = ToolDescriptor(
            name=name,
            description=description,
            direction="ingress",
            trust_tier="untrusted",
            source_type="web_page",
            tags=("remote", "web"),
        )
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def spec(self) -> ToolDescriptor:
        return self._spec

    def fetch(self, arguments: dict[str, Any]) -> MCPToolResult:
        url = str(arguments["url"])
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "TrustLayer-MCP-Gateway/0.1"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            body = response.read(self.max_bytes)
            charset = response.headers.get_content_charset() or "utf-8"
            content = body.decode(charset, errors="ignore")
            return MCPToolResult(
                source_type="web_page",
                origin=response.geturl(),
                content=content,
                metadata={
                    "status_code": getattr(response, "status", None),
                    "content_type": response.headers.get("Content-Type"),
                    "fetched_url": url,
                    "bytes_read": len(body),
                },
            )


class RemoteJSONRAGAdapter:
    def __init__(
        self,
        *,
        name: str = "remote_rag_fetch",
        description: str = "Fetches a remote JSON document and extracts a RAG chunk through TrustLayer MCP Gateway.",
        timeout_seconds: int = 10,
        max_bytes: int = 200_000,
    ) -> None:
        self._spec = ToolDescriptor(
            name=name,
            description=description,
            direction="ingress",
            trust_tier="untrusted",
            source_type="rag_chunk",
            tags=("remote", "rag", "json"),
        )
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def spec(self) -> ToolDescriptor:
        return self._spec

    def fetch(self, arguments: dict[str, Any]) -> MCPToolResult:
        url = str(arguments["url"])
        content_field = str(arguments.get("content_field", "content"))
        title_field = str(arguments.get("title_field", "title"))
        id_field = str(arguments.get("id_field", "doc_id"))
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "TrustLayer-MCP-Gateway/0.1"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            body = response.read(self.max_bytes)
            charset = response.headers.get_content_charset() or "utf-8"
            payload = json.loads(body.decode(charset, errors="ignore"))

        extracted = payload.get(content_field, "")
        if isinstance(extracted, list):
            content = "\n".join(str(item) for item in extracted)
        else:
            content = str(extracted)

        title = payload.get(title_field)
        doc_id = payload.get(id_field)
        prefix_parts = [str(part) for part in (title, doc_id) if part]
        if prefix_parts:
            content = " | ".join(prefix_parts) + "\n" + content

        return MCPToolResult(
            source_type="rag_chunk",
            origin=url,
            content=content,
            metadata={
                "title": title,
                "doc_id": doc_id,
                "content_field": content_field,
                "title_field": title_field,
                "id_field": id_field,
                "bytes_read": len(body),
            },
        )


class MCPGatewayService:
    def __init__(
        self,
        defense_service: DefenseGatewayService,
        tools: list[MCPToolAdapter] | None = None,
    ) -> None:
        self.defense = defense_service
        self._tools = {tool.spec().name: tool for tool in (tools or [])}

    def list_tools(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for name in sorted(self._tools):
            spec = self._tools[name].spec()
            items.append(
                {
                    "name": spec.name,
                    "description": spec.description,
                    "direction": spec.direction,
                    "source_type": spec.source_type,
                    "destination_type": spec.destination_type,
                    "trust_tier": spec.trust_tier,
                    "trust_level": spec.trust_tier,
                    "tags": list(spec.tags),
                }
            )
        return items

    def resolve_egress_tool(self, destination_type: str) -> ToolDescriptor | None:
        for name in sorted(self._tools):
            spec = self._tools[name].spec()
            if spec.direction == "egress" and spec.destination_type == destination_type:
                return spec
        return None

    def resolve_tool(self, tool_name: str) -> ToolDescriptor | None:
        tool = self._tools.get(tool_name)
        if tool is None:
            return None
        return tool.spec()

    def fetch_tool(
        self,
        *,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return self.invoke_tool(
            tenant_id=tenant_id,
            session_id=session_id,
            tool_name=tool_name,
            direction="ingress",
            arguments=arguments,
        )

    def sanitize_supplied_tool_result(
        self,
        *,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        source_type: str,
        origin: str,
        content: str,
        result_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ToolNotFoundError(tool_name)
        spec = tool.spec()
        if spec.direction != "ingress":
            raise ToolDirectionNotSupportedError(f"{tool_name}:{spec.direction}")

        request_id = f"mcpreq_{uuid.uuid4().hex[:12]}"
        audit_metadata = {
            "tool_name": tool_name,
            "direction": spec.direction,
            "trust_tier": spec.trust_tier,
            "tool_tags": list(spec.tags),
        }
        effective_source_type = spec.source_type or source_type
        self.defense.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="mcp_tool_result",
            summary=f"MCP gateway accepted supplied {tool_name} result",
            metadata={
                **audit_metadata,
                "source_type": effective_source_type,
                "origin": origin,
                "result_metadata": result_metadata or {},
                "tool_output_excerpt": self._excerpt(content, limit=400),
                "tool_output_length": len(content),
            },
        )
        sanitized = self.defense.sanitize_ingress(
            tenant_id=tenant_id,
            session_id=session_id,
            source_type=effective_source_type,
            origin=origin,
            content=content,
            request_id=request_id,
            audit_metadata=audit_metadata,
        )
        return {
            "request_id": request_id,
            "tool_name": tool_name,
            "tool": {
                "name": spec.name,
                "direction": spec.direction,
                "trust_tier": spec.trust_tier,
                "source_type": spec.source_type,
                "destination_type": spec.destination_type,
                "tags": list(spec.tags),
            },
            "source": {
                "origin": origin,
                "source_type": effective_source_type,
                "metadata": result_metadata or {},
            },
            "decision": sanitized.decision,
            "risk_flags": sanitized.risk_flags,
            "matched_policies": sanitized.matched_policies,
            "sanitized_content": sanitized.payload,
        }

    def invoke_tool(
        self,
        *,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        direction: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ToolNotFoundError(tool_name)
        spec = tool.spec()
        if spec.direction != direction:
            raise ToolDirectionNotSupportedError(f"{tool_name}:{spec.direction}")

        request_id = f"mcpreq_{uuid.uuid4().hex[:12]}"
        audit_metadata = {
            "tool_name": tool_name,
            "direction": spec.direction,
            "trust_tier": spec.trust_tier,
            "tool_tags": list(spec.tags),
        }
        self.defense.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="mcp_tool_invoked",
            summary=f"MCP gateway invoked {tool_name}",
            metadata={
                **audit_metadata,
                "arguments": arguments,
                "arguments_pretty": json.dumps(arguments, ensure_ascii=True, sort_keys=True),
            },
        )

        if spec.direction == "egress":
            return self._invoke_egress_tool(
                tenant_id=tenant_id,
                session_id=session_id,
                request_id=request_id,
                spec=spec,
                arguments=arguments,
                audit_metadata=audit_metadata,
            )

        tool_result = tool.fetch(arguments)
        self.defense.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="mcp_tool_result",
            summary=f"MCP gateway received {tool_name} result",
            metadata={
                **audit_metadata,
                "source_type": tool_result.source_type,
                "origin": tool_result.origin,
                "result_metadata": tool_result.metadata,
                "tool_output_excerpt": self._excerpt(tool_result.content, limit=400),
                "tool_output_length": len(tool_result.content),
            },
        )

        sanitized = self.defense.sanitize_ingress(
            tenant_id=tenant_id,
            session_id=session_id,
            source_type=tool_result.source_type,
            origin=tool_result.origin,
            content=tool_result.content,
            request_id=request_id,
            audit_metadata=audit_metadata,
        )
        return {
            "request_id": request_id,
            "tool_name": tool_name,
            "tool": {
                "name": spec.name,
                "direction": spec.direction,
                "trust_tier": spec.trust_tier,
                "source_type": spec.source_type,
                "destination_type": spec.destination_type,
                "tags": list(spec.tags),
            },
            "arguments": arguments,
            "source": {
                "origin": tool_result.origin,
                "source_type": tool_result.source_type,
                "metadata": tool_result.metadata,
            },
            "decision": sanitized.decision,
            "risk_flags": sanitized.risk_flags,
            "matched_policies": sanitized.matched_policies,
            "sanitized_content": sanitized.payload,
        }

    def _invoke_egress_tool(
        self,
        *,
        tenant_id: str,
        session_id: str,
        request_id: str,
        spec: ToolDescriptor,
        arguments: dict[str, Any],
        audit_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        destination = str(arguments["destination"])
        payload = str(arguments["payload"])
        request_excerpt = str(arguments.get("request_excerpt", "") or "")
        destination_type = spec.destination_type or str(arguments.get("destination_type", "external"))
        self.defense.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="mcp_tool_routed",
            summary=f"MCP gateway routed {spec.name} to egress pipeline",
            metadata={
                **audit_metadata,
                "destination": destination,
                "destination_type": destination_type,
                "payload_excerpt": self._excerpt(payload, limit=400),
                "payload_length": len(payload),
                "approval_request_excerpt": self._excerpt(request_excerpt, limit=400) if request_excerpt else None,
            },
        )
        decision = self.defense.check_egress(
            tenant_id=tenant_id,
            session_id=session_id,
            destination=destination,
            destination_type=destination_type,
            payload=payload,
            request_excerpt=request_excerpt or None,
            request_id=request_id,
            audit_metadata=audit_metadata,
        )
        return {
            "request_id": request_id,
            "tool_name": spec.name,
            "tool": {
                "name": spec.name,
                "direction": spec.direction,
                "trust_tier": spec.trust_tier,
                "source_type": spec.source_type,
                "destination_type": spec.destination_type,
                "tags": list(spec.tags),
            },
            "arguments": arguments,
            "decision": decision.decision,
            "risk_flags": decision.risk_flags,
            "matched_policies": decision.matched_policies,
            "egress": decision.payload,
        }

    def _excerpt(self, value: str, *, limit: int) -> str:
        normalized = " ".join(value.split())
        if len(normalized) <= limit:
            return normalized
        return normalized[:limit] + "..."


def build_default_mcp_gateway(defense_service: DefenseGatewayService) -> MCPGatewayService:
    return MCPGatewayService(
        defense_service,
        tools=[
            RemoteWebFetchAdapter(),
            RemoteJSONRAGAdapter(),
            CallableMCPToolAdapter(
                name="webhook_post",
                description="Routes outbound webhook payloads through TrustLayer egress policy.",
                source_type="internal",
                direction="egress",
                trust_tier="trusted",
                destination_type="webhook",
                tags=("egress", "webhook"),
                handler=lambda arguments: MCPToolResult(
                    source_type="internal",
                    origin=f"egress://{arguments.get('destination', 'unknown')}",
                    content=str(arguments.get("payload", "")),
                    metadata={"destination": arguments.get("destination")},
                ),
            ),
        ],
    )
