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


@dataclass(frozen=True)
class MCPToolSpec:
    name: str
    description: str
    source_type: str
    trust_level: str = "untrusted"
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class MCPToolResult:
    source_type: str
    origin: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class MCPToolAdapter(Protocol):
    def spec(self) -> MCPToolSpec:
        ...

    def fetch(self, arguments: dict[str, Any]) -> MCPToolResult:
        ...


class CallableMCPToolAdapter:
    def __init__(
        self,
        *,
        name: str,
        description: str,
        source_type: str,
        handler: Callable[[dict[str, Any]], MCPToolResult],
        tags: tuple[str, ...] = (),
    ) -> None:
        self._spec = MCPToolSpec(
            name=name,
            description=description,
            source_type=source_type,
            tags=tags,
        )
        self._handler = handler

    def spec(self) -> MCPToolSpec:
        return self._spec

    def fetch(self, arguments: dict[str, Any]) -> MCPToolResult:
        result = self._handler(arguments)
        if result.source_type != self._spec.source_type:
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
        self._spec = MCPToolSpec(
            name=name,
            description=description,
            source_type="web_page",
            tags=("remote", "web"),
        )
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def spec(self) -> MCPToolSpec:
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
        self._spec = MCPToolSpec(
            name=name,
            description=description,
            source_type="rag_chunk",
            tags=("remote", "rag", "json"),
        )
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def spec(self) -> MCPToolSpec:
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
                    "source_type": spec.source_type,
                    "trust_level": spec.trust_level,
                    "tags": list(spec.tags),
                }
            )
        return items

    def fetch_tool(
        self,
        *,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ToolNotFoundError(tool_name)

        request_id = f"mcpreq_{uuid.uuid4().hex[:12]}"
        self.defense.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="mcp_tool_invoked",
            summary=f"MCP gateway invoked {tool_name}",
            metadata={"tool_name": tool_name, "arguments": arguments},
        )

        tool_result = tool.fetch(arguments)
        self.defense.audit.append_event(
            session_id=session_id,
            request_id=request_id,
            tenant_id=tenant_id,
            event_type="mcp_tool_result",
            summary=f"MCP gateway received {tool_name} result",
            metadata={
                "tool_name": tool_name,
                "source_type": tool_result.source_type,
                "origin": tool_result.origin,
                "result_metadata": tool_result.metadata,
            },
        )

        sanitized = self.defense.sanitize_ingress(
            tenant_id=tenant_id,
            session_id=session_id,
            source_type=tool_result.source_type,
            origin=tool_result.origin,
            content=tool_result.content,
        )
        return {
            "request_id": request_id,
            "tool_name": tool_name,
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


def build_default_mcp_gateway(defense_service: DefenseGatewayService) -> MCPGatewayService:
    return MCPGatewayService(
        defense_service,
        tools=[RemoteWebFetchAdapter(), RemoteJSONRAGAdapter()],
    )
