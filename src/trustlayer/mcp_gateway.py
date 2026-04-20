from __future__ import annotations

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
