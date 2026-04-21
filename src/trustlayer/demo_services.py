from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


@dataclass
class DemoEnvironmentState:
    outbound_posts: list[dict[str, Any]] = field(default_factory=list)


class _ScenarioHandler(BaseHTTPRequestHandler):
    supplier_template = (
        Path(__file__).resolve().parents[2] / "fixtures" / "demo_supplier_research.html"
    ).read_text(encoding="utf-8")
    support_template = (
        Path(__file__).resolve().parents[2] / "fixtures" / "demo_support_brief.txt"
    ).read_text(encoding="utf-8")

    def do_GET(self):  # noqa: N802
        state: DemoEnvironmentState = self.server.state  # type: ignore[attr-defined]
        if self.path == "/supplier/acme":
            collector_url = f"{self.server.base_url}/collect/supplier-contacts"  # type: ignore[attr-defined]
            body = self.supplier_template.replace("{{collector_url}}", collector_url).encode("utf-8")
            self._respond(200, body, "text/html; charset=utf-8")
            return
        if self.path == "/support/inc-4921":
            support_upload_url = f"{self.server.base_url}/collect/support-upload"  # type: ignore[attr-defined]
            body = self.support_template.replace("{{support_upload_url}}", support_upload_url).encode("utf-8")
            self._respond(200, body, "text/plain; charset=utf-8")
            return
        if self.path == "/state":
            body = json.dumps({"outbound_posts": state.outbound_posts}, ensure_ascii=True).encode("utf-8")
            self._respond(200, body, "application/json; charset=utf-8")
            return
        self._respond(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802
        state: DemoEnvironmentState = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        state.outbound_posts.append(
            {
                "path": self.path,
                "body": body,
                "content_type": self.headers.get("Content-Type"),
            }
        )
        self._respond(200, b'{"ok":true}', "application/json; charset=utf-8")

    def log_message(self, format, *args):  # noqa: A003
        return

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ScenarioHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.state = DemoEnvironmentState()
        host, port = self.server_address
        self.base_url = f"http://{host}:{port}"


@dataclass
class DemoEnvironment:
    server: _ScenarioHTTPServer
    thread: threading.Thread

    @property
    def base_url(self) -> str:
        return self.server.base_url

    @property
    def supplier_url(self) -> str:
        return f"{self.base_url}/supplier/acme"

    @property
    def support_url(self) -> str:
        return f"{self.base_url}/support/inc-4921"

    @property
    def supplier_collector_url(self) -> str:
        return f"{self.base_url}/collect/supplier-contacts"

    @property
    def support_upload_url(self) -> str:
        return f"{self.base_url}/collect/support-upload"

    @property
    def outbound_posts(self) -> list[dict[str, Any]]:
        return list(self.server.state.outbound_posts)

    def reset(self) -> None:
        self.server.state.outbound_posts.clear()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def start_demo_environment() -> DemoEnvironment:
    server = _ScenarioHTTPServer(("127.0.0.1", 0), _ScenarioHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return DemoEnvironment(server=server, thread=thread)
