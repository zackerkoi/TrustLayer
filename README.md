# TrustLayer

这是一个独立的最小工程，用来实现 `TrustLayer` 第一阶段的网关和审计基础设施。

当前实现覆盖三类能力：

- `ingress sanitize`：来源分级、隐藏内容剥离、超长文本裁剪、风险打标
- `egress check`：secret / PII 扫描、新域名检测、外发决策
- `audit timeline`：按 `session_id` 回放关键事件
- `mcp gateway`：统一代理 MCP / skill 风格输入，并复用 ingress sanitize

当前迁移策略是：

- `POST /v1/mcp/invoke` 作为统一新入口
- `POST /v1/egress/check` 在存在匹配 egress tool 时，会自动转到 unified invoke
- 其他未映射的 egress 类型仍保留旧路径，避免一次性打断兼容性

## 快速开始

运行测试：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

启动本地 HTTP 服务：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.main --port 8080
```

带外部策略文件启动：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.main --port 8080 --policy-file config/policy.example.json
```

回放某个 session 的审计时间线：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.replay --db-path audit.sqlite3 --session-id sess_demo
```

运行最小评估框架：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.evaluation
```

可用接口：

- `POST /v1/ingress/sanitize`
- `POST /v1/egress/check`
- `GET /v1/mcp/tools`
- `POST /v1/mcp/tools/fetch`
- `POST /v1/mcp/invoke`
- `GET /v1/sessions/<session_id>/timeline`
- `GET /v1/approvals/queue?tenant_id=<tenant>`
- `GET /approvals/queue?tenant_id=<tenant>`
- `GET /healthz`

默认 MCP 入口工具：

- `remote_web_fetch`：通过真实远程 HTTP 抓取网页，并在返回给 Agent 前自动做 sanitize
- `remote_rag_fetch`：通过真实远程 HTTP 拉取 JSON 文档，并抽成 `rag_chunk`

最小 fetch 示例：

```bash
curl -s http://127.0.0.1:8080/v1/mcp/tools/fetch \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "demo",
    "session_id": "sess_remote_fetch",
    "tool_name": "remote_web_fetch",
    "arguments": {
      "url": "https://raw.githubusercontent.com/zackerkoi/TrustLayer/main/fixtures/remote_hidden_supplier.html"
    }
  }'
```

最小 RAG fetch 示例：

```bash
curl -s http://127.0.0.1:8080/v1/mcp/tools/fetch \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "demo",
    "session_id": "sess_remote_rag",
    "tool_name": "remote_rag_fetch",
    "arguments": {
      "url": "https://raw.githubusercontent.com/zackerkoi/TrustLayer/main/fixtures/remote_rag_chunk.json"
    }
  }'
```

最小 unified invoke 示例：

```bash
curl -s http://127.0.0.1:8080/v1/mcp/invoke \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "demo",
    "session_id": "sess_invoke_egress",
    "tool_name": "webhook_post",
    "direction": "egress",
    "arguments": {
      "destination": "https://hooks.example.net/collect",
      "payload": "Contact alice@example.com for the next update."
    }
  }'
```

## 当前场景覆盖

- 网页隐藏内容剥离
- MCP 返回值默认不可信
- Secret 外发阻断
- 新域名 + PII 外发提级
- 审计时间线回放
