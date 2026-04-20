# TrustLayer

这是一个独立的最小工程，用来实现 `TrustLayer` 第一阶段的网关和审计基础设施。

当前实现覆盖三类能力：

- `ingress sanitize`：来源分级、隐藏内容剥离、超长文本裁剪、风险打标
- `egress check`：secret / PII 扫描、新域名检测、外发决策
- `audit timeline`：按 `session_id` 回放关键事件
- `mcp gateway`：统一代理 MCP / skill 风格输入，并复用 ingress sanitize

当前迁移策略是：

- `POST /v1/mcp/invoke` 作为统一新入口
- `POST /v1/ingress/sanitize` 在带 `tool_name` 时，会补挂到统一 ingress tool identity
- `POST /v1/egress/check` 在存在匹配 egress tool 时，会自动转到 unified invoke
- 其他未映射的 egress 类型仍保留旧路径，避免一次性打断兼容性

## 快速开始

一键部署本地服务：

```bash
cd TrustLayer
bash scripts/deploy-local.sh
```

脚本会自动优先选择可用的 `python3.10+`。

带策略文件启动：

```bash
cd TrustLayer
POLICY_FILE=config/policy.example.json bash scripts/deploy-local.sh
```

当前这份策略文件不再只是阈值样例，而是一份完整的数据库策略包。启动时会先导入 SQLite，再由运行时从库里读取：

- `policy_settings`
- `source_policies`
- `detector_rules`
- `decision_rules`
- `approval_summary_rules`

控制面存储默认还是本地 SQLite，方便开发和 PoC；生产路径已经支持把控制面元数据切到 PostgreSQL DSN：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.main \
  --control-db-path postgresql://trustlayer:secret@localhost:5432/trustlayer
```

如果要启用 PostgreSQL 控制面依赖：

```bash
pip install '.[postgres]'
```

审计回传默认走本地 SQLite 总线，生产路径支持切到 Kafka URL：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.main \
  --audit-bus-url kafka://localhost:9092/trustlayer.audit
```

如果要启用 Kafka 总线依赖：

```bash
pip install '.[kafka]'
```

本地拉起 PostgreSQL 并跑一遍控制面真库集成测试：

```bash
cd TrustLayer
bash scripts/test-control-plane-postgres.sh
```

这个脚本会：

- 启动 [docker-compose.postgres.yml](docker-compose.postgres.yml)
- 安装 `.[postgres]`
- 设置 `TRUSTLAYER_TEST_POSTGRES_DSN`
- 运行 `ControlPlanePostgresIntegrationTest`

运行测试：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

如果你想手动启动服务，也可以直接运行：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.main --port 8080
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

输出一份最小运营报表：

```bash
cd TrustLayer
PYTHONPATH=src python3 -m trustlayer.ops_report --db-path audit.sqlite3
```

运营规则、误报/漏报闭环和指标化方式，可参考：

- [docs/15-operations-sop.md](docs/15-operations-sop.md)
- [docs/16-production-control-plane-architecture.md](docs/16-production-control-plane-architecture.md)

可用接口：

- `POST /v1/ingress/sanitize`
- `POST /v1/egress/check`
- `GET /v1/mcp/tools`
- `POST /v1/mcp/tools/fetch`
- `POST /v1/mcp/invoke`
- `POST /v1/control/policies/publish`
- `POST /v1/control/tenants/bind`
- `GET /v1/control/tenants/<tenant_id>/policy`
- `POST /v1/control/distribution/sync`
- `POST /v1/control/audit/forward`
- `POST /v1/control/audit/consume`
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

最小控制面发布和分发示例：

```bash
curl -s http://127.0.0.1:8080/v1/control/policies/publish \
  -H 'Content-Type: application/json' \
  -d @<(python3 - <<'PY'
import json
from pathlib import Path

document = json.loads(Path("config/policy.example.json").read_text(encoding="utf-8"))
document["settings"]["allowed_destination_hosts"] = ["api.rollout.example"]
print(json.dumps({
    "created_by": "secops@example.com",
    "change_summary": "Roll out a new allowlisted host.",
    "document": document,
}))
PY
)
```

```bash
curl -s http://127.0.0.1:8080/v1/control/tenants/bind \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"demo","bundle_version":"<bundle_version>"}'
```

```bash
curl -s http://127.0.0.1:8080/v1/control/distribution/sync \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"demo","instance_id":"gw-local"}'
```

```bash
curl -s http://127.0.0.1:8080/v1/control/audit/forward \
  -H 'Content-Type: application/json' \
  -d '{"batch_size":100}'
```

```bash
curl -s http://127.0.0.1:8080/v1/control/audit/consume \
  -H 'Content-Type: application/json' \
  -d '{"batch_size":100}'
```

## 当前场景覆盖

- 网页隐藏内容剥离
- MCP 返回值默认不可信
- Secret 外发阻断
- 新域名 + PII 外发提级
- 审计时间线回放
