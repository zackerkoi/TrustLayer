# TrustLayer

这是一个独立的最小工程，用来实现 `TrustLayer` 第一阶段的网关和审计基础设施。

当前实现覆盖三类能力：

- `ingress sanitize`：来源分级、隐藏内容剥离、超长文本裁剪、风险打标
- `egress check`：secret / PII 扫描、新域名检测、外发决策
- `audit timeline`：按 `session_id` 回放关键事件

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
- `GET /v1/sessions/<session_id>/timeline`
- `GET /v1/approvals/queue?tenant_id=<tenant>`
- `GET /approvals/queue?tenant_id=<tenant>`
- `GET /healthz`

## 当前场景覆盖

- 网页隐藏内容剥离
- MCP 返回值默认不可信
- Secret 外发阻断
- 新域名 + PII 外发提级
- 审计时间线回放
