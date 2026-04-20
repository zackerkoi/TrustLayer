# 模块 4：HTTP API

更新时间：2026-04-20

## 模块防御目标

HTTP API 的目标不是做完整平台，而是提供最小集成面，让外部 Agent 或工作流能把输入、输出和审计查询接进来。

当前只暴露四个接口：

- `GET /healthz`
- `POST /v1/ingress/sanitize`
- `POST /v1/egress/check`
- `GET /v1/sessions/<session_id>/timeline`

## 设计思路

当前使用 WSGI 而不是框架，是为了：

- 零额外依赖
- 便于本地运行
- 便于先把 PoC 场景跑通

等策略配置和控制台逐渐丰富后，再决定是否升级到完整 Web 框架。

## 关键代码示例

路由分发在
[app.py](../src/trustlayer/app.py)：

```python
if method == "POST" and path == "/v1/ingress/sanitize":
    ...

if method == "POST" and path == "/v1/egress/check":
    ...

if method == "GET" and path.startswith("/v1/sessions/") and path.endswith("/timeline"):
    ...
```

服务启动在
[main.py](../src/trustlayer/main.py)：

```python
with make_server("127.0.0.1", args.port, app) as server:
    server.serve_forever()
```

## 验证测试设计

当前 HTTP 层主要验证：

1. WSGI 路由可以正常接 ingress 请求
2. timeline 接口可以按 `session_id` 查询

当前相关测试：

- `test_wsgi_timeline_endpoint_returns_session_events`

## 测试过程记录

当前结果：

- HTTP 层核心路径已通过最小验证

## 当前限制

- 还没有请求鉴权
- 还没有统一错误码体系
- 还没有 OpenAPI / schema

## 下一步演进

- 补 replay 接口或 CLI
- 补策略配置接口
- 如果模块继续变复杂，再评估迁移到 FastAPI
