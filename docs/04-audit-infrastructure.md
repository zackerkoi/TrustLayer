# 模块 3：Audit Infrastructure

更新时间：2026-04-20

## 模块防御目标

审计模块的目标不是“保存聊天记录”，而是保证关键动作链路能被独立记录和回放。

Starter 里优先保证三件事：

1. 输入事件可见
2. 外发事件可见
3. 策略命中和最终决策可回放

## 设计思路

当前版本用 SQLite 做独立事件存储，原因很现实：

- 标准库可用
- 本地 PoC 易部署
- 对时间线查询足够

为了兼容性，当前实现刻意避免依赖 SQLite 的 JSON 扩展函数，而是在 Python 层解析 `metadata_json`。

## 关键代码示例

事件写入在
[audit.py](../src/trustlayer/audit.py)：

```python
conn.execute(
    """
    INSERT INTO events (
        event_id, session_id, request_id, tenant_id, event_type,
        decision, policy_id, summary, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
)
```

时间线查询：

```python
SELECT event_id, session_id, request_id, tenant_id, event_type,
       decision, policy_id, summary, metadata_json, created_at
FROM events
WHERE session_id = ?
ORDER BY rowid ASC
```

## 事件设计

当前重点事件有：

- `source_received`
- `source_sanitized`
- `policy_matched`
- `egress_attempted`
- `egress_scanned`
- `destination_new_domain`
- `egress_blocked`
- `egress_review_required`
- `egress_allowed`

## 验证测试设计

当前审计相关验证主要分两类：

1. 服务层直接查 `timeline(session_id)`
2. HTTP 层查 `/v1/sessions/<id>/timeline`

重点看：

- 事件顺序是否正确
- 事件数量是否完整
- 决策和策略是否可见

## 测试过程记录

当前已通过：

- Ingress 后时间线包含 `source_received -> policy_matched -> source_sanitized`
- Egress 阻断后时间线包含 `egress_blocked`
- HTTP timeline 接口可返回 session 级事件

## 当前限制

- 只有单表事件存储
- 还没有统计聚合视图
- 还没有 replay 脚本输出格式

## 下一步演进

- 增加 replay CLI
- 增加按 event type / policy_id 查询
- 增加统计接口
