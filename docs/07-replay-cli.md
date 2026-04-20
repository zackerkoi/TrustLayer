# 模块 6：Replay CLI

更新时间：2026-04-20

## 模块防御目标

Replay CLI 的目标不是替代控制台，而是先解决 PoC 里一个特别实际的问题：

**让我们能在没有前端的情况下，快速把某个 session 的关键审计事件读出来。**

这对两类场景特别重要：

1. 攻防实验复盘
2. 向客户演示“证据链已经建立”

## 设计思路

当前实现保持极简：

- 直接读 SQLite 审计库
- 通过 `session_id` 拉时间线
- 输出人类可读的多行文本

这一步是“最小可用回放能力”，不是最终控制台。

## 关键代码示例

核心格式化逻辑在
[replay.py](../src/trustlayer/replay.py)：

```python
def format_timeline(session_id: str, events: list[dict]) -> str:
    lines = [f"Timeline for session {session_id}"]
    for index, event in enumerate(events, start=1):
        ...
```

CLI 用法：

```bash
PYTHONPATH=src python3 -m trustlayer.replay \
  --db-path audit.sqlite3 \
  --session-id sess_demo
```

## 验证测试设计

新增测试：

- `test_replay_formatter_emits_human_readable_timeline`

这个测试只验证一件事：

**回放输出要对人可读，而不是只是一堆 JSON。**

## 测试过程记录

当前结果：

- Replay 相关场景：`1/1` 通过
- 全量测试：`11/11` 通过

## 当前限制

- 只支持 `session_id` 回放
- 只输出文本
- 没有过滤、分页和事件高亮

## 下一步演进

- 支持按 `event_type` 过滤
- 支持输出 markdown 版回放
- 如果控制台需求变强，再迁移到前端界面
