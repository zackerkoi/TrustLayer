# 模块 9：Approval Queue

更新时间：2026-04-20

## 模块防御目标

单条 `approval_summary` 能证明系统会解释风险，但还不够像真实操作面。

审批队列模块要解决的是：

- 多条待审批请求同时出现时，真正高风险的请求能不能排在前面
- 审批者能不能一眼看到目标地址、决策类型和风险摘要

Starter 阶段我们只做最小队列视图，不做完整审批系统。

## 设计思路

当前队列直接从审计事件聚合：

- 只收 `egress_review_required`
- 和 `egress_blocked`

排序规则保持非常直接：

1. `block`
2. `review_required`

再按时间和请求号稳定排序。

这样虽然简单，但足够证明：

**同样是一堆外发请求，系统可以把最该先看的那条顶到前面。**

## 关键代码示例

聚合逻辑在
[audit.py](../src/trustlayer/audit.py)：

```python
priority = {"block": 0, "review_required": 1}
items.sort(key=lambda item: (priority.get(item["decision"], 99), item["created_at"], item["request_id"]))
```

服务出口：

```python
def approval_queue(self, tenant_id: str, limit: int = 20) -> list[dict[str, Any]]:
    return self.audit.approval_queue(tenant_id, limit=limit)
```

HTTP 接口：

- `GET /v1/approvals/queue?tenant_id=demo`

HTML 页面：

- `GET /approvals/queue?tenant_id=demo`

文本格式化：

```python
def format_approval_queue(items: list[dict]) -> str:
    ...
```

## 验证测试设计

当前审批队列相关测试有两类：

1. `test_approval_queue_prioritizes_blocked_requests_and_exposes_summaries`
   验证队列里 `block` 会排在 `review_required` 前面，并且每条都有 `approval_summary`

2. `test_wsgi_approval_queue_endpoint_returns_prioritized_items`
   验证 HTTP 队列接口返回的数据顺序和字段都正确

3. `test_html_approval_queue_page_renders_prioritized_items`
   验证 HTML 页面可以直观看到优先级顺序、目标地址和审批摘要

## 测试过程记录

当前结果：

- 审批队列相关场景：`3/3` 通过
- 全量测试：`28/28` 通过

## 当前价值

这一步让 PoC 又更像一个可演示产品，而不是只是一堆后端规则。

现在我们已经能同时展示：

- 风险请求如何被检测
- 风险摘要如何生成
- 多条风险请求如何排队
- 审批者最终看到的最小 HTML 队列视图长什么样

## 当前限制

- 还是只读队列，没有真正的审批动作
- 没有风险分数
- 没有按租户/会话筛选以外的高级检索

## 下一步演进

- 增加风险分级和排序权重
- 增加“批准 / 拒绝”模拟动作
- 把 HTML 队列升级成更像真实审批面板的交互页面
