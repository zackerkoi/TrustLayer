# TrustLayer 开发笔记索引

更新时间：2026-04-20

这套目录不是产品方案文档，而是开发中的工程笔记。

写法固定按模块拆分，每篇文档都尽量覆盖：

- 模块防御目标
- 设计思路
- 关键代码示例
- 验证测试设计
- 测试过程记录
- 下一步演进方向

## 当前文档

1. [01-overview.md](01-overview.md)
   TrustLayer 基础设施总览、模块边界和当前测试范围。

2. [02-ingress-gateway.md](02-ingress-gateway.md)
   输入治理模块：来源分级、隐藏内容剥离、超长文本裁剪、MCP 返回值不可信打标。

3. [03-egress-gateway.md](03-egress-gateway.md)
   外发控制模块：secret 阻断、PII 提级、新域名治理、外发配额控制。

4. [04-audit-infrastructure.md](04-audit-infrastructure.md)
   独立审计模块：事件存储、时间线回放、审计字段设计。

5. [05-http-api.md](05-http-api.md)
   WSGI 接口、请求路径、最小集成方式与接口测试。

6. [06-policy-config.md](06-policy-config.md)
   外部策略配置：阈值、允许名单和服务注入方式。

7. [07-replay-cli.md](07-replay-cli.md)
   审计回放 CLI：按 session 输出人类可读时间线。

8. [08-realistic-scenario-comparisons.md](08-realistic-scenario-comparisons.md)
   真实业务场景对照测试：无防御如何失守，有防御如何感知、拦截和留痕。

9. [09-approval-assistant.md](09-approval-assistant.md)
   审批摘要模块：把 noisy 风险请求翻译成更清晰的 review 信号。

10. [10-approval-queue.md](10-approval-queue.md)
   审批队列模块：把 block / review 请求聚合成可排序的待处理队列。

11. [11-evaluation-framework.md](11-evaluation-framework.md)
   量化评估框架：统计误报、漏报、正常任务保真率与平均延迟。

12. [12-trustlayer-boundaries.md](12-trustlayer-boundaries.md)
   TrustLayer 第一阶段边界说明：明确承诺、非承诺、已知 blind spot 与升级时机。

13. [13-mcp-gateway.md](13-mcp-gateway.md)
   MCP Gateway：把 ingress 从显式 sanitize API 演进成统一取数入口。

14. [14-unified-mcp-gateway.md](14-unified-mcp-gateway.md)
   Unified MCP Gateway 设计稿：底座合一，Ingress / Egress 策略分流。

## 当前状态

- 基础设施已具备最小可运行版本
- 当前测试总数：`45`
- 当前全部通过
- 下一开发顺序：
  1. 继续扩更真实的业务场景
  2. 如有需要，再补最小前端控制台
