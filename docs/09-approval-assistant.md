# 模块 8：Approval Assistant

更新时间：2026-04-20

## 模块防御目标

这个模块不是完整审批系统，而是一个最小证明：

**当请求已经进入 `review_required` 或 `block` 时，系统不能只丢一串风险标签给人看，而应该给出一句可读的风险摘要。**

它要解决的不是“会不会拦”，而是：

- 人类能不能快速看懂为什么这条请求危险
- 在审批疲劳场景下，真正危险的请求能不能被突出出来

## 设计思路

当前实现非常克制：

- 不引入审批工作流
- 不引入审批状态存储
- 只在 egress 决策结果里生成 `approval_summary`

这样可以先证明一个关键中间价值：

**Starter 不只是把请求拦下来，它还能把风险原因翻译成审批者看得懂的话。**

## 关键代码示例

核心逻辑在
[service.py](../src/trustlayer/service.py)：

```python
approval_summary = self._approval_summary(
    decision=decision,
    destination_host=destination_host,
    risk_flags=risk_flags,
)
```

摘要生成规则：

```python
if "secret_detected" in risk_flags:
    reasons.append("contains secret material")
if "pii_detected" in risk_flags:
    reasons.append("contains PII")
if "new_domain" in risk_flags:
    reasons.append("targets a new destination")
if "payload_oversized" in risk_flags:
    reasons.append("payload is oversized")
```

## 验证测试设计

当前审批摘要相关测试有四类：

1. `test_egress_reviews_new_domain_with_pii`
   验证 review 摘要里能明确出现 `new destination` 和 `PII`

2. `test_egress_block_summary_mentions_secret_exfiltration`
   验证 block 摘要里能明确出现 `secret`

3. `test_approval_assistant_turns_a_noisy_request_into_a_clear_review_signal`
   验证一个 noisy request 会被翻译成更清晰的审批说明

4. `test_approval_fatigue_scenario_highlights_the_final_risky_request`
   验证在多条 routine review 请求之后，最终危险请求仍能被突出

5. `test_approval_social_engineering_summary_overrides_reassuring_request_wording`
   验证摘要不会复述“already approved / low risk”这类误导性审批话术

6. `test_false_safe_wording_cannot_mask_secret_block_reason`
   验证“safe to send / routine maintenance”这类伪安全措辞，不能掩盖真正的 secret 风险

## 测试过程记录

当前结果：

- 审批摘要相关场景：`6/6` 通过
- 全量测试：`25/25` 通过

## 当前价值

这一步的价值不在“又加了一条规则”，而在于它开始证明：

- Review gate 不是黑盒
- 风险原因可以被人类快速理解
- 在审批疲劳场景中，系统有机会减少“看一眼就批”的误操作
- 即使攻击者主动把请求包装成“已批准、低风险、例行操作”，摘要仍然能用独立风险事实覆盖这层包装

## 当前限制

- 还没有真正的人类审批状态机
- 没有批量审批队列视图
- 没有风险优先级排序

## 下一步演进

- 增加审批请求结构化对象
- 增加按风险等级排序的审批队列
- 补更接近真实 UI 的审批队列视图或导出格式
