# 模块 2：Egress Gateway

更新时间：2026-04-20

## 模块防御目标

Egress Gateway 解决的是：

**即使 Agent 被带偏，敏感数据也不要轻易离开系统。**

当前版本重点防四类情况：

1. Secret 外发
2. PII 外发
3. 首次访问新域名
4. 大体量 payload 外发

## 设计思路

Starter 阶段不做复杂决策树，只保留三种结果：

- `allow`
- `block`
- `review_required`

并把规则优先级压成非常明确的顺序：

1. Secret 命中直接 `block`
2. PII / 新域名 / 超大 payload 命中则 `review_required`
3. 其余默认 `allow`

这样做的好处是：

- 客户容易理解
- 实验结果容易解释
- 不会在 PoC 阶段引入太多状态分叉

## 关键代码示例

核心决策在
[service.py](../src/trustlayer/service.py)：

```python
decision = "allow"
if "secret_detected" in risk_flags:
    decision = "block"
elif any(flag in risk_flags for flag in ("pii_detected", "new_domain", "payload_oversized")):
    decision = "review_required"
```

风险识别目前采用轻量规则：

```python
if self._contains_secret(payload):
    risk_flags.append("secret_detected")
if self._contains_pii(payload):
    risk_flags.append("pii_detected")
if len(payload) > OVERSIZED_EGRESS_THRESHOLD:
    risk_flags.append("payload_oversized")
```

## 验证测试设计

当前 Egress 模块对应四组已通过测试：

1. `test_egress_blocks_secrets_and_records_block_event`
2. `test_egress_reviews_new_domain_with_pii`
3. `test_egress_reviews_oversized_payloads`
4. `重复域名放行`

## 测试过程记录

当前结果：

- Egress 相关场景：`4/4` 通过

已验证行为：

- Secret 命中后会阻断
- PII + 新域名会提级
- 超阈值 payload 会提级
- 同一域名在首次触达后可以按历史状态放行 benign payload

## 当前限制

- 目的地信誉只做“是否首次出现”
- 还没有白名单和租户级配置
- 还没有业务标签级 DLP

## 下一步演进

1. 支持更多目的地级策略
2. 增加租户级 allowlist / blocklist
3. 扩展 DLP 规则源
