# 模块 6：Policy Config

更新时间：2026-04-20

## 模块防御目标

这一轮之后，TrustLayer 不再把净化、DLP、审计相关规则写死在服务代码里。

当前目标很明确：

- 运行时规则全部从数据库读取
- 代码只保留执行引擎
- 策略变更可以通过导入策略文档落到 SQLite

## 设计思路

现在的策略层拆成了五类表：

1. `policy_settings`
2. `source_policies`
3. `detector_rules`
4. `decision_rules`
5. `approval_summary_rules`

这五类表解决的是不同问题：

- `policy_settings`
  放阈值、allowlist、审计队列优先级、运营报表统计口径
- `source_policies`
  定义不同 `source_type` 的 trust level、抽取方式和静态风险标签
- `detector_rules`
  定义净化和 DLP 的检测规则，比如正则、阈值、新域名判断
- `decision_rules`
  定义命中哪些 flag 后是 `allow / review_required / block`
- `approval_summary_rules`
  定义审批摘要里每个风险标签怎么翻译成人能读的描述

## 关键代码示例

策略存储在
[policy.py](../src/trustlayer/policy.py)：

```python
class PolicyStore:
    def __init__(self, db_path: str | Path, *, seed_file: str | Path | None = None) -> None:
        self.db_path = str(db_path)
        self.seed_file = str(seed_file or DEFAULT_POLICY_FILE)
        self._init_db()
        self._seed_if_empty()
```

服务层不再直接持有硬编码规则，而是在每次决策时读策略快照：

```python
snapshot = self.policy_store.snapshot()
source_policy = snapshot.source_policy_for(source_type)
```

入口净化和出口 DLP 的命中逻辑，都走统一 detector 评估：

```python
for rule in snapshot.detector_rules_for("egress"):
    if self._rule_matches(rule, context, snapshot):
        flags.append(rule.flag_name)
        matched_policies.append(rule.policy_id)
```

最终决策也改成从数据库里的 `decision_rules` 读取：

```python
decision_rule = snapshot.decision_rule_for("egress", risk_flags)
decision = decision_rule.decision
```

## 当前策略文档长什么样

默认策略文档在：
[policy.example.json](../config/policy.example.json)

现在它已经不是只有三个阈值的小文件，而是一份完整策略包，里面包含：

- `settings`
- `source_policies`
- `detector_rules`
- `decision_rules`
- `approval_summary_rules`

服务启动时，会先把这份策略文档导入 SQLite。  
运行时真正读取的是数据库，而不是 JSON 文件本身。

## 验证测试设计

这一轮最关键的验证不只是“旧测试还能过”，还要证明：

**改数据库策略，行为真的会跟着变。**

新增验证重点：

- 旧行为全量回归仍然成立
- 允许名单和阈值改动仍能影响决策
- 替换数据库里的 secret 检测正则后，拦截行为会跟着变化

对应测试包括：

- `test_policy_config_allowlists_destination_and_lowers_oversized_threshold`
- `test_policy_config_can_load_from_file`
- `test_full_policy_document_from_database_can_replace_dlp_pattern`

## 测试过程记录

这次改动最大的风险是“看上去去掉了硬编码，实际上只是换了个壳”。

所以我专门加了一条反向测试：

- 从默认策略文档里删掉 GitHub token 的 secret 正则
- 新增一条自定义 `TEAMSECRET-*` 正则
- 再看服务是否真的按数据库里的新规则执行

结果是：

- 自定义 secret 会被 `block`
- 原来的 GitHub token 不再命中 `secret_detected`

这条测试的价值比普通回归更大，因为它直接证明：

**规则来源已经从代码切到了数据库。**

## 下一步演进

- 支持多租户策略版本
- 支持热更新和版本回滚
- 把策略变更历史也写进独立审计链
