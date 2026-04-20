# 模块 10：Evaluation Framework

更新时间：2026-04-20

## 模块防御目标

前面的 PoC 已经能演示“怎么拦、怎么审计、怎么排队”，但要真正走向更可信的验证，还需要一层量化评估。

这一层要回答四个问题：

1. 对危险样本的检出率有多高
2. 对正常样本的误报有多少
3. 正常任务保真率怎么样
4. 每次决策大概增加了多少延迟

## 设计思路

当前评估框架保持最小可复现：

- 用 JSON 文件维护样本集
- 本地 runner 直接逐条跑 ingress / egress
- 输出一份文本版评估报告

当前不做：

- 大规模 benchmark 平台
- 自动图表
- 真正的线上流量采样

## 当前指标

### Detection

- `false_positive_count`
- `false_negative_count`
- `detection_recall`

### Operations

- `benign_retention`
- `average_latency_ms`

## 关键代码落点

- 样本集：
  [eval_samples.json](../config/eval_samples.json)
- 评估 runner：
  [evaluation.py](../src/trustlayer/evaluation.py)
- 测试：
  [test_evaluation.py](../tests/test_evaluation.py)

## 关键代码示例

样本评估核心逻辑：

```python
decision_ok = result.decision == sample.expected_decision
required_ok = set(sample.required_flags).issubset(flags)
forbidden_ok = not (set(sample.forbidden_flags) & flags)
```

汇总指标：

```python
"benign_retention": benign_ok / benign_total if benign_total else 0.0,
"detection_recall": risky_detected / risky_total if risky_total else 0.0,
"average_latency_ms": round(avg_latency, 3),
```

## 验证测试设计

当前评估框架有三类测试：

1. `test_load_samples_reads_fixture_file`
   验证样本文件能被正确加载

2. `test_evaluate_samples_computes_summary_metrics`
   验证指标计算正确，且当前基准样本在现有实现上全部通过

3. `test_format_evaluation_report_contains_summary_and_results`
   验证输出报告中包含摘要和逐样本结果

## 测试过程记录

当前结果：

- 评估框架相关测试：`3/3` 通过
- 全量测试：`31/31` 通过

## 当前本地评估结果

基于当前样本集 `eval_samples.json` 的一次本地运行结果：

- `total_samples = 7`
- `false_positive_count = 0`
- `false_negative_count = 0`
- `benign_retention = 1.000`
- `detection_recall = 1.000`
- `average_latency_ms = 0.074`

这组结果的意义是：

- 在当前这组很小的固定样本上，Starter 的最小实现没有出现误报或漏报
- 正常样本都能保留预期行为
- 本地单机执行的平均决策延迟很低

但这不代表真实生产结果已经足够好。它只能作为当前 PoC 的一个起始基线。

## 扩展 benign pack 结果

基于 `eval_samples_benign_extended.json` 的一次本地运行结果：

- `total_samples = 6`
- `false_positive_count = 0`
- `false_negative_count = 0`
- `benign_retention = 1.000`
- `average_latency_ms = 0.065`

这里的 `detection_recall = 0.000` 不代表防御失效，而是因为这组扩展样本全部是 benign，不包含 risky 样本，所以这项指标在这组数据上没有意义。

这组 benign pack 说明：

- 当前最小实现对这批正常业务流量还没有出现误报
- 平均延迟依然很低
- 可以开始继续扩更复杂、更接近真实生产的正常样本集

## 扩展 hard risky pack 结果

基于 `eval_samples_hard_risky.json` 的一次本地运行结果：

- `total_samples = 6`
- `false_positive_count = 0`
- `false_negative_count = 0`
- `detection_recall = 1.000`
- `average_latency_ms = 0.076`

这里的 `benign_retention = 0.000` 不代表系统误伤严重，而是因为这组 hard risky 样本全部是 risky，不包含 benign 样本，所以这项指标在这组数据上没有意义。

这组 hard risky pack 说明：

- 当前实现对这批更隐蔽、但仍在 Starter 能力边界内的危险样本没有出现漏报
- 风险识别不只依赖“陌生域名”，对已知域名上的 PII / secret 风险也能命中
- 本地延迟仍然维持在很低水平

## adversarial pack 结果

`eval_samples_adversarial.json` 和前两组样本不一样，它不是为了证明“当前都能拦住”，而是为了把当前边界显性化。

当前这组样本分两类：

- `should_detect`
- `known_gap`

本地运行结果：

- `adv_detect_secret_literal` -> `block`
- `adv_gap_contact_count_only` -> `allow`
- `adv_gap_obfuscated_email_words` -> `allow`
- `adv_gap_low_signal_summary` -> `allow`

这组结果说明：

- 当前 Starter 对“字面 secret”这类高确定性风险仍然能稳定命中
- 但对于：
  - 不直接出现 PII 字面值的“联系人数量”表达
  - 用 `alice at example dot com` 这类弱混淆写法表达的联系方式
  - 看起来像普通业务摘要的低信号外发请求
  
  目前仍然会放行

这不是测试失败，而是当前能力边界的真实暴露。

## 运行方式

```bash
cd ..
PYTHONPATH=src python3 -m trustlayer.evaluation
```

## 当前价值

这一步把 PoC 从“能演示”往“能量化”推进了一步。

现在我们已经可以：

- 固定样本集
- 固定指标定义
- 重复跑评估
- 对比后续改动是否引入误报、漏报或性能退化

## 当前限制

- 样本集还很小
- false-positive 扩展集刚起步，覆盖面仍然有限
- hard risky 扩展集也还偏小，且仍主要围绕当前规则最擅长的风险类型
- adversarial pack 目前只证明了少数已知盲点，还不等于系统性压力测试
- 延迟只是本地单机执行延迟，不等于真实生产延迟

## 下一步演进

- 扩 benign 样本，压测误报
- 扩困难 risky 样本，压测漏报
- 扩 adversarial 样本，明确记录哪些风险现在就是已知 blind spot
- 把评估输出接到 HTML 页面或 markdown 报告
