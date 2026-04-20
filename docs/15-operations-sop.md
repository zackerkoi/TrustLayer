# 模块 15：运营 SOP

更新时间：2026-04-20

## 这份 SOP 解决什么问题

这份文档不讲“防御框架为什么成立”，只讲上线之后谁来盯、怎么调、出了误报和漏报怎么办。

对当前这版 TrustLayer，运营目标可以压成五件事：

1. 规则变更有节奏，不在生产里乱调
2. 每天有人看 review / block 和异常趋势
3. 误报和漏报都有固定处理闭环
4. 有最小可追的指标体系
5. 每周能从案例里反推规则和接入问题

## 当前可配规则

当前代码里真正能直接配置的运行时项，只有这三个：

```json
{
  "ingress_oversized_threshold": 600,
  "egress_oversized_threshold": 500,
  "allowed_destination_hosts": [
    "safe.example"
  ]
}
```

文件位置参考：
[policy.example.json](../config/policy.example.json)

这三个配置分别控制：

- `ingress_oversized_threshold`
  输入内容多长开始被标成 `oversized_text`
- `egress_oversized_threshold`
  外发 payload 多大开始被标成 `payload_oversized`
- `allowed_destination_hosts`
  哪些目的地不按“首次出现新域名”处理

## 规则怎么配

### 第一天不要做的事

- 不要一上来把阈值压得特别低
- 不要先把所有老域名都加白名单
- 不要直接按单个样本改规则

第一周更稳的做法是：

- `ingress_oversized_threshold` 保持默认或略高
- `egress_oversized_threshold` 先按现有导出体量粗设
- `allowed_destination_hosts` 只放业务已经确认的老域名

### 规则调整顺序

每次只改一个方向：

1. 先改 ingress 阈值
2. 再看 egress 阈值
3. 最后再动 allowlist

这样做的好处是，出了误报或漏报，能更容易定位是：

- 输入裁剪过早
- 外发阈值过低
- 目的地白名单过宽或过窄

## 日常运营怎么跑

### 每日

每天至少看三样东西：

1. 审批队列
2. block 事件
3. 新域名趋势

最小操作面：

- 打开 `GET /approvals/queue`
- 抽样回放 `GET /v1/sessions/<session_id>/timeline`
- 看当天 `egress_blocked` 和 `egress_review_required` 是否突然升高

### 每周

每周做一次固定复盘：

1. 复盘误报
2. 复盘漏报
3. 跑固定样本评估
4. 对照真实场景测试有没有退化

建议每周固定跑：

```bash
cd /Users/koi/blog/TrustLayer
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m trustlayer.evaluation
PYTHONPATH=src python3 -m trustlayer.ops_report --db-path audit.sqlite3
```

## 怎么监控

当前这版还没有专门的 metrics backend，所以最实用的做法是直接从审计库和审批队列里看趋势。

### 最小监控面板

我会先盯这六个数字：

1. `source_sanitized_count`
2. `egress_review_required_count`
3. `egress_blocked_count`
4. `new_domain` 命中次数
5. `secret_detected` 命中次数
6. `pii_detected` 命中次数

这些指标现在可以直接通过运营报表脚本看：

```bash
cd /Users/koi/blog/TrustLayer
PYTHONPATH=src python3 -m trustlayer.ops_report --db-path audit.sqlite3
```

### 报表能回答什么

这个脚本当前会汇总：

- 总事件数
- 总 session 数
- `source_sanitized` 次数
- `egress_review_required` 次数
- `egress_blocked` 次数
- `policy_matched` 次数
- 风险标签 Top N
- 目的地主机 Top N
- 决策分布

这里的风险标签和决策分布，按最终信号事件统计：

- 输入侧看 `source_sanitized`
- 输出侧看 `egress_allowed / egress_review_required / egress_blocked`

这样做是为了避免同一个请求在 `policy_matched`、`egress_scanned`、最终决策事件里被重复放大。

它不是完整的运营平台，但已经足够回答：

- 今天 review 是不是明显变多了
- 哪类风险标签最常见
- 哪个目的地最常触发控制

## 误报怎么处理

误报最常见的三类来源是：

1. 老域名没进 allowlist
2. 正常导出体量撞到了 `payload_oversized`
3. 正常长文输入撞到了 `oversized_text`

处理顺序建议固定：

1. 先回放时间线
2. 确认是规则误伤，不是业务方忽视了真实风险
3. 记录是哪条规则、哪个 session、哪个业务动作
4. 只改一个配置项
5. 跑回归测试和评估再上线

误报不要直接靠“口头放行”消化。  
真正该落地的是：

- 白名单补齐
- 阈值微调
- 场景样本补进评估集

## 漏报怎么处理

漏报处理比误报更重要，因为它会直接决定下一轮规则是不是在进步。

最小闭环是：

1. 复盘这次实际外发或险情
2. 看时间线里输入、动作、目的地分别发生了什么
3. 判断漏在 ingress、egress 还是 blind spot
4. 把样本补进：
   - 真实场景对照
   - hard risky pack
   - adversarial pack
5. 再决定是调阈值、补 allowlist，还是承认当前边界

对于当前这版 TrustLayer，要特别留意三类漏报：

- 低信号外发
- 弱混淆 PII
- 只出现“联系人数量”但没有字面 PII 的导出

这些现在本来就在已知 blind spot 里。  
真正需要警惕的是“原本应该命中的高确定性风险却没命中”。

## 怎么指标化运营

如果只保留最小指标体系，我会建议看四组：

### 1. 覆盖指标

- 每天有多少 session 经过 ingress / egress
- 有多少高风险链路已经接到 unified gateway

### 2. 风险指标

- `review_required` 数量
- `block` 数量
- `new_domain` 命中数量
- `secret_detected` 命中数量

### 3. 质量指标

- 每周误报数
- 每周漏报数
- `benign_retention`
- `detection_recall`

### 4. 运营效率指标

- 审批平均处理时长
- 每周被复盘的高风险 case 数
- 从 case 到规则更新的平均耗时

## 一条可执行的周会节奏

如果团队还小，我会把运营节奏压成一场 30 分钟周会：

1. 看本周 `block / review / new_domain`
2. 复盘 1-2 条误报
3. 复盘 1-2 条漏报或险情
4. 确认本周是否要调阈值或补 allowlist
5. 确认哪些样本要补进测试集

这样做的目的不是把运营搞复杂，而是避免规则永远停在第一天。

## 当前边界

这份 SOP 是按当前 TrustLayer 实现写的，所以要诚实说明边界：

- 规则配置目前还是轻量级
- 还没有独立 metrics backend
- 还没有自动化告警编排
- 审批处理仍然偏 PoC 形态

但对于第一阶段产品来说，这套东西已经足够回答一个关键问题：

**上线后谁来看、看什么、怎么调、出了误报和漏报怎么办。**
