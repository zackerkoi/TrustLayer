# 模块 1：Ingress Gateway

更新时间：2026-04-20

## 模块防御目标

Ingress Gateway 的目标不是“识别所有注入语义”，而是先把最容易被系统直接喂给模型的脏输入收一遍。

当前版本重点防三类问题：

1. 隐藏内容原样进入 Agent
2. 超长输入整份直通 Agent
3. 第三方工具返回值被误当成可信系统内容

## 设计思路

当前实现故意把输入治理拆成两个动作：

1. **清洗**
   把网页里的注释、隐藏元素、脚本样式区去掉，只留下可见文本。

2. **打标**
   不试图在这一层“判定恶意意图”，只做结构化风险标签：
   - `external_origin`
   - `hidden_content`
   - `oversized_text`
   - `tool_output_untrusted`

这个思路和前面的设计保持一致：

**Starter 阶段先缩小暴露面，而不是幻想靠语义识别一步到位。**

## 关键代码示例

隐藏内容剥离逻辑在
[sanitizer.py](../src/trustlayer/sanitizer.py)：

```python
is_hidden = (
    "hidden" in attrs_dict
    or "display:none" in style
    or "visibility:hidden" in style
)
```

输入打标逻辑在
[service.py](../src/trustlayer/service.py)：

```python
if removed_regions:
    risk_flags.append("hidden_content")
if len(raw_content) > OVERSIZED_THRESHOLD:
    risk_flags.append("oversized_text")
if source_type == "mcp_response":
    risk_flags.append("tool_output_untrusted")
```

## 验证测试设计

当前 Ingress 模块对应三组测试：

1. `test_ingress_strips_hidden_html_and_audits_timeline`
2. `test_ingress_marks_mcp_responses_as_untrusted_tool_output`
3. `test_ingress_trims_oversized_content_into_selected_chunks`

这些测试分别验证：

- 隐藏 HTML 不原样进入
- MCP 返回值默认不可信
- 超长输入不会整份直通

## 测试过程记录

当前结果：

- Ingress 相关场景：`3/3` 通过

已观察到的行为：

- 可见文本保留
- 隐藏内容不在 `visible_excerpt`
- `removed_regions` 正常记录
- 超长输入会被压成有限数量的 `selected_chunks`

## 当前限制

- 只对 `web_page` 做 HTML 级清洗
- 还没有做附件、PDF、Office 的格式化处理
- 还没有按字段级白名单做暴露面控制

## 下一步演进

- 按来源类型做不同的 sanitizer
- 把 chunk 策略改成可配置
- 为 RAG 片段补单独的输入元数据模型
