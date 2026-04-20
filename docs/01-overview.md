# 模块 0：基础设施总览

更新时间：2026-04-20

## 模块防御目标

这一版基础设施只解决三件事：

1. 外部不可信输入在进入 Agent 前先被治理
2. 外发数据在离开 Agent 前先被检查
3. 关键事件不依赖 Agent 自述，而由独立审计链路记录

对应四层防御框架，这一版主要覆盖：

- 第一层：输入分级和过滤
- 第三层：外发型行为约束
- 第四层：独立审计

## 设计思路

工程上刻意保持克制：

- 技术栈先用 Python 标准库
- 服务先做最小 WSGI
- 审计先用 SQLite
- 策略先内嵌在服务里
- 测试先围绕场景，而不是围绕内部函数细节

这样做的原因是当前目标不是做生产系统，而是把 TrustLayer 最关键的链路先验证通。

## 当前模块边界

### 已实现

- `Ingress Gateway`
- `Egress Gateway`
- `Audit Store`
- `Timeline Query`
- `HTTP API`

### 暂不实现

- 完整策略中心
- 本地文件权限控制
- 命令执行限制
- 运行时沙箱
- 完整控制台

## 关键代码落点

- 服务编排：
  [service.py](../src/trustlayer/service.py)
- 审计存储：
  [audit.py](../src/trustlayer/audit.py)
- HTTP API：
  [app.py](../src/trustlayer/app.py)
- 测试：
  [test_gateway.py](../tests/test_gateway.py)

## 当前测试设计

当前测试采用“场景先行”的思路，先覆盖最小闭环：

1. 隐藏 HTML 内容剥离
2. MCP 返回值不可信标记
3. 超长输入裁剪
4. Secret 外发阻断
5. 新域名 + PII 外发提级
6. 超大外发提级
7. 时间线接口查询

## 当前测试过程记录

执行命令：

```bash
cd ..
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前结果：

- 通过：`11`
- 失败：`0`

## 下一步开发顺序

1. 继续扩更多真实外发场景
2. 评估是否需要最小前端控制台
3. 再决定何时引入更完整的策略模型
