# 模块 5：Policy Config

更新时间：2026-04-20

## 模块防御目标

策略外置的目标不是一开始就做完整策略中心，而是先解决一个很实际的问题：

**不要把所有阈值和允许名单都硬编码在服务里。**

Starter 阶段优先把这些东西外置：

- 输入超长阈值
- 外发超长阈值
- 允许直接放行的目标域名

## 设计思路

当前实现选择了最简单的形态：

- `PolicyConfig` 数据类
- JSON 文件加载
- 服务初始化时注入

这样做的原因是：

- 改动小
- 容易测试
- 不会把 PoC 过早推成复杂配置平台

## 关键代码示例

配置模型在
[policy.py](../src/trustlayer/policy.py)：

```python
@dataclass(frozen=True)
class PolicyConfig:
    ingress_oversized_threshold: int = 600
    egress_oversized_threshold: int = 500
    allowed_destination_hosts: set[str] = field(default_factory=set)
```

服务接入方式在
[service.py](../src/trustlayer/service.py)：

```python
def __init__(self, audit_store: AuditStore, policy: PolicyConfig | None = None) -> None:
    self.audit = audit_store
    self.policy = policy or PolicyConfig()
```

新域名判定也开始受配置影响：

```python
is_new_domain = (
    destination_host not in self.policy.allowed_destination_hosts
    and not self.audit.has_seen_destination(tenant_id, destination_host)
)
```

## 验证测试设计

新增测试：

- `test_policy_config_allowlists_destination_and_lowers_oversized_threshold`

它验证两件事：

1. 允许名单域名首次访问不再被当成新域名提级
2. 外部配置可以降低外发超长阈值，并改变决策结果

## 测试过程记录

第一次加测试时，测试失败原因很直接：

- `trustlayer.policy` 模块不存在

随后补了 `policy.py`，并把服务中的阈值和允许名单接入配置对象，再次测试全部通过。

当前结果：

- 新增策略配置相关场景：`1/1` 通过
- 全量测试：`9/9` 通过

## 配置样例

样例文件：
[policy.example.json](../config/policy.example.json)

## 下一步演进

- 增加更多租户级策略字段
- 支持按 source type / destination type 分层配置
- 再考虑是否引入真正的策略 DSL
