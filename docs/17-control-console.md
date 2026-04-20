# 模块 17：控制台 Web UI

更新时间：2026-04-20

## 模块目标

给 `TrustLayer` 补一层最小 Web 控制台，先解决四件事：

- 让安全负责人能直接看到当前运行态
- 让策略、租户绑定和分发状态不只停在 API 返回里
- 让审计检索从 CLI/JSON 变成可浏览页面
- 保持 PoC 轻量，不引入额外前端框架

这一版的定位不是完整后台系统，而是一个内置在 WSGI 服务里的最小控制台。

## 页面范围

当前控制台一共四页：

- `Dashboard`
- `Policies`
- `Distribution`
- `Audit Search`

另外保留原来的审批页：

- `/approvals/queue?tenant_id=<tenant>`

## 设计思路

### 1. 先用服务内嵌页面，不单独起前端工程

PoC 阶段最重要的是把控制面信息露出来，而不是先搭一套前后端分离工程。

所以这版直接在 [app.py](/Users/koi/blog/TrustLayer/src/trustlayer/app.py) 里渲染 HTML：

- `GET /console`
- `GET /console/dashboard`
- `GET /console/policies`
- `GET /console/distribution`
- `GET /console/audit`

### 2. 页面数据直接复用现有控制面和审计存储

控制台不另外造一层 view DB，而是先直接复用：

- [control_plane.py](/Users/koi/blog/TrustLayer/src/trustlayer/control_plane.py)
- [audit.py](/Users/koi/blog/TrustLayer/src/trustlayer/audit.py)

这也是为什么这一轮除了 UI，还补了几类查询能力：

- `list_bundles()`
- `list_tenant_bindings()`
- `list_distribution_status()`
- `dashboard_stats()`
- `search_events()`

### 3. 样式做轻，不做“安全产品模板味”

页面风格用暖底色、卡片和横向导航，目的是让控制台在 PoC 演示时更像一套产品，而不是默认表格页。

## 关键代码

### 控制台路由

入口在 [app.py](/Users/koi/blog/TrustLayer/src/trustlayer/app.py)：

```python
if method == "GET" and path == "/console/dashboard":
    return _html_response(
        start_response,
        200,
        _render_console_dashboard_page(service, control_store),
    )
```

### 控制面列表查询

控制面新增了 bundle、绑定和分发状态查询：

```python
def list_distribution_status(
    self,
    limit: int = 100,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    return self._backend.list_distribution_status(limit, tenant_id)
```

对应文件：
[control_plane.py](/Users/koi/blog/TrustLayer/src/trustlayer/control_plane.py)

### 审计检索和概览

审计页依赖这两个新接口：

```python
def search_events(...):
    ...

def dashboard_stats(self) -> dict[str, Any]:
    ...
```

对应文件：
[audit.py](/Users/koi/blog/TrustLayer/src/trustlayer/audit.py)

## 测试设计

这轮 UI 测试不测像素，只测三类事情：

1. 页面能打开
2. 页面能显示真实控制面数据
3. 页面筛选条件真的生效

对应测试都在 [test_control_plane.py](/Users/koi/blog/TrustLayer/tests/test_control_plane.py)：

- `test_console_dashboard_page_renders_live_stats`
- `test_console_policies_page_lists_bundles_and_bindings`
- `test_console_distribution_page_filters_by_tenant`
- `test_console_audit_page_renders_search_results`

## 测试结果

本轮新增控制台测试 `4` 条。

当前全量测试结果：

- `60` 条通过
- `1` 条按预期跳过（PostgreSQL live test 默认不跑）

## 已知边界

这版控制台还是 PoC 形态，明确还没有：

- 登录和权限模型
- 真正的规则编辑器
- 时序图或图表组件
- 分页和高性能检索
- 多租户权限隔离页面

它当前更像一个“可演示、可操作、可验证”的控制面外壳。
