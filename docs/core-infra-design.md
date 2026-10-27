# Security Core / Runtime / Tools / Agent Infra

更新：2026-09-26。完整目标以 [Security Agent 主设计](security-agent.md) 为准。
本页描述依赖边界和当前代码映射；未来实施顺序见 [MVP 计划](mvp-design.md)。

## 职责与依赖

Security Core 包含领域模型与 Security Runtime。Runtime 管理假设、证据、调查动作和结论生命周期；
当前 core/ 与 pipeline/ 已承载部分职责，已有持续调查初版，阶段内恢复待建设。

```text
CLI（组装）
 ├─ inputs：Git 基线与函数定位
 ├─ pipeline + core：五阶段、安全规则、证据、预算、状态与报告
 │       ├─ AgentExecutor：推理执行端口
 │       └─ FactQueries：代码事实查询契约
 ├─ infra/claude：实现 AgentExecutor，使用 Claude Agent SDK
 ├─ infra/opencode、infra/hermes：新增宿主适配器，可按角色选择
 └─ tools：语义查询与 CodeTool 适配器，当前 CodeGraph / AST / 源码

validation + examples/replay_session：独立回归辅助入口
```

Core 不导入 SDK、具体工具适配器或旧 session 模块。Controller 接收执行器与查询工厂，
CLI 注入具体实现。Agent Infra 不决定规则、读取范围或漏洞结论；Tools 不决定调查生命周期。
SecurityTool 是 Core 交给执行器的工具描述，SDK 将其暴露给模型。

## 当前执行与目标执行

当前：输入目标 → 准备范围/索引 → Investigator（可多次查询）→ 版本化证据 →
独立 Judge → 有限补查/再次裁决 → 输出。角色通过可替换的执行端口运行。

实现：外层五阶段保留，在 review-execute 中加入 Runtime 管理的 Hypothesis 与 Action 循环；
缺失事实或 Judge follow_up 可推进新一轮调查。内层模型/工具循环继续使用 SDK。

目前已有状态恢复不意味着完整 Runtime 已实现；跨轮证据版本和停止策略已有初版，准备阶段行动恢复仍是后续工作。

## 使用入口

```text
review --repo REPO --file FILE --function FUNCTION
review --repo REPO --file FILE
review --repo REPO --base BASE --head HEAD
```

默认 HEAD，commit-only；不检视未提交修改。函数由 Tree-sitter 定位，重载通过限定名/--line 消歧。
取证可跨文件，Finding 范围仍受用户目标限制。无需历史目录，CodeGraph 完整本地索引也不意味着整仓入 prompt。

## 当前隔离与边界

Investigator / Judge 使用独立 SDK client，会话不共享；Judge 只接收范围、证据与规则。
CWE 包由 Core 显式加载，SDK 不自动加载目标仓的 Skill/配置。独立会话不等于独立模型共识。

哈希和冻结提交用于本地基线/产物检查，不是防止所有本地文件同时被篡改的签名系统。
当前测试验证 Core 无 SDK/具体 Tools 依赖，真实工具测试验证查询与基线失效；
已有 Judge 补查和跨轮中断恢复测试；还需更多真实案例和准备阶段恢复验证。
