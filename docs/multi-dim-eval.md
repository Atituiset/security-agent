# 多维评估：可用性、可扩展性、健壮性、安全性、成本

2026-09-27。本页是对当前实现的多维检查与不合理点记录；发现的低成本问题已直接修复，
较大缺口给出改动面量化并保留优先级。评估类结果（成对面板、故障矩阵、保留集）见
[validation.md](validation.md)，面板时间序列见 [trace-eval.md](trace-eval.md)。

## 可用性

实测项与结果：

- README 与实现一致性：已修正三处过时表述（准备阶段恢复、分层预算、trace/eval 入口）。
- CLI 错误路径：`review --file` 不存在 → exit 2，报错现包含 PREPARING 目录处理提示
  （此前只报错不说明现场残留，用户重跑会撞 "already prepared" 类困惑）。
- 修正参数后重跑同一 `--run` 目录可按原配置恢复准备（实测通过，含真实模型调用完成）。
- 中断恢复：`review` 被 SIGTERM/SIGINT → exit 130，`resume` 继续；`--prepare-only` 可先冻结定位。
- 退出码语义：0 干净、1 有确认项、2 未完成/UNKNOWN/覆盖缺口/输入错误、130 中断——与文档一致，实测符合。
- 不合理点（已修复）：空范围运行（diff 中无 C/C++ 文件）此前 execution=COMPLETED 且
  coverageComplete=true、exit 0，违反"零 Finding 不是安全证明"原则；
  现在空范围写入覆盖缺口，coverageComplete=false、exit 2（`core/output.py`，含回归测试）。

遗留可用性事项（低优先）：

- 报错中英文混排，与项目文档风格一致，暂不统一。
- OpenCode/Hermes 后端的费用上报为 null 时，报告只写 null，没有更醒目的"费用未知"提示。

## 可扩展性

以"完成一个真实扩展任务需要改什么"衡量：

| 扩展任务 | 改动面 | 评估 |
| --- | --- | --- |
| 新增执行后端（Agent SDK） | `infra/` 一个适配器 + `routing.py` 注册；Core 零改动 | 已被三次验证（Claude/OpenCode/Hermes），seam 健康 |
| 新增工具后端（如 ast-grep） | 实现 `CodeTool` 协议（check/query 两方法）+ `SemanticQueries` 组合点（一处 `graph.capabilities` 判断）+ CLI/benchmark 工厂 | seam 已在但只有一个真实图后端；能力驱动路由（多后端按能力择优）未实现，目前 graph 为单例注入 |
| 新增 CWE 规则包 | 6 处生产硬编码需参数化：`core/skills.py`（注册表+按 id 校验）、`controller.py`（按适用性 dispatch）、`core/judge.py`×3（fingerprint/记录）、`core/output.py`×3（SARIF/报告 ruleId）；外加规则包本身（contract+三角色提示词）与基准案例 | 架构已预留（rule 字典随状态流转、rule_hash 入评分），但契约驱动 dispatch 未实现；是下一个中等工作量任务 |
| 新增输入类型（远程 PR） | `inputs/` 新模块 + `input.json` provenance；Runtime 不感知来源 | 本地 diff/文件/函数已验证，远程 PR 入口未做 |

结论：执行后端维度已证明可替换；工具与规则维度的 seam 存在但尚未被第二个真实实现检验，
在做成对可扩展性比较前，先完成"第二个 CWE 规则包"或"第二个工具后端"中的一项最有说服力。

## 健壮性

- 恢复：行动级检查点覆盖模型调用（M1）与准备阶段（M4）；崩溃点矩阵有回归测试
  （响应落盘后、请求发出结果未知、索引中断、索引失败降级）。
- 预算：Run/Investigation/Action 三层；预留不退还；未知费用不计免费。
- 失效：基线移动、规则变化、产物篡改、评估源不匹配均使 run STALE 或拒绝评分。
- 协议：v6/v7 双版本评分白名单，恢复执行只认当前版本。
- 测试 138 项（含 CodeGraph 真实集成），覆盖上述路径；故障注入成对实验见 validation.md。

## 安全性

- 目标仓只读：不执行目标代码、不写目标源码；模型侧无 Bash/Read/Edit 开放。
- 基线宿主策略白名单：只读命令原子化、禁 shell 操作符、写仅限 `.review` 会话区。
- 证据绑定：源码字节内容寻址、产物 SHA-256 密封、报告只是视图。
- 凭证：只从 settings env 读取，不写入 run 目录；SDK 失败记为 UNKNOWN 而非伪造。
- 局限（如实记录）：哈希是本地完整性检查，不抵抗同时篡改文件与 manifest 的攻击者。

## 成本

- security-agent 开发集 10×3 面板总费用 $2.548（均值 $0.085/案例·次），预留 $30。
- review-skills 原生宿主单次合规运行约 $5.45–$5.72（C001/C002），且 deepseek-v4-flash
  协议合规率目前 1/5，每次失败同样计费。
- 费用口径：两侧都是 SDK total_cost_usd，同 provider；provider 账单可能不同，结论以
  "相同预留上限下的完成率/失败率" 为主、美元为辅。
