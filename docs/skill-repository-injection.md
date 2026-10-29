# Agent 能力复用与 Skill 场景仓设计讨论

更新：2026-10-29。状态：讨论记录与候选设计，**不代表 Skill 场景仓或动态注入已经实现**。
当前行为以 [Tools 与 Skills](tools-and-skills.md)、[主设计](security-agent.md) 和代码为准。

## 1. 讨论问题与结论

本讨论围绕四个问题展开：仓库如何分层、Claude Agent SDK 在哪里接入、SDK 已有能力是否被重复建设，
以及能否让业务场景 Skill 同时服务于 Security Agent 和原生 Agent。

结论是：

- 项目没有重建 SDK 的模型请求、工具调用和多轮交互内层循环；自建的是安全调查所需的外层控制。
- Subagent、会话记忆和自动 Skill 发现并非 SDK 不支持，而是主 Runtime 当前有选择地关闭或不采用。
- 可以建设独立的 Skill 场景仓，并通过宿主适配层注入，让场景作者主要编写标准 Skill 内容，而不关心宿主类型。
- 第一版应在 **run 创建时固定 Skill 集合并绑定哈希**，先复用现有完整性、恢复和 STALE 机制；
  运行中追加 Skill 作为后续扩展，必须引入追加式事件和版本留痕，不能直接修改已冻结的 run 输入。
- 便携性不等于无条件通用：使用 Security Agent 专属查询能力的 Skill，在其他宿主上仍需要相同工具契约或明确降级。

## 2. 当前分层与 SDK 接入点

当前依赖方向是 CLI 组装具体实现，Pipeline/Core 定义业务控制，Infra 和 Tools 提供可替换能力：

| 层 | 主要职责 |
| --- | --- |
| `cli.py` | 解析参数，组装后端、查询工具、规则和运行目录 |
| `inputs/` | 解析 Git 基线和调查范围，冻结内容寻址源码快照 |
| `pipeline/` | 五阶段编排、跨轮调查、预算、恢复和 Judge 补查 |
| `core/` | 后端与查询 Protocol、规则契约、证据门禁、裁决接纳、持久化与哈希校验 |
| `infra/` | Claude Agent SDK、OpenCode、Hermes 的会话适配 |
| `tools/` | CodeGraph、Tree-sitter、冻结源码查询及事实精度归一化 |
| `validation/` | 基线宿主、基准、故障注入和评估追溯 |

Core 不直接 import 某个 Agent SDK，这是依赖隔离要求，并有 `tests/test_architecture.py` 约束。
因此“没有看到 SDK import”不代表没有使用 SDK。

Claude SDK 的主要接入点是 `security_agent/infra/claude.py`：在函数内惰性导入
`ClaudeAgentOptions`、`ClaudeSDKClient`、`ResultMessage`、`tool` 和 `create_sdk_mcp_server`。
依赖在 `pyproject.toml` 中声明。另一个接入点是 `security_agent/validation/baseline_host.py`，
用于原生基线宿主，包含 `AgentDefinition` 和 `HookMatcher`。

主 Claude 适配器当前为每次角色/尝试新建会话，禁用会话续接，工具面只放行 Runtime 审过的
`mcp__security__*` 工具，并显式设置 `skills=[]`、`plugins=[]`、`setting_sources=[]`。
SDK 调用失败统一形成失败执行结果，再按流程保留为 UNKNOWN，不能转成“无漏洞”。

## 3. SDK 能力的复用与取舍

| 能力 | 当前使用情况 | 原因与边界 |
| --- | --- | --- |
| Tool calling | 已复用 | SDK 执行“模型请求工具 → 返回结果 → 继续推理”；Runtime 只提供受控工具桥接 |
| 多轮模型交互 | 已复用 | 不在 Python 中重写通用 Agent 内层循环 |
| Subagent | SDK 支持；基线宿主使用，主 Runtime 未启用 | 主流程要求每次模型行动、预算和原始结果可落盘；自由派生子 Agent 会扩大审计和恢复边界 |
| Memory / 会话续接 | 主 Runtime 显式关闭 | 可恢复状态来自 `state.json`、行动、尝试和证据记录，而非模型隐含记忆 |
| Agent Skills | SDK 能力保留，但自动发现关闭 | 当前由 Core 主动加载并哈希绑定 CWE-476 规则包，避免宿主环境改变 run 输入 |
| 证据门禁、预算、恢复 | Security Runtime 自有 | 属于安全业务控制，不是通用 SDK 内层循环的替代品 |

因此，当前架构不是“SDK 能做什么就全部开放”，而是“复用通用执行能力，只开放满足调查契约的子集”。
`skills/cwe476/` 本身就是包含指令与结构化契约的版本化规则包；关闭的是 SDK 自动发现机制，
不是 Skill 这种知识载体。

## 4. 为什么不能直接打开自动 Skill 发现

直接让 SDK 扫描本机或目标项目的 Skill，会破坏三个现有不变量：

1. **输入可冻结**：run 创建后，本机新增或修改 Skill 不应静默改变调查行为。
2. **产物可校验**：规则与指令需要内容哈希；变化必须使旧结论 STALE，而不是继续展示旧 Finding。
3. **角色可隔离**：Judge 输入只能包含 scope、规则、证据和来源限制，不能继承 Investigator 的场景指令或宿主环境。

这些约束不否定 Skill 能力，只反对未经选择和留痕的隐式加载。正确方向是显式解析、绑定和注入。

## 5. Skill 场景仓方案

### 5.1 目标

- Skill 使用标准 Agent Skills 目录与 `SKILL.md` 格式，业务作者无需了解 Security Runtime 内部实现。
- 每个包具有稳定名称和版本；场景仓可以独立维护、评审和发布。
- Security Agent 与原生 Agent 各自通过薄适配层加载同一份场景内容。
- Skill 提供调查方法和场景知识，不获得绕过宿主权限、预算和证据门禁的能力。

### 5.2 职责划分

| 部分 | 负责 | 不负责 |
| --- | --- | --- |
| Skill 场景仓 | 场景说明、调查步骤、反例策略、适用条件、版本 | 修改宿主状态、授予工具、定义 Finding 接纳规则 |
| 宿主适配层 | 发现显式选择的包、解析版本、映射到宿主 Skill 配置 | 擅自扫描并启用未选择的内容 |
| Security Core | `contract.json`、required evidence、裁决 schema、UNKNOWN 约定 | 依赖某个 SDK 的自动发现行为 |
| Security Runtime | 哈希绑定、角色隔离、工具授权、预算、持久化、恢复、STALE | 把 Skill 文本当作已验证事实 |

核心安全契约必须由 Core 持有且不可被场景 Skill 覆盖。否则“写场景的人”实际上可以改写裁决规则，
场景仓就不再只是可复用知识包。

### 5.3 创建时注入流程

建议第一版采用以下流程：

1. 用户通过 CLI 显式选择场景仓、Skill 名称和版本；禁止使用浮动的未记录版本。
2. 宿主解析完整 Skill 集合，拒绝重复 ID、缺失依赖和不支持的声明。
3. 对每个包的全部内容计算 SHA-256，将名称、版本、来源和哈希写入 run 的固定配置及基线产物。
4. 创建调查任务时携带已冻结的 Skill 引用；Claude 适配器把其映射到 SDK 的 Skill 配置，替换当前的空集合。
5. 只向 Investigator（必要时包括准备阶段）注入场景 Skill；Judge 仍只接收 Core 规则和证据包。
6. 恢复、输出和密封校验时重新核对包哈希；不一致则标记 STALE 并撤下旧结论。
7. Skill 内容和其引入的上下文占用纳入现有上下文与调用预算。

这一步只扩展“固定输入如何进入 Investigator”，不需要改变证据接纳和裁决语义。

### 5.4 运行中动态注入

运行中追加 Skill 可以满足人机协同，但应作为独立阶段实现：

- 每次追加生成不可变事件，记录 Skill ID、版本、完整哈希、操作者、时间、适用 Investigation 和原因。
- 追加只影响之后创建的行动；历史 attempt 继续引用原 Skill 集合，保证重放含义不变。
- 恢复时从初始固定集合和追加事件重建当前集合，不能依赖宿主目录当前内容。
- 已经生成的 Evidence、JudgeDecision 和 Finding 保留原输入版本；若新 Skill 改变判断依据，必须产生新证据版本和新裁决。
- 对移除或替换采用“新集合版本”，不原地改写历史记录。
- 需要明确动态注入是否允许无人值守自动发生；首版建议只允许用户显式追加。

若跳过这些记录，所谓动态注入会使同一 run 的前后行为无法解释，也会破坏中断恢复和审计。

## 6. 跨宿主便携契约

Skill 作者可以不关心宿主，但宿主必须对 Skill 声明的能力有一致解释。建议分两类：

- **通用场景 Skill**：只使用标准 Skill 指令和宿主通用能力，可直接在 Security Agent 与原生 Agent 间复用。
- **安全调查 Skill**：可声明七类语义查询及读取/搜索冻结源码等能力；其他宿主若提供同名同语义工具即可复用，否则必须在加载时报告不支持或明确降级，不能假装查询已经执行。

现有七类查询词汇可以成为跨宿主能力契约，但还必须携带结果语义：`text-candidate`、
`syntax-observation`、`candidate-relation` 等精度不能被宿主静默升级。
可在 Skill 元数据中增加可选的 `precision_hints` 等扩展字段：Security Agent 消费，其他宿主忽略未知可选字段。

无论 Skill 如何描述结论，最终 Evidence 仍须通过 `admit()` 等确定性门禁。
坏 Skill 最坏应导致无效调查或预算耗尽，而不能凭空制造 Finding。

## 7. 安全与故障边界

- Skill 是半可信指令输入，需要防范场景仓或目标仓库中的提示注入；不能因为格式是 `SKILL.md` 就默认可信。
- Skill 不自动授予 Bash、文件写入、外部 MCP、Subagent 或网络权限；工具面仍由 Runtime 决定。
- 场景包解析失败、版本缺失、哈希变化或宿主能力不足，应如实形成配置失败或能力缺口。
- Judge 不加载场景包，不接收 Investigator 的隐含会话状态。
- Skill 只影响调查建议，不能修改预算、基线、UNKNOWN 约定或 STALE 规则。

## 8. 推荐落地顺序

1. **固定集合注入**：支持显式选择 Skill、完整哈希绑定、Investigator 单角色注入和恢复校验。
2. **便携能力声明**：定义通用/安全 Skill 的能力与可选精度扩展，验证不支持时的明确失败或降级。
3. **运行中追加**：增加追加式事件、集合版本和历史重放，再开放用户显式动态注入。
4. **真实验证**：覆盖原生宿主复用、坏 Skill、哈希变化、中断恢复、Judge 隔离、预算和零 Finding 边界。

第一版改动面集中在 CLI、`Task`/运行配置、Core 的 Skill 加载器和 Claude 适配器。
正式实现前需要核对当前锁定版 `claude-agent-sdk` 的 `skills` 参数类型与加载语义；
本讨论没有验证该 API 的具体字段形态，不能据此假定可直接传路径列表。

## 9. 当前决策

采用“**复用 SDK 通用能力 + Security Runtime 保留业务控制 + 独立 Skill 场景仓显式注入**”。
不以重建 Subagent、Tool calling、Memory 或 Skills 为目标，也不以牺牲可恢复性、证据门禁和 Judge 隔离为代价换取自动发现。
先完成创建时固定集合注入，再根据实际场景决定是否开放运行中追加。
