# Security Runtime MVP 实施计划

更新：2026-09-26。架构与术语分别以 [主设计](security-agent.md) 和 [领域词汇](../CONTEXT.md) 为准。
本页列出工程顺序和验收。M1–M4 已落地，详见 [Runtime 记录](runtime-implementation.md)；
用户后续要求已扩展多执行后端，详见 [Agent Infra](agent-backends.md)。M5 尚未全部完成。

## 1. 已完成的基础切片

- C/C++ Git 提交输入：文件、指定函数、diff；新仓库无需旧检查目录。
- 默认 Claude Agent SDK，新增 OpenCode/Hermes；Investigator 与 Judge 可独立选宿主，使用独立会话。
- Core 加载版本化 CWE-476 包；源码引用由程序验证，确认项通过证据门禁。
- Tools：CodeGraph、Tree-sitter、冻结源码搜索，七类查询入口及能力缺口说明。
- 五阶段产物、原始证据与来源、Markdown/SARIF、调用预算、超时、基础恢复与失效检查。

初始切片是一次 Investigator 加一次 Judge；当前已增加 Judge 驱动的有界跨轮补查。当前验证记录见 [validation.md](validation.md)。

## 2. 下一轮范围与顺序

按下列顺序逐步替换现有控制流程，不一次性重写 SDK、Tools、证据和输出模块。
所有协议演进必须绑定版本，旧 run 不原地升级语义；后端扩展不得改变 Core 的领域契约。

### M1：持久化调查模型与行动账本

引入 Hypothesis、MissingFact、Action、EvidenceSetVersion、JudgeDecisionVersion。
现有 scenario 映射为 Hypothesis；保留源产物和 ID 对照，明确执行状态与结论分离。

每次动作先记录输入版本、幂等键和预算预留，完成后记录原始结果与归一化结果；
业务状态推进与结果接纳有可重放的事务边界。保持文件存储、原子替换、单写入者。

验收：在“已保存原始响应、尚未接纳”之间中断，恢复只做接纳，不再次调用模型；
在“已发出请求、结果未知”处中断，记录 INTERRUPTED，新 attempt 不抹掉旧费用预留。
旧证据版本的 JudgeDecision 不得确认新版本假设。

### M2：有界持续调查

Runtime 支持 DISCOVER → EXPAND → EVIDENCE_REVIEW → JUDGE 的循环。
每轮 Investigator 接收目标、当前假设、已知证据、Missing Fact 和已尝试动作摘要，
返回新增/修订假设、证据选择、反例和下一步建议。SDK 会话内仍允许多次查询。

增加每调查/假设的轮数、工具/调用配额、整体截止时间、重复行动去重和无进展停止。
预算从 Run 下拨，不能通过新建假设绕过总上限；多假设顺序公平调度，暂不并行。

验收：一个跨文件案例必须经历至少两轮且第二轮确实利用第一轮证据；
重复同一问题无新事实时停止；预算不足保持 UNKNOWN 并记录具体未解问题；
一个假设耗尽预算不静默丢弃其他假设。

### M3：Judge 驱动补查

扩展 Judge 输出 missing_facts 和 follow_up，绑定 evidence_version。
Judge 给 UNKNOWN 并提出事实问题；Runtime 校验、去重后调度 Investigator，再构造新证据包重判。
Judge 仍不继承 Investigator 会话，不直接调用工具或改写业务状态。

验收：首轮缺失 callee 的空返回条件，Judge 请求补查，补查后能形成可核验证据；
补查也可能发现 guard 而 REJECTED。禁止仅改变提示措辞、多次询问直到得到确认。
Judge 建议超范围、工具不支持、循环补同一问题时安全终止，保留 UNKNOWN 与原因。

### M4：阶段内恢复与报告

为 pre-process、索引准备、preload、dispatch 增加真实行动检查点与失败产物。
阶段交接由代码校验契约和引用，恢复按已完成动作推进，不仅检查阶段名。
报告增加每假设的证据版本、补查摘要、停止原因、执行失败与 Coverage，保留修复状态 NOT_STARTED。

验收：索引超时/中断不产生完成标记；恢复使用匹配的代码/规则/索引；
依赖改变使结论失效，历史原文仍可审计；已有有效结果和失败项同时可见。

### M5：对照验证与评估

先用执行接口替身精确验证控制状态机，再用真实工具验证事实契约，最后做预算受控的真实模型验证。
复用原 review-skills 的规则与案例语义，但它保持独立只读；不把旧 verdict 当测试真值。

| 案例 | 必须观察的行为 |
| --- | --- |
| 明确空值跨函数传递 | 自主找到 origin、传播和 sink 的来源证据 |
| 有早返回 guard | 寻找反例后排除具体假设，不确认错误漏洞 |
| 同名重载/虚调用 | 保留候选身份与不确定性，不能随便选第一个 |
| 缺失外部定义 | 有针对性的查询与降级尝试，最终 UNKNOWN |
| Judge 缺口 | 新证据推动后续轮次，或解释为何无法补齐 |
| 中断/超时/预算耗尽 | 保留原始结果、预留与 Missing Fact，可恢复且不伪装成功 |
| 基线/索引/规则变化 | 旧结论失效，不能携带旧确认项继续使用 |
| 全新仓库指定函数 | 无旧 session、无预置 sink 清单也能调查 |

指标分开记录：标注样本上的误报/漏报、UNKNOWN 与覆盖、每场景模型和查询成本、
调查轮数、重复查询率、中断后的重复付费次数。多次真实运行记录波动，不凭单次案例宣布优于旧架构。

## 3. 当前不扩展的事项

暂不做 Joern/ast-grep/clang 的全部适配、远程执行、Web UI、自动修复、
多 Agent 并行调度、通用持久化平台或局部依赖失效引擎。
Tools 接口保留后续扩展；优先证明一个 CWE 的持续调查有效，而不是增加抽象数量。

## 4. 代码演进位置

| 当前模块 | 演进职责 |
| --- | --- |
| core/contracts.py、core/judge.py | 假设/行动/裁决契约、版本门禁 |
| core/context.py、core/skills.py | 根据调查检查点生成有界任务、加载 Skill |
| pipeline/controller.py、pipeline/stages.py | 外层五阶段与持续调查调度；复杂后再提取 runtime 模块 |
| tools/ | 事实契约、能力与工具适配；不接管调查状态机 |
| infra/claude.py | 保持 SDK 适配职责，不加入补查策略 |
| core/storage.py、core/output.py | 原始记录、状态恢复及报告视图 |

文件路径是演进建议，不承诺必须新增 runtime/ 目录；职责比目录名称更重要。
