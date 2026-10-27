# Security Investigation

本项目围绕代码安全调查组织假设、事实、证据和结论。目标是带有 Security Runtime 的 Security Agent。

## Language

**Security Agent（安全调查 Agent）**：依据安全知识和调查进展提出假设、选择取证行动、寻找反例并请求裁决的调查主体。
_Avoid_: 将报告生成器或固定步骤流水线单独称为完整 Agent。

**Security Runtime（安全运行时）**：管理安全调查生命周期、行动约束、证据依赖与结论有效性的专用执行机制。
_Avoid_: 与通用模型会话运行时混称。

**Security Core（安全核心）**：安全领域模型、调查规则与 Security Runtime 的整体。
_Avoid_: 将 Core 仅理解为提示词或数据结构。

**Review Target（检视目标）**：用户指定、绑定代码基线的待检视范围。
_Avoid_: 将辅助取证访问的代码都算成检视目标。

**Investigation（调查）**：围绕一个检视单元及其安全问题展开的持续取证活动，可以包含多个假设。
_Avoid_: Finding、已确认漏洞。

**Hypothesis（假设）**：关于特定代码位置和条件可能形成漏洞的可检验主张。
_Avoid_: 在确认前称为漏洞事实。

**Fact（事实）**：工具或源码提供的观察，带有位置、来源、精度和适用范围。
_Avoid_: 将文本匹配、图候选或分析解释视为确定的程序行为。

**Evidence（证据）**：经过来源与完整性检查、被选中支持或反驳一个具体假设的事实及其引用。
_Avoid_: 模型生成但无法核验的源码引用。

**Missing Fact（缺失事实）**：妨碍判断某个假设的具体未解问题，可对应下一步取证行动。
_Avoid_: 没有问题描述的“上下文不足”。

**Verdict（漏洞结论）**：对指定假设和证据版本作出的 CONFIRMED、REJECTED 或 UNKNOWN 判断。
_Avoid_: 与执行是否成功、修复是否完成混用。

**Finding（确认项）**：通过裁决与证据接纳条件的漏洞记录。
_Avoid_: 待调查位置、模型猜测、所有 scenario 的统称。

**Coverage（覆盖情况）**：已调查范围、方法能力及未解决限制的描述。
_Avoid_: 从零 Finding 推导整体安全。

**Remediation（修复状态）**：确认项的修复处置进展，独立于调查执行和漏洞结论。
_Avoid_: 将新一轮未发现问题等同于已修复。
