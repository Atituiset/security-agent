# Security Agent Architecture Design

## 1. 背景

当前系统已经形成一套面向代码安全检视的 5-stage Pipeline：

```text
pre-process
    ↓
preload
    ↓
dispatch
    ↓
review-execute
    ↓
post-process
```

目标是围绕 C/C++ 代码安全检视，结合：

- Git diff / PR
- 函数级代码切分
- CodeGraph
- ripgrep
- ast-grep
- clang / LLVM
- CWE Security Skills
- LLM Reasoning
- Judge
- SARIF

形成一套可扩展的 Security Review 系统。

初始实现可以直接基于 Claude Code，通过 Skill 驱动完整 5-stage。

随着系统演进，需要回答一个核心架构问题：

> 是否应该进一步构建独立 Security Agent，以及 Security Agent 与 Claude Code、Codex、Agent SDK、ACP、OpenHands 等通用 Agent 基础设施之间应该是什么关系？

本文档给出最终架构判断及演进路线。

---

# 2. 核心结论

当前不应该重新实现 Claude Code/Codex 所提供的通用 Agent Harness。

系统长期应该形成：

```text
Security Domain
      │
      ▼
AgentExecutor Port
      │
      ▼
Replaceable Agent Infrastructure
```

其中：

```text
Security Domain
```

属于系统长期核心资产。

包括：

```text
5-stage
Finding
Evidence
Security Skill
Judge
Verdict
SARIF
Vulnerability Assessment IR
```

而：

```text
Claude Code
Claude Agent SDK
Codex
Gemini
ACP
OpenHands
```

均属于可替换的 Agent Infrastructure。

核心原则：

> Security System 是主体，Agent 是执行器。

而不是：

> Claude Code 是主体，Security Review 只是其中一个 Skill。

---

# 3. 不重新造 Claude Code

Claude Code / Codex 这类 Coding Agent 已经解决了大量通用 Agent Infra 问题：

```text
Agent Loop
Session
Context Management
Tool Calling
Filesystem
Shell
MCP
Permission
Retry
Cancel
Compaction
Subagent
Streaming
```

Security Review 并不应该重新建设这些能力。

因此系统应遵循：

```text
Agent Infra：复用
Security Intelligence：自研
```

真正应该投入研发精力的是：

```text
Security Workflow
Security Skill
Evidence Model
Finding Lifecycle
Judge
Security Control Plane
```

---

# 4. 三层架构

整个系统可以分成三个逻辑层次。

## 4.1 Security Domain Layer

这是整个系统最重要、最稳定的一层。

```text
Security Domain
│
├── Review
├── Finding
├── Evidence
├── Vulnerability Assessment IR
├── Security Skill
├── Judge
├── Verdict
├── Remediation
├── Verification
└── SARIF / VEX
```

这一层：

- 不依赖 Claude
- 不依赖 OpenAI
- 不依赖 Gemini
- 不依赖 OpenHands
- 不依赖 ACP
- 不依赖具体 Agent SDK

这是长期技术资产。

---

## 4.2 Security Control Layer

负责 Security Workflow 的执行。

```text
Security Controller
│
├── pre-process
├── preload
├── dispatch
├── review-execute
└── post-process
```

其职责是决定：

```text
分析什么
需要什么证据
调用哪个 Skill
什么时候进入 Judge
什么时候继续调查
什么时候允许结束 Finding
```

这里应该尽量使用确定性代码，而不是全部交给 LLM。

---

## 4.3 Agent Infrastructure Layer

负责真正执行 Reasoning Agent。

```text
Agent Infrastructure
│
├── Claude Code
├── Codex
├── Gemini CLI
├── Claude Agent SDK
├── ACP Agent
└── Future Local Agent
```

它负责：

```text
LLM reasoning
tool loop
context
session
tool invocation
```

但不拥有 Security Domain。

---

# 5. 当前 5-stage 的定位

5-stage 本质是：

> Security Analysis Pipeline

而不是 Agent Runtime。

```text
PR
 │
 ▼
pre-process
 │
 ▼
preload
 │
 ▼
dispatch
 │
 ▼
review-execute
 │
 ▼
post-process
```

建议将不同 Stage 分成两类。

## 5.1 Deterministic Stage

尽量由程序控制：

```text
pre-process
preload
dispatch
post-process
```

例如：

```text
Git diff parsing
Function extraction
Symbol preload
Rule matching
Finding creation
SARIF generation
```

这些事情不应该依赖：

```text
“LLM 有没有记得做”
```

---

## 5.2 Reasoning Stage

Agent 主要介入：

```text
review-execute
```

负责：

```text
漏洞假设调查
上下文补充
证据选择
调用 CodeGraph
调用代码查询工具
安全语义推理
寻找反例
```

最终输出：

```text
Evidence
```

而不是直接输出最终事实。

---

# 6. 为什么最终不能只依赖 Claude Code Skill

Claude Code + Skills 非常适合作为 MVP。

例如：

```text
/security-review
    │
    ├── pre-process
    ├── preload
    ├── dispatch
    ├── review
    └── post-process
```

优点：

```text
实现快
代码少
调试方便
Claude Code 已具备完整 Agent 能力
适合快速验证 Security Workflow
```

因此当前应该继续使用。

但长期存在几个问题。

## 6.1 Workflow 是 Prompt 约定

如果 5-stage 完全由 Skill 驱动：

```text
Prompt
 ↓
Claude 理解
 ↓
Claude 执行
```

可能出现：

```text
stage 被跳过
preload 不完整
dispatch 漏掉
提前结束 review
不同 run 行为不一致
```

因此随着系统成熟，5-stage 应逐渐变成程序控制流。

---

# 7. Finding 一等对象

长期不能让 Finding 只是聊天上下文中的文本。

应该形成结构化对象：

```text
Finding
├── id
├── cwe
├── location
├── function
├── hypothesis
├── status
├── evidence[]
├── verdict
├── confidence
├── remediation
└── verification
```

Finding 生命周期可以定义为：

```text
NEW
 ↓
INVESTIGATING
 ↓
EVIDENCE_READY
 ↓
JUDGING
 ↓
CONFIRMED
 /     \
REJECTED
UNKNOWN
 ↓
REMEDIATING
 ↓
VERIFYING
 ↓
CLOSED
```

这将成为 Security Control Plane 的核心对象。

---

# 8. Evidence 是系统真正核心

Security Agent 最大区别不应该是：

> 更会聊天。

而应该是：

> 更会形成可验证、可追踪、可审计的安全证据。

Evidence 可以定义为：

```text
Evidence
├── id
├── kind
├── producer
├── source
├── location
├── content
├── provenance
├── confidence
└── timestamp
```

例如：

```json
{
  "id": "E17",
  "kind": "call_path",
  "producer": "codegraph",
  "path": [
    "recv_packet",
    "parse_packet",
    "copy_payload"
  ],
  "location": "parser.c:123",
  "confidence": "deterministic"
}
```

这样：

```text
Tool Result
      ↓
Evidence Normalization
      ↓
Evidence Store
      ↓
Investigator
      ↓
Judge
```

而不是：

```text
Tool Result
      ↓
Conversation Context
      ↓
LLM 自己记住
```

---

# 9. Security Skill Contract

Security Skill 不应该长期停留在：

```text
“请检查 CWE-787。”
```

而应该逐渐形成 executable specification。

例如：

```yaml
id: CWE-787

required_evidence:
  - destination_buffer
  - write_size
  - buffer_capacity
  - attacker_control
  - reachable_path

tools:
  - find_definition
  - find_callers
  - find_callees
  - find_assignments
  - find_pattern

reasoning:
  - compare_size_constraints
  - determine_attacker_control
  - inspect_sanitization

completion:
  judge_when:
    - required_evidence_complete

  fallback:
    - UNKNOWN
```

Security Skill 最终越来越像：

```text
Security Pass
```

而 5-stage 类似：

```text
Pass Pipeline
```

---

# 10. Vulnerability Assessment IR

整个 Security System 可以进一步形成统一 IR：

```text
Source Code
     │
     ▼
Security Frontend
     │
     ▼
Vulnerability Assessment IR
     │
     ├── Finding
     ├── Evidence
     ├── Call Path
     ├── Constraints
     ├── Reachability
     ├── Exploitability
     └── Verdict
             │
             ▼
        Security Passes
             │
        Judge / Verifier
             │
             ▼
     SARIF / VEX / CRA
```

这也是未来将：

```text
SAST
SCA
Reachability
Exploitability
Remediation
```

统一起来的关键中间表示。

---

# 11. Judge 与 Investigator 分离

建议长期采用：

```text
Investigator
      │
      ▼
Evidence
      │
      ▼
Judge
      │
      ▼
Verdict
```

Investigator 负责：

```text
查代码
调用工具
形成假设
补充证据
寻找路径
```

Judge 负责：

```text
证据是否完整
漏洞是否成立
Reachability 是否成立
Exploitability 是否成立
Fix 是否有效
```

Judge 只消费：

```text
Finding
+
Evidence
+
Policy
```

而不是共享 Investigator 全部上下文。

这样可以减少：

```text
confirmation bias
reasoning contamination
```

也便于以后引入：

```text
JEV
Rule-based Judge
Small Judge Model
Independent Large Model
```

---

# 12. AgentExecutor：真正需要稳定的基础抽象

短期不需要选定某一个所谓“统一 Agent Framework”。

只需要定义非常薄的一层：

```python
class AgentExecutor(Protocol):

    async def execute(
        self,
        task: SecurityTask,
        workspace: Workspace,
        tools: list[SecurityTool],
        context: SecurityContext,
    ) -> AgentResult:
        ...
```

Security Core 只允许依赖：

```text
AgentExecutor
```

而不能依赖：

```text
Claude Agent SDK Type
ACP Session Type
OpenHands Conversation
Codex Event
```

这样可以形成 Ports & Adapters 架构：

```text
                 Security Core
                       │
                       ▼
                AgentExecutor
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
ClaudeCodeAdapter  CodexAdapter    ACPAdapter
                                       │
                                    future
```

---

# 13. 为什么不直接把 Claude Agent SDK 当架构核心

Claude Agent SDK 非常适合实现 Agent Harness，包括：

```text
Agent Loop
Tool Loop
Session
Context
MCP
Hooks
Permission
Filesystem
Bash
```

但是如果 Security Domain 直接依赖它：

```text
Security Core
     ↓
Claude Agent SDK
```

长期会形成厂商绑定。

正确方式应该是：

```text
Security Core
     ↓
AgentExecutor
     ↓
ClaudeAgentAdapter
     ↓
Claude Agent SDK
```

Claude SDK 是 Adapter Implementation，而不是 Domain Dependency。

---

# 14. ACP 的正确定位

ACP，即 Agent Client Protocol，主要解决：

```text
Client / IDE
       ↕
Coding Agent
```

例如：

```text
Zed
 ├── ACP → Claude Code
 ├── ACP → Codex
 └── ACP → Gemini
```

它解决的是：

```text
Agent interoperability
```

而不是完整解决：

```text
Security workflow
workspace orchestration
finding lifecycle
evidence store
parallel scheduling
remote worker
container management
```

因此 ACP 不应该成为 Security Domain 的基础接口。

正确关系：

```text
Security Core
      ↓
AgentExecutor
      ↓
ACPAdapter
      ↓
ACP
      ↓
Coding Agent
```

ACP 是 Adapter，而不是 Domain Contract。

---

# 15. OpenHands 的正确定位

OpenHands 主要解决：

```text
Agent Runtime / Host / Workspace Infrastructure
```

包括：

```text
Agent execution
Conversation
Workspace
Container
Sandbox
Remote runtime
HTTP/WebSocket API
Process lifecycle
```

因此它真正有价值的场景不是：

```text
单个本地 PR Review
```

而是：

```text
100 个 PR
   ↓
Task Queue
   ↓
100 个隔离 Workspace
   ↓
并发 Agent
   ↓
资源限制
   ↓
任务恢复
```

此时 OpenHands 能避免自己重新建设：

```text
Agent Runtime Infrastructure
```

因此：

```text
OpenHands
```

属于未来可选 Runtime，而不是当前必选依赖。

---

# 16. 最终目标架构

最终推荐架构：

```text
                    Security Control Plane
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
            ▼                 ▼                 ▼
       pre-process         preload           dispatch
                                              │
                                              ▼
                                           Finding
                                              │
                                              ▼
                                      AgentExecutor Port
                                              │
                     ┌────────────────────────┼──────────────────┐
                     ▼                        ▼                  ▼
              Claude Adapter            ACP Adapter        Local Adapter
                     │                        │                  │
                 Claude Code        Claude/Codex/Gemini      Local Agent
                                              │
                                              ▼
                                           Evidence
                                              │
                                              ▼
                                           Judge
                                              │
                                              ▼
                                        post-process
                                              │
                                     ┌────────┼────────┐
                                     ▼        ▼        ▼
                                   SARIF     VEX     Report
```

长期进一步演进：

```text
Security Control Plane
│
├── Review Scheduler
├── Finding Scheduler
├── Evidence Store
├── Security Skill Registry
├── Judge Service
├── AgentExecutor
├── Remediation
└── Verification
```

---

# 17. 演进路线

## Phase 0：当前阶段

```text
Claude Code
    +
5-stage Skills
```

目标：

```text
验证 Security Workflow
验证 CWE Skill
验证 CodeGraph Tool
验证 LLM Security Reasoning
```

暂时不要增加：

```text
OpenHands
ACP orchestration
自研 Agent Runtime
复杂分布式架构
```

---

# 18. Phase 1：抽离 Security Domain

从 Claude Code Skill 中逐渐抽出：

```text
Finding
Evidence
Verdict
Security Skill Contract
SARIF
```

形成：

```text
security-core/
├── review/
├── finding/
├── evidence/
├── skill/
├── judge/
└── output/
```

此时仍然可以：

```text
Claude Code
      │
     Skill
      │
      ▼
Security Core CLI
```

例如：

```bash
sec-core review-create diff.json

sec-core finding-add ...

sec-core evidence-add ...

sec-core judge F001

sec-core export-sarif
```

---

# 19. Phase 2：引入 AgentExecutor

当 Security Core 稳定后：

```text
Security Core
      │
      ▼
AgentExecutor
      │
      ▼
ClaudeCodeAdapter
```

此时开始把：

```text
Agent execution
```

从 Claude Code Skill 中进一步抽象出来。

但第一阶段只实现：

```text
ClaudeCodeAdapter
```

不要为了“架构完整”同时实现三家。

---

# 20. Phase 3：验证可替换 Agent

只有出现真实需求时再增加：

```text
CodexAdapter
ACPAdapter
LocalAgentAdapter
```

目标：

> 验证 Security Domain 与具体 Agent 真正解耦。

不是为了炫技同时支持所有 Agent。

---

# 21. Phase 4：Security Control Plane

当 PR / Finding 数量增大时：

```text
PR
 ↓
20 Findings
 ↓
Finding Scheduler
 ↓
┌────────┬────────┬────────┐
▼        ▼        ▼
Agent A  Agent B  Agent C
│        │        │
▼        ▼        ▼
Evidence Evidence Evidence
```

系统开始需要：

```text
parallelism
Finding budget
timeout
retry
workspace isolation
context isolation
Judge isolation
replay
```

此时形成真正的：

```text
Security Control Plane
```

---

# 22. Phase 5：Runtime 选型

只有出现如下需求：

```text
大量并发
远程执行
Docker/Kubernetes
Workspace 生命周期
Agent 进程管理
失败恢复
资源限制
网络隔离
```

才评估：

```text
OpenHands
```

或者其他 Agent Runtime Platform。

此时做选择：

```text
Build
vs
Buy/Open Source Runtime
```

而不是今天提前引入。

---

# 23. 什么时候真正需要自研 Security Agent Runtime

只有通用 Agent Harness 本身开始阻碍 Security Invariant 时。

例如系统要求：

```text
I1
Verdict 必须引用 Evidence ID

I2
required evidence 未满足
禁止进入 Judge

I3
Reason Model 不得修改原始 Evidence

I4
Judge Context 必须与 Investigator 隔离

I5
Fix 未 Verify
Finding 不允许 Close

I6
所有 Tool Result 必须保留 provenance

I7
所有 Finding 必须能够 replay

I8
每个 Finding 有独立 token/tool budget

I9
Agent 崩溃不得破坏 Finding 状态

I10
不同 Agent 实现不得改变 Security Domain Semantics
```

如果现有 Agent Infra 无法满足这些要求：

```text
Generic Agent Runtime
        ↓
开始限制 Security System
```

才考虑：

```text
Security-native Runtime
```

而不是提前实现。

---

# 24. 当前工程原则

## Principle 1

```text
Deterministic where possible,
Agentic where necessary.
```

能够使用：

```text
AST
CodeGraph
Rule
Compiler
Static Analysis
```

得到的事实，不应该让 LLM 猜。

---

## Principle 2

```text
Tools produce facts.
Agents investigate.
Judges decide.
Evidence makes results auditable.
```

这是整个系统最重要的设计原则。

---

## Principle 3

```text
Agent is replaceable.
Security Domain is not.
```

---

## Principle 4

不要因为担心 Vendor Lock-in，就提前实现所有 Provider。

解决锁定最有效的方法不是：

```text
今天同时支持 Claude + Codex + Gemini
```

而是：

```text
Security Domain 不出现任何 Claude-specific 类型。
```

---

## Principle 5

不要提前造 Runtime。

Runtime 应该由真实复杂度逼出来。

---

# 25. 推荐代码结构

初期可以采用：

```text
security-agent/
│
├── core/
│   ├── review.py
│   ├── finding.py
│   ├── evidence.py
│   ├── verdict.py
│   └── context.py
│
├── pipeline/
│   ├── preprocess.py
│   ├── preload.py
│   ├── dispatch.py
│   ├── review_execute.py
│   └── postprocess.py
│
├── skills/
│   ├── cwe_787/
│   ├── cwe_416/
│   ├── cwe_190/
│   └── ...
│
├── tools/
│   ├── codegraph.py
│   ├── clang.py
│   ├── ripgrep.py
│   └── astgrep.py
│
├── judge/
│   ├── protocol.py
│   ├── llm_judge.py
│   └── rule_judge.py
│
├── agent/
│   ├── executor.py
│   └── claude_code.py
│
├── output/
│   ├── sarif.py
│   ├── report.py
│   └── vex.py
│
└── cli/
    └── main.py
```

早期：

```text
agent/
└── claude_code.py
```

即可。

未来：

```text
agent/
├── executor.py
├── claude_code.py
├── codex.py
├── acp.py
└── local.py
```

---

# 26. 第一版 AgentExecutor Contract

保持极小：

```python
class AgentExecutor(Protocol):

    async def execute(
        self,
        task: SecurityTask,
        workspace: Workspace,
        context: SecurityContext,
    ) -> AgentResult:
        ...
```

不要过早暴露：

```text
session
MCP
Claude message
Codex event
ACP update
```

如果确有需求再扩展。

---

# 27. 第一版 SecurityTask

例如：

```python
@dataclass
class SecurityTask:
    finding_id: str
    cwe: str
    hypothesis: str

    file: str
    function: str

    required_evidence: list[str]

    allowed_tools: list[str]

    budget: TaskBudget
```

---

# 28. 第一版 AgentResult

```python
@dataclass
class AgentResult:
    finding_id: str

    evidence: list[Evidence]

    unresolved_questions: list[str]

    notes: str | None

    status: Literal[
        "evidence_ready",
        "insufficient_evidence",
        "failed",
    ]
```

注意：

```text
AgentResult
```

最好不要直接包含：

```text
TRUE_POSITIVE
FALSE_POSITIVE
```

最终漏洞 Verdict 应由：

```text
Judge
```

决定。

---

# 29. 第一版 MVP 范围

建议第一版只支持：

```text
语言：
C / C++

入口：
Git Diff / PR

漏洞：
约 10 个高价值 CWE

工具：
ripgrep
ast-grep
CodeGraph
clang

模型：
一个 Reason Model

Judge：
一个独立 Judge

输出：
Markdown
SARIF
```

明确暂时不做：

```text
IDE
Web UI
SCA
CRA
VEX
自动修复闭环
远程 Runtime
多租户
OpenHands
ACP 多 Agent
```

先把：

```text
Security Review Quality
```

做到足够好。

---

# 30. 最终技术叙事

整个项目可以形成一个非常明确的技术叙事：

```text
General Coding Agent
        │
        ▼
Security Control Plane
        │
        ├── Security Skills
        ├── Security Tools
        ├── Evidence IR
        ├── Finding Lifecycle
        └── Judge
        │
        ▼
Auditable Security Decision
```

核心不是：

> 做一个 Security 版 Claude Code。

而是：

> 构建一个能够使用不同 Coding Agent 作为 Reasoning Executor 的 Security-native Analysis Control Plane。

Claude Code、Codex、Gemini、本地模型只是：

```text
execution backend
```

真正长期稳定的是：

```text
Security Skill
Security IR
Evidence
Finding
Judge
Control Plane
```

---

# 31. 一句话架构原则

最终可以把整个设计浓缩成：

> **Use existing agents as reasoning engines, deterministic tools as fact producers, an evidence-centric Security Core as the source of truth, and an independent Judge as the decision boundary.**

中文：

> **复用通用 Agent 作为推理执行器，以确定性工具生产事实，以 Evidence-centric Security Core 作为事实与状态中心，以独立 Judge 作为最终安全决策边界。**

这应该成为整个系统后续架构演进的核心不变量。