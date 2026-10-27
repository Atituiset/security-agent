# MVP 验证记录

日期：2026-09-26。Python 3.12.3，claude-agent-sdk 0.2.160。

## 离线控制流验证

执行 `.venv/bin/python -m unittest discover -s tests -v`。
测试在临时真实 Git 仓库上使用真实 SDK adapter、options 和 message 类型，
仅把 `ClaudeSDKClient` 换成可控响应的测试 client。

覆盖：

- 裸空指针确认 → 独立 Judge → Finding → Markdown/SARIF。
- guard 排除、缺失定义 UNKNOWN、跨文件来源（未变更 provider）以及 C++ 文件名。
- 伪造代码摘录、缺少必要证据、Judge 捏造引用/漏判、未解决问题却强行确认。
- 总调用预算/上下文字节预算、SDK 预算错误、超时保留部分消息流。
- 中断后仅重试未完成角色、突发退出后预算不退还、重复恢复不重复 Finding。
- head 移动（包括只改 callee）、快照/原始响应/已确认 Finding 被修改、修改旧预算 → STALE。
- 单写者锁、删除文件、非源码、非 UTF-8、符号链接、特殊路径。
- 真实 SDK 可能返回 `subtype=success` 但 `is_error=true` 的认证失败：必须 FAILED/UNKNOWN。

这些是控制层和契约测试，不是模型能力或漏洞准确率评测。
`pip check` 同时验证依赖一致性。

## 真实 SDK smoke

用 `examples/smoke.py` 创建只有 4 行 C 代码的临时 Git 仓库，真实调用
`ClaudeSDKClient`，上限两次调用、每次 $0.25、每次 45 秒。

第一次在受限沙箱中超时；第二次获准在沙箱外执行，SDK 成功建立消息流，
模型返回 `authentication_failed` / `Not logged in · Please run /login`。
最终 ResultMessage 的 `is_error=true`，`total_cost_usd=0`。
控制层正确输出 FAILED、UNKNOWN、零 Finding，保留请求与消息流。

本机路径（临时验证产物，不属于可移植样例）：
`/tmp/security-agent-sdk-smoke-02/review/`。
以上初始 smoke 未验证语义闭环；后续使用本机兼容 provider 的真实 AetherStack 验证已完成，见下节。
不将离线替身结果冒充真实模型确认结果，也不要求用户把凭证发到对话中。


## AetherStack 历史 session 真实回归（最终结果）

输入 session：`/home/atituiset/Projects/AetherStack/.review/sessions/review-20260915-142528-400bd1b5d0af`。
基线：`ed126a8ed87fefd2698affe928c875e52b663d0d`。
范围：`stack/core/src/bs_node.cpp` 的 25 个指定 CWE-476 sink 场景；它是旧 session 的文件检视范围，不是最近一次 NAS diff。

只读预检查通过：112 条证据引用可解析，14 个依赖 SHA-256 与 Git 提交源码一致。
25 个场景的 ID 与位置成为待调查对象；旧 excluded 结论仅用于事后比较，未进入模型。

最终运行：`.runs/aetherstack-reference-v3/`。
唯一执行后端：Claude Agent SDK 0.2.160；模型：本机兼容配置 `deepseek-v4-flash`。
两次独立 SDK client 调用（Investigator / Judge），每次上限 $1.50，总预留上限 $3。
SDK 报告成本合计 $1.162261；兼容 provider 的真实账单可能与 SDK 估算不同。

结果：

- execution = COMPLETED；25 个候选完整经过 Investigator 与独立 Judge。
- 控制层从 Git 源码生成 99 条可追溯证据，不要求模型复制证据原文。
- Judge：25 REJECTED、0 CONFIRMED、0 UNKNOWN 场景；0 Finding，与旧 CWE-476 场景结论一致。
- 仍存在调查层面的宏/编译配置、外部调用者等覆盖限制；因此 coverageComplete=false，CLI 返回 2，不宣称全仓安全。
- report.md / review.sarif / comparison.json 已生成；最终 SARIF 通过公开 SARIF 2.1.0 JSON Schema 校验。
- 审计产物未发现本机 provider token/key 的原值；AetherStack 仍只有原有三个未跟踪目录，源码未修改。

本次真实回归修正了实际工程问题：整仓 prompt 过长改成按需源码工具；重复传输目标文件改为复用初始上下文；
模型复制源码的行边界误差改为确定性证据提取；同一场景多个 sink 的支持改为确认必须引用主 sink；
Judge 的依赖上下文改为标注范围的合并窗口，缺失上下文必须 UNKNOWN；已保存的 SDK 响应可重放归一化，避免重复付费调用。
失败的早期尝试原样保留于本地 `.runs/`，没有替换成成功记录。

最终离线测试：48 项通过；可编辑安装后的 `security-agent --help` 和 `pip check` 通过。
确认项的离线 SARIF 和真实零确认项 SARIF 均通过公开 schema 校验。
这些验证证明该范围的流程可执行、状态可审计；不代表已测得准确率/召回率或构成形式化安全证明。

## Core / Infra 分离后的直接函数验证

运行目录：`.runs/aetherstack-function-core/`。输入只有 AetherStack 仓库、
`stack/core/src/bs_node.cpp` 和 `core::BsNode::attach_xn`；没有历史 session，也没有预置候选。
Git 基线仍为 `ed126a8ed87fefd2698affe928c875e52b663d0d`。
Tree-sitter 定位到 1064–1068 行，初始请求只包含 5 行函数正文及有限索引。

Claude Agent SDK 经本机配置执行 Investigator / Judge 两次独立调用，
每次预留 $0.50、超时 180 秒。结果 execution=COMPLETED，1 个自主发现的调查场景，
5 条源码证据，Judge=UNKNOWN，0 Finding，coverageComplete=false，CLI 返回 2。
原因是缺少可证明空指针实参可达的调用者或接口契约；未将局部解引用直接确认为漏洞。
Markdown 与 SARIF 已输出。

离线测试 51 项通过，覆盖 Core 的依赖边界、通用执行接口替身、全新仓库的直接函数入口、
函数范围约束和独立 SDK 适配器。Tree-sitter 固定为 0.25.2；0.26.0 在本机实际 C++ 文件解析中
出现进程崩溃，降级后真实函数定位与测试进程均正常退出。
策略版本更新为 `cwe476-v4-core-infra`；旧版本运行的恢复会判定基线策略失效，原始产物保留。

## 五阶段契约、规则包与 Tools（v5）

新增 8 项查询/集成测试，全套 59 项通过（CODEGRAPH_CLI 指向本机构建版本）。
真实 CodeGraph 集成使用全新临时 Git 仓库：建索引、查调用者、独立执行接口替身完成
调查/Judge、记录五阶段与证据 query_refs；重复恢复不调用模型；源码改变后 STALE。
另测文本候选降级、AST 观察、截断、预算、参数约束、退出码零但非 JSON、进程超时。

真实模型运行 `.runs/aetherstack-tools-v5-final/`：AetherStack 的 `core::BsNode::attach_xn`，
没有历史 session 或预置候选。独立完整提交 checkout 建立 CodeGraph 索引，目标仓未修改。
Investigator 实际发起 4 次语义查询：find_callers、find_definition、find_references、find_definition；
原始工具输出、源码、请求与归一化结果均保存；8 条 Evidence 含 12 条关联 query_refs。
两次 SDK 调用均 COMPLETED；SDK 估算成本 $0.279059，总预留上限 $1。

场景结论为 REJECTED（所见调用者传入非空对象地址），调查整体仍 UNKNOWN：
调用者覆盖非穷尽且缺少编译配置，因此 0 Finding、coverageComplete=false、CLI 返回 2。
这不是“所有调用均安全”的证明。SARIF 通过官方 2.1.0 schema 校验。
真实运行后增加了查询 source-view 哈希与工具子进程组超时清理，相关查询测试再次通过。
wheel 构建验证规则 contract 和三份指令文件均随包发布。

## Security Runtime 与可替换 Agent Infra（v6）

用户后续要求将单执行后端范围扩展为本机多宿主；归档设计第 12–14 节的 AgentExecutor 端口
继续作为 Core 边界。实现说明见 [Runtime](runtime-implementation.md) 和 [多后端](agent-backends.md)。

回归扩展至 81 项（含真实 CodeGraph 集成，全部通过）：
多轮证据版本、Judge 补查、确认/排除、无进展停止、轮数与调用预算、持久化截止时间、
补查中断恢复、结果收据写入后模拟崩溃、旧证据拒绝、已裁决假设保留、重复查询复用、
实际 MCP stdio、鉴权/工具白名单、子进程超时和显式角色路由。
状态机测试使用执行端口替身；不把这些结果算作真实模型推理成功。

### 真实 Claude SDK 两轮调查

`.runs/aetherstack-runtime-v6/`：AetherStack 的 core::BsNode::attach_xn，未使用旧 session。
Investigator → Judge → Investigator → Judge 共四次真实 SDK 调用均完成。
第二次 Judge 仍为 UNKNOWN，且建议的一个 find_assignments 缺少局部范围。
最初实现把这个无效行动建议当成整个裁决失败；修正为保留 UNKNOWN、拒绝该建议并记录原因。
重放已保存的结果完成接纳，没有增加第五次模型调用。
最终因配置的两轮/四次调用上限停止：BUDGET_EXHAUSTED、0 Finding；缺失空值调用者的事实仍可见。
该运行使用规则 1.1.0，后续规则版本更新后不可作为当前规则继续恢复；原始记录保留。

### 新宿主真实工具调用

- `.runs/opencode-tools-smoke-v3/`：OpenCode 1.18.32 + deepseek/deepseek-flash，真实调用白名单工具读取随机值，返回值与工具值一致。
- `.runs/hermes-tools-smoke-v2/`：本机 Hermes AIAgent + deepseek-flash，同样完成随机值工具验证。
- 早期失败产物保留：MCP 2.x 与旧装饰器 API 不兼容；Hermes 默认工具搜索代理改变允许集合。
  分别改用当前 MCP API、显式关闭工具搜索代理并核对工具集合，未开放原生任意执行工具来绕过问题。

### 混合宿主完整闭环

`.runs/mixed-runtime-v6-validated/`：全新临时 Git 仓库中只有一个四行 C 函数，
局部 int* 初始化为 0 后直接解引用。OpenCode 调查，Hermes 独立 Judge，规则 1.1.2。
两次执行 COMPLETED，1 个 CONFIRMED Finding；原始响应、证据与角色/模型均可追溯。
存在模型报告的覆盖限制，因此 coverageComplete=false、CLI 返回 2，不当作全仓安全证明。

之前两个混合尝试原样保留：分别由于把已解决说明写入 unresolved、缺少显式 path 引用而拒绝确认。
加强规则说明后重跑，没有放宽确认门禁或修改模型原始结果。
这些尝试也说明能执行工具不代表所有宿主/模型组合都稳定满足安全契约，仍需更大案例集评估。
OpenCode/Hermes 归一化费用当前为 null；Runtime 的美元预留不代表这两个宿主有原生费用硬上限。

## 开始建立成对评估（尚未证明优越）

新增 10 个有独立预期结论的开发案例及评分器。6 项评分/语法检查测试通过，
覆盖失败分母、UNKNOWN 不冒充负例、重复试验去重、源码不匹配拒绝与运行波动。
这些案例是开发集，不作为 held-out 准确率证据。
真实 pilot 目录 `.runs/benchmark-pilot-v1/`，预先选定 C001/C002/C003/C008，最多 16 次调用、总预留 $4。
完成记录：Claude SDK + deepseek-v4-flash，四例均执行 COMPLETED。
C001、C003 为 CONFIRMED，C002 为 REJECTED，C008 为 UNKNOWN，与开发集预期一致。
这只是一次四案例 pilot：没有重复运行，没有原 review-skills 的真实五 worker 对照，不能宣称更好。
本次完整测试运行 87 项：86 项通过、1 项跳过；不能把跳过的 CodeGraph 集成计作本次通过。
评估规范见 [evaluation-plan.md](evaluation-plan.md)。

### 开发集首轮与规则 1.1.3 修正

规则 1.1.2 下，另在 `.runs/benchmark-pilot-v2/` 完成其余六例；
两批合并评分保存在 `.runs/benchmark-development-rule-112/`。
10/10 执行完成，4/4 正例确认，未产生误报，5 个负例中仅 3 个明确排除，
另 2 个保留 UNKNOWN；缺失外部定义的 C008 正确为 UNKNOWN。三分类正确率为 8/10。
这是一次开发集测量，没有重复运行或基线对照，不能推断泛化或稳定性优越。

C006（重新赋为非空地址）、C010（重载 operator*）的原始调查都自行排除了候选，
返回空场景，Judge 无对象可裁决。评分器没有将空 Finding 伪装成正确负例。
规则 1.1.3 要求即使没有预设 candidates，也列出疑似解引用表达式及保护/类型证据，
交给独立 Judge 排除。原始失败保留；新规则重跑目录为
`.runs/benchmark-rule-113-regression/`，其结果不替换规则 1.1.2 的分数。
新规则两例真实重跑均为 COMPLETED / REJECTED，独立 Judge 得到了可裁决场景。
本轮完整回归运行 94 项：93 项通过、1 项 CodeGraph 集成跳过。
规则变化使旧运行不能按当前规则继续恢复，旧证据与观察记录仍保留用于历史评估。

评分器同时修正：未完成运行里的正确 Finding 不算误报，但仍不取得完成/召回分；
正确命中附带错误 Finding 的运行不取得整次完全正确分。

新增基线拓扑审核器 `validation/topology.py`，检查原始 SDK hook 顺序、真实调用句柄、
五个不同 worker、各自读取拥有的 Stage Skill、停止及工具返回配对；
拒绝仅有 handoff 自述、复用上下文、缺失返回与错误阶段。
目前用合成事件测试审核逻辑，尚未接通真实基线宿主；该检查不验证漏洞事实，
也不能认证人为伪造的事件文件，后续必须与宿主记录和源码/产物校验绑定。

### 真实基线宿主首轮（v1/v2）与评分类

`.runs/baseline-native-probe-v1/`（$2 上限）：原生子 Agent 真实启动，
拓扑审核确认两个不同 worker 的真实句柄，但只有 pre-process、preload 两个阶段；
Main 在委派前自行 Glob 目标目录，审核器已明确拒绝这种执行轨迹；
阶段二手返回进度文本而非结构化 handoff，预算 $1.96/2 耗尽后停止，拓扑不通过。
`.runs/baseline-native-probe-v2/`（$4 上限）：四个 worker 启动，
第三个 worker 违反约束读取全部五个 Stage Skill，dispatch/post-process 没有独立执行，
最终 `error_max_budget_usd`，费用 $4.03；16 次拒绝多为宿主策略过窄的只读命令。
这两轮失败本身是基线在该宿主/模型组合下的成本与依从性数据，
不计为原 Skill 的准确性缺陷，也不构成成对比较。

宿主策略随后放宽：只读范围扩大到整个只读 Skill 仓（agents/、schemas/），
新增 ls、find（禁止 -exec/-delete）、git --version、rev-parse 通用只读标志、
worktree list；写入仍只允许目标仓 .review 会话区。该变化只减少无效拒绝循环，
不改变源码/Skill 包的只读保护和命令白名单性质。

新增 `validation/benchmark.py: baseline_observation`：从基线运行目录提取评分观察，
复核案例源码哈希与目标文件/函数；receipt 声称 COMPLETED 但拓扑未通过时
按执行失败计入分母，不采纳其 Finding；仅拓扑通过且报告存在时从
output/findings.json 提取确认项与 scenario_counts 判定 CONFIRMED/REJECTED/UNKNOWN。
v1 真实目录经其提取为 FAILED/UNKNOWN，调用数与费用保留。

### 首个真实基线对照点（v3，C001）

拓扑审核器修正一处误报：Main 只读访问只读 Skill 包（如 Glob 包内 markdown）
属于编排元数据加载，不再算 Stage 工作；Main 对目标仓的 Glob/Grep、
一切 Bash 与写入仍判违规。v1/v2 原始记录经新版审核器重新评估，结论不变
（仍失败），v3 的 `topology.json` 由原始未改动的 hooks.jsonl 重新生成。

`.runs/baseline-native-probe-v3/`（宿主策略放宽后，$8 上限）：
五个阶段各自真实启动独立 review-worker，每个只读取本阶段 Skill，
hook 顺序、句柄、返回配对全部通过；COMPLETED，报告确认 main.cpp:3
CWE-476，与开发集预期一致；5 次 worker 调用，费用 $5.45，墙钟约 7 分钟。
提取的评分观察保存于该目录 `observation.json`。

同案例同模型下 security-agent 规则 1.1.2 单次运行：COMPLETED、CONFIRMED
同一位置、2 次调用、$0.052（`.runs/benchmark-development-rule-112/`）。
这是第一个成对观察：双方结论一致，原生五阶段协议在本案例上成本约高两个
数量级。单次单案例不能外推；基线协议负担、模型依从性差异与费用口径
均需更多重复与更多案例，superiority_established 仍为 false。

### 基线负例 C002 首轮：协议依从性失败（记录在案）

`.runs/baseline-native-c002-v1/`（$8 上限，费用 $5.72）：五个 worker 顺序启动，
但 preload 与 dispatch 的 worker 擅自额外读取了下一阶段 Skill，
违反 stage-agent/1 "loads exactly its owning Stage Skill" 约束；拓扑不通过。
Main 的委派提示词经核对已正确要求各自只读本阶段，违规来自 worker 模型自身行为。
该轮按执行失败计入分母（observation.json 已保存），不报 Finding，
也不计为原 Skill 的准确性缺陷——这是 deepseek-v4-flash 在该协议下的
依从性不稳定性证据，与 v3 的合规完成形成对照（目前合规率 1/2）。

### 基线 C002 重复与首个合并评分快照

`.runs/baseline-native-c002-v2/`（$8 上限，费用 $5.39）仍拓扑不通过：
Main 四次 Bash（其中两次为只读包外目标仓操作，明确违规），
dispatch worker 再次越界读取 review-execute Skill。Main 委派提示词本身正确，
违规仍是模型行为。审核器随后把 Main 的"只读包内编排元数据"豁免扩展到
Bash 白名单命令（ls/find/sha256sum，禁操作符与 -exec），五个运行目录的
topology.json 均由原始 hooks.jsonl 用最终审核器统一重新生成，结论不变。

`.runs/paired-snapshot-v1/`：合并 security-agent 开发集首轮（规则 1.1.2）
与五次基线观察的评分快照。security-agent 10/10 完成、三分类 8/10、零误报；
review-skills 原生宿主 1/5 完成（唯一完成的 C001-v3 结论正确且位置精确），
协议依从性失败是主因。面板不成对（paired_panel=false），
superiority_established=false；基线侧目前测量的是协议可行性/成本，
尚不能比较准确性。基线五轮累计费用约 $22.5。

CodeGraph 集成测试在本机 CLI 可用时不再跳过：设
CODEGRAPH_CLI=~/Projects/codegraph/dist/bin/codegraph.js 后全量 103 项通过。

### 开发集规则 1.1.3 三次重复面板（10 案例 × 3）

`.runs/benchmark-development-r113-x3/`：30/30 执行 COMPLETED，
三分类准确率 30/30（recall 1.0、负例明确排除率 1.0、误报 0、
C008 UNKNOWN 3/3 正确保留），10 个案例的重复结论零不一致。
总费用 $2.548（预留 $30），无未知费用。
这是当前规则首个完整重复面板，仍是开发集证据，不构成 held-out 准确率；
基线侧成对面板尚缺，superiority_established 仍为 false。

### 成对故障注入首轮（fault-matrix-v1）

`.runs/fault-matrix-v1/`（experiment.json 先行、trials/ 逐试验记录、matrix.json 汇总），
按 evaluation-plan 稳定性节对两系统注入相同故障。security-agent 侧为桩执行器试验
（确定性、零真实费用，新增 `validation/faults.py` 与 tests/test_faults.py 9 项测试）：

- model-interrupt：执行器在第二调查单元调用中被杀 → INTERRUPTED；恢复只重试未完成动作，
  重复付费调用 0，已确认 Finding 保留，中断详情可见。
- crash-after-receipt：结果收据落盘后模拟进程被杀 → 恢复时重放缓存收据，
  零次新模型调用，Finding 保留。
- index-timeout：prepare/index 失败降级为源码 fallback，间隙写入 state 与 report.md。
- baseline-change / rule-change：HEAD amend 或规则哈希变化后 run 判 STALE，
  旧确认项从导出产物撤下（SARIF results 为空），原因写入 detail，零次重复调用。

review-skills 侧两个真实试验（claude SDK + deepseek-v4-flash，C001 夹具）：

- 中断试验（预留上限 $1）：第一个 review-worker 启动（SubagentStart）后 8 秒
  SIGKILL 驱动进程组。宿主只留下 hooks/messages 片段，无 receipt/topology/checkpoint；
  no-session-persistence 且输出目录单次使用，无恢复入口，重跑即全新付费运行。
  被杀前真实花费未知（无 ResultMessage），保留未知不以 0 代替。
  重复付费证据引用既有探针对：v1 花费 $1.96 无任何可恢复状态，
  v2 对同一目标从零重付 $4.03（4 个 worker 启动），无一次调用被携带。
- 基线变化试验（预留上限 $2，实际 $2.007194）：pre-process worker 完成后 amend
  夹具 HEAD（def89cc→06a5f5e）。随后完成的 preload worker 仍按记录的旧 commit 报告
  completed、errors 为空；没有任何阶段在付费窗口内标记 HEAD 偏移，
  运行到 dispatch 阶段预算耗尽（error_max_budget_usd）FAILED，3 个 worker 调用全部
  无结论产出，0 Finding 发布，拓扑不通过。detached worktree 设计使在途审查仍针对
  旧 commit（内容内部一致），但分歧未被系统表面化——只有外部审计者能从
  session meta（pin def89cc）与仓库 HEAD（06a5f5e）的对照中看到；
  post-process 的发布前 HEAD 校验从未到达，完整运行下能否在发布时被捕获未测定。
- crash-after-receipt / index-timeout / rule-change 三类本轮未对基线真实注入，
  matrix 中标记 not-run；宿主结构性无检查点/恢复路径对一切故障成立。

本轮新花费：已知 $2.007194，未知 1 次（被杀运行，预留 $1）；硬上限 $12 未用尽，
按"控制成本"要求只做了这两个真实试验。结论边界：桩试验证明检查点/恢复语义而非
真实模型行为；基线真实注入只有单案例两类故障；matrix.json 仍
superiority_established=false。本轮完整回归 128 项通过
（CODEGRAPH_CLI 指向本机构建版本）。

### 冻结保留集建立（尚未被模型消耗）

`benchmarks/corpus-heldout.json`（split=held-out，15 例：6 CONFIRMED / 5 REJECTED /
4 UNKNOWN，8 个多文件案例）与 `benchmarks/HELDOUT.md` 冻结记录。
标签与依据在运行前固定，含两个 AetherStack 真实项目人工逐行确认案例（H014/H015）。
冻结哈希与纠错规则见 HELDOUT.md；开发集流程不变。

### 保留集首测（规则 1.1.3，单次，15 例）

`.runs/benchmark-heldout-r113-x1/`：13/15 COMPLETED 且结论全部符合冻结预期；
三分类准确率 13/15=0.867，recall 1.0、负例明确排除率 1.0、误报 0；总费用 $2.054。
H007（宏遮蔽定义）与 H013（缺失回调定义）中，Investigator 已标记缺失事实，
Judge 仍返回 CONFIRMED；证据门禁按"确认含未解决关键事实"拒绝接纳，
执行 FAILED 而非伪装成正确 UNKNOWN——失败留在分母，不计分。
这是保留集上发现的真实失败模式：缺失事实场景下 Judge 过度确认。
按冻结规则不改标签、不删案例；是否据此改进规则（及由此带来的
"保留集已被见过"声明）留待成对评估完成后决定。本结果已登记 eval 账本。

### 保留集三次重复（规则 1.1.3，45 次试验）

`.runs/benchmark-heldout-r113-x3/`：三分类准确率 35/45=0.778，执行完成率 0.778，
recall 0.833，负例明确排除率 1.0，**45 次零误报**；5 个案例重复间结论不一致。
失败模式分布：H007（宏遮蔽）3/3 因 Judge 过度确认被证据门禁拒绝；
H012/H013 两次 BUDGET_EXHAUSTED；H008/H009 在 FAILED 与正确 CONFIRMED 间波动。
所有失败都倒向 FAILED/UNKNOWN，没有一次产生错误 Finding——
系统的保守性成立，准确率代价集中在缺失事实/组合陷阱案例。
费用 $6.143。已登记 eval 账本（heldout-r113-x3）。

### 基线面板策略说明：stage-scope 强制

成对面板前 7 个补录试验（C002-r3、C003-r1..3、C004-r1..3，宿主策略 v1）全部拓扑不通过，
违规模式一致：worker 越界读取相邻阶段 SKILL.md（Main 委派提示词本身正确）。
自 C005-r1 起宿主加入 stage-scope 强制（`baseline_host.StageScope`）：
跟踪 Main 委派提示中的阶段归属，worker 读其他阶段 SKILL.md 即拒绝并计入 receipt
（`stage_scope_denials`），委派提示无法唯一解析时不拦截（fail-open，审核器仍兜底）。
这使成对比较测量的是准确性而非提示词依从运气，与 Runtime 的程序化契约执行对等；
纠正行为全部可见。C005-r1 即验证：COMPLETED、拓扑通过、1 次强制拒绝、$5.99。
两个策略版本的试验在同一面板中并存并在 experiment.json 标注；
v1 的失败试验不剔除，仍计入成本/失败率侧证据。

补充：stage-scope 解析升级为 v2.1——显式委派措辞优先（"isolated worker for stage X" 等），
无法解析时按 worker 首次读取的阶段 SKILL 自归属（bootstrap 先读本阶段），
后续跨阶段读取拒绝。当前面板批次仍以 v2 运行；收尾时对仍失败的试验用 v2.1 补跑，
策略版本逐试验记录在 receipt。

## 首个完整成对面板（paired-panel-v1，开发集，双方各 33 次试验）

`.runs/paired-panel-v1/`：security-agent 面板来自 `.runs/benchmark-development-r113-x3/`
（规则 1.1.3，10 案例 × 3，另 C002/C003/C004 补 repeat-4）；
review-skills 为原生五 worker 宿主逐案例重复，含三个宿主策略版本
（v1 无强制、v2 worker stage-scope、v3 追加 Main 编排范围强制，逐试验记录在 receipt）。
paired_panel=true，已登记 eval 账本。

结果（失败全部计入分母）：

| 系统 | 完成率 | 三分类准确率 | 召回 | 负例明确排除 | 误报 | 重复不一致 | 总费用 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| security-agent | 33/33 | 33/33 = 1.000 | 1.000 | 1.000 | 0 | 0 | $2.81 |
| review-skills | 9/33 | 9/33 = 0.273 | 0.31 | 0.24 | 0 | 7 | $181.70 |

关键事实：

- review-skills 每一次真实合规完成的结论都正确（9/9），其短板不是分析质量而是
  协议完成率：同一模型下五 worker 协议在无强制时几乎必然被违反
  （worker 越界读相邻阶段、Main 亲自做 Stage 工作），逐级强制后完成率仍只有 9/33。
- C003、C004 各尝试 4 次仍无合规完成；其余 8 个案例均至少一次合规完成且结论正确。
- 等效面板成本差约 65 倍（$2.81 vs $181.70）；security-agent 每次案例预留 $1
  远低于基线 $8 上限，资源更低而完成率更高。
- 故障注入对照（fault-matrix-v1）补充稳定性维度：security-agent 中断恢复零重复付费、
  基线/规则变化撤下旧确认项；基线中断即全损需全额重付，HEAD 移动在付费窗口内未被检出。

按 evaluation-plan 的失败计入分母规则，开发集上 security-agent 在准确性
（完成率加权）、稳定性、成本三个维度均显著占优；review-skills 的合规完成准确性
与 security-agent 相当（9/9）。superiority_established 仍为 false：
开发集不是 held-out，基线侧保留集面板与置信区间尚未做，最终结论需人工审计确认。

### 交付件自包含与签名验证

SARIF 每条 result 内嵌 relatedLocations（证据角色/行范围/源码原文/commit/blob/sha256），
run 级带 versionControlProvenance 与规则版本/哈希；用官方 SARIF 2.1.0 schema
（oasis-tcs/sarif-spec）校验通过。`security-agent sign/verify` 端到端实测：
可复现 tar 包（两次打包字节一致）、GPG 签名验证通过、解包完整性 OK、
篡改 state.json 一字节后 verify 报 modified 且退出码 2。
无密钥环境 sign 拒绝出包并提示建钥。测试新增 4 项，全量 136 通过。

补充：交付形态最终定为三件套——`review.html`（自研自包含渲染，单文件内嵌证据卡片、
规则/策略版本、行动成本，源码全转义；sarif-tools 生成的 HTML 不含 relatedLocations、
commit 与覆盖状态，不满足自解释要求，已弃用）、`review.sarif`（机器可读）、签名 tar 包。
微软 sarif-vscode 插件对合法文件存在 loader 兼容问题（其 issue 列表多例），
不作为交付目标；兼容性如被交付方强制要求再单独评估。
全量 137 项通过。
