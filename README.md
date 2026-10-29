# Security Agent

目标是带有 **Security Runtime 的 Security Agent**：从文件/函数或 Git diff 出发，自主调查、补证据并接受独立裁决。
当前已实现 C/C++、CWE-476 的基础切片；已支持有界跨轮调查、Judge 反馈补查、执行结果恢复与准备阶段内恢复（M4）。
使用 **Claude Agent SDK（`claude-agent-sdk`，原 Claude Code SDK）** 作为默认执行后端；新增本机 OpenCode、Hermes 适配器，可分别为 Investigator/Judge 选择宿主。

Claude 路径直接调用 SDK；OpenCode 使用官方非交互 CLI，Hermes 使用本机 AIAgent。

Investigator 形成调查场景与证据，独立 SDK 会话的 Judge 给出结论。
确定性控制层检查文件和行范围，从快照生成证据原文并校验引用完整性，只有 CONFIRMED 场景能生成 Finding。
REJECTED 只排除具体场景；UNKNOWN 和执行失败不会被当成“无漏洞”。

正常入口是“仓库 + 文件 + 函数”，程序自行发现调查场景，不需要旧检查记录。
Git diff 是另一个输入入口。职责划分见 [Core / Infra 设计](docs/core-infra-design.md)。

## 评估结论（2026-09-27，开发集成对面板）

与只读基线 `../review-skills`（原生五 worker Skill 包）在同一模型（deepseek-v4-flash）、
同一开发集（10 案例）下成对比较，双方各 33 次试验，失败全部计入分母：

| 系统 | 完成率 | 三分类准确率 | 误报 | 重复不一致 | 总费用 |
| --- | --- | --- | --- | --- | --- |
| security-agent | 33/33 | 33/33 = 100% | 0 | 0 | $2.81 |
| review-skills | 9/33 | 9/33 = 27.3% | 0 | 7 例 | $181.70 |

基线每次合规完成的结论也都正确（9/9），差距在执行纪律与成本（约 65 倍），不在分析质量。
保留集（15 例，含真实项目人工确认案例）上本系统 45 次试验零误报、三分类 35/45。
故障注入显示本系统中断恢复零重复付费，基线中断即全损。
`superiority_established` 保持 false：基线侧保留集面板与置信区间未做，待人工审计。
完整证据链见 [验证记录](docs/validation.md)，方法论见 [对照评估计划](docs/evaluation-plan.md)。

## 文档导览

架构速览（`security_agent/` 包）：

| 目录 | 职责 |
| --- | --- |
| `inputs/` | Git diff / 文件 / 函数入口，冻结快照（内容寻址源码字节） |
| `core/` | 领域核心：契约校验、证据门禁、裁决接纳、原子存储与哈希密封 |
| `pipeline/` | 五阶段控制层；LLM 只参与 review-execute，其余阶段由程序确定性完成 |
| `tools/` | 取证工具：CodeGraph 调用图、Tree-sitter AST、冻结源码搜索，七类查询契约 |
| `infra/` | 执行后端适配器：Claude Agent SDK / OpenCode / Hermes，可互换 |
| `validation/` | 评估设施：基准评分、拓扑审核器、基线宿主、故障注入、trace/eval |
| `skills/cwe476/` | 版本化规则包（当前 1.1.3）：Investigator/Judge 提示词与证据契约 |

关键机制：证据引用必须是冻结快照里真实存在的字节且行号匹配才予接纳；
CONFIRMED 需要 origin/sink/path 三类证据齐全；模型调用先落盘再记账，中断恢复不重复付费；
基线 commit 移动、规则变化或产物篡改会使旧结论撤下（STALE）。

- [CONTEXT.md](CONTEXT.md)：领域术语表（Investigation/Hypothesis/Evidence/Verdict/Finding…）。
- [docs/security-agent.md](docs/security-agent.md)：主设计；[docs/archive/](docs/archive/)：最初总设计（历史）。
- [docs/mvp-design.md](docs/mvp-design.md) + [docs/runtime-implementation.md](docs/runtime-implementation.md)：里程碑验收与实现记录。
- [docs/evaluation-plan.md](docs/evaluation-plan.md)：评估方法论（考题设计、计分规则、防作弊约束）。
- [docs/validation.md](docs/validation.md)：全部实验流水账（从下往上读是最新结果）。
- [docs/multi-dim-eval.md](docs/multi-dim-eval.md)：可用性/可扩展性/健壮性/安全性/成本多维评估。
- [docs/trace-eval.md](docs/trace-eval.md)：trace/eval 追溯机制；[docs/tools-and-skills.md](docs/tools-and-skills.md)、[docs/agent-backends.md](docs/agent-backends.md)：工具层与执行后端。
- [docs/skill-repository-injection.md](docs/skill-repository-injection.md)：Agent 能力复用、Skill 场景仓与动态注入候选设计（未实现）。
- `benchmarks/`：考题库（`cases/` 开发集、`heldout/` 冻结保留集、`HELDOUT.md` 冻结记录）；`.runs/`：全部实验现场。

## 安装与运行

需要 Python 3.11+、Git 和 Linux/macOS（使用 POSIX 文件锁）；开发验证环境为 Linux/Python 3.12。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .

.venv/bin/security-agent review \
  --repo /path/to/cpp-repo \
  --file src/parser.cpp --function parse_packet --head HEAD \
  --run /tmp/my-security-review \
  --model sonnet --max-calls 20 --call-usd 0.5 --timeout 120

.venv/bin/security-agent resume --run /tmp/my-security-review
```

请按 [Claude Agent SDK 官方说明](https://code.claude.com/docs/en/agent-sdk/quickstart) 配置认证。
SDK 自带底层 Claude Code 执行能力；此项目直接调用 SDK API。
默认仅从本机 `~/.claude/settings.json` 的 `env` 中读取认证、接口地址与模型映射白名单；
进程环境变量优先。可用 `--claude-settings /path/to/settings.json` 显式指定。
不会载入该配置的 hooks、插件、权限或项目指令，也不把密钥写入 run。
因此现有 Claude Code 的 DeepSeek/代理配置可沿用，无需改成 Anthropic 官方账号；
兼容接口仍须支持 Agent SDK 所需的工具调用/结构化输出，失败会记录为 UNKNOWN。
provider 的美元用量若未准确上报，SDK 费用数字不能视为该供应商的真实账单。

每个角色一个新的 `ClaudeSDKClient`，不复用 Investigator 会话给 Judge。
源码来自冻结 Git blob。初始 prompt 含目标函数或文件及路径索引，Investigator 通过 SDK 暴露的
七类语义查询和 `read_source` / `search_source` 按需取证；Tools 调用已配置的 CodeGraph、Tree-sitter
及冻结源码搜索，原始工具响应和查询产物保留在 run 中。
不开放 Bash/Read/Edit 或外部 MCP；不加载目标项目设置或 Skill。Judge 不开放任何查询工具。
系统不执行目标代码，也不修改目标源码。

`--run` 如指定必须是新目录；省略时自动在 `.runs/` 创建。
若指定目录是上次中断留下的准备中（PREPARING）运行，会按原参数校验后从中断行动继续准备；
已准备完成的目录不能重复创建，用 `resume` 继续执行。
`--file FILE --function NAME` 选择函数；只给 `--file` 检查整文件；
`--base BASE --head HEAD` 检查 Git diff。这两类选择不混用。
函数重载可用限定名称和 `--line` 消歧；`--prepare-only` 可先定位并冻结而不调用模型。
`base..head` 是直接比较，不隐式求 merge-base；两端都必须解析为提交。
未提交文件不会参与检视。若要按分支共同祖先比较，可先用 `git merge-base main HEAD` 得到 base。
调查范围是 head 中仍存在的变更 C/C++ 文件的全部 sink，不仅新增行，所以删除 guard 的改动也在范围内。
报告不声称每个发现都是本次新引入。重命名按删除/新增处理。

退出码：`0` 已完成且无覆盖缺口/确认项；`1` 有确认项且无覆盖缺口；
`2` 未完成、UNKNOWN、覆盖缺口或输入错误（即使同时有 Finding）；`130` 中断。
零 Finding 永远不是仓库安全证明。

## 产物与恢复

- `state.json`：五阶段进度、调查对象、执行状态、场景 Verdict、Evidence、Finding、预算。
- `manifest.json`、`tree.raw`、`diff.patch`：固定策略/配置、完整 head tree 和原始 diff。
- `snapshots/`：内容寻址的原始源码字节；每条证据可回溯 commit/blob/SHA-256。
- `attempts/`：每次 SDK 请求、SDK 消息流、stderr、结构化结果；失败尝试也保留。
- `assessments/`：已归一化并校验的证据包。
- `report.md`、`review.sarif`：当前报告。SARIF results 只包含确认项，缺口进入通知和 properties。
  每条 result 的 `relatedLocations` 内嵌全部证据（origin/sink/path 角色、行范围、源码原文、
  commit/blob/sha256），配合 run 级 `versionControlProvenance` 与规则版本/哈希，
  单个 SARIF 文件即可自解释，可作为审计/合规交付的机器可读件（已过官方 SARIF 2.1.0 schema 校验）。

每次 SDK 调用前预留一次额度；超时/中断/崩溃不退还额度。恢复只重试未完成角色，
已完成的调查对象不重跑；已保存的完整 SDK 响应优先重放归一化，不重复付费调用。`--max-calls × --call-usd` 是保守预留总额；SDK 实际费用另存。
Investigator 默认最多 12 次只读工具调用、14 个 SDK turns；Judge 最多 4 turns。
目标源码与工具响应默认累计上限 120000 字节（`--max-context-bytes`），超限保持 UNKNOWN。
本地快照另有 10 MB 上限（`--max-snapshot-bytes`），快照内容不会自动全部发送给模型。
美元限制交给 SDK，不是供应商账单硬上限；没有宣称精确 token 限额。

恢复和输出前检查 revision 是否仍指向原 commit、快照和原始产物摘要是否一致。
任何不一致使 run 变成 STALE，当前报告不再展示旧 Finding，原始证据保留。
不能在旧 run 上偷偷换基线、预算或模型；需要新建 run。
固定 SHA 的检视不因工作区变动失效，因为它始终只描述该提交。
哈希提供本地完整性检查，不是针对能同时篡改文件与 manifest 的攻击者的签名机制。

## 验证

```bash
.venv/bin/python -m unittest discover -s tests -v
# 或用 pytest（138 项；设 CODEGRAPH_CLI 后包含真实 CodeGraph 集成，0 跳过）：
CODEGRAPH_CLI=~/Projects/codegraph/dist/bin/codegraph.js .venv/bin/python -m pytest tests/ -q
# 实际模型 smoke，最多两次每次 $0.25 的 SDK 调用：
.venv/bin/python examples/smoke.py /tmp/security-agent-smoke
# 开发集基准（真实调用模型，experiment.json 先行写入预算上限）：
.venv/bin/python examples/benchmark.py --run .runs/benchmark-development --repeat 3
# 保留集基准（benchmarks/corpus-heldout.json，冻结标签见 benchmarks/HELDOUT.md）：
.venv/bin/python examples/benchmark.py --corpus benchmarks/corpus-heldout.json --run .runs/benchmark-heldout --repeat 3
```

离线测试用真实 Git 仓库和实际 SDK 类型，仅替换 SDK client 的模型响应；它验证控制流和隔离约束，
不测量模型准确率。真实 smoke 的凭证/网络失败会明确记录，不会替换成假 Finding。

评估产物有统一追溯：`security-agent trace --run DIR` 输出任一运行目录的归一化执行时间线；
`security-agent eval` 把评分面板登记进追加式账本并支持面板间指标对比，见 [trace-eval](docs/trace-eval.md)。

对外交付审计/合规件：

```bash
# 自包含 HTML 交付报告（单文件、内嵌证据原文/哈希/成本，随每次运行自动生成，也可重新渲染）：
.venv/bin/security-agent report --run /tmp/my-first-run
# 打包 run 目录（可复现 tar.gz + 全文件 SHA256 清单）并 GPG 分离签名：
.venv/bin/security-agent sign --run /tmp/my-first-run --key "Name <email>"
# 收件人验证：签名有效性 + 解包后逐文件哈希完整性
gpg --verify <bundle>.sig <bundle>
.venv/bin/security-agent verify --dir <解包目录> --sums <bundle>.SHA256SUMS.txt
```

三种交付形态：`review.html`（自包含自解释，浏览器直接看）、`review.sarif`
（机器可读，relatedLocations 内嵌证据）、签名 tar 包（完整证据链 + 防篡改）。
签名证明"封存后未改动"（哈希只证明内容与记录一致）；没有配置 GPG 密钥时
`sign` 会报错并提示建钥命令，不会生成无签名却看似完整的交付包。

## 当前边界

已接入可选 CodeGraph 和 Tree-sitter 查询，尚无编译数据库分析。文本匹配、语法观察与图候选关系
分别标注精度，不能等同于完整类型或数据流分析。已支持持久化多轮假设推进与 Judge 补查；无新证据时停止再次裁决。
准备阶段行动级恢复与 Run/Investigation/Action 三层预算已实现；复杂覆盖缺口关闭仍未实现。
超大工程、外部定义、编译配置、间接调用等缺失事实会限制判定，必须保留 UNKNOWN。
Judge 与 Investigator 使用同一选定模型的不同会话，是上下文隔离，不是形式化证明或独立模型共识。
Finding 修复状态始终为 NOT_STARTED；没有自动修复、自动关闭或验证修复逻辑。

目标架构见 [主设计](docs/security-agent.md)，当前基础与下一轮验收见 [实施计划](docs/mvp-design.md)，
领域术语见 [CONTEXT.md](CONTEXT.md)。相邻 `../review-skills` 保持独立，只读参考，无运行时依赖。

## 用历史 Skill session 做回归

```bash
.venv/bin/python examples/replay_session.py \
  --session /path/to/.review/sessions/review-ID \
  --run /tmp/session-regression \
  --call-usd 2 --max-calls 2
```

该辅助脚本只读 session，校验证据引用及 Git 提交内的依赖哈希，再使用旧 session 的
**提交与文件范围**创建全新运行。这是明确的文件范围回归，不伪造 Git diff；正常 `review` 支持文件、函数或 Git diff。
历史结论只存入 `reference.json`，不注入任一模型上下文，不直接转换成新 Finding。
仅场景 ID 和 sink 范围作为显式候选传入 Investigator；每个候选必须被调查，包括受 guard 保护的场景。
`comparison.json` 按 sink 行范围辅助对照；位置重合不等于两个场景语义相同，未匹配项不算通过。
`--prepare-only` 只做确定性预检查，随后可用正常 `resume` 执行已创建的运行。

### CodeGraph 与语义查询

在 review 命令增加 `--codegraph-cli /path/to/codegraph/dist/bin/codegraph.js`，
即可为指定提交建立独立索引，并向调查任务提供七类语义查询工具。
不配置时使用语法/源码降级，并明确图能力缺口。
五阶段契约、规则包、Tools 扩展方式与当前边界见 [Tools 与 Skills](docs/tools-and-skills.md)。


## Runtime 与执行后端

`--max-rounds`（默认 3）、`--max-hypotheses`（20）、`--max-no-progress`（1）、
`--total-timeout`（1800 秒，自创建起含停机等待）约束持续调查。
分层预算：Run 级 `--max-calls × --call-usd`，Investigation 级 `--investigation-max-calls` /
`--investigation-max-usd`（按预留计），Action 级 `--max-action-attempts`（默认 3）。
`state.json` 中的 actions/rounds/hypotheses 与 `attempts/*/outcome.json` 支持跨轮恢复；
准备阶段（snapshot/scope/index/handoff）也有行动级检查点，索引失败降级为源码 fallback 且报告可见。
旧规则/策略运行不原地升级。[Runtime 实施与边界](docs/runtime-implementation.md)。

```bash
.venv/bin/python -m security_agent backends
.venv/bin/python -m security_agent review \
  --repo /path/to/repo --file src/example.cpp --function example \
  --backend opencode --model deepseek/deepseek-flash \
  --judge-backend hermes --judge-model deepseek-flash
```

OpenCode/Hermes 目前无原生美元硬上限，call-usd 仅用于 Runtime 预留账本；实际费用未知时记 null。
配置、认证隔离、工具接入与能力差异见 [Agent Infra 扩展](docs/agent-backends.md)。
