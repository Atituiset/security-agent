# Five-stage、Security Skill 与 Tools

本页记录当前基础切片，不代表完整 Security Runtime 已完成。目标架构与持续调查设计见
[主设计](security-agent.md)，后续工作见 [实施计划](mvp-design.md)。

本实现保留独立项目文档第 5 节的选择：程序调度确定性阶段，SDK 执行推理任务。
不是相邻轻量包的五个独立 Stage Agent 拓扑，也不修改或运行时加载相邻包。

```text
CLI 组装
 ├─ pipeline：阶段顺序、检查点、预算、恢复
 │   └─ core：规则包、查询契约、Evidence、Judge、Finding
 ├─ tools：SemanticQueries → CodeGraph / Tree-sitter / 冻结源码搜索
 └─ infra：Claude Agent SDK → 模型与工具交互循环
```

Tools 和 Agent Infra 分开：前者生产代码事实，后者执行模型会话。
Core 的 FactQueries 接口不知道 node 命令、CodeGraph 输出或 Tree-sitter。
CLI 注入查询工厂，Core 将七类查询包装为通用 SecurityTool，SDK 只翻译工具描述。

## 阶段与产物

| 阶段 | 当前实现 | 产物 |
| --- | --- | --- |
| pre-process | 固定提交、确定文件/函数范围、可选建立独立 CodeGraph 索引 | stages/pre-process.json、graph/binding.json |
| preload | 绑定冻结源码和函数范围；指定函数时运行图符号查询 | stages/preload.json、graph/preload/ |
| dispatch | 将 C/C++ 调查单元分配给已加载的 CWE-476 规则版本 | stages/dispatch.json |
| review-execute | SDK 调查、按需查询、原文取证、独立 Judge | attempts/、assessments/、stages/review-execute.json |
| post-process | 接纳确认项，输出结论、执行状态和覆盖缺口 | report.md、review.sarif、stages/post-process.json |

stages/pipeline.json 保存五阶段契约、状态、尝试次数和交接产物。
preload 当前只保证目标源码/范围，类型、宏和依赖尚需后续查询，明确标为 PARTIAL。
整文件/diff 当前仍按文件创建调查单元，未实现按所有函数自动拆分；指定函数已有语法定位。

## 规则包

security_agent/skills/cwe476/contract.json 声明规则 ID、版本、适用语言、查询操作、
证据要求、Judge 交接与 UNKNOWN 约定。system.md、investigator.md、judge.md 为实际加载的指令。
Core 以完整包内容哈希绑定运行；规则变化使旧运行 STALE。
这是一套由 Core 加载的安全规则包，不依赖 Claude Code 自动发现 Skill；SDK 的 skills=[] 仍有意保留。

## 查询层

统一入口为 execute(operation, request)，七类操作是 find_definition、find_references、
find_callers、find_callees、find_assignments、find_pattern、find_related_symbols。
请求包含 purpose、symbol、可选 file/start/end、pattern kind/text 和 limit。

- CodeGraph 提供符号和调用关系候选，明确声明 capabilities；不声称完整 C++ 语义。
- Tree-sitter 提供函数定义及赋值、解引用、条件、return、call 等语法观察；不证明类型或控制流。
- 冻结源码字面搜索提供 text-candidate；同名匹配不会升级为已解析引用。
- 不满足查询前提时返回 unsupported/error；歧义、截断、工具错误后的降级返回 partial 与原因。
- 成功返回候选不等于 exhaustive。当前保守地保留非穷尽语义。

查询目录保存 request.json、原始 stdout/stderr、图候选、精确源码、result.json 和 delivered.json。
每条 fact 有位置、precision、raw_ref；结果有依赖 SHA-256、工具版本和覆盖限制。
Evidence 在范围匹配时附上 query_refs；原始源码仍由 Core 再次校验。
所有查询与 read/search 共用调用次数和返回字节预算，原始结果与实际交付结果分开保存。
当前不跨查询复用缓存；已完成模型响应仍支持恢复重放，避免误用未验证的查询缓存。

## 基线与运行

显式传入 --codegraph-cli 指向本机已构建 JS CLI。未配置时使用语法与源码降级，返回图能力缺口。
首次准备创建运行目录内独立 Git checkout，取完整提交以建立图索引，不修改目标仓和已有索引。
这是独立应用的本地运行视图，不采用轻量 Skill 包的共享 worktree 缓存协议。
拒绝符号链接基线；索引与完整源码内容、工具 JS 文件哈希绑定；恢复及图查询前后检查失效。
索引读取失败、非 JSON 或退出码零但输出错误文本，均不能当空成功。

```bash
.venv/bin/python -m security_agent review \
  --repo /path/to/repo --file src/example.cpp --function ns::function \
  --codegraph-cli /path/to/codegraph/dist/bin/codegraph.js \
  --run .runs/example --prepare-only
.venv/bin/python -m security_agent resume --run .runs/example
```

后续 Joern、ast-grep、自研 clang 工具应加入 tools 层，声明支持的语义操作和结果精度，
实现同一事实契约，并通过真实工具的契约测试。无需让 CWE Skill 或 Claude SDK 知道其 CLI。
当前没有添加这些工具或第二个模型后端，也没有实现编译数据库/宏展开和完整数据流分析。
