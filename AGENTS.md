# AGENTS.md

带 Security Runtime 的 C/C++ 安全调查 Agent（当前规则 CWE-476）：Investigator 调查、
独立 Judge 裁决，Runtime 程序化强制证据、预算与恢复。术语以 [CONTEXT.md](CONTEXT.md) 为准。

## 结论纪律

- Finding 只能经证据门禁产生：引用冻结快照的真实字节、行号匹配、origin/sink/path 齐全。
- UNKNOWN 留在 UNKNOWN；执行失败保持失败。零 Finding 不写安全结论。
- 凭证、网络、工具失败如实记录，产物哈希不匹配的 run 标记 STALE 并撤下旧结论。
- 报告由记录重建；改结论走证据链与新版裁决。

## 评估纪律

- 标签先于运行固定；纠错走版本勘误（[benchmarks/HELDOUT.md](benchmarks/HELDOUT.md)）。
- 超时、预算耗尽、UNKNOWN、执行失败全部计入分母；每次试验保留运行目录。
- 面板登记 eval 账本（`security-agent eval --record`），corpus/规则/面板哈希绑定；trace 只从持久化产物派生。
- `superiority_established` 恒为 false，最终结论由人审计。
- `../review-skills` 只读参考，不修改。

## 工程纪律

- 恢复/预算/裁决语义变更必须升 `POLICY_VERSION`；旧 run 失效不原地迁移。
- 预算预留不退还；费用未知记 null。
- 改动后全量测试通过：`CODEGRAPH_CLI=~/Projects/codegraph/dist/bin/codegraph.js .venv/bin/python -m pytest tests/ -q`（不设该变量则集成测试跳过，不计入通过数）。
- 真实模型实验记录进 [docs/validation.md](docs/validation.md)：费用、失败、结论边界如实写。

## 深入阅读

- 评估方法论、计分规则、防偏差约束 → [docs/evaluation-plan.md](docs/evaluation-plan.md)
- 实验记录（最新在文末）→ [docs/validation.md](docs/validation.md)
- 架构与扩展方式 → [docs/security-agent.md](docs/security-agent.md)、[docs/core-infra-design.md](docs/core-infra-design.md)
