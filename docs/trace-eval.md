# Trace 与 Eval 机制

2026-09-27 建立。目的：让每次评估都可追溯、可复算、可横向比较，而不是散落在运行目录里的临时结论。

## Trace（执行追溯）

`security_agent/validation/trace.py` 把两类运行目录归一化成同一条时间线视图：

- security-agent Runtime 运行（state.json + attempts/）：prepare 行动、每次模型调用
  （角色、action、轮次、执行状态、预留与实际费用）、轮次接纳、裁决、Finding、阶段检查点。
- review-skills 原生宿主运行（host/）：worker 委派跨度与所读阶段、权限拒绝、
  拓扑审核结论、费用与 hook/message 完整性哈希。

原则是**只从持久化产物派生，不信任报告自述**；trace 携带 state/hooks/messages 的
SHA-256 绑定，事后改动产物会被发现。费用区分已知与未知，未知不计为免费。

```bash
.venv/bin/python -m security_agent trace --run .runs/benchmark-development-r113-x3/C001-1
.venv/bin/python -m security_agent trace --run .runs/baseline-native-probe-v3
```

## Eval（评估账本）

`security_agent/validation/evaluate.py` 维护一个追加式账本（默认 `.runs/eval/`）：

- `panel_record` 把一个评分面板（observations.json + scores.json）登记为一条记录，
  绑定 corpus 哈希、规则哈希、面板路径与 observations 哈希——分数不能被
  静默改挂到别的语料或规则版本上。
- 同名记录只允许完全相同的内容（幂等重放），同名不同内容直接拒绝。
- `compare` 给出两条记录间各系统的指标差（准确率、召回、误报、完成率、重复不一致、费用），
  并标明是否同一 corpus。

```bash
.venv/bin/python -m security_agent eval --record dev-r113-x3 --corpus benchmarks/corpus.json \
  --panel .runs/benchmark-development-r113-x3
.venv/bin/python -m security_agent eval --history
.venv/bin/python -m security_agent eval --compare paired-snapshot-v1 paired-panel-v1
```

账本是派生数据（.runs 不入库）；权威证据始终是记录所指向的运行目录。
每次产生新面板（开发集、成对面板、保留集、故障矩阵）都应登记，形成时间序列，
用 `eval --compare` 做规则/策略变更前后的回归对照。
