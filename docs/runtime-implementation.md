# 持续调查 Runtime 实施记录

2026-09-27；策略 cwe476-v7-runtime，CWE 包 1.1.3。
主设计见 [security-agent.md](security-agent.md)，本页区分已实现与后续范围。

## 已实现

- 每调查 round、Hypothesis 投影、Missing Fact、不可变轮次证据与 Judge 结果引用。
- Action 按 investigation/round/role 标识，绑定输入哈希、证据版本、后端与模型；重试增加 Attempt。
- Judge 的 UNKNOWN 可附结构化 follow_up（问题、语义操作、参数）。Runtime 校验后推进 Investigator。
- 后续轮次仅更新被请求的假设，保持 ID 与 sink；已确认/排除的其他假设不被丢弃。
- 没有新增源码证据时不重复裁决，保留原 UNKNOWN，达到无进展上限就结束。
- 相同事实查询可复用先前完成/partial 的冻结结果，仍计入响应字节和工具次数；错误允许重试。
- 轮数、假设数、无进展次数、总调用预算和从创建起计算的总截止时间。
- 分层预算：Run（--max-calls/--call-usd/--total-timeout）、Investigation
  （--investigation-max-calls/--investigation-max-usd，按预留计，未知费用不记免费）、
  Action（--max-action-attempts 重试上限，旧预留不退还）。任何一层耗尽都拒绝新动作。
- 多调查按轮次轮转，避免第一个调查的持续补查完全抢占后续调查。
- 原始响应和 outcome.json 先落盘，再推进检查点；在这之间崩溃可恢复而不再次调用模型。
- 旧证据 ID 无法用于新轮次确认；未接纳轮次的原始产物同样参与完整性检查。
- 报告含轮次、停止原因、Hypothesis 缺口、Action/Attempt、确认项证据版本与补查拒绝诊断。
- M4 准备阶段内恢复：snapshot/scope/index/handoff 四个行动各自持久化
  （RUNNING 不是完成标记）；索引失败降级为源码 fallback 并在报告 Coverage 中可见；
  中断后按原配置/基线/规则校验恢复；评分核验信任 v6/v7 两个策略版本，恢复执行只认当前版本。
- SARIF 自包含：每条 result 的 relatedLocations 内嵌证据角色、行范围、源码原文与
  commit/blob/sha256；run 级携带 versionControlProvenance、规则版本/哈希与策略版本，
  单文件可自解释，已过官方 SARIF 2.1.0 schema 校验。
- 签名交付（core/delivery.py）：run 目录打包为可复现 tar.gz（排序固定、mtime 归零）
  + 全文件 SHA256 清单 + GPG 分离签名（`security-agent sign`）；
  收件人 `gpg --verify` + `security-agent verify` 两步离线验证；无密钥时拒绝出包。
- 自包含 HTML 交付报告（`security-agent report`，随 export 自动生成 review.html）：
  单文件内联样式，含执行/覆盖状态、基线 commit、规则版本与哈希、每条 Finding 的
  证据卡片（角色/行范围/源码原文/三级哈希）、裁决、行动历史与成本；源码内容全部转义。

无效补查建议不会擦除合法的 UNKNOWN 裁决：不执行该建议，并保留 rejected_follow_up 诊断。
若 JSON 结构、证据引用或确认前提本身无效，则仍然失败关闭，不能生成 Finding。

## 参数与产物

--max-rounds 默认 3，--max-hypotheses 默认 20（每调查），--max-no-progress 默认 1，
--total-timeout 默认 1800 秒，包含 prepare-only 后的等待和进程停机时间。
每轮可能有一次 Investigator 与一次 Judge；无进展轮不再调用 Judge。
与 --max-calls、每次 timeout、工具调用/字节预算共同约束，任何一项耗尽都不能绕过。

state.json 包含 actions、各调查 rounds/hypotheses/follow_up；
attempts/<id>/action.json、response.json、result.json、outcome.json 保存原始响应与执行收据；
assessments/ 保留每个已尝试轮次的证据。报告是这些记录的投影视图。
旧 v5 run 因策略/规则变化失效，不在原目录悄悄迁移。

## 当前边界

M1–M4 已落地；分层预算的 Investigation/Action 层按预留计费，token 级计量待后端统一上报。
当前状态机内部仍用 investigator/judge/done，未为了命名重写为六阶段 enum。
Hypothesis 初次批量发现，补查期间不能新建/改名/移动 sink；需要更广范围时新建调查。
全局覆盖缺口保守累积，尚未实现带解决证明的覆盖缺口关闭。
无进展按源码证据集合判断，不等价于证明两个语义推理完全相同。
查询复用限同一 run 的冻结视图，不是跨 run 缓存；能力与整体成本调度还有完善空间。
目标提交和规则/证据检查已实现，Agent 宿主版本与完整依赖锁定仍需后续加强。
