# 可替换的 Agent Infra：Claude、OpenCode、Hermes

2026-09-26：按用户扩展要求，解除此前“仅一个执行后端”的阶段范围限制。
本页落实 [归档设计第 12–14 节](archive/security-agent-before-runtime.md) 的 AgentExecutor 端口，
而不是把某一个 SDK 提升成 Security Core 的基础依赖。

## 架构

```text
Security Runtime → Task / AgentExecutor / AgentResult
                            ↓
                    显式的角色执行配置
                   /         |         \
            Claude SDK    OpenCode    Hermes AIAgent
                   \         |         /
                  Core 提供的白名单工具
                            ↓
                     Tools / 事实 / 证据
```

Investigator 和 Judge 可以选择不同后端、不同模型；每次行动均新建会话。
Runtime 拥有假设、证据版本、预算、恢复与接纳门禁，适配器拥有宿主会话和协议转换。
后端失败保留原始输出并返回执行失败，不自动更换模型，也不跨后端续接隐藏会话。
恢复依赖持久化证据与行动记录，不能依赖厂商 conversation ID。

多执行后端不是并行多 Agent 编排。本轮提供角色路由和顺序调查，尚未实现并行 worker 或远程宿主。
未来 ACP/OpenHands 等可以实现同一端口，但目前没有虚设可运行的 ACP 后端。

## 当前能力差异

| 能力 | Claude | OpenCode | Hermes |
| --- | --- | --- | --- |
| 执行设施 | Claude Agent SDK | 本机非交互 CLI JSON 事件 | 本机 Hermes Python 的 AIAgent |
| 工具接入 | SDK MCP | 本地 MCP stdio → 鉴权 loopback bridge | 显式工具注册 → 鉴权 loopback bridge |
| JSON 输出 | 原生输出 schema + Core 校验 | 指令要求 JSON + Core 校验 | 指令要求 JSON + Core 校验 |
| 原生美元预算 | SDK 支持，非最终账单硬保证 | 当前适配器无 | 当前适配器无 |
| 次数、超时、原始输出 | Runtime / SDK | Runtime / 子进程组清理 | Runtime / 子进程组清理 |
| 模型费用 | SDK 上报 | 当前归一化为未知 | 当前归一化为未知 |

Run 的次数和费用预留账本对所有后端生效，但 OpenCode/Hermes 的 call-usd 是预留值，
不能解释为宿主已强制执行美元上限。未知成本保存 null，不能伪装成 0。
配置必须指定非 Claude 模型；不同后端的模型标识不可相互猜测或自动映射。

## 隔离与认证

OpenCode 使用临时工作目录和独立 XDG 配置/数据目录，禁用项目配置和外部 Skill，
纯模式不加载外部插件；原生权限默认拒绝，仅允许本次 security MCP 工具。
只从本机 OpenCode auth.json 复制所选 provider 的认证记录到临时目录，结束即清理。
目前不自动继承复杂自定义 provider、OAuth 插件或宿主私有 MCP 配置。

Hermes 使用本机已安装解释器与源代码，创建临时 HERMES_HOME，禁用项目上下文、记忆、
后台 review 和默认工具搜索代理；只注册本次 SecurityTool，并在调用模型前核对工具集合。
从本机 ~/.hermes/.env 只读取所选 provider 的已知 API key；不复制全部用户配置/密钥。
默认 provider 为 deepseek，也提供显式 --hermes-provider。自定义/OAuth profile 尚未完整适配。

Bridge 绑定 127.0.0.1，使用每次行动随机 Bearer token，校验工具名和参数，串行保护预算状态。
它是同机传输，不是远程 Runtime。Token 不写入 request 审计产物；原始输出仍应按源码证据保护。
这不是操作系统沙箱；保证来自工具白名单、宿主隔离配置和 Core 校验，不能假设防御被篡改的宿主二进制。

## 使用

```bash
.venv/bin/python -m security_agent backends

.venv/bin/python -m security_agent review \
  --repo /path/to/repo --file src/example.cpp --function example \
  --backend opencode --model deepseek/deepseek-flash \
  --judge-backend hermes --judge-model deepseek-flash \
  --max-calls 6 --max-rounds 3 --timeout 180 --total-timeout 900
```

省略 --judge-backend 时同主后端；若改变 Judge 后端，必须指定 --judge-model。
默认仍为 Claude。Hermes 安装不在默认位置时使用 --hermes-source、--hermes-python；
OpenCode 可通过 --opencode-binary 指定可执行文件。
所有角色配置随 manifest 冻结，修改需新建 run。

## 验证与后续

已有实际 MCP stdio、鉴权/工具白名单、子进程超时、角色路由和 JSON 门禁测试。
OpenCode/Hermes 均运行真实工具随机值 probe，避免把能输出文本误认为能执行工具。
混合后端的源码调查/Judge 验证及失败尝试见 [验证记录](validation.md)。
当前适配器针对本机 OpenCode 1.18.32、Hermes 的实际接口、MCP Python 2.2.0 验证，
不是任意版本兼容保证。后续应增加宿主版本绑定、启动能力探测和更广泛的契约矩阵，
再考虑受策略控制的故障切换；仍不将 ACP 或任一宿主的类型泄漏到 Core。
