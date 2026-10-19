# 02 · Agent 执行环境适配库

PRD 1.0 · 2026-10-18 · 买方接入组件 · 第一批或第二批  
状态：设计提案，未实现/未付款/未提交。先读[总体接入设计](../总体接入设计.md)与[接口事件约定](../接口与事件约定.md)。

## 1. 用户与真实场景

**用户：**在 Python 应用或自己的 Agent 宿主里接入 Passport 的开发者；首版只选 Python 与一个受支持宿主。

**第一次使用：**一个研究 Agent 需要购买数据。宿主通过库取得真实报价、申请用户批准、执行购买，并把结构化结果返回任务；另一位用户的任务不能共用它的会话。

**问题：**直接拼 shell 命令容易传错参数、串用当前会话、泄漏本地 token；网络等待又容易被宿主误判成失败并重付。

**Kite 接入价值：**在当前支持的 kpass CLI 外建立可靠的进程适配和结果类型，不恢复已移除的 Passport MCP，也不虚构完整 HTTP SDK。用户批准与 Agent 身份仍由 Passport 提供。

## 2. MVP 范围

**P0，首版必须完成：**

- 版本与命令能力探测；仅支持经过契约测试的一组 kpass/ksearch 版本，未知版本显式告警或拒绝付款。
- Python 参数数组进程调用、受控工作目录和凭证上下文；首版单进程单身份，跨身份进程与配置隔离。
- 统一返回 Approved、HumanActionRequired、ReuseCandidate、Pending、Completed、Failed 等结果；原始敏感响应不写普通日志。
- 持久化 session_id、Passport 操作幂等 key、商家 operation_id 和输入摘要；宿主恢复后可检查原操作。

**P1，有真实反馈后再做：**

- 在首版稳定后增加一个宿主插件；第二语言使用同一契约测试集。
- 为宿主展示批准入口、价格和执行证据，不隐藏用户批准步骤。

**首版排除：**不创建无授权会话、不自动批准、不维护新钱包、不承诺 headless 环境免 passkey。

## 3. 完整用户流程

1. 宿主检查当前身份与已登录账号，读取 CLI 版本能力。
2. 通过 ksearch 读取真实服务示例，普通 HTTP 预检报价和网络。
3. 按当前 delegation 约束调用 session create；返回 reuse_available 时确认目标匹配，不擅自选不同用途会话。
4. 向用户展示 approval_url，等待真实批准；仅 approved 后执行。
5. 通过 session execute 显式指定 method、session_id 和操作 key。
6. 保存结果与付款证据；pending 或超时返回未决，调用方不得把重试视为新购买。

## 4. Kite 能力接入

| 官方能力 | 接入方式 | 保存与验证 |
|---|---|---|
| 服务发现 | ksearch service search 与 --example | 端点、方法、示例、pitfalls；发现不是自建服务自动入目录的保证 |
| 会话 | agent:register、session create/status | 实际 Agent 类型、request_id、approval_url、session_id、delegation |
| 执行 | session execute --output json | 付款结果、协议、状态、usage、receipt 与商家响应 |

**接入前置：**所有涉及真实付款的路径先完成 G0，固定 network/asset/facilitator/CLI/账户环境；见总体接入设计。真实身份或 Runtime 不可得时明确 blocked，不能用 mock 替代。

**授权边界：**应用与业务权限自己验证；Passport 的 passkey 批准保留给真实用户；本轮 PRD 编制不发起任何授权或支付。协议实例、金额、会话和示例均以现场预检与实际输出为准。

## 5. 接口与数据

**拟提供接口：**拟提供 Python 接口 inspect_runtime()、discover()、request_session()、check_approval()、execute()、resume_operation()。这些函数是项目设计；底层只调用固定文档中的真实 CLI。输入 TargetRequest(method,url,headers,body,operation_id)。

**核心对象：**RuntimeProfile、OwnerBinding、ApprovalRequest、SessionBinding、Operation、CliInvocation、ExecutionEvidence。owner/agent/session 绑定一起存储，不只保存 current_session_id。

operation_id、付款证据、业务版本及产物按公共事件契约关联。接口/包名属于本项目设计，不代表官方已经发布同名能力。

## 6. 状态与恢复

UNAUTHENTICATED → READY → APPROVAL_REQUIRED → APPROVED → EXECUTING → COMPLETED；另有 REUSE_REVIEW、PENDING、UNKNOWN、REJECTED、EXPIRED。

- 不以字符串 shell 执行或直接执行返回的 next_command；解析允许的命令类型与参数。
- 批准等待超时不等于拒绝；付款进程超时不等于未付款。按 CLI 文档给足等待窗口，后续仅查询原操作。
- 检测账号切换和 CLI 更新，旧 session 不跨身份复用；配置隔离方式必须按实际 CLI 支持验证，不能编造隔离环境变量。

任何付款未知均不能通过换 key 自动重买；任何产物恢复都需要原权限。测试桩中的假付款不产生真实交付承诺。

## 7. 开发任务拆分

- 02-T01：确定一个宿主和 CLI 版本范围，完成登录/配置隔离 PoC。
- 02-T02：实现类型、参数构造、错误归一和敏感信息清理。
- 02-T03：实现批准与会话状态管理、操作持久化。
- 02-T04：实现恢复契约与故障测试。
- 02-T05：发布 Python 包和一个小型付费数据购买示例。

**投入粗估：**4–6 人周。先做 M0 兼容与样本验证，再做独立核心、真实互通及发布；外部批准、环境开通和审核不计入可承诺工期。

## 8. 界面与使用体验

提供最小状态组件：报价、待批准、执行中、未决、结果；不做通用聊天前台。

在需要用户决定时展示价格、范围、权限和失败状态；普通产品页面不堆协议实现细节，技术证据留在诊断/报告页。

## 9. 验收与演示

下面是目标，尚未运行或达成。

- R01：相同输入形成正确 argv；命令注入字符作为数据，不执行。
- R02：两用户/两 Agent 并发或恢复时不能串 session 与凭证。
- R03：批准、拒绝、reuse_available、会话过期和 execute 未决均能保留语义。
- R04：按固定版本做一次真实发现—批准—购买，返回可复核证据；模拟结果另标。

**完整演示：**同一宿主先返回待批准，真实批准后完成付费查询；模拟响应丢失后恢复原操作，证明没有新发起收费。

**试用观察：**接入代码量、身份/会话错误数、可恢复未决操作比例与宿主集成反馈。

## 10. 提交与独立性

开发工具贡献；不直接等同于语言 Wrapper 赛道。可在已有相关客户端项目扩展，提交前核实工具类适用范围。

项目核心包括本 PRD 定义的模型、业务引擎/状态/断言与样本；支付和基础依赖可正常共享，不复制其他参赛实现换名。EC 映射、活动审核与真实贡献是否被统计分别跟踪，不用本 PRD 保证收录。
