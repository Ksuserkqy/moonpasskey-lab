# MoonPasskey Lab｜申报参考草稿（AI 辅助）

本稿按 2026-11-12 仓库已有实现与验收记录，由 AI 辅助整理，供维护者撰写申报书时核对事实。官方章程 §5.1 要求参赛者人工撰写一页 Markdown 项目申报书。请维护者以本人表述完成正式版本，覆盖至少三个完整场景、目标、功能、路线、来源和仓库，并填写以下信息。十一月适用条款及方向见 [资格核对](ELIGIBILITY.md)。

| 待维护者填写 / 确认 | 内容 |
| --- | --- |
| 作者 / 团队 | 【填写真实姓名或团队名；按表单要求补充成员与分工】 |
| 联系方式 | 【填写可公开或仅供赛事使用的真实联系方式】 |
| 参赛方向与资格 | 【与主办方确认新项目或社区方向及对应资格，再填写最终选择】 |

## 项目名称与摘要

**MoonPasskey Lab：由 MoonBit 驱动的 WebAuthn / Passkey 协议分析与验证工具。**

项目面向开发者，提供从浏览器原始认证字节到逐项验证报告的可追溯路径。MoonBit Core 负责有界解析、ES256 公钥与签名检查、RP 策略和计数器风险判断；CLI 与 Vue Dashboard 展示同一套结果，Node / SQLite 参考 RP 管理挑战和原子状态提交。项目已有 Safari/macOS 平台 Passkey 的真实历史 PASS 记录，以及四个编译目标的回归证据。当前定位是可复用的协议分析工具与集成范例，已实现范围和未完成能力分别公开记录。

## 问题与目标用户

WebAuthn 横跨浏览器 API、原始 JSON、AuthenticatorData、CBOR / COSE 和签名格式。单一成功或失败提示不足以解释实际检查了什么，重新序列化原始 JSON、混淆 DER 与 raw64、误读计数器也会影响调试判断。

MoonPasskey Lab 服务于正在接入 Passkey 的开发者、学习协议的学生，以及希望在 MoonBit 项目中复用解析和验证能力的贡献者。目标是让输入、执行的检查、失败位置和未执行的检查都有明确对应，方便复现和讨论。

## 三个完整预期使用场景

| 使用者与需求 | 输入与操作 | 可检查的输出 |
| --- | --- | --- |
| 接入 Passkey 的开发者定位认证失败 | 把脱敏或合成请求保存为 JSON，经 CLI 执行 verify-assertion | 查看 challenge、Origin、UV 或签名的具体错误，按相同文件复现 |
| 协议学习者理解原始认证字节 | 在 Dashboard 导入公开夹具，查看 ClientData、AuthenticatorData 与逐项检查 | 将 UP/UV/BE/BS、DER 签名结果、计数器状态与策略要求对应起来 |
| MoonBit 集成开发者验证宿主状态处理 | 启动 Reference RP，在本地完成测试注册和 Assertion，检查重复挑战及版本冲突用例 | 对照 Core 验证、事务提交和脱敏报告，复用安全解析与宿主集成接口 |

## 已实现成果

| 成果 | 当前能力 |
| --- | --- |
| MoonBit 基础包 | Base64URL、边界安全读取、有界 CBOR；严格 UTF-8、重复键、资源预算和源范围 |
| WebAuthn Core | ClientDataJSON、AuthenticatorData、AttestationObject 结构；ES256 参数、公钥点、SHA-256、DER Assertion 验签 |
| Assertion 策略 | challenge、精确 origin、RP ID hash、凭证与账户绑定、UP/UV、BE/BS、计数器风险与更新建议 |
| 工具入口 | 共用 analysis JSON 接口；CLI 文本 / JSON 输出；Dashboard 原生 Passkey 调用、导入分析和脱敏导出 |
| 本地参考 RP | 安全随机挑战、会话绑定、时效、一次性消费、SQLite 事务与凭证 version 条件更新 |
| 部署准备 | Ubuntu / Nginx 配置、预检、TLS 材料生成、回滚与隔离环境运行测试；真实部署待执行 |

本次申报整理处于功能冻结阶段，不增加协议算法或产品能力。

## MoonBit 的核心作用

协议解析、签名消息构造和 Assertion 策略均集中在 MoonBit。Node 宿主加载编译后的 JS Core，负责 HTTP(S)、随机数、会话、数据库和事务；Vue 负责原生浏览器调用、传输编码和结果展示。CLI 也调用相同 analysis 包。

这使原始字节处理和安全规则有共同来源，并能在 native、js、wasm、wasm-gc 四目标验证。当前网页通过 Node 上的 JS Core 工作；浏览器直接运行 Wasm 的集成尚未实现。密码学运算复用固定 MoonCrypt `0.4.16` 的纯 MoonBit 调用路径，适配层保留坐标域范围、格式与错误约束。

## 项目特点与可复用价值

1. **检查层级清楚。** 结构解析、参数检查、公钥点导入、验签和 RP 策略有独立结果；未执行的检查保留 `NOT_PERFORMED`，避免由解析成功推断信任。
2. **原始字节可追溯。** ClientDataJSON 保留原文参与哈希，解析结果和适用错误保存字节位置；报告输出采用字段允许列表脱敏。
3. **验证与状态提交衔接。** 参考 RP 展示挑战消费与凭证更新的原子提交，版本冲突后重新读取并完整验证，配有实际 Core 和 SQLite 竞争测试。
4. **便于复核与复用。** Apache-2.0 代码、标准映射、来源与许可记录、CLI 和参考宿主一起交付，可用于协议教学、调试，以及 MoonBit 项目的集成试验。

这些价值目前来自实现和可复现材料；项目未以用户规模、商业部署或行业采用作为成果依据。

## 验收与真实设备证据

已有验收记录共计 **631 个独立测试用例**：Core 491、CLI 7、RP / 预检 57、Dashboard / 报告 26，以及部署 50 个独立叶用例。Core 和 CLI 在四目标重复运行，总数只计一次；Node 部署测试输出为 51/51，其中 1 项为父测试，不能再计为独立用例。该数字是已有记录的汇总，不表示本次文稿整理新执行了完整测试。

2026-11-12，维护者在 Safari/macOS 亲自完成系统 Passkey 注册和认证。历史脱敏导出记录请求 UV=preferred、实际 UV=true，ES256/P-256 检查通过、DER 签名有效，Core 12 项 PASS。Provider 按维护者选择记为 iCloud Keychain / 平台 Passkey，来源为 `MAINTAINER_SELECTED`。旧报告未记录显式事务版本，不能补写为新格式证据。

Ubuntu 22.04 隔离虚拟机中实际执行了 Nginx、上游 TLS 验证、Basic Auth、代理传输与拒绝路径测试。公网域名、真实服务器、Let's Encrypt 申请或续期没有执行。Safari UV required、iOS、Chrome 等新设备矩阵尚未验收。

固定验收环境为 MoonBit `0.10.20+65efd5b93`、MoonCrypt `0.4.16`、Node.js `24.18.0`。详细命令、历史环境差异与结果保存在开发和部署记录中，远程 CI 以对应提交的实际记录为准。

## AI 协作与人的责任

维护者定义阶段目标和边界；AI 编码助手参与 API 核验、候选后端调查、实现、测试、静态审阅和文档整理。遇到原任务 raw64 要求与 WebAuthn ES256 wire DER 规则的差异时，维护者明确选择 DER Assertion 入口，保留基础 raw64 验签接口。真实系统认证也由维护者亲自完成。

自动化测试、外部向量核对和 AI 相互审阅构成工程证据，最终接受仍由维护者负责；材料不将其表述为独立安全审计或已完成的人工代码审查。[开发故事](DEVELOPMENT_STORY.md)

## 当前限制与后续工作

当前仅支持 ES256 Assertion 和 `none` 最小测试登记。其他算法、attestation 证书链及信任、完整注册与 WebAuthn 符合性未实现；模糊测试、性能基准与密码学后端独立审计证据仍缺失。参考 RP 是本地单机实验工具，生产账户、恢复、分布式协调和长期运维能力待建设。[限制说明](LIMITATIONS.md)

后续优先完成维护者实际设备验收、受保护 HTTPS 部署验证和独立审查；协议扩展需另行给出标准依据与测试。本稿未承诺完成日期，也未把计划能力计入本次成果。

## 开源与材料入口

源码仓库：[Ksuserkqy/moonpasskey-lab](https://github.com/Ksuserkqy/moonpasskey-lab)。项目使用 [Apache-2.0](../../LICENSE)，第三方依赖及 W3C、NIST、Wycheproof 测试数据来源和许可分别保留在仓库记录中。

[一页概览](PROJECT_OVERVIEW.md) · [架构](ARCHITECTURE.md) · [答辩问答](FAQ.md) · [开发与测试记录](../../docs/DEVELOPMENT.md) · [真实设备记录](../../docs/ASSERTION-INTEROP.md) · [部署验证](../../deploy/ubuntu-nginx/VALIDATION.md)
