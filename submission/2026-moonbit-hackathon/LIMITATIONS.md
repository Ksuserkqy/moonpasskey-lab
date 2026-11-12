# 能力与证据边界

本材料按 2026-11-12 已有记录整理。MoonPasskey Lab 当前是面向开发者的协议分析、ES256 Assertion 验证与本地集成实验工具；各入口的 PASS 仅表示其实际执行的检查通过。

## 已实现与未实现

| 范围 | 当前状态与边界 |
| --- | --- |
| 字节与结构解析 | Base64URL、ByteReader、有界 CBOR、ClientDataJSON、AuthenticatorData 和 AttestationObject 已实现；完整 CBOR 覆盖为部分实现，floats / tags / indefinite-length 明确不支持 |
| ES256 | 已实现严格参数与坐标域范围、公钥曲线点导入、SHA-256、raw64 原语与 WebAuthn DER Assertion 验签 |
| Assertion 策略 | 已实现 challenge、精确 origin / topOrigin、RP ID hash、凭证 / 账户绑定、UP/UV、BE/BS、计数器风险及更新建议 |
| 测试登记 | 仅接受 `fmt=none` 与空 statement Map，完成最小测试绑定和 ES256 公钥检查 |
| Attestation 信任 | 逐格式签名、X.509 证书链、可信根与信任策略未实现；其他格式仅保留结构及未验证状态 |
| 算法与扩展 | ES384、ES512、RS256、PS256、EdDSA 等语义验证未实现；扩展数据有界解析后保留，具体语义及 AppID 特殊路径未实现 |
| 完整符合性 | 未声明完整 WebAuthn / CTAP 符合性或认证；未建立模糊测试、性能基准与形式化证明 |

## 策略和宿主责任

默认 UV 为 `Preferred`，counter 为 `ReportOnly`，跨域关闭；Origin 由可信调用方显式配置。Preferred 下 PASS 不表示必须出现 UV，需查看实际 flags。计数器 0→0 表示 `NOT_SUPPORTED`；非递增是风险信号，默认报告风险并保留历史最大值，可显式选择 Reject。

RP ID 只做当前 ASCII 域名标签语法检查，不完成 PSL、IDNA、域名授权或浏览器适用性推断。账户查找、challenge 随机性 / 有效期 / 一次性消费、`uvInitialized` 生命周期和业务授权属于宿主边界。参考 RP 已实现本地挑战和 SQLite 原子提交范例，其他集成仍须自行实现这些责任。

参考 RP 默认 loopback 监听、内存数据库，为单机测试服务。生产账户与恢复、全面限流、长期清理、分布式协调和运维审计未实现。CLI 在 Core 限长前读取整个文件，宿主仍须控制不可信大文件和跨请求资源。

## 真实设备与部署

| 验证范围 | 实际证据 |
| --- | --- |
| Safari/macOS 历史流程 | 维护者完成真实平台 Passkey 测试注册与 Assertion；UV preferred / 实际 true，DER 有效、Core 12 项 PASS |
| Provider 来源 | iCloud Keychain / 平台 Passkey 为维护者选择记录，`MAINTAINER_SELECTED`；协议字段未独立证明 Provider 身份 |
| 历史事务信息 | 当时成功路径在提交后响应，但旧导出无显式事务版本；新格式字段不回填，旧字段保持 UNKNOWN |
| 新设备矩阵 | Safari required、iOS、Chrome、Windows Hello、USB / NFC FIDO2 等未完成；iOS 跨设备验收受已验证 HTTPS 入口缺项阻塞 |
| Ubuntu / Nginx | 隔离虚拟机中实际运行配置、TLS、代理与拒绝路径测试；证书、端口和认证材料均为临时合成资源 |
| 公网部署 | 真实服务器、域名 / DNS、Let's Encrypt 申请及续期、公网 HTTPS 与新设备访问均未执行 |

本地合成 TLS、签名和导入演示的 PASS 不增加真实设备或公网部署证据。新报告的 schema 校验通过，只证明格式与脱敏符合当前契约，不证明设备流程发生。

## 测试和审查如何解读

现有记录为 **631 个独立用例**：Core 491 + CLI 7 + RP / 预检 57 + Dashboard / 报告 26 + 部署独立叶用例 50。四目标重复执行只计一次；部署 Node 输出 51/51 包含一个父测试。向量循环中的条目不另加到该总数。历史与当前记录须按对应阶段、目标和提交阅读。

固定 MoonCrypt `0.4.16` 后端存在已公开的非规范坐标接受问题；项目在导入前保留严格 `< p` 检查，并有回归测试。未找到该版本的独立第三方安全审计报告。源码审阅、外部向量与自动化测试属于项目自身工程证据，AI 审阅不等于独立审计或维护者人工验收。工具链或后端升级需要重新验证。

[仓库完整限制](../../docs/LIMITATIONS.md) · [开发记录](../../docs/DEVELOPMENT.md) · [设备矩阵与原始报告](../../docs/ASSERTION-INTEROP.md) · [部署验证](../../deploy/ubuntu-nginx/VALIDATION.md)
