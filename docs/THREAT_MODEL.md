# 威胁模型

## 范围与信任边界

基础包的入口是调用方提供的 `StringView` 和 `BytesView`，按攻击者可控数据处理。P6 另区分不可信 Assertion 响应与可信的预期 challenge、账户凭证记录和 RP 策略。资产包括进程可用性、原始字节完整性、身份绑定、策略结果和状态更新的准确性。Core 负责有界验证，调用方负责可信上下文、输入获取和处理公开 Result。

当前实现依赖 MoonBit 运行时、不可变 Bytes/BytesView 语义和标准库严格 Base64 解码器。固定大小限制约束每次 Base64URL 操作，P7 参考服务进一步约束单次 HTTP 输入和挑战容量，CLI 的文件读取与进程级总资源预算仍由调用环境管理。

## 已实现的防护

| 风险 | 实现措施 | 技术依据 | 测试证据 |
| --- | --- | --- | --- |
| 非字母表字符产生歧义 | 原文校验，拒绝空白、NUL、Unicode、`+`、`/` | RFC 4648 §3.3、§5、§12 | 全 ASCII 非法字符及 Unicode 测试 |
| padding 错误或尾部数据混入 | 标准库严格 decode，错误转换为 InvalidEncoding | RFC 4648 §3.2 | malformed padding 测试 |
| 非零未使用位产生多个编码 | 标准库检查末组低 4 位或低 2 位 | RFC 4648 §3.5 的允许拒绝策略 | 64 个末尾 sextet 全变异测试 |
| 超大输入导致资源消耗 | 编码前检查 1 MiB，解码前检查文本及输出长度 | 本项目资源策略 | 精确上限、超限及长度优先检查测试 |
| 有符号容量计算溢出 | 先限长再进行有界 Int 运算 | 本项目整数安全不变量 | 上限和超限测试，源码审阅 |
| 负读取长度或偏移加法溢出 | 先验证非负且 length <= remaining，之后相加 | 本项目读取不变量 | Int 最小值、最大值测试 |
| 截断整数造成部分消耗 | 整数读取复用完整宽度 read_bytes | 本项目错误原子性契约 | 每种截断宽度及非零游标测试 |
| 读取输入视图范围之外 | 私有状态，使用 get_view 校验区间 | 标准库 BytesView 契约 | 子视图、精确末尾及末尾后读取测试 |

上述 RFC 条款描述编码和解码的规则。1 MiB、错误类型和失败后游标位置属于本项目实现契约。[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html)

## 必须保持的不变量

- `0 <= position <= input.length()`。
- `remaining == input.length() - position`。
- `read_bytes(n)` 成功时返回恰好 n 字节，失败时 position 保持原值。
- 原始输入字节保持不可变，返回视图的范围落在输入视图之内。
- `read_u32_be` 在 UInt 域组装，覆盖 `0..4294967295`。
- Base64URL 解码前完成输入与预期输出大小检查，异常通过 Result 交给调用方。

## Assertion 验证的安全边界

P6 的统一入口验证 ES256 authentication assertion 的 challenge、Origin、RP ID hash、身份绑定、UP/UV、BE/BS、DER 签名及计数器风险。它接受可信的服务器挑战、RP 配置和已登记账户凭证记录。外层响应类型检查、账户查询、服务端会话和持久化由调用方负责。原始 clientDataJSON 和 authenticatorData 进入 P5 签名接口。[WebAuthn Level 3 §7.2](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion)

Phase 1 提出的 CBOR 输入、嵌套深度、重复键、截断和不支持类型要求已在 Phase 2 的有界解码器中实现，并通过独立的 Generic 与 Ctap2Canonical 编码策略执行对应检查。CBOR 的当前支持子集、精确资源预算、语义键与错误定位依据见 ARCHITECTURE.md、LIMITATIONS.md 和 SPEC_MAPPING.md。

ByteReader 本身通过视图读取已有数据，整体文件大小、并发次数和进程资源预算由调用层设置。分析报告、其他算法、注册信任评估与真实设备互操作仍需对应证据。

## P6 攻击面与控制

| 风险 | P6 控制 | 调用方责任 |
| --- | --- | --- |
| 挑战替换、编码歧义 | 严格无 padding Base64URL、非空、规范表示与字节比较 | 从可信会话取出预期值，使用安全随机数并确保足够熵 |
| 重放旧响应 | 与本次预期 challenge 精确匹配 | 挑战有效期、一次性存储和原子消费 |
| 恶意 Origin、子域名、端口伪装 | 显式精确 Origin allowlist | 保护所有允许的 Origin，禁止在其中运行不可信代码 |
| 跨域 iframe 冒用 | 默认禁用跨域，存在 topOrigin 时验证顶层 allowlist 和字段关系 | 按业务明确授权嵌入来源 |
| RP ID 混淆 | 拒绝当前支持范围外的 RP 配置，对原文 UTF-8 SHA-256 后安全比较 | 可信配置来源、域名授权、IDNA 和 public suffix 检查 |
| 凭证或账户替换 | credential ID 与可信记录及非空 allowCredentials 匹配，userHandle 条件匹配 | 账户所属关系、discoverable 查询及账户状态检查 |
| 缺少用户参与或验证 | UP 必需，Required 时 UV 必需，结果保留实际 flags | 按业务选择 UV 要求 |
| 备份状态误判 | 已知 BE 与历史记录一致，BS⇒BE，BS 可变化 | 决定备份状态的业务含义 |
| 签名篡改和错误消息构造 | 严格 DER，原始 authData 与原始 JSON 哈希，复用已验证公钥 | 可信注册公钥和完整传输数据 |
| 计数器不递增 | 明确报告 NonIncreasing，默认 ReportOnly，显式 Reject 才拒绝 | 根据风险策略处理，结合其他证据判断异常 |
| 并发更新覆盖 | 成功结果提供观察值、历史计数和更新建议，保留计数高水位 | 使用事务或记录 revision/CAS，冲突后重新评估并原子消费挑战 |

计数器异常可能来自克隆、故障或请求乱序。`NonIncreasing` 仅表达计数关系，不能确定设备被克隆。ReportOnly 成功时建议保存 `max(stored, received)`，同时保留实际 received 值。历史 BE 未知时，更新建议继续保存未知状态，观察值由已验证的 flags 返回。[WebAuthn §6.1.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-sign-counter) · [§6.1.3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-credential-backup)

更新建议中的历史计数与 BE 只帮助识别读取快照。计数为零或 BS 改变时，两个请求仍可能具有相同计数快照，所以存储层还需要记录版本或事务隔离。调用方必须将挑战消费与凭证状态更新放在合适的原子边界中。验证函数不读取数据库或时钟，无法判断调用方是否提供了已经消费或过期的挑战。[WebAuthn §13.4.3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-cryptographic-challenges)

P6 的严格策略拒绝 Assertion 中的 AT 和非零 RFU。扩展输出在有界结构解析后按 RP 策略忽略并保留，调用方使用依赖扩展结果的业务时应增加对应语义验证。原有结构解析入口继续保留自己的兼容性契约。[WebAuthn §6.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-authenticator-data) · [§7.2 step23](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion)

MoonCrypt 0.4.16 的已知坐标范围缺口由 P4 强制前置检查覆盖。缺少独立第三方安全审计、运行时与编译器行为、尚未执行的真实设备测试和持续模糊测试仍属于当前证据边界。[当前限制](LIMITATIONS.md)

## Phase 7 参考 RP 攻击面

| 风险 | 控制与证据 | 剩余边界 |
| --- | --- | --- |
| 预测挑战或复用 | Node CSPRNG 32字节，SHA-256 摘要，时效和一次性事务消费 | 依赖宿主随机源和可信时钟 |
| 跨会话/账户/目的混用 | 每次读取与提交重验 session/user/RP/origin/purpose，失败类型区分 | 临时测试账户绑定当前会话，生产身份生命周期待实现 |
| 并发双消费或旧状态覆盖 | BEGIN IMMEDIATE、version CAS、条件消费、同库提交与回滚 | SQLite 单机边界，未实现分布式事务 |
| 乱序 counter 导致风险丢失 | 冲突重读最新记录后由 Core 重新评估，真实 worker/连接竞争测试 | ReportOnly 风险不提供设备克隆归因 |
| CSRF、DNS rebinding 和跨站读取 | loopback bind、精确 Host/Origin、SameSite Strict、HttpOnly、CSRF token、无跨域放行、CSP | 同源代码与本机进程仍属信任边界 |
| 认证材料进入日志或导出 | MoonBit 公开入口脱敏，Host 二次过滤，Dashboard 导出允许列表 | 浏览器 options 和内存存储需要完整公开凭证标识和挑战 |
| 不可信输入耗尽资源 | HTTP body 2 MiB，Core envelope/depth/字段预算，容量与请求超时 | 单进程同步验签 CPU、长期旧记录清理和全面限流尚待评估 |
| 测试注册误用于生产 | 界面、文档和报告标注 TEST ONLY，attestation_trust=NOT_PERFORMED | 注册信任链、账户恢复、生产授权与审计未实现 |

默认数据库是内存库。显式 REFERENCE_RP_DB 启用文件持久化，保存公开 COSE key、credential ID、账户句柄、挑战摘要、状态和脱敏报告。原始认证响应不会写入数据库。文件权限0600，新目录0700，文件持久化的备份和删除由维护者管理。系统 Passkey 本身由系统 provider 保存，维护者在实验结束后自行管理测试凭证。

Node 24.18 的 node:sqlite 处于 Release candidate 稳定性等级。MoonCrypt 0.4.16 缺少已核验的独立安全审计，原有范围检查防护持续存在。P7 自动化测试和设备证据不能建立整体 WebAuthn/FIPS 合规结论。[Node SQLite](https://nodejs.org/download/release/v24.18.0/docs/api/sqlite.html) · [当前限制](LIMITATIONS.md) · [互操作记录](ASSERTION-INTEROP.md)

## Phase 7.1 HTTPS 与报告边界

跨设备设计使用固定专用测试hostname，浏览器验证边缘HTTPS证书，connector验证到loopback后端的独立TLS证书。Access应用覆盖整个hostname和所有路径，显式身份Allow策略配合connector的per-ingress JWT校验。原有Host、Origin、CSRF与会话校验继续执行，forwarded headers不参与授权配置。云端代理会处理测试认证流量，维护者须批准测试服务商与基础设施部署。

离线preflight确认配置、完整TLS输入、证书名称/时效和key配对，并将域名控制权、链信任、Access/JWT、代理头一致性和iPhone可达性标为NOT_PERFORMED。离线PASS只覆盖所列配置检查，网络侧与真实设备证据另行验收。合成TLS用例生成临时证书并通过请求级CA验证，系统trust store保持在维护者控制范围。

报告校验使用各层字段白名单，限制metadata、类型、状态、时间和provider来源。新报告只保留脱敏challenge长度、flags、计数、DER结果、Core状态与非身份事务版本。原始响应、credential ID、userHandle、公钥、签名、私钥、cookie、CSRF与TLS密钥没有导出字段。维护者填写的设备和provider文本仍需在分享前核对，结构校验无法证明实际硬件执行或provider身份。

历史报告保持原始字节，sidecar固定摘要及来源分类。数据库提交证据由成功事务之后的显式响应提供。旧导出缺少该字段时标为UNKNOWN，保留既有Core成功结果。导入分析使用自己的配置上下文，不能借用当前RP策略或生成数据库提交证据。[HTTPS方案](INTEROP-HTTPS.md) · [矩阵与报告](ASSERTION-INTEROP.md)
