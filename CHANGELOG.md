# 变更记录

此文件记录实际完成的功能与维护变更。未发布内容归入 `[Unreleased]`，发布版本与日期在获得发布授权并实际发布时记录。

## [Unreleased]

### Phase 1 基础包

- 新增 MoonBit `base64url` 包，提供 URL-safe 编解码、可选 padding、非法字符位置、编码格式错误与 1 MiB 二进制大小限制。
- 新增 MoonBit `bytereader` 包，提供有界 `u8`、大端 `u16`/`u32`、精确字节视图读取与游标状态。读取失败保留游标位置。
- 通过公开 API 覆盖 Base64URL 与 ByteReader 集成，两个包合计 44 个自动化测试。

### Phase 2 CBOR

- 新增 MoonBit `cbor` 包，提供 `parse_one`、`parse_all`、节点源字节范围、精确错误位置与嵌套 context。
- 支持 definite-length major types 0–5、完整整数参数、严格 UTF-8、boolean、null、undefined 及已列 simple 值。
- 新增语义重复键拒绝、可配置输入与容器资源预算、最大嵌套深度及节点数约束。
- 提供 `Generic` 与 `Ctap2Canonical` profile。CTAP 编码检查覆盖最短整数与长度头、按 major type / 完整编码长度 / 原始字节比较的 map 键序，以及独立的四层 array/map 嵌套上限。
- 新增一致性回归，覆盖复合 key 深度、浮点位宽错误分类、整数边界与排序。引入 W3C WebAuthn 固定版本的 77 字节 ES256 COSE_Key 官方规范示例，并记录许可和项目合成变异来源。
- CBOR 包共 63 个测试，全仓库共 107 个。wasm、wasm-gc、js、native 四个目标的已验收本地结果均为 107 通过、0 失败。

### Phase 3 WebAuthn 协议解析

- 新增原生 MoonBit `webauthn` 包，复用 ByteReader、CBOR 和其资源预算；未引入外部依赖。
- ClientDataJSON 校验 UTF-8/JSON、字段类型、嵌套重复成员与预算；保留原始字节、BOM 和顶层成员源范围。
- AuthenticatorData 解析固定字段、AT、ED、UInt32 计数器与源范围；检查 BS ⇒ BE、credential ID 长度及扩展标识符。
- AttestationObject 校验外层 Map 的三个必需且唯一字段、fmt 标识符及嵌套 authData；attStmt 接受 Map/Array，none 仍要求空 Map，其他格式返回 FormatNotValidated。
- WebAuthn CBOR 使用现有 canonical profile；共享外层、公钥及 ED 的节点预算，保留并换算嵌套错误位置。
- 审查修正拒绝额外外层字段，保留 ClientDataJSON 和 statement Map 内未知字段策略；新增 Map/Array 边界回归及 W3C §16.2/16.4/16.5 官方向量，并单独记录来源与许可。
- 新增协议黑盒及集成回归；实际数量、四目标结果与工具链版本见 [开发记录](docs/DEVELOPMENT.md)。

### Phase 4 ES256 COSE Key 参数验证

- 新增 canonical 字节入口 `validate_es256_credential_public_key` 和显式 `AttestedCredentialData::validate_es256`，返回带原始编码、源范围与 NotPerformed 曲线点状态的 Es256PublicKeyParameters。
- 检查 EC2/ES256/P-256 组合、五个必需参数、坐标32字节与域范围、压缩表示、私钥和 optional；未知参数明确不支持。
- P3 结构解析保持兼容，不自动触发 ES256 验证，不将其他算法当成 ES256；错误枚举新增相应分类，穷尽匹配调用方需处理新增变体。
- 复用已有 W3C 官方 fixture，补充参数负例、坐标边界、范围与跨模块回归。P4 阶段仅完成参数层，曲线点与签名能力由下述 P5 扩展。

### Phase 5 ES256 密码学验证

- 引入固定版本 MoonCrypt 0.4.16，复用纯 MoonBit P-256 点检查、SHA-256 和 ECDSA 验签实现，记录候选比较、依赖树与安全证据。
- 新增 `ValidatedEs256PublicKey` 和显式导入入口，保留 P4 参数 API、原始坐标、编码、范围及 NotPerformed 的参数层语义。
- 新增原始字节 `sha256` 和严格 raw64 `verify_es256_signature`，区分长度/标量错误与合法编码的验签失败，接受合法 high-S 签名。
- 新增原始 `authenticatorData || SHA256(clientDataJSON)` 构造入口和严格 DER Assertion 验签接口，按维护者确认采用 WebAuthn §6.5.5 线格式，基础 ECDSA 入口继续使用 raw64。
- 增加固定版本 Wycheproof、NIST CAVP 和 SHA-256 独立向量及合成边界回归，保留 P1–P4 全部测试与原有官方字节。
- 已评估的后端缺少可核验的独立安全审计。其公开坐标范围检查缺口由 P4 强制范围检查覆盖，具体限制和四目标证据见开发记录。
- CI 在解析外部依赖前初始化 Mooncakes registry，供全新 runner 获取固定版本元数据。

### Phase 6 ES256 Assertion 与 RP 策略

- 新增统一 `verify_webauthn_es256_assertion`，组合身份绑定、严格挑战、精确 Origin、跨域与顶层 Origin、RP ID hash、UP/UV、BE/BS 和原始 DER 验签。
- 新增 CounterStatus 与默认 ReportOnly/显式 Reject 策略，成功后返回保留历史计数高水位及当前 BS 的凭证更新建议。
- 复用现有解析预算、Base64URL、P5 密码学和安全字节比较，增加字段路径、相对原始字节位置与可区分的失败类型。
- 补充官方集成与固定合成签名回归，记录挑战生命周期、并发提交、扩展策略和真实设备 `NOT_PERFORMED` 状态。详细阶段记录见 [P6 变更记录](docs/CHANGELOG.md)。
- CI 将 setup-node 固定到使用 Node24 runtime 的官方 v6.5.0 提交，以处理旧 Action 的弃用警告。

### Phase 7 集成与互操作

- 新增纯 MoonBit analysis JSON bridge 和现有 cmd/main 的文件 CLI，支持独立解析、Assertion 分析/验证、逐项状态、脱敏报告和退出码。
- 新增本地 TEST ONLY Node/SQLite RP，安全随机挑战、会话绑定、时效、一次性消费和凭证 version CAS 同事务提交。
- 新增真实多连接竞争测试，覆盖乱序计数、ReportOnly、Reject、BS/BE 与重放，并通过实际编译 Core 执行 HTTP 集成。
- 新增 Vue Dashboard，调用浏览器原生 create/get，保留原始 clientDataJSON，显示实际 Core 结果并提供脱敏导出。
- 增加独立前端与参考 RP CI，四目标增加 CLI 入口测试。取得 Safari/macOS 真实平台 Passkey 的 Core PASS 与脱敏导出，其他环境按专项矩阵标记。

### 文档与仓库流程

- 记录架构、威胁模型、标准映射、竞品分析、开发过程和当前限制。
- 增加贡献指南、变更记录和 PR 模板，约定逐 Phase feature branch / PR、Conventional Commits、逻辑提交、测试报告、CI 通过后申请合并及用户明确合并授权。
- 为本次 Bootstrap 记录已授权的 P1/P2 单 PR 整合例外，后续按独立 Phase 交付。
- 增加 MoonBit CI 配置，用于自动化验证仓库检查、构建和目标测试。远程运行状态由对应 PR 的 Actions 结果记录。

### 当前实现边界

`Generic` 与 `Ctap2Canonical` 整体状态均为 `PARTIAL`。IEEE 754 binary16/32/64 的结构化结果和值模型为 `NOT_IMPLEMENTED`，完整 payload 返回 `UnsupportedFloat`，截断 payload 返回读取错误。Generic 的 tag 与 indefinite-length 结构解析为 `NOT_IMPLEMENTED`，CTAP profile 对相应禁止编码返回明确错误。ES256 参数约束由 P4 提供；CTAP 命令语义和其他算法待实现，设备互操作按专项矩阵记录。[当前限制](docs/LIMITATIONS.md) · [标准映射](docs/SPEC_MAPPING.md)

ClientDataJSON、AuthenticatorData 与 AttestationObject（Map/Array attStmt）的通用结构解析已实现，P5 增加 ES256 点与签名原语，P6 增加 Assertion 与 RP 策略核心，整体协议覆盖为 PARTIAL。compound 等逐格式语义、ES256 以外的 COSE 语义、注册信任为 NOT_IMPLEMENTED，P7 已实现分析 CLI 和本地 Web Dashboard。完整 WebAuthn Level 3 符合性仍待建立验证证据。[架构与后续模块](docs/ARCHITECTURE.md)
