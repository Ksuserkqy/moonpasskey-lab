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

### 文档与仓库流程

- 记录架构、威胁模型、标准映射、竞品分析、开发过程和当前限制。
- 增加贡献指南、变更记录和 PR 模板，约定逐 Phase feature branch / PR、Conventional Commits、逻辑提交、测试报告、CI 通过后申请合并及用户明确合并授权。
- 为本次 Bootstrap 记录已授权的 P1/P2 单 PR 整合例外，后续按独立 Phase 交付。
- 增加 MoonBit CI 配置，用于自动化验证仓库检查、构建和目标测试。远程运行状态由对应 PR 的 Actions 结果记录。

### 当前实现边界

`Generic` 与 `Ctap2Canonical` 整体状态均为 `PARTIAL`。IEEE 754 binary16/32/64 的结构化结果和值模型为 `NOT_IMPLEMENTED`，完整 payload 返回 `UnsupportedFloat`，截断 payload 返回读取错误。Generic 的 tag 与 indefinite-length 结构解析为 `NOT_IMPLEMENTED`，CTAP profile 对相应禁止编码返回明确错误。CTAP 命令语义、COSE 密钥约束和设备互操作验证待实现。[当前限制](docs/LIMITATIONS.md) · [标准映射](docs/SPEC_MAPPING.md)

ClientDataJSON、AuthenticatorData 与 AttestationObject（Map/Array attStmt）的通用结构解析已实现；整体协议覆盖为 PARTIAL。compound 等逐格式语义、COSE 语义、字段信任与密码学验证、分析 CLI 和 Web Dashboard 为 NOT_IMPLEMENTED。现有解析结果表达结构与编码检查结果，完整 WebAuthn Level 3 符合性仍待建立验证证据。[架构与后续模块](docs/ARCHITECTURE.md)
