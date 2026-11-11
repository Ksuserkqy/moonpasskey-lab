# MoonPasskey Lab 架构

## 阶段状态

截至 2026-11-12，Phase 1 已实现 MoonBit `base64url` 与 `bytereader` 包，Phase 2 新增 `cbor` 包，Phase 3 新增 `webauthn` 包，提供 ClientDataJSON、AuthenticatorData 和 AttestationObject 的结构解析（attStmt 支持 Map/Array）。模块身份保持 `ksuserkqy/moonpasskey_lab@0.1.0`，默认目标为 `wasm`。`cmd/main` 当前运行后输出 `Hello`，协议分析 CLI 尚未实现。结构解析成功不代表认证成功。

## 实际目录

```text
moonpasskey-lab/
├── AGENTS.md
├── LICENSE
├── README.md -> README.mbt.md
├── moon.mod
├── moon.pkg
├── moonpasskey_lab.mbt
├── moonpasskey_lab_test.mbt
├── moonpasskey_lab_wbtest.mbt
├── pkg.generated.mbti
├── base64url/
│   ├── moon.pkg
│   ├── base64url.mbt
│   ├── base64url_test.mbt
│   └── pkg.generated.mbti
├── bytereader/
│   ├── moon.pkg
│   ├── bytereader.mbt
│   ├── bytereader_test.mbt
│   └── pkg.generated.mbti
├── cbor/
│   ├── moon.pkg
│   ├── types.mbt
│   ├── semantic_key.mbt
│   ├── decoder.mbt
│   ├── cbor_test.mbt
│   ├── conformance_test.mbt
│   ├── W3C-NOTICE.md
│   └── pkg.generated.mbti
├── webauthn/
│   ├── moon.pkg
│   ├── types.mbt
│   ├── clientdata.mbt
│   ├── authdata.mbt
│   ├── attestation.mbt
│   ├── clientdata_test.mbt
│   ├── authdata_test.mbt
│   ├── attestation_test.mbt
│   ├── w3c_vectors_test.mbt
│   ├── W3C-NOTICE.md
│   └── pkg.generated.mbti
├── cmd/main/
│   ├── moon.pkg
│   ├── main.mbt
│   └── pkg.generated.mbti
├── docs/
│   ├── ARCHITECTURE.md
│   ├── COMPETITIVE_ANALYSIS.md
│   ├── THREAT_MODEL.md
│   ├── SPEC_MAPPING.md
│   ├── LIMITATIONS.md
│   └── DEVELOPMENT.md
├── .githooks/
├── .github/workflows/
└── _build/                         # 本地生成且被 Git 忽略
```

根包目前为初始化脚手架。每个子目录用自己的 `moon.pkg` 定义包，完整包名由模块名和相对目录组成。

## 分层与依赖方向

| 层 | 职责 | 当前状态 |
| --- | --- | --- |
| MoonBit Core | 字节转换、结构解析、规则、密码学验证、分析报告 | 已实现基础包、有界 CBOR 和 P3 协议结构解析；密码学验证与分析报告尚未实现 |
| CLI | 文件与参数输入、调用 Core、报告输出、退出码 | 当前只有 Hello 示例 |
| Web Dashboard | 输入、协议树、字节视图、展示 Core 结果 | 规划 Vue 3 + TypeScript + Vite |
| 测试基础设施 | 单元测试、集成测试、正负样本、互操作和回归 | 基础包、CBOR、协议解析黑盒测试及跨包集成测试；设备互操作尚未验证 |

CLI 和 Web Dashboard 后续依赖 MoonBit Core。协议校验与安全规则归属 Core。前端集成机制须以真实 MoonBit 产物验证，界面展示应保留各步骤的状态和错误信息。

## 当前核心包

### Base64URL

`encode(BytesView, padding?=false)` 返回 `Result[String, Base64UrlError]`。`decode(StringView)` 返回 `Result[Bytes, Base64UrlError]`。编码和解码的二进制大小均限于 1 MiB。编码文本输入限于 1,398,104 个 UTF-16 code units，合法输入全部属于 ASCII。

封装层负责 URL-safe 字母表、大小检查与错误转换。标准库 `moonbitlang/core/encoding/base64` 负责位编解码、padding 格式和末组未使用位校验。公开错误包括 `InputTooLarge`、带零基位置的 `InvalidCharacter` 和 `InvalidEncoding`。最后一项涵盖非法长度、padding 和非零未使用位。

### ByteReader

`ByteReader::new(BytesView)` 创建持有不可变字节视图的游标。`read_u8` 返回 `Byte`，`read_u16_be` 和 `read_u32_be` 返回 `UInt`。`read_bytes(Int)` 返回原缓冲区内的 `BytesView`。所有读取均返回 `Result`。

`position`、`remaining`、`is_empty` 描述相对输入视图的状态。负长度返回 `InvalidLength`，剩余字节不足返回 `OutOfBounds`，两种错误均携带 requested、position、remaining。读取成功才推进游标。整数读取复用 `read_bytes`。

### CBOR

`parse_one(BytesView, offset~=0, profile~=Generic, limits~=Limits::new())` 返回 `Result[Parsed, ParseError]`。`Parsed.consumed` 从指定 offset 起计数，可与下一次调用连续解析。`parse_all` 返回 `Result[Value, ParseError]`，并检查输入已完整消费。每个节点保存完整编码的半开区间 `range[start,end)`，位置相对于传入的整个 BytesView。`encoded_length()` 由区间长度计算。

`ValueKind` 支持 definite-length 的 unsigned、negative、byte string、text string、array、map，以及 boolean、null、undefined 和 simple 值 0–19、32–255。`Unsigned(UInt64)` 保存完整无符号值，`Negative(n)` 表示 `-1-n`，覆盖 CBOR 的完整整数范围。Byte string 保留原输入的 BytesView。Text string 严格校验 UTF-8 并保留 BOM。Map 保留原始 entries 顺序。

`Generic` 接受非最短整数与长度头、任意 map 顺序。`Ctap2Canonical` 在当前支持类型上增加最短头、map 键顺序和最多四层 array/map 嵌套检查。Tags、floats 和 indefinite-length 数据均有明确错误，CTAP profile 另以禁止 tag 和 indefinite-length 的错误报告对应约束。[RFC 8949 §3–4](https://www.rfc-editor.org/rfc/rfc8949.html#section-3) [CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)

`Generic` 的 RFC 8949 解码覆盖状态为 `PARTIAL`，当前支持范围为上述 definite-length 类型和 simple 值。IEEE 754 binary16、binary32、binary64 的结构化结果与值模型均待实现。两个 profile 在完整浮点 payload 上返回 `UnsupportedFloat(width=2/4/8)`，截断 payload 返回读取错误。CTAP 保留浮点编码位宽，当前浮点错误表达实现支持状态。[RFC 8949 §3.3](https://www.rfc-editor.org/rfc/rfc8949.html#section-3.3) [CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)

两个 profile 均按项目策略拒绝语义重复键。所有已支持类型可作为 map key。内部 `SemanticKey` 自底向上保留类型、去除源范围和编码宽度差异，并将 map 的键值对按内部 total order 标准化，使其等价判断忽略 entries 顺序。`SortedMap` 的 AVL 结构承担去重。CTAP 编码排序单独比较 major type、完整编码长度、编码字节。`Value` 派生的 `Eq` 包含源范围，重复检测使用独立的语义表示。[RFC 8949 §5.6.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-5.6.1)

Array/Map key 按上述三步比较契约处理。CTAP §8 的 Note 说明当前协议未使用 major types 4–6 作 map key，并提示未来使用复杂类型 key 时需重新审视规则。本包接受复合 key 的证据范围为 CBOR 编码检查，CTAP 命令语义和设备互操作仍待对应模块与测试核验。Tags 在 CTAP profile 中按 §8 的独立禁令处理。[CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)

资源预算按一次 parse 调用生效。默认输入与单字符串上限均为 1 MiB，array 上限 4096 项，map 上限 1024 对，array/map 嵌套深度 32，节点数 16384。参数须非负，可配置深度的硬上限为 64。CTAP 的四层约束独立执行，消息传输中的 1024 字节默认能力由后续传输上下文处理。

深度按根到当前节点的路径计数。根 Array/Map 为第 1 层，根标量为 0 层，Map 的 key 和 value 中的容器均计数，兄弟容器各自计算。`Generic` 使用配置的深度预算。`Ctap2Canonical` 同时检查项目预算和 CTAP 四层上限，`max_depth=64` 仍会拒绝第 5 层，较小预算可进一步收紧。

`ParseError` 提供零基 offset、嵌套 context 和可区分的错误种类，覆盖截断、非法头、UTF-8、重复键、编码 profile、资源限制及 unsupported 类型。P3 的 AuthenticatorData 和 AttestationObject 复用此解码器，COSE 密钥语义仍未实现。

#### CBOR 实现状态

| 范围 | 状态 | 当前契约 |
| --- | --- | --- |
| RFC 8949 Generic 解码整体 | `PARTIAL` | 覆盖已列 definite-length 类型和 simple 值的子集 |
| Definite major types 0–5、已列 simple 值 | `IMPLEMENTED` | 有界读取、UTF-8、完整整数域与源范围 |
| 语义重复键检测 | `IMPLEMENTED` | 两个 profile 均按项目策略拒绝，保留类型差异 |
| Ctap2Canonical 整体 | `PARTIAL` | 编码检查覆盖当前支持类型 |
| CTAP 最短整数与长度头 | `IMPLEMENTED` | 对整数及 major types 2–5 的长度执行最短表示检查 |
| CTAP map 键排序 | `IMPLEMENTED` | major type、完整编码长度、原始字节三步比较 |
| CTAP 四层深度与 tag/indefinite 禁止检测 | `IMPLEMENTED` | array/map 的 key 和 value 均计深度，调用方资源上限可进一步收紧 |
| IEEE 754 binary16/32/64 结构化结果与值模型 | `NOT_IMPLEMENTED` | 完整 payload 返回 `UnsupportedFloat`，截断返回读取错误 |
| Generic tag 和 indefinite-length 结构解析 | `NOT_IMPLEMENTED` | 识别相应头后报告 unsupported |
| CTAP 命令语义、COSE 密钥约束及互操作验证 | `NOT_IMPLEMENTED` | 待后续协议模块和测试 |

P2 验收基线为 107 个测试，其中 CBOR 为 63 个。`conformance_test.mbt` 包含 W3C 固定版本的 77 字节 ES256 COSE_Key 官方规范示例，以及项目合成的边界和重排变异。P3 首次验收新增 99 个协议解析黑盒测试，全仓库当时为 206 个。审查修正继续增加外层字段拒绝、Array statement 与 §16 官方向量回归；当前数量和四目标实际结果见 `DEVELOPMENT.md`。示例来源与许可记录见 `SPEC_MAPPING.md` 和 `cbor/W3C-NOTICE.md`。

### WebAuthn 协议结构解析

`webauthn` 包依赖现有 ByteReader 和 CBOR，三个入口均接受原始 `BytesView`、可选 `@cbor.Limits`，返回 `Result[结构化结果, ParseError]`。统一错误保存字节 offset、嵌套字段 context 和 `ErrorKind`；CBOR 错误种类通过 `Cbor` 保留，截断错误保留请求长度与剩余长度。

| 入口 | 结果 | 已实现范围 |
| --- | --- | --- |
| `parse_client_data` | `ClientData` | UTF-8、JSON 语法、顶层对象、必需字段与可选字段类型、重复成员、原始字节和顶层成员范围 |
| `parse_authenticator_data` | `AuthenticatorData` | 固定 37 字节结构、flags、UInt32 计数器、AT、ED、CBOR 完整消费和原始范围 |
| `parse_attestation_object` | `AttestationObject` | canonical CBOR 外层 Map、限定三个字段、Map/Array statement、内嵌 authData、none 空 Map 和状态标记 |

ClientDataJSON 由有界字节扫描器检查 JSON 容器、数字语法、字符串边界和预算，单个字符串 token 才交给标准库 `core/json` 解码。所有对象按解码后的成员名拒绝重复，包括转义等价名称和未知字段中的嵌套对象；未知顶层成员保留名称及 key/value token 范围，不创建完整的未知 JSON 对象树。输入首先经过严格 UTF-8 校验，解析时跳过一个初始 UTF-8 BOM，`ClientData.raw` 仍完整保留它。未配对的 Unicode surrogate escape 按项目策略拒绝。

`type_`、`challenge`、`origin` 必须存在且为字符串，空字符串在结构层可通过。`cross_origin : Bool?` 和 `top_origin : String?` 保存缺省与显式值的区别。操作类型取值、challenge 解码与匹配、origin 信任及两个可选字段之间的关系均不在此入口验证。后续哈希必须使用 `ClientData.raw`，不能重新序列化字段替代原始字节。[WebAuthn §5.8.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#dictdef-collectedclientdata)

AuthenticatorData 复用 ByteReader 读取 `rp_id_hash`、flags 与大端 `sign_count`。flags 保留原始字节、UP/UV/BE/BS/AT/ED 和 RFU 位，拒绝 BS 为真而 BE 为假的组合。保留 RFU 而不拒绝是本项目结构解析的兼容策略；它不声明输入满足 authenticator 生成时 RFU 必须为零的要求，也不将标志视为经过验证的安全属性。AT 读取 AAGUID、两字节 credential ID 长度、ID 和 CBOR map 公钥；长度上限为 1023，零长度只在结构层接受。ED 要求 map，键按扩展标识符的最多 32 octets、限定可打印 ASCII 规则检查，值保留原始 CBOR。[WebAuthn §6.1、§6.5.1、§9.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-authenticator-data)

AttestationObject 保留完整 CBOR 树及原始字节。外层 Map 只允许且必须包含 `fmt`、`authData`、`attStmt`：非 text 键与未知字段均拒绝，未知字段错误定位到键的编码起点。`fmt` 必须为符合 §8.1 标识符规则的 text，`authData` 必须为 byte string 且解析结果包含 AT。`attStmt` 接受 text-keyed Map 或 Array，并保留原始 CBOR Value 及范围；statement Map 内的未知字段继续保留。`fmt="none"` 仍只接受空 Map，状态为 `NoneStructureChecked`；其他格式的 Map/Array 均为 `FormatNotValidated`。Array 的通用结构支持不表示完成了 compound 或其他格式的语义与签名验证，整体协议覆盖仍为 `PARTIAL`。ClientDataJSON 的未知字段兼容策略不受此处外层限制影响。[WebAuthn §6.5.4、§8.1、§8.7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-generating-an-attestation-object)

#### 编码、预算与位置契约

WebAuthn 的外层对象、公钥及扩展均使用现有 `Ctap2Canonical` profile。WebAuthn §2.4 的 decoder SHOULD 作为本项目严格拒绝非 canonical 编码的选择；此选择只应用于协议入口，P2 `Generic` 行为不变。每个 CBOR 树仍受独立四层 array/map 上限约束，字节串中的内嵌 CBOR 从自己的根计深度。[WebAuthn §2.4、§3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-all-conformance-classes)

三个入口复用 `@cbor.Limits`，默认输入与单字符串均为 1 MiB、array 为 4096 项、map 为 1024 对、深度 32（硬上限 64）、节点 16384。JSON 的单字符串预算按不含引号的原始编码字节计，转义序列计入；对象的 key 和 value 都计节点。AuthenticatorData 的公钥与扩展共享节点预算；AttestationObject 的外层 CBOR 节点也从同一次调用预算扣除后再解析内嵌 authData。容器项数按各容器检查，不因 AT/ED 分支重置总节点预算。内嵌 CBOR 的 `max_values` 错误所报 `limit` 是扣除前面对象后的剩余预算。

所有源范围均为 `[start,end)`。每个公开入口的错误 offset 相对于它接收的完整输入视图；AttestationObject 将内嵌错误及重复键等错误附带的位置一起换算到外层。结果中的 `auth_data` 字段范围保持相对于 `auth_data.raw`，其外层基址由 `auth_data_payload_range.start` 提供；`auth_data_range` 则包括 byte string 编码头。调用者可将基址加到公钥或扩展范围，在外层字节中定位它们。

## 后续核心模块职责

| 模块 | 计划契约 |
| --- | --- |
| COSE | 明确支持的 key type、algorithm、curve，检查组合与字段 |
| Cryptography | 选择经核验的 MoonBit 密码学组件，验证原始签名输入 |
| Security rules | 每条规则记录标准条款、上下文、证据和测试 |
| Analysis/report | 组合解析、验证和 unsupported 状态，产生可追溯结果 |

对 `clientDataJSON` 的 SHA-256 必须使用原始输入字节。结构解析、签名验证、信任评估和认证结论需要分别记录状态。CTAP2 canonical CBOR 策略应在对应协议上下文应用。[WebAuthn Level 3 §6–7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)

## 依赖选择

使用随工具链提供的 `moonbitlang/core`，许可为 Apache-2.0。P2 与 CI 固定版本为 `0.10.20+65efd5b93`，P3 本地检查使用 `0.10.21+f125caab5`，实际验收记录见 `DEVELOPMENT.md`。`moon.mod` 的外部依赖保持为空。Base64URL 测试单独导入本项目 ByteReader 包。CBOR 生产包复用 ByteReader，并导入标准库 `encoding/utf8` 和 `sorted_map`；CBOR 测试单独导入 Base64URL。`webauthn` 复用 ByteReader、CBOR 以及标准库 `encoding/utf8`、`sorted_map` 和仅用于字符串 token 的 `json`，避免依赖不提供本项目重复键与预算契约的完整 JSON 对象解码。密码学、JavaScript FFI 和前端依赖尚未引入。
