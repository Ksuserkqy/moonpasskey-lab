# 标准映射与覆盖计划

## 参考版本

Phase 1 于 2026-11-11 核验 RFC 4648 及 WebAuthn Level 3 的 2026-08-25 Recommendation。映射记录到基础操作与后续任务，完整 WebAuthn Level 3 符合性尚待建立证据。[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html) [WebAuthn Level 3 固定版本](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)

Phase 2 同日固定 RFC 8949（2020-12，STD 94）和 CTAP 2.3 Proposed Standard（2026-02-26）的 §8。WebAuthn 固定版本的 canonical 定义链接指向 CTAP 2.1 errata（2022-06-21），其相关编码规则与 CTAP 2.3 相同。CTAP 2.3.1 Working Draft（2026-05-29）§8 亦保留相同规则，本项目采用 2.3 Proposed Standard 记录实现依据。[RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) [CTAP 2.3 PS](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding) [WebAuthn 引用的 CTAP 2.1 errata](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding) [CTAP 2.3.1 WD](https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#message-encoding)

## 已实现覆盖

| 条款或契约 | 当前行为 | 代表测试 |
| --- | --- | --- |
| RFC 4648 §3.1、§3.3 | 编码无换行，解码拒绝空白及其他非法字符 | reject whitespace and controls、reject all other ASCII characters |
| RFC 4648 §3.2 | decode 接受无 padding 或完整规范 padding，encode 可显式添加 padding | RFC 4648 section 10 vectors、reject malformed padding |
| RFC 4648 §3.5 | 编码未使用位为零，解码拒绝非零未使用位 | all final sextet values obey unused-bit constraints |
| RFC 4648 §5 | URL-safe `-`、`_`，拒绝标准字母表 `+`、`/` | URL-safe alphabet、reject standard alphabet |
| RFC 4648 §10 | 空输入及 f/fo/foo/foob/fooba/foobar 固定向量 | empty input、RFC 4648 section 10 vectors |
| 项目资源策略 | 二进制上限 1 MiB，文本上限 1,398,104 code units | accept exact maximum binary size、两个超限类别 |
| 项目读取契约 | 大端无符号整数、精确范围、失败不推进、负数拒绝 | bytereader 包 20 个测试 |
| 模块集成契约 | 解码结果通过 ByteReader 公共入口连续读取 | decoded binary can be consumed through ByteReader public API |

默认编码省略 padding 是本项目为 WebAuthn 数据选定的策略。通用基础 decode 接受规范末尾 padding。通用 decode 未执行 WebAuthn 无 padding 约束；P3 ClientDataJSON 仅保留 challenge 文本，其 Base64URL 语义及匹配仍未验证。[WebAuthn Level 3 §3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-dependencies)

## Phase 2 CBOR 覆盖

`Generic` 当前覆盖 RFC 8949 的 definite-length major types 0–5 和已列 simple 值子集，整体状态为 `PARTIAL`。两个 profile 的重复键拒绝属于项目选择的 validity-checking 策略。`Ctap2Canonical` 整体状态为 `PARTIAL`，各项状态按当前实现范围记录。

| 范围 | 状态 | 覆盖边界 |
| --- | --- | --- |
| RFC 8949 Generic 解码整体 | `PARTIAL` | 支持下表所列 definite-length 类型和 simple 值 |
| Definite major types 0–5、false/true/null/undefined、simple 0–19 和 32–255 | `IMPLEMENTED` | 保留 UInt64 整数参数 |
| 语义重复键拒绝策略 | `IMPLEMENTED` | 按 RFC §5.6.1 的类型和值等价判断，两个 profile 均拒绝 |
| Ctap2Canonical 整体 | `PARTIAL` | 对当前支持类型执行编码检查 |
| CTAP 最短整数与长度头 | `IMPLEMENTED` | major types 0–5 |
| CTAP map 键排序 | `IMPLEMENTED` | major type、完整编码长度、原始编码字节 |
| CTAP 最多四层 array/map 嵌套 | `IMPLEMENTED` | 含复合 key，独立于可配置资源预算 |
| CTAP tag 和 indefinite-length 禁止检测 | `IMPLEMENTED` | 分别报告 `ForbiddenTag`、`IndefiniteLengthNotAllowed` |
| IEEE 754 binary16/32/64 结构化结果与值模型 | `NOT_IMPLEMENTED` | 完整 payload 报告 `UnsupportedFloat`，截断报告读取错误 |
| Generic tag 和 indefinite-length 结构解析 | `NOT_IMPLEMENTED` | 识别相应头后报告 unsupported |
| CTAP 命令语义、COSE 密钥约束和设备互操作 | `NOT_IMPLEMENTED` | 由后续协议模块和测试建立证据 |

| 条款或契约 | 当前行为 | 测试范围 |
| --- | --- | --- |
| RFC 8949 §3、§3.1 | 支持 definite major types 0–5，unsigned 和 negative argument 均保留 UInt64 | 各类型、整数宽度边界、完整正负整数范围、截断 |
| RFC 8949 §3.3 | 支持 false/true/null/undefined，以及 simple 0–19、32–255 | simple 范围、非法 `f8` 后续值、float unsupported |
| RFC 8949 §3、§3.2 | 拒绝 reserved additional information、非法 indefinite head 和独立 break，合法 indefinite 结构明确 unsupported | major type 与 additional information 组合、break、indefinite |
| RFC 8949 §3.1、§5.3.1、RFC 3629 §3–4 | Text string 严格 UTF-8，保留 BOM | 合法多字节、overlong、surrogate、越界 code point、坏 continuation、截断 |
| RFC 8949 §4.1、§5.5 | Generic 接受可支持宽度的非最短整数与长度头 | 非最短正负整数、字符串与容器头、任意 map 键序 |
| RFC 8949 §5.6、§5.6.1、项目策略 | 两个 profile 均拒绝语义重复键，所有已支持类型可作 key | 编码宽度变化、跨类型差异、array key、无序 map key、嵌套重复 |
| CTAP 2.3 §8 | Ctap2Canonical 检查最短整数和长度头、map 键编码顺序、最多四层 array/map | 非最短头、同/异 major 键排序、四层边界 |
| CTAP 2.3 §8、当前实现范围 | CTAP 禁止 tag 和 indefinite-length，float 明确 unsupported | 两种 profile 的 tag/indefinite 错误及 float 位宽 |
| 项目源范围与消费契约 | 节点保存完整 `[start,end)`，parse_one 返回相对 offset 的 consumed，parse_all 拒绝尾随字节 | 非零 offset、连续两项、嵌套范围、完整消费 |
| 项目资源策略 | 每次调用约束输入、字符串、array、map、深度、节点数，检查参数与硬深度上限 | 各项边界、超限、非法参数及恶意长度声明 |
| 模块集成契约 | Base64URL 解码后经 CBOR 公共入口解析，CBOR 复用 ByteReader | 跨包输入、连续解析与源范围 |

RFC 8949 §4.1 的 preferred serialization 与 §4.2.1 的 core deterministic encoding 分别记录编码偏好和附加约束。Generic 保留可接受的非最短表示。CTAP 的键顺序按 major type、完整编码长度、字节序比较，对规范实际使用的 scalar keys 与 canonical bytes lexical order 等价。RFC §4.2.3 的 length-first order 是另一种可选排序。[RFC 8949 §4](https://www.rfc-editor.org/rfc/rfc8949.html#section-4) [CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)

Array/Map key 继续按 major type、完整编码长度、原始字节的三步契约比较。CTAP §8 的 Note 记录当前协议未使用 major types 4–6 作 map key，并提示未来使用复杂类型 key 时需重新审视规则。当前解析接受结果覆盖编码检查，CTAP 命令语义和设备互操作证据仍待建立。Tags 在 CTAP profile 中遵循 §8 的独立禁令。[CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)

CTAP §8 保留浮点的编码位宽。当前两个 profile 对完整 binary16、binary32、binary64 payload 返回 `UnsupportedFloat(width=2/4/8)`，浮点值模型和结构化结果均为 `NOT_IMPLEMENTED`。`NonMinimalEncoding` 用于整数与长度头的非最短表示，浮点位宽的保留已有专项回归测试。[CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)

UTF-8 校验遵循 RFC 3629 的字节序列范围，拒绝 overlong、surrogate、超过 U+10FFFF、非法 continuation 和截断，保留合法字符串的 BOM。[RFC 3629 §3–4](https://www.rfc-editor.org/rfc/rfc3629.html#section-3)

重复键按解码后的类型和值判断。内部 SemanticKey 将 map entries 按内部 total order 标准化，供无序语义比较和 AVL SortedMap 去重。原始 CBOR entries 和源范围保留，编码顺序检查独立执行。两种 profile 拒绝重复键是本项目选择的 validity-checking 策略。[RFC 8949 §5.6.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-5.6.1)

默认项目资源预算为输入与单字符串各 1 MiB、array 4096 项、map 1024 对、深度 32、节点 16384，可配置深度硬上限 64。CTAP profile 的四层限制只计 array/map 嵌套。CTAP 默认 1024 字节消息能力及 maxMsgSize 协商归后续传输上下文，当前 CBOR 入口使用项目输入预算。

深度从根 Array/Map 的第 1 层计起，根标量为 0 层，沿路径包含 Map key/value 内的容器，兄弟容器独立计数。新增混合容器和复合 key 回归在 `max_depth=4/5/32/64` 下核查四层与五层边界，并断言准确的错误 offset 和 context。项目预算与 CTAP 四层检查同时生效。

WebAuthn §2.4 要求各 conformance class 的 CBOR encoder 使用 CTAP2 canonical，并建议 decoder 拒绝非 canonical 和重复键。§6.5.4 定义 attestationObject 的 authData、fmt、attStmt 容器，§6.5.1 要求 credentialPublicKey 使用 canonical COSE_Key 并包含 alg。§8.7 的 none 格式要求空 attStmt map。P3 已调用此 profile 实现字段结构解析；COSE 语义和密码学验证仍未实现。[WebAuthn Level 3 §2.4、§6.5、§8.7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)

COSE_Key 的 map 与必需 kty 由 RFC 9052 §7 定义。其 §9 对 Sig_structure、Enc_structure、MAC_structure 规定 definite/minimal 编码，同时禁止生成和处理含重复 label 的 map。credentialPublicKey 的编码与可选参数限制继续按 WebAuthn §6.5.1 记录，COSE 密钥 Map 已能取得，必需参数与算法语义验证尚未实现。[RFC 9052 §7](https://www.rfc-editor.org/rfc/rfc9052.html#section-7) [RFC 9052 §9](https://www.rfc-editor.org/rfc/rfc9052.html#section-9)

## Phase 3 协议解析覆盖

P3 新增 `webauthn` 包。以下 `IMPLEMENTED` 指相应结构检查已实现，不代表执行了 §7 的完整认证流程。WebAuthn 入口选择严格 canonical 解码，通用 `cbor.Generic` API 的行为保持原样。

| 固定规范条款 | 状态与行为 | 代表测试范围 |
| --- | --- | --- |
| WebAuthn §5.8.1 | `IMPLEMENTED`：必需 type/challenge/origin 字符串，crossOrigin/topOrigin 可选字段类型；保留缺省与显式 false 的区别 | create/get、缺字段、错误类型、空字符串、可选字段 |
| WebAuthn §5.8.1、§7.1/§7.2 JSON 解码步骤 | `IMPLEMENTED`：严格 UTF-8，解析时跳过开头 BOM，原始输入及字节范围完整保留 | BOM、Unicode、空白/顺序/转义、子视图、原始字节 |
| RFC 8259 §2–7、§8.1–8.2、§9；项目拒绝歧义策略 | `IMPLEMENTED`：JSON 语法、解码后的成员名去重、资源预算；拒绝未配对 surrogate 转义 | 截断、非法数值与转义、嵌套重复、所有预算及 64/65 层 |
| WebAuthn §6.1、§6.1.3、§7.1/§7.2 备份位检查 | `IMPLEMENTED`：固定 37 字节、大端 UInt32、AT/ED 条件字段、BS 蕴含 BE | 0/UInt32 最大值、256 种 flags、全部前缀截断、AT+ED |
| WebAuthn §6.5.1 | `IMPLEMENTED`：AAGUID、16-bit credentialIdLength ≤1023、精确 credentialId 与公钥 CBOR Map 范围；`PARTIAL`：COSE_Key 只做 Map 与编码检查 | 长度 0/1023/1024/65535、公钥截断、非 Map、源范围 |
| WebAuthn §6.1、§9.1 | `IMPLEMENTED`：ED 为 Map，键符合扩展标识符规则，保留未知扩展值；`NOT_IMPLEMENTED`：逐扩展语义 | ED-only、未知值、非法标识符、CBOR 截断 |
| WebAuthn §2.4、§3、§6.5.1；CTAP 2.3 PS §8 | `IMPLEMENTED`：在现有 CBOR 支持类型上执行 canonical 与重复键检查；完整 CBOR 类型覆盖为 `PARTIAL` | outer/key/ED 非最短头、错误键序、重复键、CTAP 四层上限 |
| WebAuthn §6.1、§6.5.4、§8.1 | `IMPLEMENTED`：外层仅三个必需字段和类型、Map/Array attStmt、fmt 标识符、authData 内 AT、完整消费 | 缺字段、额外字段拒绝、Map/Array、重复、错误类型、尾随、嵌套位置换算 |
| WebAuthn §8.7 | `IMPLEMENTED`：none attStmt 必须为空 Map，返回 NoneStructureChecked；未建立 attestation 信任结论 | 空 Map 成功、非空 Map 拒绝 |
| WebAuthn §8.2–8.6、§8.8–8.9、RFC 9052 §7、RFC 9053 | `PARTIAL`：其他 fmt 保留 Map/Array 并返回 FormatNotValidated；`NOT_IMPLEMENTED`：compound 等逐格式语义、完整 COSE/密码学验证 | 未知 fmt 和 Array 原值/范围保留、none 仍拒绝 Array |
| 项目预算和来源位置契约 | `IMPLEMENTED`：外层 Map、公钥和 ED 共享节点预算；错误含字段路径和相对公共入口的 byte offset | 聚合节点边界、主/次 offset 换算、子视图 |

固定依据：[WebAuthn Level 3，2026-08-25 REC](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/) · [CTAP 2.3，2026-02-26 PS §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding) · [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html)。未引入 CTAP 测试数据或外部 JSON 依赖。

### 结构层策略与尚未执行的语义

- `crossOrigin` 和 `topOrigin` 均保留可选性；本层只校验类型，未验证 topOrigin 与 crossOrigin 的关系或任何 origin 信任。type 值、challenge 编码/匹配亦未验证。
- RFU 位原样保留。这是本解析器的容忍策略，§6.1 对认证器的生成要求仍是置零；当前不声称检查了该生成要求。UP/UV 仅表示输入声明。
- credential ID 长度零在结构层可表示；接受该编码不表示满足 §4 的 Credential ID 生成形式和安全要求。公钥可以是空 Map，尚不检查 kty/alg 等 COSE 必需参数。
- §6.5.4 的 attStmtTemplate 限定外层三个字段，attStmt 允许 Map 或 Array。审查修正已实现相应容器结构并拒绝未知外层字段；ClientDataJSON 未知字段和 statement Map 内未知字段策略保持原样。compound 的逐元素规则与组合验证仍为 `NOT_IMPLEMENTED`。
- fmt 与扩展键按 §§8.1/9.1 检查最长 32 个 ASCII 字节，字符为 VCHAR 且排除双引号和反斜线；规范未给出非空下限，本层不增加该限制。
- 所有错误 offset 相对于调用入口的 BytesView；AttestationObject 内错误及重复/排序错误中的附带位置均换算到外层。成功结果中的 AuthenticatorData/CBOR 子范围仍相对于 authData.raw，通过 auth_data_payload_range 关联到外层。

## 尚未实现的验证

challenge、origin、RP ID 匹配、计数器判断、COSE 算法/曲线/参数、公钥有效性、SHA-256、签名和证书链、可信根及最终认证判断均为 `NOT_IMPLEMENTED`。官方认证套件和真实设备互操作证据尚未建立。

## 测试数据来源与许可

RFC §10 的 Base64 输入和输出属于标准公开向量，使用其共享 ASCII 字母表验证 Base64URL。来源为 Simon Josefsson 的 RFC 4648，相关部分的复制条件见 §15。代码中的向量是测试数据摘录，未引入外部实现源码。[RFC 4648 §10](https://www.rfc-editor.org/rfc/rfc4648.html#section-10) [复制条件 §15](https://www.rfc-editor.org/rfc/rfc4648.html#section-15)

URL-safe 边界、错误变异、超长输入、ByteReader 样本及模块集成输入均为本项目合成。48 字节固定期望由 Node.js `Buffer.toString("base64url")` 与 Python `base64.urlsafe_b64encode` 独立确认。其余回环测试用于检查一致性。上述测试的来源类别为项目合成，官方 WebAuthn 规范示例另见下段。真实设备数据仍待引入。

Phase 2 原有 `cbor/cbor_test.mbt` 按上述条款构造合成字节样本，覆盖编码边界、负例、资源约束和模块集成。规范链接用于记录技术依据，这些测试数据的来源类别记录为项目合成。

新增 `cbor/conformance_test.mbt` 收录 W3C WebAuthn Level 3 2026-08-25 Recommendation §6.5.1.1 的 ES256 COSE_Key 官方规范示例，原始编码共 77 字节。测试逐项核验五个 key/value 和完整源范围。x 的 byte string 编码范围为 `[8,42)`、payload 为 `[10,42)`，y 的编码范围为 `[43,77)`、payload 为 `[45,77)`，均相对于完整示例输入。示例版权属于 2026 World Wide Web Consortium，W3C Software and Document License 2023 的许可声明保存在 `cbor/W3C-NOTICE.md`。[WebAuthn Level 3 §6.5.1.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-credentialpublickey-examples)

同文件的两种整对重排样本由官方示例派生，来源类别为项目合成变异。它们保留坐标与 label 字节，用于 Generic 接受任意 map 顺序及 CTAP 拒绝错误排序的回归。其余新增边界样本亦为项目合成。本轮新增 12 个测试，保留原有 95 个，全仓库共 107 个，其中 CBOR 为 63 个。官方 CTAP/WebAuthn 认证测试套件和真实设备互操作证据仍待引入。

P3 的 `webauthn/clientdata_test.mbt`、`authdata_test.mbt` 与 `attestation_test.mbt` 均为项目合成测试，包括手工编码、测试内构造器、截断和定向畸形变异。它们与上文 `cbor/conformance_test.mbt` 的 W3C 官方示例分开存放。没有把合成 credential key 或 none 对象标成官方向量，也未复制来源不明的数据。合成数据随本仓库采用 Apache-2.0；既有 W3C 示例继续保留原许可声明。P3 新增测试数与四目标实际验收结果见 [DEVELOPMENT.md](DEVELOPMENT.md)。

### P3 审查修正：§16 官方协议向量

`webauthn/w3c_vectors_test.mbt` 单独保存 W3C WebAuthn Level 3 2026-08-25 Recommendation 的官方测试向量：

- [§16.2 ES256 Credential with No Attestation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256)
- [§16.4 crossOrigin=true](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-crossOrigin)
- [§16.5 topOrigin](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-topOrigin)

只提取注册的 clientDataJSON/attestationObject 和认证的 clientDataJSON/authenticatorData 字节，保持规范 hex 所表示的原文，不从解析结果重新序列化。未引入私钥、签名、证书或生成算法。覆盖原始 JSON 字节、create/get 字段、crossOrigin/topOrigin、none 对象、嵌入和独立 authData、公钥 Map 以及来源范围；没有执行密码学验证。这些数据属于官方向量，区别于既有三个合成测试文件；版权与 W3C Software and Document License 2023 声明见 `webauthn/W3C-NOTICE.md`。具体计数和实际执行结果见 `DEVELOPMENT.md`。
