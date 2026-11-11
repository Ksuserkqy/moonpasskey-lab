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

默认编码省略 padding 是本项目为 WebAuthn 数据选定的策略。通用基础 decode 接受规范末尾 padding。后续 WebAuthn 字段解析需按 §3 拒绝 `=`，当前 decode 单独调用尚未执行此协议上下文约束。[WebAuthn Level 3 §3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-dependencies)

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

WebAuthn §2.4 要求各 conformance class 的 CBOR encoder 使用 CTAP2 canonical，并建议 decoder 拒绝非 canonical 和重复键。§6.5.4 定义 attestationObject 的 authData、fmt、attStmt 容器，§6.5.1 要求 credentialPublicKey 使用 canonical COSE_Key 并包含 alg。§8.7 的 none 格式要求空 attStmt map。上述字段结构与语义属于后续协议模块，当前 CBOR profile 提供编码检查基础。[WebAuthn Level 3 §2.4、§6.5、§8.7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)

COSE_Key 的 map 与必需 kty 由 RFC 9052 §7 定义。其 §9 对 Sig_structure、Enc_structure、MAC_structure 规定 definite/minimal 编码，同时禁止生成和处理含重复 label 的 map。credentialPublicKey 的编码与可选参数限制继续按 WebAuthn §6.5.1 记录，COSE 密钥解析与算法验证尚待实现。[RFC 9052 §7](https://www.rfc-editor.org/rfc/rfc9052.html#section-7) [RFC 9052 §9](https://www.rfc-editor.org/rfc/rfc9052.html#section-9)

## 后续覆盖计划

| 标准范围 | 计划模块 | 所需证据 | 当前状态 |
| --- | --- | --- | --- |
| WebAuthn §5.8.1 | ClientDataJSON | type、challenge、origin、crossOrigin、topOrigin，原始字节保留测试 | 待实现 |
| WebAuthn §6.1 | AuthenticatorData | rpIdHash、flags、32 位大端 signCount、截断负例 | 已有通用读取基础，字段解析待实现 |
| WebAuthn §6.5.1 | AttestedCredentialData | AAGUID、16 位大端 credentialIdLength、credentialId 和 COSE 边界 | 已有通用读取基础，字段解析待实现 |
| WebAuthn §6.5、§8 | AttestationObject | CBOR 结构与 none 格式，其他格式明确 unsupported | 待实现 |
| WebAuthn §7.1、§7.2 | Security rules、Cryptography | 标准步骤逐项映射、正负例、原始签名输入、算法验证向量 | 待实现 |
| WebAuthn §9 | Extensions | 每个支持扩展的结构、语义和未知扩展处理 | 待规划支持清单 |

ByteReader 提供整数值读取。credentialIdLength 的协议范围、AT/ED 条件结构等校验归入对应解析模块。[WebAuthn Level 3 §6.1、§6.5.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-authenticator-data)

CBOR 阶段已固定 RFC 8949 和 CTAP2 版本，提供 Generic 与 Ctap2Canonical 两种 profile，并记录支持类型和明确拒绝的类型。后续协议模块需在调用时选定上下文，并补齐字段类型、必需成员、算法和安全规则的证据。

## 测试数据来源与许可

RFC §10 的 Base64 输入和输出属于标准公开向量，使用其共享 ASCII 字母表验证 Base64URL。来源为 Simon Josefsson 的 RFC 4648，相关部分的复制条件见 §15。代码中的向量是测试数据摘录，未引入外部实现源码。[RFC 4648 §10](https://www.rfc-editor.org/rfc/rfc4648.html#section-10) [复制条件 §15](https://www.rfc-editor.org/rfc/rfc4648.html#section-15)

URL-safe 边界、错误变异、超长输入、ByteReader 样本及模块集成输入均为本项目合成。48 字节固定期望由 Node.js `Buffer.toString("base64url")` 与 Python `base64.urlsafe_b64encode` 独立确认。其余回环测试用于检查一致性。上述测试的来源类别为项目合成，官方 WebAuthn 规范示例另见下段。真实设备数据仍待引入。

Phase 2 原有 `cbor/cbor_test.mbt` 按上述条款构造合成字节样本，覆盖编码边界、负例、资源约束和模块集成。规范链接用于记录技术依据，这些测试数据的来源类别记录为项目合成。

新增 `cbor/conformance_test.mbt` 收录 W3C WebAuthn Level 3 2026-08-25 Recommendation §6.5.1.1 的 ES256 COSE_Key 官方规范示例，原始编码共 77 字节。测试逐项核验五个 key/value 和完整源范围。x 的 byte string 编码范围为 `[8,42)`、payload 为 `[10,42)`，y 的编码范围为 `[43,77)`、payload 为 `[45,77)`，均相对于完整示例输入。示例版权属于 2026 World Wide Web Consortium，W3C Software and Document License 2023 的许可声明保存在 `cbor/W3C-NOTICE.md`。[WebAuthn Level 3 §6.5.1.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-credentialpublickey-examples)

同文件的两种整对重排样本由官方示例派生，来源类别为项目合成变异。它们保留坐标与 label 字节，用于 Generic 接受任意 map 顺序及 CTAP 拒绝错误排序的回归。其余新增边界样本亦为项目合成。本轮新增 12 个测试，保留原有 95 个，全仓库共 107 个，其中 CBOR 为 63 个。官方 CTAP/WebAuthn 认证测试套件和真实设备互操作证据仍待引入。
