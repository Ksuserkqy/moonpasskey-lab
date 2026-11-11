# 当前限制

## 已实现范围

Phase 1 提供 Base64URL 编解码和 ByteReader；Phase 2 新增有界 CBOR 解码、源范围、语义重复键检测、可配置预算和 CTAP2 canonical profile；Phase 3 新增 ClientDataJSON、AuthenticatorData 与 map 形式 AttestationObject 的结构解析。解析、密码学验证、信任判断与认证结论须分别理解。

P2 历史验收基线为 107 个测试，其中 Base64URL 24 个、ByteReader 20 个、CBOR 63 个，四目标当时均为 107 通过、0 失败。P3 新增 99 个协议解析、资源边界和嵌套错误测试（34 个 ClientDataJSON、42 个 AuthenticatorData、23 个 AttestationObject），总数为 206。本轮本地 wasm、wasm-gc、js、native 各 206 通过、0 失败，四目标带 `--deny-warn` 的检查、测试、构建与入口运行均通过；格式和接口检查通过。远程 CI 状态见对应 PR，详细本地证据见 [开发记录](DEVELOPMENT.md)。

## Base64URL

- `encode` 默认省略 padding，`padding=true` 可输出完整 padding。
- `decode` 接受完整规范 padding 和无 padding。P3 的 ClientDataJSON 仅保留 challenge 字符串，尚未执行其 Base64URL 格式、无 padding 限制或 challenge 匹配。
- 编码二进制输入和解码输出上限均为 1,048,576 字节，文本输入上限为 1,398,104 UTF-16 code units。这是固定项目策略。
- `InvalidEncoding` 将非法长度、错误 padding、非零未使用位合并报告。`InvalidCharacter` 单独提供零基 UTF-16 位置。
- 解码优先检查原文大小，再检查字符、预期输出大小及标准库编码规则。存在多种错误时按此顺序返回。
- 标准库版本随工具链提供，需要在更换工具链后重新运行测试。

## ByteReader

- 游标只向前移动，位置相对于传入视图。读取失败时游标不变。
- `read_bytes` 返回零复制 BytesView，调用方可用 `to_owned()` 获取覆盖同一范围的 Bytes。完整底层视图会复用原值，其余视图会复制。
- `read_u16_be` 使用 UInt 返回，其取值上限为 65535。`read_u32_be` 支持完整 UInt32。
- 每个实例含可变游标，调用方需要为独立解析任务创建实例。
- ByteReader 读取已存在的缓冲区。文件大小、总请求预算和后续解析嵌套深度由相应入口负责。

## CBOR

| 范围 | 状态 | 当前边界 |
| --- | --- | --- |
| RFC 8949 Generic 解码整体 | `PARTIAL` | 当前支持 definite major types 0–5 和下列 simple 值子集 |
| Definite major types 0–5、已列 simple 值 | `IMPLEMENTED` | 完整整数参数、严格 UTF-8、边界与源范围检查 |
| 语义重复键拒绝 | `IMPLEMENTED` | 两个 profile 均采用项目 validity-checking 策略 |
| Ctap2Canonical 整体 | `PARTIAL` | 当前支持类型的编码检查 |
| CTAP 最短头、map 三步排序、四层 array/map 限制 | `IMPLEMENTED` | 排序使用 major type、完整编码长度、原始字节，深度包含复合 key |
| CTAP tag 和 indefinite-length 禁止检测 | `IMPLEMENTED` | 相应 profile 错误可区分 |
| IEEE 754 binary16/32/64 结构化结果与值模型 | `NOT_IMPLEMENTED` | 完整 payload 返回 `UnsupportedFloat`，截断返回读取错误 |
| Generic tag 和 indefinite-length 结构解析 | `NOT_IMPLEMENTED` | 识别相应头后报告 unsupported |
| CTAP 命令语义、COSE 密钥约束和互操作验证 | `NOT_IMPLEMENTED` | 待对应协议模块与测试 |

- 当前支持 definite-length 的 major types 0–5、false、true、null、undefined，以及 simple 值 0–19 和 32–255。整数支持完整 `-2^64..2^64-1`，负整数保存 unsigned argument `n`，其值为 `-1-n`。
- Tags、IEEE 754 floats 和 indefinite-length 数据分别报告 unsupported。CTAP profile 遇到 tags 或 indefinite-length 数据时报告其 profile 禁止错误。CTAP 规范保留浮点的编码位宽，浮点的 unsupported 属于当前实现范围。[CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)
- 识别到 tag 或 indefinite-length 头后立即返回错误，其后内容尚未验证。Float 先检查 payload 长度，再返回 unsupported。
- `Generic` 接受非最短整数和长度头、任意 map 键序。`Ctap2Canonical` 在支持范围上检查最短头、按 major type/编码长度/字节比较的键序和四层 array/map 嵌套。两个 profile 均按项目策略拒绝语义重复键。
- 所有已支持类型可作 map key。重复检测忽略编码宽度和源范围，保留类型差异。Array key 比较元素顺序，map key 比较键值对集合。原始 map entries 顺序保留。[RFC 8949 §5.6.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-5.6.1)
- Array/Map key 继续按 major type、完整编码长度、原始字节的三步契约处理。CTAP §8 的 Note 说明当前协议未使用 major types 4–6 作 map key，并提示未来使用复杂类型 key 时需重新审视规则。解析接受结果的证据范围为编码检查，命令语义和互操作验证仍待实现。Tags 在 CTAP profile 中遵循独立禁令。[CTAP 2.3 §8](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding)
- `Value` 派生的 `Eq` 包含源范围。调用方查看结构或值等价时须明确其比较契约，内部重复检测使用独立 `SemanticKey`。
- `parse_one` 允许尾随数据，返回相对指定 offset 的 consumed。`parse_all` 要求完整消费输入。节点范围和错误 offset 均相对于传入的整个 BytesView，嵌入更大缓冲区时由调用方记录该 view 的基准位置。
- Byte string 返回原输入视图。Text string 经过严格 UTF-8 校验并保留 BOM。数据保留 CBOR 类型，转换成 JSON 的展示与导出仍待对应层实现。
- 默认每次调用限输入 1 MiB、单字符串 1 MiB、array 4096 项、map 1024 对、array/map 深度 32、节点 16384。资源参数须非负，深度可配置到硬上限 64。CTAP 四层约束独立执行，CTAP 默认传输消息能力的 1024 字节限制留给传输上下文。
- 容器深度按根到节点的路径计数，根 Array/Map 为 1，根标量为 0。Map key/value 中的容器都计数，兄弟容器不累计。CTAP 四层检查独立于 `max_depth`，调高项目预算无法绕过，较小预算可以收紧。
- 当前 profile 检查覆盖 CBOR 编码及本项目支持范围。P3 增加 WebAuthn 容器字段解析；CTAP 命令语义、COSE 密钥约束和完整协议验证仍未实现。
- `conformance_test.mbt` 引入 W3C 固定版本的 77 字节 ES256 COSE_Key 官方规范示例及两种项目合成重排变异，覆盖编码结果和源范围。官方认证测试套件及真实设备互操作证据仍待引入，来源分类与许可见 `SPEC_MAPPING.md`、`cbor/W3C-NOTICE.md`。

## P3 协议解析边界

| 能力 | 状态 | 边界 |
| --- | --- | --- |
| ClientDataJSON 结构解析 | `IMPLEMENTED` | 必需及可选字段类型、UTF-8、完整 JSON 语法、重复成员、原始字节与顶层 token 范围 |
| AuthenticatorData 固定结构、AT 和 ED | `IMPLEMENTED` | 严格长度与消费检查、flags 展开、计数器完整 UInt32 范围、公钥与扩展 CBOR map |
| map 形式 AttestationObject 结构解析 | `IMPLEMENTED` | 必需字段、text 键、字段类型、内嵌 authData 与源范围 |
| AttestationObject 协议覆盖整体 | `PARTIAL` | 本轮仅支持 map statement；CBOR 支持范围仍受 P2 限制 |
| none statement 语法 | `IMPLEMENTED` | `attStmt` 必须为空 map；状态 `NoneStructureChecked` 仅表达结构检查 |
| 其他 map statement 格式 | `PARTIAL` | 保留 fmt 与原始结构，状态 `FormatNotValidated`；未实现具体格式验证 |
| array statement、compound attestation | `NOT_IMPLEMENTED` | WebAuthn §6.5.4 允许 array；本轮按请求的 map 范围拒绝该类型 |
| COSE Key 语义验证 | `NOT_IMPLEMENTED` | 公钥只检查 canonical CBOR map，未检查 kty/alg/curve、参数集合或数学有效性 |
| WebAuthn 安全验证流程 | `NOT_IMPLEMENTED` | 未建立 challenge、origin、RP ID、签名、证书、信任或认证结论 |

### ClientDataJSON

- `raw` 完整保留输入，包括 BOM、空白、字段顺序和转义；后续哈希须使用这些原始字节。解析时按 UTF-8 解码规则跳过一个初始 BOM，不修改 `raw`。
- `type`、`challenge`、`origin` 必须为字符串，空字符串和未知 operation type 在结构层可通过。`crossOrigin`、`topOrigin` 缺省保留为 `None`，显式值分别要求 Boolean 和 String，不接受 null。
- 不执行 challenge 的 Base64URL 解码或匹配、不判断 origin 信任、不检查 `crossOrigin` 与 `topOrigin` 的生成关系，因此此结果不表示满足整个 CollectedClientData 语义。
- 所有对象按解码后的成员名称拒绝重复，包括未知嵌套字段。未知顶层成员保留名称和原始 key/value 范围；未知值只验证语法和预算，不建立可直接访问的完整 JSON 值树。
- 严格拒绝非法 UTF-8、控制字符、错误转义和未配对 surrogate escape；最后一项是保证 Unicode scalar 字符串的项目策略。嵌套 context 对 JSON 使用成员序号与数组下标。

### AuthenticatorData 与 AttestationObject

- `BS=1 && BE=0` 被拒绝；UP、UV、BE、BS 只是输入声明。RFU 位原样保留而不拒绝是本项目兼容选择，不代表已检查 authenticator 的 RFU 必须为零的生成约束。没有添加 `UV ⇒ UP` 规则。
- credential ID 长度按 wire 结构允许 0 至 1023。零长度接受只覆盖 §6.5.1 长度字段的结构边界，不表示满足 §4 Credential ID 的生成与安全要求。公钥要求 map，未验证 COSE 算法、曲线、坐标、必需/可选参数或密钥可用性。
- 扩展必须是 map，标识符按 §9.1 的 text、最多 32 octets、限定可打印 ASCII 检查。未知标识符与任意当前 CBOR 支持类型的值被保留，扩展具体语义尚未验证。
- 外层 AttestationObject 要求 text 键和 map statement，保留未知顶层 text 字段。`fmt` 按 §8.1 的同类标识符规则检查，未检查是否已经登记；none 以外的格式不作格式级验证。内嵌 authData 要求 AT，以遵守 attestation 数据结构要求。
- 三个 WebAuthn CBOR 位置（外层、公钥、ED）均严格使用 `Ctap2Canonical`。这是对 WebAuthn §2.4 decoder SHOULD 的本项目选择；通用 CBOR `Generic` 仍接受其已支持的非 canonical 输入。当前 profile 对 float、tag 和 indefinite-length 的限制继续适用。[WebAuthn §2.4、§3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-all-conformance-classes)
- none 空 statement 的结构通过不代表签名验证、真实性或信任已通过；其他格式的 `FormatNotValidated` 必须保留到调用方结果中。

### 预算、offset 和资源

三个公开入口复用 `@cbor.Limits`，不增加另一套默认预算。输入与单字符串各限 1 MiB、array 4096 项、map 1024 对、节点 16384、深度 32，深度硬上限 64，所有参数须非负。JSON 字符串预算按不含引号的原始编码字节计算，escape 计入；JSON key 和 value 均计节点。未知 JSON 内容也受预算检查。CBOR 的独立四层 canonical 深度上限仍有效；每个内嵌 CBOR 树从自己的根计深度。

AT 公钥、ED 扩展共享同一节点预算，AttestationObject 外层树的节点也先计入，再将剩余预算传给内嵌 authData。内嵌 CBOR 的 `max_values` 错误所报 `limit` 对应该次子解析的剩余预算，可能小于入口配置的总预算。各字符串、数组、map 分别受对应限制；credential ID 的协议上限独立为 1023 字节。字节输入已由调用方提供，入口在解析与额外分配前检查其长度；文件读取、并发总内存和跨请求预算仍属于调用层责任。

所有源范围为半开区间。错误 offset 相对于公开入口收到的输入视图；AttestationObject 将内嵌 authData 错误及 CBOR 重复键等附带 offset 一起换算为外层位置。成功结果中的 `auth_data` 范围仍相对于其 `raw`，加上外层 `auth_data_payload_range.start` 才得到外层位置；`auth_data_range` 包含 CBOR byte string 编码头。不得混用两套成功结果坐标。

边界与畸形输入测试覆盖截断、恶意 UInt64 长度、尾随数据、预算与深度限制；当前没有建立形式化无 panic 证明、模糊测试或性能基准。不存在凭解析成功即可做出的安全承诺。

## 尚未实现的能力

| 功能 | 当前状态 |
| --- | --- |
| 完整 COSE Key 语义与公钥有效性验证 | `NOT_IMPLEMENTED` |
| CBOR tags、floats、indefinite-length 支持 | 当前明确 unsupported |
| challenge、origin、RP ID、ceremony 及计数器风险等安全规则 | `NOT_IMPLEMENTED`；本轮仅加入上述结构约束 |
| SHA-256、签名、证书、attestation 信任验证 | 待实现 |
| 文件分析 CLI、报告导出、退出码契约 | 当前入口仅输出 Hello |
| Vue Dashboard、JS/Wasm 前端集成 | 待实现 |
| 互操作矩阵、真实设备及浏览器测试 | 待实现 |
| 持续集成测试流水线 | 已配置四目标检查、测试、构建、格式和接口验证，实际远程状态见对应 PR |
| 模糊测试、性能基准 | 待建立 |

当前操作结果表达编码转换、读取和 CBOR 结构解析是否成功。认证结论需要后续完整验证流程。完整 WebAuthn Level 3 符合性尚未验证。[WebAuthn Level 3 §7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)
