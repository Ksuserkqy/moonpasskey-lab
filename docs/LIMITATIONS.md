# 当前限制

## 已实现范围

Phase 1 提供 Base64URL 编解码和 ByteReader，Phase 2 提供有界 CBOR，Phase 3 提供 WebAuthn 结构解析，Phase 4 提供显式 ES256 参数验证。Phase 5 增加 P-256 点导入、SHA-256、raw ES256 验签与 DER assertion 签名入口。Phase 6 增加 ES256 Assertion 的 RP 策略、身份绑定、计数器风险与状态更新建议。各入口分别记录已检查的属性。

P2 历史验收基线为 107 个测试，其中 Base64URL 24 个、ByteReader 20 个、CBOR 63 个，四目标当时均为 107 通过、0 失败。P3 首次验收新增 99 项，总计 206 项且四目标通过。审查修正保留既有覆盖（重写外层未知字段策略测试），新增 Map/Array 与 W3C §16 官方向量回归；当前测试数量及四目标结果见开发记录。远程 CI 状态见对应 PR，详细本地证据见 [开发记录](DEVELOPMENT.md)。

## Base64URL

- `encode` 默认省略 padding，`padding=true` 可输出完整 padding。
- `decode` 接受完整规范 padding 和无 padding。P3 的 ClientDataJSON 仅保留 challenge 字符串，P6 统一验证入口另外执行严格无 padding 格式、规范表示与 challenge 匹配。
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
| CTAP 命令语义和设备互操作验证 | `NOT_IMPLEMENTED` | ES256 参数检查由 P4 单独入口提供 |

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
- 当前 profile 检查覆盖 CBOR 编码及本项目支持范围。P3 增加 WebAuthn 容器字段解析；ES256 参数约束由 P4 显式入口提供；CTAP 命令语义、其他算法和完整协议验证仍未实现。
- `conformance_test.mbt` 引入 W3C 固定版本的 77 字节 ES256 COSE_Key 官方规范示例及两种项目合成重排变异，覆盖编码结果和源范围。官方认证测试套件及真实设备互操作证据仍待引入，来源分类与许可见 `SPEC_MAPPING.md`、`cbor/W3C-NOTICE.md`。

## P3 协议解析边界

| 能力 | 状态 | 边界 |
| --- | --- | --- |
| ClientDataJSON 结构解析 | `IMPLEMENTED` | 必需及可选字段类型、UTF-8、完整 JSON 语法、重复成员、原始字节与顶层 token 范围 |
| AuthenticatorData 固定结构、AT 和 ED | `IMPLEMENTED` | 严格长度与消费检查、flags 展开、计数器完整 UInt32 范围、公钥与扩展 CBOR map |
| AttestationObject 结构解析 | `IMPLEMENTED` | 外层限定三个必需字段、text 键、Map/Array statement、内嵌 authData 与源范围 |
| AttestationObject 协议覆盖整体 | `PARTIAL` | Map/Array 通用结构已支持；逐格式语义尚未验证，CBOR 类型覆盖仍受 P2 限制 |
| none statement 语法 | `IMPLEMENTED` | `attStmt` 必须为空 map；状态 `NoneStructureChecked` 仅表达结构检查 |
| 其他 Map/Array statement 格式 | `PARTIAL` | 保留 fmt 与原始结构，状态 `FormatNotValidated`；未实现具体格式验证 |
| compound 等数组型格式的语义验证 | `NOT_IMPLEMENTED` | 允许 Array 容器并保留 CBOR；未验证其逐元素格式规则、组合策略或密码学内容 |
| COSE Key 语义验证整体 | `PARTIAL` | P4 显式支持 ES256 参数与域范围，P5 通过另一入口检查 P-256 点，其他算法待实现 |
| ES256 Assertion RP 策略 | `IMPLEMENTED` | P6 检查 challenge、精确 origin、RP ID hash、身份、flags、签名与 counter，并返回状态更新建议 |

### ClientDataJSON

- `raw` 完整保留输入，包括 BOM、空白、字段顺序和转义；后续哈希须使用这些原始字节。解析时按 UTF-8 解码规则跳过一个初始 BOM，不修改 `raw`。
- `type`、`challenge`、`origin` 必须为字符串，空字符串和未知 operation type 在结构层可通过。`crossOrigin`、`topOrigin` 缺省保留为 `None`，显式值分别要求 Boolean 和 String，不接受 null。
- `parse_client_data` 保留结构层契约。P6 的独立统一入口检查 challenge、origin 与 crossOrigin/topOrigin 策略，调用方需要显式选择所需层级。
- 所有对象按解码后的成员名称拒绝重复，包括未知嵌套字段。未知顶层成员保留名称和原始 key/value 范围；未知值只验证语法和预算，不建立可直接访问的完整 JSON 值树。
- 严格拒绝非法 UTF-8、控制字符、错误转义和未配对 surrogate escape；最后一项是保证 Unicode scalar 字符串的项目策略。嵌套 context 对 JSON 使用成员序号与数组下标。

### AuthenticatorData 与 AttestationObject

- `BS=1 && BE=0` 被拒绝；UP、UV、BE、BS 只是输入声明。RFU 位原样保留而不拒绝是本项目兼容选择，不代表已检查 authenticator 的 RFU 必须为零的生成约束。没有添加 `UV ⇒ UP` 规则。
- credential ID 长度按 wire 结构允许 0 至 1023。零长度接受只覆盖 §6.5.1 长度字段的结构边界，不表示满足 §4 Credential ID 的生成与安全要求。P3 公钥字段要求 Map，后续显式调用 P4 参数检查与 P5 点导入才能取得 `ValidatedEs256PublicKey`。
- 扩展必须是 map，标识符按 §9.1 的 text、最多 32 octets、限定可打印 ASCII 检查。未知标识符与任意当前 CBOR 支持类型的值被保留，扩展具体语义尚未验证。
- 外层 AttestationObject 只允许且必须包含 fmt/authData/attStmt，非 text 键和未知键均拒绝；attStmt 允许 Map 或 Array，Map 内未知字段保留。`fmt` 按 §8.1 的同类标识符规则检查，未检查是否已经登记；none 以外的格式不作格式级验证。内嵌 authData 要求 AT，以遵守 attestation 数据结构要求。
- 三个 WebAuthn CBOR 位置（外层、公钥、ED）均严格使用 `Ctap2Canonical`。这是对 WebAuthn §2.4 decoder SHOULD 的本项目选择；通用 CBOR `Generic` 仍接受其已支持的非 canonical 输入。当前 profile 对 float、tag 和 indefinite-length 的限制继续适用。[WebAuthn §2.4、§3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-all-conformance-classes)
- none 空 statement 的结构通过不代表签名验证、真实性或信任已通过；其他格式的 `FormatNotValidated` 必须保留到调用方结果中。

### 预算、offset 和资源

三个公开入口复用 `@cbor.Limits`，不增加另一套默认预算。输入与单字符串各限 1 MiB、array 4096 项、map 1024 对、节点 16384、深度 32，深度硬上限 64，所有参数须非负。JSON 字符串预算按不含引号的原始编码字节计算，escape 计入；JSON key 和 value 均计节点。未知 JSON 内容也受预算检查。CBOR 的独立四层 canonical 深度上限仍有效；每个内嵌 CBOR 树从自己的根计深度。

AT 公钥、ED 扩展共享同一节点预算，AttestationObject 外层树的节点也先计入，再将剩余预算传给内嵌 authData。内嵌 CBOR 的 `max_values` 错误所报 `limit` 对应该次子解析的剩余预算，可能小于入口配置的总预算。各字符串、数组、map 分别受对应限制；credential ID 的协议上限独立为 1023 字节。字节输入已由调用方提供，入口在解析与额外分配前检查其长度；文件读取、并发总内存和跨请求预算仍属于调用层责任。

所有源范围为半开区间。错误 offset 相对于公开入口收到的输入视图；AttestationObject 将内嵌 authData 错误及 CBOR 重复键等附带 offset 一起换算为外层位置。成功结果中的 `auth_data` 范围仍相对于其 `raw`，加上外层 `auth_data_payload_range.start` 才得到外层位置；`auth_data_range` 包含 CBOR byte string 编码头。不得混用两套成功结果坐标。

边界与畸形输入测试覆盖截断、恶意 UInt64 长度、尾随数据、预算与深度限制；当前没有建立形式化无 panic 证明、模糊测试或性能基准。不存在凭解析成功即可做出的安全承诺。

## P4 ES256 参数检查边界

- `IMPLEMENTED`：独立 canonical 字节入口与 AT 显式方法、kty=2、alg=-7、crv=1、x/y Byte String 各 32 字节、保留前导零、每个坐标 < P-256 素数。
- `IMPLEMENTED`：拒绝缺字段、boolean y 压缩表示、d=-4 私钥、kid/key_ops/Base IV；未知 integer/text label 明确报告 UnsupportedCoseParameter，非 COSE label 类型报告 WrongType。通用 RFC 9052 允许更广泛的参数，未知拒绝是本入口的严格支持策略。
- P4 参数入口可接受满足类型、长度和域范围的 off-curve 坐标，包括 x=y=0，结果中的 `point_validation` 始终为 `NotPerformed`。P5 的点导入入口另外执行曲线方程检查，只有成功后才能取得 `ValidatedEs256PublicKey`。
- `NOT_IMPLEMENTED`：ES384、ES512、RS256、PS256、EdDSA 等算法的语义验证；有效整数 alg 非 -7 返回 UnsupportedAlgorithm，绝不视为 ES256。原有 P3 结构解析不因此拒绝它们。
- P5 引入固定 MoonCrypt 0.4.16 后端处理 P-256 曲线点和 ES256 验签，P4 参数 API 继续保存原始检查状态与范围。
- 函数与类型名中的 Parameters、公开 NotPerformed 状态和原始范围必须保留到调用层，不能将参数成功改写为密码学验证成功。

## P5 密码学范围与后端条件

| 能力 | 状态 | 当前范围 |
| --- | --- | --- |
| P-256 公钥点导入 | `IMPLEMENTED` | 接收 P4 已检查的 ES256 参数，由后端检查曲线方程后构造封装类型 |
| SHA-256 | `IMPLEMENTED` | 对原始 BytesView 计算 32 字节结果，支持空数据和子视图 |
| ES256 raw 签名验证 | `IMPLEMENTED` | 恰好 64 字节 `R || S`，`1 <= R,S < n`，message-based SHA-256 |
| assertion 签名消息构造 | `IMPLEMENTED` | 原始 authData 拼接 `SHA256(原始 clientDataJSON)` |
| WebAuthn ES256 assertion 验签 | `IMPLEMENTED` | 严格 DER 签名解码、原始签名消息构造与 P-256/SHA-256 验签 |
| 服务端认证完整交付 | `PARTIAL` | P6 已验证调用方提供的配置和记录，挑战存储、账户查找、传输封装、业务授权与持久化提交由调用方完成 |
| Attestation 证书链与信任验证 | `NOT_IMPLEMENTED` | 逐格式签名、X.509 链、可信根和 attestation 信任策略待实现 |

### 公钥与签名契约

`ValidatedEs256PublicKey` 的后端字段私有，导入需要 P4 不可变参数记录提供的 `kty=2`、`alg=-7`、`crv=1`、32 字节坐标及严格 `< p` 保证。MoonCrypt 的 affine 导入执行曲线方程检查。P-256 的 cofactor 为一，导入的 affine 点具有对应群成员属性。前导零与原始源范围完整保留，`parameters()` 中的 P4 `NotPerformed` 继续描述其参数检查阶段。

MoonCrypt 0.4.16 的公开问题 #1 包含 ECDSA 非规范坐标接受问题。本项目持续要求 P4 的 `< p` 检查先于后端导入，并通过该问题的 `x=p` 复现坐标建立回归测试。升级或替换后端时须重新核对这一入口约束。[MoonCrypt issue #1](https://github.com/moonbitstack/mooncrypt/issues/1)

Raw 验签要求固定 64 字节，在后端计算前拒绝长度错误、R/S 为零或不小于群阶的情况。合法签名编码的验证结果为 `Ok(true/false)`，格式与执行错误为 `Err(CryptoError)`。该 API 使用原始 message，由后端计算一次 SHA-256，接受合法的 low-S 和 high-S。

`verify_webauthn_es256_assertion_signature` 按 WebAuthn §6.5.5 接收 8 至 72 字节 ASN.1 DER 签名。它复用 MoonCrypt ASN.1 解析器，要求完整 SEQUENCE 恰好包含两个最短非负 INTEGER，拒绝非最短或 indefinite 长度、负数、冗余零、截断和尾随数据。必要符号零被移除，32 字节以内的短整数补齐后进入已有 R/S 范围检查。DER 错误返回 `InvalidSignatureEncoding`，零、幅值超过 32 字节或不小于群阶的标量返回带 R/S 名称的 `InvalidSignatureScalar`。通用 COSE raw64 入口继续由 `verify_es256_signature` 提供。[WebAuthn §6.5.5](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-signature-attestation-types)

SHA-256 与签名消息构造消费调用方提供的原始字节 view。空 authenticatorData 和空 clientDataJSON 可用于这些字节级接口，JSON 语义与 RP 数据有效性由对应层负责。签名消息构造检查 `authenticatorData.length + 32` 的 Int32 溢出边界。读取文件、跨请求总内存与 CPU 预算由调用层管理。

### 依赖、审查与跨平台证据

直接依赖固定为 `moonbitstack/mooncrypt@0.4.16`，Git tag 指向 `ad5f2e797c60a87e1f6541d1d6ba0dd94df70d9a`。本轮解析得到 moonbase 0.4.5、moondate 0.1.7、moonseed 0.1.3、moonbitlang/x 0.5.7，许可证均为 Apache-2.0。选定生产调用路径使用纯 MoonBit SHA-256、P-256 与 ECDSA，四个目标共享相同实现。

源代码、公开问题、版本化归档与独立向量已经核对。未找到 MoonCrypt 0.4.16 的独立第三方安全审计报告，本轮源码审查和回归测试为项目自身证据。公开 GitHub advisory 查询结果只描述查询范围，无法保证不存在其他安全问题。后端带有更多算法及私钥功能，本项目公开适配接口仅覆盖本阶段的 SHA-256、P-256 公钥和 ES256 验签。

隔离探针实际使用固定 `0.10.20+65efd5b93` 工具链，在 wasm、wasm-gc、js、native 各完成 275 项独立测试，并通过带 `--deny-warn` 的检查、生产构建和运行。最终仓库完整回归与远程 CI 状态见开发记录和对应 PR。较新 `0.10.21` 对依赖源码报告弃用警告，后续工具链变更需重新核验兼容性。[开发记录](DEVELOPMENT.md)

## P6 Assertion 验证范围

| 能力 | 状态 | 边界 |
| --- | --- | --- |
| ES256 Assertion 统一验证 | `IMPLEMENTED` | 对可信配置、已选账户记录、原始 JSON/authData 和 DER 签名执行下述检查 |
| Challenge、origin 与跨域策略 | `IMPLEMENTED` | 非空 challenge、无 padding 规范 Base64URL、精确 origin/topOrigin 允许列表与显式跨域开关 |
| RP ID hash、UP/UV 与 BE/BS | `IMPLEMENTED` | 原文 RP ID 的 SHA-256、安全字节比较、Required UV、BE 记录一致性及 BS⇒BE |
| 凭证与账户绑定 | `IMPLEMENTED` | credential ID 同时匹配可信记录和非空 allowCredentials，存在的 userHandle 匹配可信账户句柄 |
| Discoverable 账户查找 | Core 外部责任 | 调用方先解析 userHandle 对应账户并选出可信记录，Core 要求句柄存在且匹配 |
| Counter 风险与状态建议 | `IMPLEMENTED` | 区分0→0、递增与非递增，默认 ReportOnly，可显式 Reject，只有成功结果携带更新建议 |
| 真实设备与浏览器互操作 | `NOT_PERFORMED` | 方案及执行矩阵见 ASSERTION-INTEROP.md |

`AssertionVerificationPolicy::new` 默认 UV 为 `Preferred`、跨域关闭、counter 为 `ReportOnly`。Origin 列表必须非空并由可信调用方显式配置。允许列表使用完整字符串匹配，配置中写入的 scheme、大小写、端口、Unicode 和原生客户端 origin 字符串均保留。配置合法性检查只保证非空、有效 UTF-16 与字节预算，授权哪些 origin 由 RP 决定。

RP ID 配置使用 ASCII 域名标签语法检查，包括 localhost。标签长度1至63，总长度不超过253，拒绝 URL 字符、空标签、首尾连字符和末尾点。哈希保留配置原文大小写。该检查仍可接受数字或 IPv4 形式的标签，没有实现完整 valid-domain、PSL、IDNA、可注册性或浏览器 origin 与 RP ID 的授权判断，调用方应提供已建立适用性的 RP ID。§10.1.1 AppID 特殊哈希路径未实现，当前只验证配置 RP ID 的哈希。安全比较复用 MoonCrypt `@spec.eq`，等长输入逐字节折叠比较，长度属于公开信息。[WebAuthn §10.1.1](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-appid-extension)

`crossOrigin=true` 必须得到 RP 明确授权。存在 topOrigin 时，crossOrigin 必须显式为 true 且 topOrigin 匹配独立允许列表。跨域已获授权时，topOrigin 缺失仍被接受，符合该字段的可选性。P6 严格拒绝 Assertion 的 AT 和非零 RFU 位，P3 的通用结构解析行为独立保留。扩展输出经过有界解析后保留在成功结果中，本入口依 §7.2 step23 的 RP 选择忽略扩展语义，AppID 等需要专门验证流程的扩展没有实现。[WebAuthn §5.8.1、§7.2](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion)

请求 credential ID、可信记录 ID 和 allowCredentials 中各 ID 要求1至1023字节。账户 userHandle 以及存在的响应 userHandle 要求1至64字节。`Identified` 模式依赖调用方已确认的账户记录，响应句柄可省略。`Discoverable` 模式要求响应句柄存在，且账户查找和记录归属由调用方保证。响应外层 `type=public-key`、rawId 的传输解码和 HTTP/session 绑定属于调用方边界。

Counter 的 `NonIncreasing` 代表潜在风险，默认继续返回成功和风险状态。更新建议采用 `max(旧计数,收到计数)`，该高水位策略属于本项目 ReportOnly 选择。`Reject` 显式拒绝非递增情况。BS 可变化并返回最新值，已存 `backup_eligible=None` 保持未知状态。[WebAuthn §6.1.1、§6.1.3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-sign-counter)

§7.2 step24.3 的 `uvInitialized` 生命周期与初始化时可能需要的额外认证因子没有实现，相关授权更新和持久化操作由调用方完成。[WebAuthn §7.2](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion)

资源配置复用 `@cbor.Limits`，请求 JSON 与 authData 分别有界解析。预期 challenge 不超过输入预算与 Base64URL 的1 MiB上限，配置字符串按 UTF-8 字节计数，列表项数使用 `max_array_items`，DER 签名沿用8至72字节限制。跨请求 CPU、并发内存与文件读取总预算仍由调用层控制。

`verify_webauthn_es256_assertion` 返回 `Err` 时没有状态建议，解析、配置、身份、策略、签名格式、签名不匹配与 counter 拒绝可分别识别。错误保留字段路径与适用的原始字节 offset。Core 只能匹配调用方提供的 outstanding challenge。调用方必须生成足够随机的 challenge，按 §13.4.3 建议至少16字节，并负责有效期、服务端存储与成功后的原子消费。并发 Assertion 可能乱序，提交建议前应通过事务或 revision/CAS 重读旧状态并协调挑战消费，避免重复使用与覆盖更新。[WebAuthn §13.4.3、§7.2](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-cryptographic-challenges)

## 尚未实现的能力

| 功能 | 当前状态 |
| --- | --- |
| COSE 整体语义与公钥有效性 | `PARTIAL`，ES256 参数与显式 P-256 点导入已实现，其他算法待实现 |
| CBOR tags、floats、indefinite-length 支持 | 当前明确 unsupported |
| Challenge 生命周期与事务 | P7 本地参考宿主已实现 CSPRNG、绑定、时效、一次性消费与同库 version CAS，生产账户/分布式系统待实现 |
| ES384、ES512、RS256、PS256、EdDSA 等密码学能力 | `NOT_IMPLEMENTED` |
| 证书链、attestation 逐格式签名与信任验证 | `NOT_IMPLEMENTED` |
| 文件分析 CLI、报告导出、退出码契约 | P7 已实现，文件整体读取先于 Core 限长，宿主需控制超大文件 |
| Vue Dashboard 与 JS bridge | P7 已实现 Vue/Node/编译 JS Core，同源本地展示；浏览器直接 Wasm 集成尚未实现 |
| 真实设备及浏览器互操作执行 | `NOT_PERFORMED`，复现步骤与矩阵见 ASSERTION-INTEROP.md |
| 持续集成测试流水线 | 已配置四目标检查、测试、构建、格式和接口验证，实际远程状态见对应 PR |
| 模糊测试、性能基准 | 待建立 |

各入口分别返回结构、参数、密码学或 ES256 Assertion 策略验证结果。完整服务端事务和 WebAuthn Level 3 符合性仍需部署流程与对应测试。[WebAuthn Level 3 §7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)

## P7 集成限制

本地参考 RP、挑战生命周期、SQLite 原子提交、真实竞争测试、CLI 和 Vue Dashboard 已实现。最小注册适配器仅支持 fmt=none 的空 Map，完成测试所需绑定与 ES256 点检查。完整生产注册、attestation 信任和数组型格式语义验证保持未实现。

参考服务默认内存存储，显式文件路径才持久化公开凭证状态与脱敏报告。单机 SQLite、可信本地会话和系统时钟属于运行边界。长期记录清理、生产账户认证恢复、全局限流、分布式事务和运维审计尚未实现。数据库 API 使用 Node 24.18 内置 node:sqlite，官方稳定性等级为 Release candidate。CLI 文件 API 会先读取全文件，超大不可信文件需在宿主侧设置资源预算。

真实设备和浏览器覆盖按实际执行填写，未执行环境保持 NOT_PERFORMED。交互中的系统认证由维护者完成，自动化测试的合成签名与真实设备证据分别记录。[互操作矩阵](ASSERTION-INTEROP.md) · [参考 RP](REFERENCE-RP.md)
