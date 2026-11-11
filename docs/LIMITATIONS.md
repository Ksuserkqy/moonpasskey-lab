# 当前限制

## 已实现范围

Phase 1 提供 Base64URL 编解码和 ByteReader，两个包已补强为 44 个自动测试。Phase 2 新增有界 CBOR 解码、源字节范围、语义重复键检测、可配置资源预算和 CTAP2 canonical 编码 profile。测试覆盖基础 API、错误路径、大小边界和跨包集成。

当前保留原有 95 个黑盒测试，并新增 12 个一致性测试，共 107 个，其中 CBOR 为 63 个。全套测试已在 wasm、wasm-gc、js、native 四个目标实际运行，每个目标均为 107 通过、0 失败。

## Base64URL

- `encode` 默认省略 padding，`padding=true` 可输出完整 padding。
- `decode` 接受完整规范 padding 和无 padding，WebAuthn 字段的无 padding 限制待后续上下文解析实现。
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
- 当前 profile 检查覆盖 CBOR 编码及本项目支持范围。CTAP 命令语义、WebAuthn 容器字段、COSE 密钥约束和完整协议验证待相应模块实现。
- `conformance_test.mbt` 引入 W3C 固定版本的 77 字节 ES256 COSE_Key 官方规范示例及两种项目合成重排变异，覆盖编码结果和源范围。官方认证测试套件及真实设备互操作证据仍待引入，来源分类与许可见 `SPEC_MAPPING.md`、`cbor/W3C-NOTICE.md`。

## 待实现功能

| 功能 | 当前状态 |
| --- | --- |
| ClientDataJSON、AuthenticatorData、AttestationObject、COSE | 待实现 |
| CBOR tags、floats、indefinite-length 支持 | 当前明确 unsupported |
| challenge、origin、RP ID、flags 等 WebAuthn 安全规则 | 待实现 |
| SHA-256、签名、证书、attestation 信任验证 | 待实现 |
| 文件分析 CLI、报告导出、退出码契约 | 当前入口仅输出 Hello |
| Vue Dashboard、JS/Wasm 前端集成 | 待实现 |
| 互操作矩阵、真实设备及浏览器测试 | 待实现 |
| 持续集成测试流水线 | 已配置四目标检查、测试、构建、格式和接口验证，实际远程状态见对应 PR |
| 模糊测试、性能基准 | 待建立 |

当前操作结果表达编码转换、读取和 CBOR 结构解析是否成功。认证结论需要后续完整验证流程。完整 WebAuthn Level 3 符合性尚未验证。[WebAuthn Level 3 §7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)
