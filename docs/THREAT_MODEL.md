# 威胁模型

## 范围与信任边界

Phase 1 的入口是调用方提供的 `StringView` 和 `BytesView`，按攻击者可控数据处理。当前资产包括进程可用性、输入字节完整性、读取位置和错误信息的准确性。Core 负责有界转换和读取，调用方负责获取输入及处理公开 Result。

当前实现依赖 MoonBit 运行时、不可变 Bytes/BytesView 语义和标准库严格 Base64 解码器。固定大小限制约束每次 Base64URL 操作，调用方的并发次数、文件读取预算和进程级资源管理仍需在未来 CLI/服务入口落实。

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

## 后续阶段的安全边界

WebAuthn 验证还需要 challenge、origin、RP ID、UP/UV 等 flags、签名与 attestation 信任评估。后续报告必须明确每一步的执行状态和依据。原始 clientDataJSON 字节需要保留并用于哈希。WebAuthn 上下文需要额外强制省略 padding。[WebAuthn Level 3 §3、§7](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)

Phase 1 提出的 CBOR 输入、嵌套深度、重复键、截断和不支持类型要求已在 Phase 2 的有界解码器中实现，并通过独立的 Generic 与 Ctap2Canonical 编码策略执行对应检查。CBOR 的当前支持子集、精确资源预算、语义键与错误定位依据见 ARCHITECTURE.md、LIMITATIONS.md 和 SPEC_MAPPING.md。

WebAuthn 字段安全规则、密码学验证和分析报告仍待对应协议模块实现。ByteReader 本身通过视图读取已有数据，整体文件大小和并发预算由相应入口及调用方设置。
