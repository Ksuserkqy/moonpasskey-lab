# 开发与审计记录

本文前六节保留 Phase 1 初始开发与验收记录，其中 39 项测试为当时实际运行结果。后续补强和 P1/P2 Bootstrap 的当前状态见文末。

## 初始仓库审计

2026-11-11，根目录 AGENTS.md 已完整阅读。初始分支为 `main`，唯一提交为 `3cb9618 chore: initialize MoonBit project`。`origin` 的 fetch/push 地址均为 `https://github.com/Ksuserkqy/moonpasskey-lab.git`。

初始工作区有用户对 AGENTS.md 的未提交修改，因此先暂停分支操作并报告。用户要求以新版 MD 为准，且暂不提交该文件后，建立 `feat/v0.1-core` 进行开发。

初始根 `moon.pkg` 为 0 字节，根生产及测试文件均只有脚手架注释。`cmd/main/moon.pkg` 声明 `pkgtype(kind: "executable")`。`README.md` 是指向 `README.mbt.md` 的符号链接。初始检查、构建和 Hello 示例可运行，初始测试数为 0。

`moon.mod` 中实际元数据为 `ksuserkqy/moonpasskey_lab@0.1.0`、`preferred_target = "wasm"`、`license = "Apache-2.0"`，外部依赖为空，repository 和 description 字段为空。

## 实测环境

| 工具 | 实际版本 |
| --- | --- |
| CPU 架构 | arm64 |
| moon | 0.1.20261104，940aa18，2026-11-04 |
| moonc | v0.10.20+65efd5b93，2026-11-05 |
| moonrun | 0.1.20261104，940aa18 |
| core | 0.10.20+65efd5b93 |
| Node.js | v24.18.0 |
| npm | 12.0.2 |

`moon` 位于 `~/.moon/bin/moon`。本机 `moon help` 中实际提供 check、test、build、run、info、fmt、doc、explain、tree 等命令。当前命令清单没有 `moon ide`。

## 标准库 API 核验

核验对象为本机 `~/.moon/lib/core` 下的源码和 `pkg.generated.mbti`，开发期间用实际编译和运行确认调用方式。

| API | 确认签名或语义 | 源码位置，均相对 core 根 |
| --- | --- | --- |
| Bytes、BytesView | 不可变字节数据及视图 | builtin/builtin_types.mbt |
| BytesView.length | 返回 Int | builtin/bytesview.mbt |
| BytesView.get_view | `get_view(start?, end?) -> BytesView?`，错误区间返回 None | builtin/bytesview.mbt |
| BytesView 索引 | 有效范围内返回 Byte，调用前须确保边界 | builtin/bytesview.mbt |
| Byte.to_uint | 返回 UInt32，UInt 是 UInt32 别名 | builtin/builtin_types.mbt、builtin/pkg.generated.mbti |
| Bytes.make、makei、from_array | 测试数据构造 | builtin/intrinsics.mbt、builtin/bytes.mbt |
| StringView.length、get、code_units、to_owned | UTF-16 位置及拥有式字符串转换 | builtin/stringview.mbt、builtin/string_methods.mbt |
| String.replace_all | `replace_all(old~, new~) -> String` | builtin/string_methods.mbt、builtin/pkg.generated.mbti |
| base64.encode | `encode(BytesView, padding?=true) -> String` | encoding/base64/encode.mbt |
| base64.decode | `decode(StringView, ignore_whitespace?=false) -> Bytes raise Malformed` | encoding/base64/decode.mbt |
| Result | `Ok(T)` / `Err(E)`，E 可使用普通公开枚举 | builtin/builtin_types.mbt |
| Result.map | 仅在 Ok 时映射值，保持 Err | builtin/result.mbt |
| Eq、Debug | 错误枚举派生，显式 extend 避免隐式方法提升警告 | builtin、debug |

标准库 Base64 字母表使用 `+`、`/`，支持严格 padding 和非零未使用位检测。封装层校验原始字符、转换 `-`/`_` 后调用该实现。其 `Malformed` 异常通过 `try/catch` 映射到本项目 `Result`。[MoonBit 错误处理](https://docs.moonbitlang.com/en/latest/language/error-handling.html)

## 包与测试组织

`base64url/` 与 `bytereader/` 各有一个 `moon.pkg`，包名由目录确定。测试文件使用 `_test.mbt`，通过 `@base64url`、`@bytereader` 调用公开 API。`base64url/moon.pkg` 的 `for "test"` import 仅供模块集成测试。`_wbtest.mbt` 可访问内部实现，本阶段新增测试均为黑盒测试。[包配置](https://docs.moonbitlang.com/en/latest/toolchain/moon/package.html) [测试组织](https://docs.moonbitlang.com/en/latest/language/tests.html)

测试使用 `assert_eq` 和模式断言，错误类型派生 `Eq`、`Debug`。当前 Base64URL 包含 20 个测试，其中 1 个为 ByteReader 集成测试。ByteReader 包含 19 个测试。向量来源和合成样本说明见 SPEC_MAPPING.md。

## 实际验证命令

在仓库根目录执行默认目标验收。

```sh
moon info && moon fmt
moon fmt --check
moon check
moon test
moon build
moon run cmd/main
```

本阶段另外运行以下命令核验后端一致性、测试入口和依赖。

```sh
moon test --target wasm-gc
moon test --target js
moon test --target native
moon test --outline
moon tree
git diff --check
git diff --stat
git status --short --branch
```

默认 wasm 和额外三个目标各执行相同的 39 个测试，每个目标均为 39 通过、0 失败。Hello 示例用于确认原入口可运行。生成接口由 `moon info` 维护，新增公开 API 仅在两个新包中。

## 依赖与许可证核查

`moon tree` 显示模块无外部依赖。生产 Base64URL 仅显式导入 `moonbitlang/core/encoding/base64`，ByteReader 使用默认 prelude。core 来自本机工具链，其 `moon.mod` 和 LICENSE 均确认 Apache-2.0。项目 LICENSE 为 Apache-2.0。

RFC 测试向量来源与许可见 SPEC_MAPPING.md。其他测试输入为本项目合成。竞品仅用于技术比较，其代码和第三方依赖尚未加入工程。

## 原定后续开发顺序（Phase 1 记录）

下一阶段先为 ClientDataJSON 和有界 CBOR 制定公开结果类型及负例，再实现 AuthenticatorData 与 none attestation 的结构解析。随后接入真实 Core 的文件分析 CLI，逐步增加标准映射规则和经核验的密码学组件。

## P1/P2 当前验收记录

Phase 1 初始验收后新增 5 个永久回归测试，Base64URL 为 24 项，ByteReader 为 20 项，共 44 项。Phase 2 新增 CBOR 解码与最终一致性审查测试 63 项，全仓库合计 107 项。wasm、wasm-gc、js、native 四目标均已实际运行，每目标 107 通过、0 失败。

CBOR 当前支持范围、资源预算、Generic 与 Ctap2Canonical 的 `PARTIAL` 状态及 W3C 官方示例来源分别记录在 ARCHITECTURE.md、LIMITATIONS.md 和 SPEC_MAPPING.md。上述 Phase 1 原定顺序中的 CBOR 工作现已完成，后续协议模块依项目后续 Phase 指令推进。

早期暂不提交 AGENTS.md 的记录对应当时授权。本轮用户已明确授权将 P1/P2 成果和仓库开发规范纳入逻辑提交、推送功能分支并创建 Bootstrap PR。当前整合采用 P1、P2、仓库流程三个功能边界组织提交，跨阶段文档随 P2 一并纳入。

## Bootstrap 开发流程与 CI

本次完善 AGENTS.md 的唯一 Git Workflow Policy，增加 CONTRIBUTING.md、CHANGELOG.md、PR 模板和 MoonBit CI。后续每个 Phase 使用独立 feature branch 与 PR，采用 Conventional Commits，PR 附真实测试报告，当前提交 CI 通过后申请合并。合并需要用户明确授权。

CI 固定 Ubuntu 24.04、MoonBit 归档 `0.10.20+65efd5b93` 和 Node.js 24，分别运行 wasm、wasm-gc、js、native 的检查、107 项测试、构建及 Hello 入口，同时验证格式和生成接口。安装使用官方脚本，checkout / setup-node 使用已核验的固定提交。远程执行状态和运行链接记录在 Bootstrap PR，仓库配置中的四目标矩阵本身表达待执行检查。

P1 和 P2 提交分别从暂存区独立导出验证，P1 为 44 通过，P2 为四目标各 107 通过。当前工作区另行复测四目标，每目标仍为 107 通过、0 失败。`moon check --deny-warn`、`moon build --deny-warn`、`moon fmt --check`、`git diff --check` 均通过，`moon run cmd/main` 输出 `Hello`，`moon tree` 显示无外部依赖。`moon info && moon fmt` 未产生额外的公开接口或代码变化。

整合期间再次检测环境时，本机工具链已变为 moon / moonrun `0.1.20261111`（`8b8d15b`）、moonc / core `0.10.21+f125caab5`。本次任务未执行安装或升级操作。A/B 导出验证使用前述 `0.10.20+65efd5b93` 工具链，最后一轮工作区复测使用 `0.10.21+f125caab5`，四目标各 107 通过，且分别通过带 `--deny-warn` 的 check、build、入口运行。生成接口和代码保持一致。CI 固定原验收版本，并以远程执行日志确认实际安装结果。

## P3 WebAuthn 协议解析首次验收（审查修正前）

P3 从已同步的 `origin/main`（`b8ec3a6087d2e39c3725c3d0bb3a82de56e8b242`）建立 `feat/p3-webauthn-parser`；已确认 P1/P2 与公开规范 PR 均已合并。模块身份、原有包、默认目标与 CI 固定版本保持一致。

实施按三个结构解析入口分工，统一放在 `webauthn` 包；私有读取/错误/预算辅助函数供包内复用。公共接口为 `parse_client_data`、`parse_authenticator_data`、`parse_attestation_object`，均接受 `BytesView` 和可选 `cbor.Limits`，返回带类型的 Result。`moon info` 只新增 `webauthn/pkg.generated.mbti`，原有 `.mbti` 未改变。

### 标准库与依赖选择

本机 `moonbitlang/core` 为 `0.10.21+f125caab5`，Apache-2.0；`moon tree` 确认无外部模块依赖。CI 仍固定 core/工具链归档 `0.10.20+65efd5b93`，远程结果在 P3 PR 单独记录。

已检查 core/json 的解析实现与公开接口。当前版本提供重复成员与嵌套深度选项，但没有本任务需要的成员/数组/字符串/总节点预算或原始字节范围。直接构建完整 Json 对象也无法保留重复成员的源位置。P3 因此使用有界字节扫描器负责 JSON 语法、预算、重复成员与范围，仅将已经检查过长度和转义的单个字符串 token 交给 core/json 解码。没有依赖新版本可选参数，其他调用为 core/encoding/utf8、core/sorted_map 和既有 ByteReader/CBOR。无需新增外部依赖、锁文件或许可证。

扫描器保留原始输入，严格检查 UTF-8，解析时只跳过开头 BOM，拒绝不成对的 surrogate 转义。未知字段照常扫描检查并通过源范围保留。它没有把重新序列化的 JSON 当作原文。完整解析契约、容忍策略和未验证的语义见 ARCHITECTURE、LIMITATIONS 与 SPEC_MAPPING。

### 资源与错误审查

统一复用 `cbor.Limits`：默认输入和单字符串各 1 MiB、数组 4096 项、Map/Object 1024 对、容器深度 32（配置硬上限 64）、总值 16384。JSON 字符串预算计引号内编码字节，键和值均计入总值；WebAuthn CBOR 使用 canonical profile，另有每个 CBOR 容器树最多四层的限制。外层 CBOR、嵌入公钥和 ED 共用总节点预算，后续调用扣除已消耗节点；嵌套 CBOR ResourceLimit 的 limit/actual 按该次剩余预算报告。固定二进制字段按协议精确长度读取，credential ID 另有 1023 字节线格式上限。

ByteReader 负责边界读取，CBOR 返回消费长度与原始范围；解析失败保留请求/剩余长度。错误主位置均相对公共入口输入，AttestationObject 同时换算嵌套 CBOR DuplicateMapKey/UnsortedMapKey 的附带位置。成功结果的 AuthenticatorData 子范围相对于其 raw，并提供父对象 auth_data_payload_range 连接两套坐标。

已执行 AI 静态代码审查及自动测试，未发现可复现越界、整数溢出或 panic；这不构成形式化证明或维护者人工验收。全套模糊测试与真实设备互操作尚未建立。签名、SHA-256、证书链、可信根与认证判断均未实现。

### 实际本地执行

| 环境 | P3 实测版本 |
| --- | --- |
| OS / CPU | Darwin / arm64 |
| moon / moonrun | 0.1.20261111，8b8d15b |
| moonc / core | 0.10.21+f125caab5 |
| Node.js | v24.18.0 |
| native C 编译器 | Apple clang 21.0.0 |

保留基线 107 项，新增 99 项黑盒测试：ClientDataJSON 34、AuthenticatorData 42、AttestationObject/集成 23，总计 206 项。首次验收的三个 P3 测试文件均为项目合成，既有官方 W3C 示例当时位于 CBOR 测试中并单独保留 NOTICE；审查修正新增的 §16 官方向量见下节。

按 `.github/workflows/ci.yml` 的实际步骤对每个目标运行以下命令（用目标名替换 TARGET）：

```sh
moon info && moon fmt
moon fmt --check
moon check --target TARGET --deny-warn
moon test --target TARGET --deny-warn
moon build --target TARGET --deny-warn
moon run cmd/main --target TARGET --deny-warn
git diff --check
```

| 目标 | 新增 / 总测试 | 通过 / 失败 | check | build | 现有入口 |
| --- | --- | --- | --- | --- | --- |
| wasm | 99 / 206 | 206 / 0 | PASS | PASS | Hello |
| wasm-gc | 99 / 206 | 206 / 0 | PASS | PASS | Hello |
| js | 99 / 206 | 206 / 0 | PASS | PASS | Hello |
| native | 99 / 206 | 206 / 0 | PASS | PASS | Hello |

`moon info && moon fmt`、`moon fmt --check`、`git diff --check` 均通过。所有 check/test/build/run 使用 `--deny-warn`，未隐藏编译警告。CLI 仍为既有 Hello 入口，P3 未添加分析 CLI 或前端。固定旧版本工具链的 Ubuntu CI 证据以当前 P3 PR 的实际 Actions 为准，不以本机结果代替。


## P3 Review Follow-up（2026-11-12）

本次从 `3bba475cf3a50cd1bbd0e236b495ec4cafdfa43e` 在原 `feat/p3-webauthn-parser` 分支追加修正，PR 仍为 #3，目标 `main`。未修改默认分支、工具链、CI 配置或依赖。

### 标准符合性修正

- 按 WebAuthn §6.5.4 的 CDDL，外层 Map 只允许且必须包含 fmt/authData/attStmt；未知 text 键返回 `UnexpectedField(String)`，offset 是键编码的起点。非 text 键、重复键、必需字段与类型检查继续保留。
- attStmt 允许 text-keyed Map 或 Array，原始 CBOR Value 与范围保持不变。none 仍必须为空 Map；其他格式继续返回 `FormatNotValidated`。compound 等数组型格式的逐元素规则、组合与密码学验证未实现。
- ClientDataJSON 未知字段兼容性及 statement Map 内未知字段保留策略保持原样。
- `moon info` 的公开接口差异仅为新增 `ErrorKind.UnexpectedField(String)`；函数签名、结构模型和 StatementStatus 未改变。对错误枚举做穷尽匹配的调用方需处理新分支。

### 官方向量与测试保留

新增 `webauthn/w3c_vectors_test.mbt` 的 6 项集成测试，分别覆盖固定版 W3C 2026-08-25 Recommendation §16.2、§16.4、§16.5 的注册与认证字节。只复制解析所需的 clientDataJSON、attestationObject、authenticatorData；不复制私钥、签名或证书。12 段输入由固定 HTML 提取，并独立与测试源中的拼接 hex 比较，全部一致，JSON 未重建或重新序列化。

| 来源 | 注册 JSON / object | 认证 JSON / authData |
| --- | --- | --- |
| §16.2 none ES256 | 255 / 194 bytes | 132 / 37 bytes |
| §16.4 crossOrigin=true | 254 / 194 bytes | 251 / 37 bytes |
| §16.5 topOrigin | 168 / 194 bytes | 285 / 37 bytes |

三个注册对象都包含 164-byte authData、32-byte credential ID 和 77-byte 公钥 CBOR Map。测试检查原始 JSON、可选字段、外层对象、嵌入和独立 authData、AT、公钥五组 label/value 与范围。来源、固定版本及完整 W3C 许可见 `webauthn/W3C-NOTICE.md`；官方数据与既有合成文件分开保存。

原有 206 项覆盖保留：按要求将未知外层字段接受测试改为拒绝测试，并调整与新数组支持相关的错误类型输入。新增 11 项合成回归和 6 项官方向量测试，净增 17 项，全仓库共 223 项（Base64URL 24、ByteReader 20、CBOR 63、ClientDataJSON 34、AuthenticatorData 42、AttestationObject 34、官方向量 6）。未删除 P1/P2 测试或降低有效断言。

### 实际验收结果

本机仍为 Darwin arm64，moon/moonrun `0.1.20261111`、moonc/core `0.10.21+f125caab5`、Node.js `v24.18.0`。运行 `moon info && moon fmt`、`moon fmt --check` 与 `git diff --check` 均通过，并审查了上述唯一 `.mbti` 差异。对每个目标实际运行 `moon check/test/build --target TARGET --deny-warn` 和 `moon run cmd/main --target TARGET --deny-warn`：

| 目标 | 总数 | 通过 / 失败 | check | build | run |
| --- | --- | --- | --- | --- | --- |
| wasm | 223 | 223 / 0 | PASS | PASS | Hello |
| wasm-gc | 223 | 223 / 0 | PASS | PASS | Hello |
| js | 223 | 223 / 0 | PASS | PASS | Hello |
| native | 223 | 223 / 0 | PASS | PASS | Hello |

已完成 AI 静态审查和官方数据独立核对；这不替代维护者人工审查。CI 继续固定 `0.10.20+65efd5b93`，新提交的远程执行证据记录在 PR #3。此次只完成结构修正，不表示已经实现数组型格式语义、COSE Key 或密码学验证。

## Phase 4 ES256 COSE 参数验证（2026-11-12）

开始时工作区干净。通过 fetch 与 GitHub 状态确认 PR #3 已合并，`origin/main` 包含合并提交 `cc6a3001df829710fd80267bb064a05d9553d14b`，P1–P3 基线为 223 项测试。从该远程提交创建 `feat/p4-es256-cose-key`。模块身份与固定 CI 工具链沿用项目配置。

### 实现与接口

新增 `webauthn/cose_key.mbt`，公开 `validate_es256_credential_public_key(BytesView, limits?)`、`AttestedCredentialData::validate_es256()` 和结果 `Es256PublicKeyParameters`。结果包含已检查的 kty/alg/crv、原始 x/y、key 编码、Map/参数源范围与 `CurvePointValidation.NotPerformed`。

独立入口调用既有 CBOR canonical 解码，复用预算、重复键、尾随与错误处理。AT 方法查看已经完成结构解析的不可变 Map，范围与错误相对于 authData.raw，raw 只保存 key 编码。语义调用检查 alg/kty/crv、必需参数、坐标类型/32字节长度/域范围、压缩 y、私钥和可选参数。已知禁止参数、私钥与未知支持范围分别返回错误，错误内容仅包含位置、类型、字段路径和必要长度。对坐标的操作仅为固定宽度字节比较。

检查顺序为 CBOR、label 策略、alg、kty、crv、x、y。未知 integer/text label 使用 UnsupportedCoseParameter，反映本入口的严格支持策略。有效整数 alg 非 -7 使用 UnsupportedAlgorithm，包括 ES384、ES512、RS256、PS256 和 EdDSA。P3 的结构调用仍可获取这些算法的 Map，语义调用由调用方显式选择。

`moon info` 生成的差异仅在 WebAuthn 包，新增上述类型、方法及九个语义错误变体。原有函数签名保持兼容，穷尽匹配 ErrorKind 的调用方需处理新增分支。`cbor/moon.pkg` 只增加 test-only WebAuthn import，以复用原有官方 fixture。生产依赖为 WebAuthn → CBOR → ByteReader。`moon tree` 确认无外部模块依赖。

### 曲线点验证依赖调查

检查了本机 core `0.10.21+f125caab5` 的公开接口，以及 Mooncakes/GitHub 的以下候选。调查只读源码、接口和 CI 配置，未引入第三方实现或依赖。

| 候选 | 版本、许可与维护证据 | 点验证 API 与目标证据 | 需补证据 |
| --- | --- | --- | --- |
| moonbitstack/mooncrypt | registry 0.4.15，源码0.4.16，Apache-2.0，存在持续源码更新与多OS CI | PublicKey::of_xy 与 SEC1 导入具备曲线检查，CI check/build/test 使用 --target all | 固定0.10.20兼容性、独立安全审查。of_xy 的字段范围契约仍需单独核查 |
| mizchi/experimental_crypto | 0.0.2，Apache-2.0，源码含测试与内部审查记录，作者标注实验性及未经独立审计 | PublicKey::from_uncompressed 检查编码、坐标与曲线。主测试矩阵 native/js/wasm-gc，另有 wasm smoke | 固定工具链四目标完整测试、安全审计与生产适用性 |
| Lfan-ke/mooncat / moonbitstack/mooncat | 旧项目已转向当前服务器模块，Apache-2.0 | 当前密码学依赖 mooncrypt | 作为服务器栈并未提供独立的、已核验的轻量P-256依赖证据 |

mooncrypt 核验源码提交为 `62ff461366f7932506bdd922db209f6949a71c86`，experimental_crypto 为 `d5a3c7005515a02fd9a0260cffaae7b738e69f6b`。mooncrypt 的 of_xy 路径检查坐标宽度和曲线方程，字段值 < p 的检查出现在另一个 SEC1 解码路径，后续集成需要结合调用入口审查。其 CI 安装最新工具链，未提供本项目固定版本的兼容性结果。experimental_crypto 的作者明确记录实验性与独立审计缺失。当前调查不足以确认候选满足本阶段引入密码学依赖的要求，因此曲线点成员检查状态为 NOT_IMPLEMENTED。

来源包括版本化 API、CI 和作者说明。[mooncrypt API](https://github.com/moonbitstack/mooncrypt/blob/62ff461366f7932506bdd922db209f6949a71c86/src/sign/ecdsa/pkg.generated.mbti) · [mooncrypt 构造器](https://github.com/moonbitstack/mooncrypt/blob/62ff461366f7932506bdd922db209f6949a71c86/src/sign/ecdsa/ecdsa.mbt) · [mooncrypt CI](https://github.com/moonbitstack/mooncrypt/blob/62ff461366f7932506bdd922db209f6949a71c86/.github/workflows/ci.yml) · [experimental_crypto 说明](https://github.com/mizchi/experimental_crypto/blob/d5a3c7005515a02fd9a0260cffaae7b738e69f6b/README.md) · [其 P-256 API](https://github.com/mizchi/experimental_crypto/blob/d5a3c7005515a02fd9a0260cffaae7b738e69f6b/p256/pkg.generated.mbti) · [其 CI](https://github.com/mizchi/experimental_crypto/blob/d5a3c7005515a02fd9a0260cffaae7b738e69f6b/.github/workflows/ci.yml)。

### 测试来源与计数

保留 P1–P3 的全部 223 项测试，新增45项。

| 类别 | 新增测试块 |
| --- | ---: |
| 合成正向、范围和预算边界 | 7 |
| 合成负例与不支持算法 | 30 |
| 合成跨模块兼容及错误定位 | 4 |
| 复用 W3C 官方向量 | 4 |
| 合计 | 45 |

官方4项分别复用 §6.5.1.1 的既有77字节示例和 §16.2/16.4/16.5 的既有注册向量。核对 §6.5.1.1 的原始 bytes 与固定规范/任务字节逐字节相同，两个既有官方测试文件的原内容保持一致，仅在末尾追加调用与断言。没有重复复制、移动或重新序列化官方输入。既有 W3C NOTICE 继续适用。合成负例为 `webauthn/cose_key_test.mbt`，覆盖缺参、类型、label、私钥/optional、非canonical、重复键、所有前缀截断、尾随、UInt64边界、坐标p-1/p/p+1/最大值、前导零及输入子视图。30是负例测试块数量，块内部分按多个输入循环。域内不在曲线上的坐标测试核验 NotPerformed 状态。

### 实际本地验收

本机环境为 Darwin arm64，moon/moonrun `0.1.20261111`（8b8d15b），moonc/core `0.10.21+f125caab5`，Node.js `v24.18.0`。完成 `moon info && moon fmt`，检查生成接口差异。`moon fmt --check`、`git diff --check` 均通过。

四目标分别实际执行以下命令。

```sh
moon check --target TARGET --deny-warn
moon test --target TARGET --deny-warn
moon build --target TARGET --deny-warn
moon run cmd/main --target TARGET --deny-warn
```

| 目标 | 通过 | 失败 | check | build | run |
| --- | ---: | ---: | --- | --- | --- |
| wasm | 268 | 0 | PASS | PASS | Hello |
| wasm-gc | 268 | 0 | PASS | PASS | Hello |
| js | 268 | 0 | PASS | PASS | Hello |
| native | 268 | 0 | PASS | PASS | Hello |

总数268由P1/P2的107项、P3的116项和P4的45项组成。测试阶段曾出现一项集成 context 预期仍使用独立key路径的失败，现按方法的 authData 相对路径修正预期，并完成上述四目标全量复测。代码和标准映射已进行 AI 静态审查，维护者人工验收由 PR 审查完成。

### 远程 CI 验收

PR #4 的实现提交 `293b7075397d0e2dc4e755b087eec6fccba0137d` 已完成四目标 CI。日志确认 Ubuntu24.04、moon/moonrun `0.1.20261104`、moonc/core `0.10.20+65efd5b93` 和 Node24。四目标各268项通过、0失败，格式、接口比对、check/test/build/run全部成功。[Actions 43074874102](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43074874102)

日志中 checkout 收尾步骤有既有 Node punycode 弃用提示，MoonBit 检查与编译在 `--deny-warn` 下通过。维护者人工审查待完成。后续文档提交的当前 head CI 状态记录在 PR #4。[P4 PR](https://github.com/Ksuserkqy/moonpasskey-lab/pull/4)

曲线点成员、SHA-256/签名、证书链、attestation信任与完整RP流程的状态均为 NOT_IMPLEMENTED。
