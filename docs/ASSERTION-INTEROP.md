# 浏览器与真实设备互操作记录

## Phase 7 历史执行状态

2026-11-12 已完成 Safari/macOS 真实平台 Passkey 的测试注册与 Assertion。维护者完成系统注册和认证，页面显示两条测试注册 PASS 与一条 Assertion PASS。最终 Assertion 的12项检查通过，ES256/P-256 公钥有效、DER 签名 Valid，Core 最终 PASS。公开记录来自 Dashboard 的实际脱敏导出。

| 环境 | 设备与软件 | Provider | 注册 | Assertion/Core |
| --- | --- | --- | --- | --- |
| Safari + macOS | Mac16,12，macOS 27.2.1 build26B131，Safari27.2 | iCloud Keychain / 平台 Passkey，按维护者选择记录 | PASS | PASS |
| Safari + iOS | NOT_RECORDED | iCloud Keychain | NOT_PERFORMED | NOT_PERFORMED |
| Chrome + Google Password Manager | NOT_RECORDED | Google Password Manager | NOT_PERFORMED | NOT_PERFORMED |
| Chrome + Windows Hello | NOT_RECORDED | Windows Hello | NOT_PERFORMED | NOT_PERFORMED |
| USB FIDO2 | NOT_RECORDED | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |
| NFC FIDO2 | NOT_RECORDED | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |

机型、系统和 Safari 版本来自本机只读系统元数据，provider 按维护者此前选择的 iCloud Keychain / 平台 Passkey 记录，未通过浏览器协议字段独立识别 provider。RP ID 为 localhost，Origin 为 http://localhost:8787，服务监听127.0.0.1。默认 UV preferred、counter report-only。


### Safari/macOS 成功记录

| 字段 | 实际值 |
| --- | --- |
| 测试时间 | 2026-11-12 13:02:59.977 CST，原始 capturedAt 为2026-11-12T05:02:59.977Z |
| RP ID / Origin | localhost / http://localhost:8787 |
| 请求 UV / 实际 UV | preferred / true |
| UP / BE / BS | true / true / true |
| AT / ED / RFU | false / false / 0 |
| AuthenticatorData 长度 | 37字节 |
| signCount | stored0，received0，NOT_SUPPORTED |
| 公钥 / 签名 | ES256，P-256 validated，DER，signatureValid=true |
| ClientData | webauthn.get，crossOrigin=false，topOrigin缺省，challenge只保留43字符长度 |
| Core 最终结果 | PASS，12项检查PASS，counter为NOT_SUPPORTED |

页面的 PASS 响应来自参考 RP 完成原子提交后的成功路径。两次测试注册与一次 Assertion 均来自维护者完成的真实 Safari 系统流程。尚未执行该设备的递增计数器测试、UV required 策略和其他平台矩阵。

脱敏 JSON 的 SHA-256 为 0f27841c5fcf6d84927a7b53b66a9f6b24aa2fa0feb84f7caa711cd13311c9af。公开文件省略完整 credential ID、userHandle、挑战、公钥编码、原始响应和签名。[实际 Dashboard 导出](interop/safari-macos-2026-11-12.redacted.json)

## 复现步骤

1. 按 REFERENCE-RP 构建真实 MoonBit JS bridge、Dashboard 并启动服务。
2. 在同一台 Mac 的 Safari 打开 http://localhost:8787，确认 Local RP connected 且注册按钮可用。页面仅在 window.isSecureContext、PublicKeyCredential 和 navigator.credentials 可用时启用操作。
3. 由维护者点击 Register test passkey 并完成系统 provider 的创建确认。服务生成32字节挑战，MoonBit 验证 none 注册绑定与公钥，成功后同事务消费挑战并登记记录。
4. 由维护者点击 Verify with passkey 并完成系统认证。前端直接传输 response 的原始 clientDataJSON、authenticatorData、DER signature、rawId 和 nullable userHandle。
5. 观察 Core 逐项状态、真实 flags、counter 与最终 PASS，再查看凭证 version 已更新。
6. 在 Test reports 填写实际设备、操作系统、浏览器和 provider，导出脱敏报告，核对没有完整 credential ID、userHandle、challenge、公钥坐标、签名或原始认证字节。

默认 localhost HTTP 使用浏览器对 loopback potentially-trustworthy origin 的开发支持。移动设备上的 localhost 指向该移动设备自身，跨设备测试需要维护者配置可访问的受信任 HTTPS origin、匹配 RP ID 和受保护访问路径。当前服务限制 loopback 绑定。[Secure Contexts 固定版](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#is-origin-trustworthy) · [参考 RP](REFERENCE-RP.md)

## 设备报告字段

每次完整运行需记录真实设备型号、OS/browser版本、选中的 provider、RP ID、origin、请求 UV 策略、实际 UP/UV/BE/BS/AT/ED/RFU、signCount、DER 验签结果、Core 最终状态、事务提交结果和测试时间。provider 名称由完成系统流程的维护者确认。软件版本来源与浏览器 user agent 分别记录。

发布报告只保留脱敏字段。原始响应在前端和验证进程内存中处理，默认数据库为内存库。系统 provider 中的测试 Passkey 会持续存在，维护者可按测试数据保留安排管理。数据库持久化属于显式选项。

## 自动化互操作边界

Host HTTP 集成测试通过真实编译 Core 完成服务器挑战、none 测试登记、原始 DER Assertion、状态提交、重放与负例。测试 key 来自 Node/OpenSSL 临时生成，仅用于合成测试，私钥不写入仓库。三个额外竞争用例在不同 worker 中加载实际 Core，使用父进程已签名的公开请求，确认同挑战唯一提交、ReportOnly 乱序风险和 Reject 最新计数重评估。

原有 W3C §16.2、§16.4、§16.5 官方字节与许可保留在既有测试中，官方向量与合成测试均无法替代真实物理设备证据。此前 P6 的手工捕获步骤和当时 NOT_PERFORMED 状态可在 P6 合并版本查看，P7 当前流程使用服务器挑战与事务存储。[P6 历史互操作文档](https://github.com/Ksuserkqy/moonpasskey-lab/blob/725c40ba10dc942498c96834e05d76ab644e5ac7/docs/ASSERTION-INTEROP.md) · [挑战生命周期](CHALLENGE-LIFECYCLE.md)

## Phase 7.1 设备验收矩阵

本节追加 Phase 7.1 的新验收范围。前述 P7 Safari/macOS 成功记录及原始 JSON 保留原样。P7 的 preferred 请求、实际 UV=true 和 signCount0 继续属于历史证据，A1 的 required 策略需要新的真实设备流程。

| 项目 | 优先级 | 真实环境与要求 | 当前状态 | 待补证据 |
| --- | --- | --- | --- | --- |
| A1 | P0 | Safari/macOS，UV Required | NOT_PERFORMED | 新登记、实际 UP/UV=true、Core PASS、COMMITTED及导出 |
| A2 | P0 | Safari/iOS，真实注册和 Assertion | BLOCKED | 专用测试域名、可信 HTTPS、访问控制和实际 iPhone |
| A3 | P0 | Safari/iOS，HTTPS 跨设备访问 | BLOCKED | 边缘与后端 TLS、Access/JWT、允许和拒绝访问的实际结果 |
| A4 | P1 | Chrome/macOS，Google Password Manager | NOT_PERFORMED | 实际 provider 选择、注册、Assertion与导出 |
| A5 | P1 | Chrome/macOS，UV Required | PASS | 本地注册与两次 Assertion，实际 UV=true、DER有效、COMMITTED；[归档记录](#chromemacos-uv-required-最终归档) |
| A6 | P1 | Safari/macOS或iOS，重复认证与状态更新 | NOT_PERFORMED | 同一凭证至少两次新挑战、COMMITTED版本递增、独立导出 |
| A7 | P2 | Chrome/Windows Hello | NOT_PERFORMED | 真实设备及环境元数据 |
| A8 | P2 | USB FIDO2 | NOT_PERFORMED | 真实密钥型号、浏览器、注册与Assertion |
| A9 | P2 | NFC FIDO2 | NOT_PERFORMED | 支持NFC的真实设备、密钥及完整流程 |

尚未执行的项目没有新设备型号、OS/browser版本、实际 provider、flags、signCount、DER结果、Core结果、事务结果或测试时间。这些字段保持未记录，完成对应设备流程后从实际导出填写。每次记录实际 RP ID、完整 Origin、请求UV、实际UP/UV/BE/BS、计数器、DER验证、Core结果、数据库提交及时间。设备未执行、基础设施缺项和实际验证失败分别使用 NOT_PERFORMED、BLOCKED、FAILED。自动化合成测试的 PASS 单独记录于 DEVELOPMENT。

### Provider 来源与报告版本

新报告使用版本化严格字段白名单，providerSource 为 MAINTAINER_SELECTED、INDEPENDENTLY_VERIFIED 或 UNKNOWN。系统界面的维护者明确选择属于 MAINTAINER_SELECTED。浏览器、OS、UV和备份flags本身不构成 provider 身份证明。只有存在可核对的独立依据时，维护者才记录 INDEPENDENTLY_VERIFIED，并在验收说明中注明依据。无法确定时使用 UNKNOWN。

历史 JSON 的 SHA-256 继续为0f27841c5fcf6d84927a7b53b66a9f6b24aa2fa0feb84f7caa711cd13311c9af。新增 provenance sidecar 将原有明确 provider 标签归类为 MAINTAINER_SELECTED。检查器只在内存中规范化旧结构，保留原有 PASS，并将旧文件缺失的显式事务字段标为 UNKNOWN。前述历史文档的提交成功说明来自 RP 成功响应代码路径，原始导出未包含版本级事务字段。

新 RP 成功响应在 SQLite commit 之后包含 databaseTransaction 的 COMMITTED、previousVersion、version。Dashboard 按每次响应保存配置和事务快照，重复认证可以核对准确的提交版本。导入分析没有数据库提交，相关状态使用 NOT_PERFORMED。失败响应缺乏提交观察时使用 NOT_OBSERVED。

```sh
node --experimental-strip-types scripts/check-interop-reports.mjs
npm --prefix dashboard test
```

新Dashboard导出文件名以.redacted.json结尾。检查器默认扫描docs/interop中的这些文件，也可用命令末尾的实际文件路径校验Downloads中的导出。检查器校验 schema、允许的状态、设备时间、provider来源、各层允许字段及历史文件摘要。检查通过说明报告结构与脱敏规则满足当前契约。真实设备是否实际执行仍需维护者和相应证据核对。[报告 schema](interop/report.schema.json) · [历史来源 sidecar](interop/safari-macos-2026-11-12.provenance.json)

### 人工验收交接

工程准备完成后，由维护者配置和执行真实设备流程。当前 A2/A3 缺少已批准并验证的专用域名与跨设备 HTTPS 入口，实际 iPhone URL 尚未建立。占位地址为 https://passkey-test.<owned-test-domain>/，替换和部署通过后才用于手机访问。HTTPS拓扑、身份授权、证书、iPhone与Chrome步骤及关闭清理见专项文档。[HTTPS 操作说明](INTEROP-HTTPS.md)

先完成 macOS Safari 的 required 独立验收时，可使用空闲本地端口，避免与既有8787测试服务冲突。在仓库根目录、固定 Node24.18 与 MoonBit工具链下运行。

```sh
moon build analysis --target js --deny-warn
npm --prefix dashboard run build
REFERENCE_RP_PORT=8789 REFERENCE_RP_UV=required node reference-rp/start.mjs
```

维护者在 Safari 打开 http://localhost:8789，确认 required、正确RP/origin、注册与Assertion实际PASS。填写真实设备与provider来源，分别导出注册、第一次Assertion和重复Assertion的脱敏报告。跨设备和Chrome扩展验收使用审核后的固定HTTPS地址。回传实际导出的报告、测试项编号、HTTPS访问与未授权拒绝结果、实际软件版本，以及失败或阻塞原因。

## Chrome/macOS UV Required 最终归档

2026-11-12，维护者提供三份 Dashboard 脱敏导出，并在核对浏览器元数据后明确确认实际使用 Chrome。本批记录归入 A5。报告原始字节保留，环境字符串沿用导出值，Provider 来源保持 `UNKNOWN`。

| 环境与策略 | 导出值 |
| --- | --- |
| 设备 / OS / 浏览器 | MacBookAir / MacOS 27.2 / Google Chrome 157.0.8103.39 |
| Provider 标签 / 来源 | 1Password / UNKNOWN |
| RP ID / Origin | localhost / http://localhost:8789 |
| 请求 UV / Counter | required / report-only |
| 实际 UP / UV / BE / BS | 三份均为 true / true / true / true |

| 报告 | capturedAt（UTC） | Core | 数据库提交 | 签名 / 计数器 |
| --- | --- | --- | --- | --- |
| [测试注册](interop/local-uv-required-registration-2026-11-12.redacted.json) | 2026-11-12T12:32:12.347Z | PASS，11项检查PASS | COMMITTED，null→0 | signature、counter、attestation_trust 均 NOT_PERFORMED |
| [第一次 Assertion](interop/local-uv-required-assertion-1-2026-11-12.redacted.json) | 2026-11-12T12:32:25.476Z | PASS，12项检查PASS | COMMITTED，0→1 | DER、signatureValid=true，signCount=0，NOT_SUPPORTED |
| [第二次 Assertion](interop/local-uv-required-assertion-2-2026-11-12.redacted.json) | 2026-11-12T12:32:29.280Z | PASS，12项检查PASS | COMMITTED，1→2 | DER、signatureValid=true，signCount=0，NOT_SUPPORTED |

注册的 AT=true、AuthenticatorData 长度162字节；两次 Assertion 的 AT=false、长度37字节。三份均 ED=false、RFU=0、crossOrigin=false、topOrigin=null，challenge 仅保留43字符长度。

数据库版本按三份导出依次初始化和递增。signCount 始终为0，未建立递增签名计数器证据。脱敏记录没有 credential ID 或完整 challenge，不能单独证明三份记录属于同一凭证或采用三个不同挑战。报告中的身份、challenge 检查结果按 Core 当时返回值记录。

本批提供 Chrome Required 记录，A1 Safari Required、A4 Google Password Manager、A6 Safari 重复认证及 iOS / 公网 HTTPS 项继续按上表待完成状态记录。`1Password` 为报告中的标签，`UNKNOWN` 不升级为独立 Provider 验证。

### 原始文件与摘要

下表对应原导出文件名和归档文件 SHA-256。仅变更归档文件名，文件内容逐字节一致。

| 原导出文件名 | 归档文件 | SHA-256 |
| --- | --- | --- |
| moonpasskey-report-2026-11-12T12-32-12.347Z.redacted.json | local-uv-required-registration-2026-11-12.redacted.json | fde491fc34ec512fc1c82e3f9958376906985ab039f6cf498866dc15cb0c0dcf |
| moonpasskey-report-2026-11-12T12-32-25.476Z.redacted.json | local-uv-required-assertion-1-2026-11-12.redacted.json | 14b8f254c9064e063d5c8c375c53a75bb093b768a0281e95034984a5591d60c1 |
| moonpasskey-report-2026-11-12T12-32-29.280Z.redacted.json | local-uv-required-assertion-2-2026-11-12.redacted.json | 0394bc95e7540038256bb7fd552d3201727e52c1194617a62e8779289070171c |

```sh
node --experimental-strip-types scripts/check-interop-reports.mjs
```

现有检查器默认扫描本目录，四份报告均通过，包含原 Safari preferred 报告及其摘要校验。v1 报告按既有 schema 和逐层字段允许列表校验，无需新增 sidecar。此次仅验证导出结构、脱敏和字段一致性，原始认证字节及签名不在报告中，验签结果为当时保存的 Core 结果。
