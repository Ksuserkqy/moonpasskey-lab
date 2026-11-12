# 浏览器与真实设备互操作记录

## Phase 7 当前执行状态

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
