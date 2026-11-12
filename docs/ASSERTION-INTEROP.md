# 浏览器与真实设备互操作记录

## Phase 7 当前执行状态

2026-11-12，已在这台 Mac 的 Safari 打开本地 Dashboard，参考 RP 已连接，原生 WebAuthn 注册入口可用。维护者报告已完成系统 Passkey 注册与认证，但当前读取的 Safari 页面仍显示未登记，成功报告尚待定位与核对。当前真实设备完整成功记录仍为 **NOT_PERFORMED**，取得实际 Core 结果后更新。自动化签名测试均标注为项目合成数据。

| 环境 | 设备与软件 | Provider | 注册 | Assertion/Core |
| --- | --- | --- | --- | --- |
| Safari + macOS | Mac16,12，macOS 27.2.1 build26B131，Safari27.2 | 用户选择 iCloud Keychain / 平台 Passkey，待系统流程确认 | NOT_PERFORMED | NOT_PERFORMED |
| Safari + iOS | NOT_RECORDED | iCloud Keychain | NOT_PERFORMED | NOT_PERFORMED |
| Chrome + Google Password Manager | NOT_RECORDED | Google Password Manager | NOT_PERFORMED | NOT_PERFORMED |
| Chrome + Windows Hello | NOT_RECORDED | Windows Hello | NOT_PERFORMED | NOT_PERFORMED |
| USB FIDO2 | NOT_RECORDED | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |
| NFC FIDO2 | NOT_RECORDED | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |

机型、系统和 Safari 版本来自本机只读系统元数据，完整设备认证结果尚待执行。RP ID 为 localhost，Origin 为 http://localhost:8787，服务监听127.0.0.1。默认 UV preferred、counter report-only。

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
