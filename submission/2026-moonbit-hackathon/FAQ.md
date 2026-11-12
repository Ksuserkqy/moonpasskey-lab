# 答辩问答

## 1. 项目解决什么问题？

帮助开发者理解和调试 WebAuthn / Passkey 响应，把原始字节对应到结构、flags、签名、RP 策略与计数器结果，并明确哪些检查没有执行。可以在 Dashboard 操作，也可以用 CLI 或 MoonBit 包复用。

## 2. MoonBit 在项目中承担什么？

MoonBit 实现字节解析、ES256 参数与密码学适配、Assertion 策略和统一分析报告。Node 管理 HTTP(S)、随机挑战、会话与 SQLite 事务，Vue 负责浏览器原生调用和展示；它们使用同一 MoonBit Core 的结果。当前网页运行的是 Node 上的 JS Core，浏览器直接 Wasm 集成尚未实现。

## 3. 展示的 Passkey 是真实设备产生的吗？

仓库保留一组历史 Safari/macOS 真实平台 Passkey 证据：维护者完成系统注册和认证，UV 请求为 preferred、实际 true，DER 有效、Core 12 项 PASS。iCloud Keychain / 平台 Passkey 标签按维护者选择记录。演示导入的合成夹具会明确标识，不能当作新增设备验收。

## 4. 一次 PASS 能说明什么？

说明所选入口执行的检查通过。独立解析不自动执行 RP 策略；最小 `none` 测试登记不执行 attestation 信任；导入分析没有数据库提交。应同时看逐项状态、实际 flags 和 `NOT_PERFORMED`，完整限制见 [能力边界](LIMITATIONS.md)。

## 5. 为什么 Assertion 使用 DER，而基础验签还有 raw64？

WebAuthn ES256 wire 签名是 DER，基础 ECDSA 入口使用固定宽度 `R || S`。维护者明确选择保持两个格式契约：Assertion 接收严格 DER，检查后转换并调用原语；基础接口继续接收 raw64。原始浏览器签名因此可直接进入 Assertion 验证。[开发决策](DEVELOPMENT_STORY.md)

## 6. 为什么要保留原始 ClientDataJSON？

验签使用原始 `authenticatorData || SHA256(clientDataJSON)`。空白、顺序和转义都属于原始字节，重新序列化字段会改变哈希输入。项目传输并保留浏览器返回的字节，同时提供解析范围和适用错误位置。

## 7. signCount 为 0 仍然 PASS 正常吗？

0→0 记录为 `NOT_SUPPORTED`，不能据此声称已验证递增计数器。其他非递增情况在默认 ReportOnly 策略下报告风险，更新建议保留历史最大值；显式 Reject 可拒绝风险。计数器不是所有凭证通用的克隆判据。

## 8. 631 项测试如何统计？

Core 491、CLI 7、RP / 预检 57、Dashboard / 报告 26，加部署 50 个独立叶用例，共 631 项。四目标重复运行只计一次。部署 Node 统计为 51/51，包含一个父测试；向量循环中的条目也不额外计入总数。数字来自已有验收记录，并非此次整理新执行的测试。

## 9. Ubuntu / Nginx 是否已经上线？

已经在 Ubuntu 22.04 隔离虚拟机中实际测试 Nginx 配置、Basic Auth、代理传输、上游 TLS 及错误证书拒绝。真实服务器、公网域名 / DNS、Let's Encrypt 和公网 HTTPS 设备流程尚未执行；配置准备和本地测试不作为上线证据。

## 10. AI 做了什么，维护者做了什么？

AI 辅助 API 调查、实现、测试、静态审阅与文档。维护者定义阶段目标和授权边界，决定 DER 接口取舍，亲自完成真实系统认证，并负责最终接受。AI 相互审阅不记为人工代码审查或独立安全审计。

## 11. 其他项目如何复用？

可按 Apache-2.0 使用 MoonBit 解析 / 验证包，调用 analysis JSON 接口，或参考 CLI 与 Node / SQLite 宿主的集成方式。复用时须保留依赖许可，提供可信 RP 策略与账户记录，落实 challenge 生命周期及状态提交，并在自己的设备、目标和部署环境重新验证。

## 12. 当前最优先的后续工作是什么？

完成 Safari UV required、iOS 与 Chrome 的实际设备验收，以及受保护 HTTPS 的部署和访问控制验证；再推进独立审查。其他算法、attestation 信任、模糊测试和性能基准属于后续工作，本次功能冻结不将其计为已交付能力。

[申报稿](APPLICATION.md) · [架构](ARCHITECTURE.md) · [原始开发证据](../../docs/DEVELOPMENT.md) · [真实设备矩阵](../../docs/ASSERTION-INTEROP.md) · [部署验证](../../deploy/ubuntu-nginx/VALIDATION.md)
