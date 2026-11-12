# MoonPasskey Lab｜项目一页概览

**由 MoonBit 驱动的 WebAuthn / Passkey 协议分析与验证工具。** 面向调试认证流程、学习协议和复核测试结果的开发者，把浏览器返回的字节转换为可追溯的结构、策略检查与密码学验证结果。

## 要解决的问题

Passkey 调用返回的 JSON、二进制 flags、CBOR 公钥和 DER 签名分属不同层次。开发者需要知道一次失败发生在结构解析、RP 策略、签名还是状态提交，也需要辨明“解析成功”与“认证检查通过”的差别。

## 已交付的体验

在本地 Dashboard 完成测试注册与 Assertion，查看 ClientData、UP/UV/BE/BS、ES256/P-256、DER、计数器和逐项检查；也可导入请求，或通过 CLI 输出文本与脱敏 JSON 报告。CLI 与参考 RP 共用 MoonBit Core，协议规则集中实现。

```text
浏览器原生 Passkey → Vue Dashboard → Node / SQLite 参考 RP
                                           ↓
CLI ───────────────────────────────→ MoonBit Core → 脱敏报告
```

## 技术与复用价值

- MoonBit 实现 Base64URL、ByteReader、有界 CBOR、WebAuthn 结构解析、ES256 参数与 Assertion 策略；固定 MoonCrypt 后端完成 P-256 / SHA-256 验签。
- 保留原始 `clientDataJSON` 参与哈希，区分结构、参数、密码学与策略状态，错误附带适用的字段和字节位置。
- Core 在 native、js、wasm、wasm-gc 验证；参考 RP 提供挑战生命周期与 SQLite 原子提交范例，可作为协议教学、调试和 MoonBit 集成的起点。

## 已有证据与边界

| 证据 | 已记录结果 |
| --- | --- |
| 自动化回归 | 631 个独立用例：原有 581 项 + 部署套件 50 个独立叶用例；四目标重复运行只计一次 |
| 真实设备 | Safari/macOS 历史注册与 Assertion PASS；请求 UV=preferred，实际 UV=true，DER 有效、Core 12 项 PASS |
| 部署工程 | Ubuntu 22.04 隔离虚拟机中实际 Nginx / TLS / 访问控制测试通过；未部署公网服务器 |

Chrome/macOS UV Required 另有一次注册和两次 Assertion PASS，DER有效、数据库 COMMITTED，Provider 来源保持 UNKNOWN。当前支持 ES256 Assertion 和最小 `none` 测试登记，其他算法、attestation 信任与完整 WebAuthn 符合性待实现。Safari required、Google Password Manager、iOS 与公网 HTTPS 仍待验收。[设备记录](../../docs/ASSERTION-INTEROP.md)

项目使用 Apache-2.0 许可证。验收环境固定 MoonBit `0.10.20+65efd5b93`、MoonCrypt `0.4.16`、Node.js `24.18.0`。AI 辅助实现与审阅，维护者决定标准取舍、完成真实系统认证并负责最终接受。

[申报参考草稿](APPLICATION.md) · [架构](ARCHITECTURE.md) · [限制](LIMITATIONS.md) · [原始开发记录](../../docs/DEVELOPMENT.md) · [真实设备记录](../../docs/ASSERTION-INTEROP.md) · [部署验证](../../deploy/ubuntu-nginx/VALIDATION.md)
