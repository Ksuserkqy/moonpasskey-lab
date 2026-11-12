# 最终参赛验收报告

核对日期为 2026-11-12，结论为 **PASS_WITH_WARNINGS**。工程与展示材料已具备评审入口，真实设备覆盖为部分完成，报名与资格确认仍需维护者完成。

## 工程基线与本次范围

PR #10 已于 `2026-11-12T12:23:24Z` 合入 main，merge commit 为 `fee2974859779b11a5264594234b6812a54b3dd8`。本次在独立 feature 分支归档脱敏报告并同步文档，生产源码、依赖、密码学实现与已有测试保持基线内容。[PR #10](https://github.com/Ksuserkqy/moonpasskey-lab/pull/10)

已实现 MoonBit Base64URL / ByteReader / 有界 CBOR、WebAuthn 结构解析、ES256/P-256/SHA-256/DER Assertion 验证、RP 策略、挑战生命周期与 SQLite 原子提交。CLI、Reference RP、Vue Dashboard 和 Ubuntu/Nginx 部署工程围绕现有 Core 提供运行与复核入口。[项目概览](PROJECT_OVERVIEW.md) · [架构](ARCHITECTURE.md)

## 自动化证据

独立用例继续为 **631**，按 Core491、CLI7、RP/预检57、Dashboard/报告26、部署50统计。跨目标重复执行只计一次，新增三份设备报告单独记录。

| 证据 | 核验结果 |
| --- | --- |
| PR #10 head `cf01dcb457daa06eebc6a1c4800b5845930155f7` | 四目标各 Core491/491、CLI7/7，RP57/57、Dashboard26/26 |
| main `fee2974859779b11a5264594234b6812a54b3dd8` | 六项 CI completed/success，包含 wasm、wasm-gc、js、native、RP、Dashboard |
| 本轮既有报告检查器 | 三份原导出均 schema v1 PASS，归档默认扫描共4份PASS |
| 本轮 Dashboard / 报告回归 | 26/26，0失败 |
| 本轮一次性字段交叉核对 | 原文件/归档字节一致，时间顺序、环境、required UV、COMMITTED版本、DER与计数器一致 |
| Ubuntu 22.04 隔离虚拟机历史实测 | 部署51 TAP项、50独立叶用例、0跳过，含实际 Nginx 和 systemd unit 检查 |

[PR #10 head CI](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43210565358) · [main CI](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43217448307) · [详细测试证据](TEST_EVIDENCE.md) · [Ubuntu 实测范围](../../deploy/ubuntu-nginx/VALIDATION.md)

本轮执行的主要命令如下，Node 固定为24.18.0。

```sh
node --experimental-strip-types scripts/check-interop-reports.mjs
npm --prefix dashboard test
git diff --check
```

另以只读脚本核对原始文件 SHA-256、归档字节、报告间字段和 Markdown 引用。此次按数据和文档变更范围执行检查，完整四目标结果引用上表固定 CI 提交。

## 真实设备证据

历史 Safari/macOS preferred 报告继续保留，实际 UV=true、DER有效、Core12项PASS，Provider 来源为 MAINTAINER_SELECTED，旧事务字段为 UNKNOWN。

本次三份报告的 browser 均为 Google Chrome 157.0.8103.39。维护者在发现与任务最初 Safari 描述的差异后，明确确认实际使用 Chrome，按报告原值归档。设备/系统字段为 MacBookAir / MacOS 27.2，Provider 标签为1Password、来源 UNKNOWN。RP为 localhost，Origin为 `http://localhost:8789`，UV required、counter report-only。

| 导出 | UTC时间 | 实际保存结果 |
| --- | --- | --- |
| 注册 | 12:32:12.347 | PASS，UP/UV/BE/BS=true，COMMITTED null→0；signature / counter / attestation_trust 均 NOT_PERFORMED |
| Assertion 1 | 12:32:25.476 | Core12项PASS，DER有效，COMMITTED 0→1，signCount0 / NOT_SUPPORTED |
| Assertion 2 | 12:32:29.280 | Core12项PASS，DER有效，COMMITTED 1→2，signCount0 / NOT_SUPPORTED |

A5 Chrome/macOS UV Required 更新为 PASS。原始文件字节与摘要、归档链接及逐项范围集中保存在设备文档。[设备矩阵与归档](../../docs/ASSERTION-INTEROP.md#chromemacos-uv-required-最终归档)

验证脚本检查报告结构、允许字段、脱敏及状态一致性。签名有效和数据库提交为原导出保存的结果，报告缺少原始认证字节，无法据此重新验签。数据库版本递增与 signCount 是不同字段。三份脱敏报告没有 credential ID 或完整 challenge，独立确认同一凭证和不同挑战需要维护者流程记录。

## 剩余矩阵与技术限制

- A1 Safari/macOS UV Required、A6 Safari重复认证仍为 NOT_PERFORMED。
- A2/A3 iOS注册、Assertion及跨设备HTTPS受已验证HTTPS入口缺项阻塞。
- A4 Google Password Manager、A7 Windows Hello、A8 USB FIDO2、A9 NFC FIDO2仍为 NOT_PERFORMED。
- 1Password 为报告标签，Provider 身份来源继续 UNKNOWN。
- 真实服务器、DNS、Let's Encrypt申请/续期、公网HTTPS设备流程仍待执行。Ubuntu记录来自隔离虚拟机及临时合成材料。
- 当前支持 ES256 Assertion 和最小 none 测试登记。完整 attestation 信任、其他算法、完整 WebAuthn 符合性、生产账户/恢复、分布式协调、独立安全审计、模糊测试及性能基准仍有未实现或缺证据范围。[限制说明](LIMITATIONS.md)

## 材料完整性与人工操作

README、项目概览、申报参考稿、架构图、产品截图、CLI/网页演示、约4分40秒讲解稿、AI辅助开发历程、测试记录和清单均已提供。既有截图分别记录首页和 SYNTHETIC 分析，新增 Chrome 证据使用脱敏 JSON 归档。[README](../../README.md) · [演示稿](DEMO_SCRIPT.md) · [截图来源](assets/README.md) · [提交清单](SUBMISSION_CHECKLIST.md)

维护者后续操作如下。

1. 审查本次证据归档与文档分支，决定是否合入 main。
2. 亲自撰写一页 Markdown 正式申报书，核对三个完整场景，并填写作者、团队及赛事所需信息。当前 APPLICATION 为 AI 辅助事实参考。
3. 按十一月官方口径确认方向、开发/审核时间、有效LOC、最终格式、报名审核记录及入群事项。
4. 补充 Mooncakes 发布版本链接，或取得赛事组对交付形式的明确答复。
5. 按需补充 Provider 来源与同一凭证流程说明，并执行剩余设备和受保护 HTTPS 验收。

资格与评审结果由赛事组确认，当前材料保留待确认状态。[申报参考](APPLICATION.md) · [资格核对](ELIGIBILITY.md)
