# Phase 6 变更记录

项目完整阶段历史见仓库根目录的 [CHANGELOG](../CHANGELOG.md)。本文件记录任务要求的 P6 交付变化，发布状态属于 Unreleased。

- 新增 AssertionVerificationRequest、AssertionCredentialRecord、AssertionVerificationPolicy、AssertionVerificationResult、AssertionCredentialUpdate 及可区分的错误模型。
- 新增 UserVerificationRequirement、AssertionUserIdentification、CounterRiskPolicy、CounterStatus，以及具有安全默认值的策略构造器。
- 新增统一验证入口，复用原始 JSON/authData 解析和 ES256 DER 验签，完成 challenge、Origin、crossOrigin/topOrigin、RP ID hash、身份绑定与 flags 策略。
- 默认 ReportOnly 报告非递增风险，显式 Reject 才将该风险作为失败。建议更新保留计数高水位、已知/未知 BE 与当前 BS，只在完整验证成功后返回。
- 新增协议和策略正反回归、44个固定项目合成签名、三组 W3C 官方集成上下文。原有 P1–P5 测试继续保留，实际数量和四目标结果见开发记录。
- 更新架构、标准映射、限制和威胁模型，增加真实设备测试步骤与 `NOT_PERFORMED` 矩阵。

P6 继续使用 MoonCrypt 0.4.16 和固定 MoonBit 0.10.20+65efd5b93，所选生产路径使用纯 MoonBit。调用方负责外层响应检查、可信账户查询、挑战随机性/有效期/一次性消费、事务或 CAS 状态提交、uvInitialized 与附加认证因素策略。AppID 特例、其他算法和注册信任验证继续留在当前支持范围之外。[开发记录](DEVELOPMENT.md) · [当前限制](LIMITATIONS.md)
