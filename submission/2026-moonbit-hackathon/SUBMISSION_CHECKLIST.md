# 参赛提交清单

截至 2026-11-12，材料整理基线为 `582de40`。勾选表示已有对应仓库证据，实际报名和审核进度由维护者填写。规则依据和待确认口径见 [参赛资格核对](ELIGIBILITY.md)。

## 已有工程材料

- [x] 公开 GitHub 仓库、Apache-2.0 许可证、可追踪提交与 PR 历史。
- [x] MoonBit 协议解析、ES256 验签和 Assertion 策略核心，配套 CLI、参考 RP 与 Dashboard。
- [x] 已保存 631 个独立用例的基线记录，测试口径和范围见 [测试证据](TEST_EVIDENCE.md)。
- [x] 固定旧提交 `6e4136b` 的六项远程 CI 成功记录。
- [x] Safari/macOS preferred 真实 Passkey 的脱敏报告与来源记录。
- [x] Ubuntu22/Nginx 隔离实测、部署操作说明及回滚说明。
- [x] 自有源码逐文件盘点，生产、测试、fixture 与工具分列。

## 材料最终检查

- [x] README、约 4 分 40 秒演示脚本、架构图及实际截图已提供。
- [ ] 申报书由维护者亲自撰写，一页 Markdown，覆盖至少三个完整使用场景、目标、核心功能、路线和参考来源。
- [ ] 维护者能解释 AI 辅助代码、技术取舍、测试证据和支持边界。
- [x] 已提供分支 Actions 核对入口，最终 SHA 和六项检查结果可从堆叠 Draft PR 核对。
- [x] 已核对材料 diff、本地文件链接、来源许可和脱敏输出。
- [ ] Mooncakes 发布已完成并保留版本链接，或获得赛事组对此交付形式的明确答复。

## 维护者与赛事组确认

- [ ] 通过官网报名表完成申报并保存最后有效提交时间、审核邮件与获批范围。
- [ ] 确认新生态项目或季度社区方向，说明仓库创建、开发和审核通过时间的关系。
- [ ] 确认十一月报名及验收截止时间，记录官方通知来源。
- [ ] 确认 MoonBit 有效 LOC 的阈值、测试和 fixture 计入方式、采用的统计工具。
- [ ] 确认最终材料入口、文件格式、项目故事或视频要求。
- [ ] 队伍人数与全部 GitHub ID 已确认，成员已加入赛事群并设置 GitHub ID 昵称。
- [ ] 已向赛事组说明相似生态项目与本项目新增贡献，维护者确认本届有效工作范围。

报名表入口来自十一月赛事官网。章程现有日期存在历史内容，具体时间按十一月官方通知确认。[十一月官网](https://moonbitlang.github.io/Hackathon2026/) · [报名表](https://bxup9uklfcb.feishu.cn/share/base/form/shrcnWUMlgpbwHaXgzV7HmNhNhg)

## 范围声明

新 UV Required、iPhone 与 Chrome 设备验收仍待完成，真实公网部署和 Let's Encrypt 仍待执行。当前材料只使用已保存的真实 Safari 报告以及明确标注的合成测试记录。完整 attestation 信任、生产账户认证与恢复的支持状态见项目限制文档。[限制说明](../../docs/LIMITATIONS.md) · [设备矩阵](../../docs/ASSERTION-INTEROP.md)
