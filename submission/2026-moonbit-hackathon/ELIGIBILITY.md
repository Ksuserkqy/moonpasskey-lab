# 参赛资格核对

核对日期为 2026-11-12。当前状态为 **待赛事组确认**。仓库材料已经准备，报名、通过审核、参赛方向和奖励资格仍需维护者提供实际记录。

## 官方规则与时效

中文官网当前横幅指向十一月赛。活动实时页面明确支持新项目及已有项目的本期实质新增，要求 MoonBit 为主要实现语言，并以通过审核前最后一次有效表单提交或修改作为报名时间。十一月报名和验收截止日期均交由官方通知确定。[MoonBit 中文官网](https://www.moonbitlang.cn/) · [十一月赛事官网](https://moonbitlang.github.io/Hackathon2026/)

赛事官网链接的飞书章程已通过浏览器只读核对，页面显示 10 月 30 日修改，但部分流程标题仍写 9 月 30 日，时间表仍列 8—10 月。以下条款应与十一月官方通知一并确认，旧日期不能直接作为本期截止日期。[赛事章程](https://bxup9uklfcb.feishu.cn/wiki/Dx4Bwd6D1i3GfHkajQCcF7SznEd)

| 核对项 | 官方条款与本项目状态 |
| --- | --- |
| 新项目或社区方向 | 章程 §3.2、§4.1、§4.2、§5.2 区分新生态项目建设与季度社区维护方向。社区方向要求参赛者为主要贡献者，允许其他贡献者。维护者须向赛事组确认本项目归属。 |
| 选题重合 | §4.1 要求核对 Mooncakes 现有项目，类似项目须说明新增价值。现有对比见 [竞品分析](../../docs/COMPETITIVE_ANALYSIS.md)，最终选题判断由赛事组作出。 |
| 申报书 | §5.1 要求人工撰写、一页 Markdown、至少三个完整预期使用场景，以及目标、功能、路线、来源和仓库。仓库中的 AI 辅助草稿需由维护者亲自撰写确认后提交。 |
| 开发记录 | §5.1 要求至少 10 个有效 commits，禁止空提交或无意义拆分。提交数量和时间可核验，实质有效性仍由评审判断。 |
| 验收材料 | §5.1 要求公开源码、README、可复现样例、核心路径测试、覆盖 check/build/test 的 CI、OSI 许可证与 Mooncakes 发布。当前没有 Mooncakes 发布证据，须完成或获得赛事组明确口径。 |
| 有效贡献 | §6 要求本届新增且可验证的开发或维护贡献。历史成果和既有完成度需如实申报。 |
| 组队和入群 | 十一月官网要求最多三人，队长填队员 GitHub ID，参加赛事群并将昵称设为 GitHub ID。队员、入群和报名记录待维护者填写。 |
| 代码行数 | 实时首页没有数值阈值。已核对章程的申报、验收、激励和开源条款中尚未核得明确数值，须询问十一月是否存在有效 MoonBit LOC 下限、测试是否计入及统计工具。 |
| 创建与审核时间 | 首页给出报名时间判定，章程描述审核通过后启动。仓库创建与首次提交时间见下表，审核时间尚无证据。须确认已完成代码在新项目方向的计算方式，不能从仓库日期自行推定通过。 |
| 最终格式与故事 | 首页要求代码、README、测试和可复现演示说明。最终申报入口、材料格式、项目故事或演示视频的硬性要求须按十一月通知确认。 |

## 历史仓库快照

下表保留 `582de40` 材料整理时的历史基线。PR 的当前合并状态见下一节。

| 项目 | 2026-11-12 只读核验结果 |
| --- | --- |
| 仓库 | [Ksuserkqy/moonpasskey-lab](https://github.com/Ksuserkqy/moonpasskey-lab)，public |
| GitHub created_at | 2026-11-11T06:40:51Z，即北京时间 14:40:51 |
| 首个提交 | `3cb961863e97e8fe1ea1abd9bd5eb85e5568783f`，2026-11-11T16:59:26+08:00 |
| 历史提交数量 | `582de40` 共 41 commits，其中 34 个非 merge commits，实质有效性待评审 |
| 功能冻结基线 | `582de401fba9b1ec816f1c26003395bae7589ea5` |
| PR #8 历史状态 | 初次整理时为 Draft/OPEN，head 为 `6e4136bac9f18dd88359e5b783ccdd9ee160636c`，六项 CI 成功 |
| 报名、审核邮件 | 未提供，维护者待补 |

仓库元数据可用 `gh api repos/Ksuserkqy/moonpasskey-lab` 只读复核。首次提交可用 `git log --reverse --format=fuller` 复核。提交历史本身不能证明报名审核已经通过。

## 已核实的合并记录与修订前 CI

2026-11-12 通过 GitHub API 重新核验以下记录。本表固定本次修订提交创建前的核验快照。

| 记录 | 当前状态与对应提交 |
| --- | --- |
| PR #8 | 已于 `2026-11-12T10:58:03Z` 合入 `main`，head 为 `6e4136bac9f18dd88359e5b783ccdd9ee160636c`，merge commit 为 `6947564bccd421bccef8e3337ff5bab4db6347cc`。[PR #8](https://github.com/Ksuserkqy/moonpasskey-lab/pull/8) |
| PR #9 | 已于 `2026-11-12T11:00:31Z` 合入 `feat/p7-1-interoperability-closure`，head 为 `85e63f3c48c43ae7d6303a6807697dcf4d91761e`，merge commit 为 `e944fd1cf8f7026ed8bed2489b70e02b36162084`。该合并的目标分支为 P7.1。[PR #9](https://github.com/Ksuserkqy/moonpasskey-lab/pull/9) |
| 功能分支已验 CI | `85e63f3c48c43ae7d6303a6807697dcf4d91761e` 对应六个 job 均 success。[运行 43199498333](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43199498333) |
| main 已验 CI | `6947564bccd421bccef8e3337ff5bab4db6347cc` 对应六个 job 均 success。[运行 43204987911](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43204987911) |
| 本次最终修订的核对入口 | 新 PR 的 head SHA 与实际运行链接在该 PR 的验收说明中记录，可通过对应功能分支的 Actions 查证。[分支 Actions](https://github.com/Ksuserkqy/moonpasskey-lab/actions?query=branch%3Afeat%2Fp7-2-ubuntu-nginx-deployment) |

## 自有源码盘点

在仓库根目录执行下列命令，可从指定 Git commit 重建统计，不读取依赖或构建目录。

```sh
python3 submission/2026-moonbit-hackathon/count-source.py 582de40
```

| 语言与范围 | 文件 | 物理行 | 非空行 |
| --- | ---: | ---: | ---: |
| MoonBit 生产实现 | 20 | 4,203 | 3,988 |
| MoonBit 测试 | 19 | 16,455 | 15,909 |
| MoonBit fixture 命名源码 | 2 | 399 | 389 |
| JavaScript 生产实现 | 7 | 769 | 722 |
| JavaScript 测试 | 13 | 1,948 | 1,822 |
| JavaScript fixture | 2 | 68 | 64 |
| JavaScript 工具 | 2 | 470 | 448 |
| TypeScript 生产实现 | 3 | 587 | 554 |
| TypeScript 测试 | 2 | 646 | 612 |
| TypeScript 工具 | 1 | 8 | 7 |
| Vue 生产实现 | 1 | 853 | 825 |
| Shell 部署工具 | 6 | 262 | 246 |
| Shell 测试入口 | 1 | 19 | 18 |

物理行和非空行包含注释，不能直接称为有效 LOC。统计仅纳入已提交的项目自有 `.mbt/.mjs/.js/.ts/.vue/.sh`，排除 `.mooncakes`、`node_modules`、`_build`、生成 `.mbti`、资产、配置、文档和参赛统计脚本。fixture 命名文件单列，含向量断言的测试文件仍归测试。逐文件清单保存在 [source-counts.json](source-counts.json)。生产 MoonBit 承担协议解析、策略和验签，Node/Vue 提供宿主及演示界面。MoonBit 主要语言的验收认定仍以赛事组为准。
