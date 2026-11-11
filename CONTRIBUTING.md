# 贡献指南

MoonPasskey Lab 使用 MoonBit 实现 WebAuthn / Passkey 协议解析、安全诊断与互操作测试。核心解析、安全规则和密码学验证归属 MoonBit Core，CLI 与前端消费实际 Core 结果。新增功能需要自动化测试，安全规则需要可追溯的技术依据。开发前完整阅读仓库约束、架构、标准映射与当前限制。[AGENTS.md](AGENTS.md) · [架构](docs/ARCHITECTURE.md) · [标准映射](docs/SPEC_MAPPING.md) · [当前限制](docs/LIMITATIONS.md)

## Phase、分支与 PR

- 每个后续 Phase 从最新可构建、可测试的 `main` 建立独立 feature branch，并通过独立 PR 交付。
- 保留现有 `feat/` 命名习惯，例如 `feat/phase-3-client-data`。Codex 默认创建的 `codex/` 前缀也适用，例如 `codex/phase-3-client-data`。
- 一个 PR 说明该 Phase 的目标、实现范围、测试证据、已知限制和后续计划。跨 Phase 的新增范围按独立分支和 PR 推进。
- 本次 Bootstrap 经用户明确授权，在现有 `feat/v0.1-core` 分支以一个 PR 整合已经完成的 Phase 1、Phase 2 及仓库维护流程。此例外仅适用于本次 Bootstrap，后续恢复逐 Phase 分支与 PR。
- `main` 必须保持可构建、可测试。提交与 PR 保留真实的实现顺序、运行结果和来源记录，禁止伪造历史、提交日期或验证证据。

## 开始修改前

先检查工作区、当前分支、远程地址、最近提交以及现有模块配置。

```sh
git status --short --branch
git branch --show-current
git remote -v
git log -5 --oneline
cat moon.mod
moon version --all
```

保留用户已有改动、模块身份和生成的项目结构。按实际环境排查工具链问题，依赖调整需要技术理由。遵守 AGENTS.md 的仓库保护要求，推送按用户明确授权的范围执行。

## 实现与测试

- MoonBit 文件按 `///|` 分隔代码块，每个包在自己的目录通过 `moon.pkg` 声明依赖。
- `_test.mbt` 通过公开 API 验证行为，`_wbtest.mbt` 用于包内实现。现有有效测试集中在 `base64url/`、`bytereader/` 与 `cbor/`，根包测试文件保留初始化脚手架。
- 每项支持功能补齐自动化测试，覆盖正常输入、错误路径、边界及所影响的集成入口。稳定结果优先使用 `assert_eq` 或模式断言，结构化快照使用 `Debug` 与 `debug_inspect`。
- 修改公开 API 后检查 `moon info` 生成的 `.mbti` 差异，并确认与预期一致。快照更新需审阅实际输出变化。
- 外部向量记录规范固定版本、章节、来源类别和许可。项目合成样本与官方规范示例须明确标注，派生变异说明原始来源和变换方式。当前 W3C 示例的许可声明随测试保留。[标准映射与测试来源](docs/SPEC_MAPPING.md) · [W3C 许可声明](cbor/W3C-NOTICE.md)
- 支持状态与限制随实现更新。当前 `Generic` 与 `Ctap2Canonical` 整体均为 `PARTIAL`，float、tag、indefinite-length 的行为按当前限制记录。解析、签名验证、信任评估和认证结论各自需要对应证据。[当前限制](docs/LIMITATIONS.md)

## 本地验收

在仓库根目录完成接口更新、格式化、检查、构建及四目标测试。

```sh
moon info && moon fmt
moon fmt --check
moon check
moon build
moon test --target wasm
moon test --target wasm-gc
moon test --target js
moon test --target native
git diff --check
git diff -- '*.mbti'
```

PR 测试报告填写实际工具链版本、命令、通过与失败数量及失败处理。新增或变更测试后更新计数。本次 Bootstrap 已验收的基线为每个目标 107 个测试，其中 Base64URL 24 个、ByteReader 20 个、CBOR 63 个。

## CI 环境

`MoonBit CI` 在 PR、`main` 推送及手动触发时运行，使用 Ubuntu 24.04 与 Node.js 24。四目标矩阵分别执行格式验证、生成接口比对、带 `--deny-warn` 的检查、测试、构建及现有入口运行。当前入口输出 `Hello`，协议分析 CLI 待后续实现。[CI 配置](.github/workflows/ci.yml)

CI 使用 MoonBit 官方安装脚本，归档版本固定为 `0.10.20+65efd5b93`，包含匹配的工具链与 core。此归档对应已验收的 moon `0.1.20261104` 与 moonc `v0.10.20+65efd5b93`。安装命令为 `bash moonbit-install.sh 0.10.20+65efd5b93`，脚本从官方 HTTPS 地址下载。更换版本时重新核验 API、生成接口与四目标测试。JavaScript 测试使用 Node.js，native 使用 runner 的 C 工具链，wasm / wasm-gc 使用安装包中的 moonrun。[官方安装说明](https://docs.moonbitlang.com/en/stable/tutorial/tour.html#installation)

CI 配置通过仓库策略要求合并前成功，GitHub Rulesets 和保护规则由用户另行确认设置。

## 提交约定

采用 Conventional Commits，每个 commit 聚焦一个可解释、可审阅的逻辑改动。按实际工作内容组织实现、测试、文档与流程改动，提交说明记录原因和影响。

```text
feat(base64url): add bounded URL-safe decoding
feat(cbor): add bounded decoding profiles
test(cbor): cover canonical encoding boundaries
docs: document protocol support limits
ci: verify MoonBit targets
```

使用 `feat`、`fix`、`test`、`docs`、`refactor`、`ci` 或 `chore` 等适合实际改动的类型。存在破坏性 API 变化时使用 `!` 并在正文写明 `BREAKING CHANGE`。提交前审阅暂存差异，确认未包含凭据、私密数据或无关改动。

## PR、CI 与合并

使用仓库 PR 模板，向审阅者交代项目背景、该 Phase 的交付范围与可复现证据。Bootstrap PR 需说明本次 P1/P2 合并交付例外，并将 Phase 3 标为后续计划。

PR 必须附本地测试报告和远程 CI 运行链接、状态。尚未执行的检查填写 `pending`，失败检查记录原因与处理。代码更新后重新核验受影响检查，并等待当前 PR 提交的 CI 全部通过，再申请合并。

申请合并时提供当前 PR、提交、测试结果和已知限制。合并必须获得用户明确授权，并在授权范围内执行。GitHub Release 与 Mooncakes 发布分别需要用户明确授权。
