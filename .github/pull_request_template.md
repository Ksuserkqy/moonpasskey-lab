## 背景与 Phase

<!-- 简述 MoonPasskey Lab 中本次工作的目标、所属 Phase，以及它与已有 MoonBit Core 的关系。 -->

- Phase 与目标
- 分支与关联任务
- 本次 Bootstrap 如适用，说明用户已授权将现有 P1/P2 整合到一个 PR，后续恢复逐 Phase 独立分支与 PR

## 实现范围

<!-- 列出已完成的包、公开 API、行为变化及所涉及的架构层。说明有证据支持的实现状态。 -->

- 已完成内容
- 公开 API 与 `.mbti` 变化
- 核心解析、安全规则与前端调用的影响

## 测试报告

<!-- 按实际执行填写版本、命令、数量和结果。未执行填 pending，失败记录原因与处理。Bootstrap 本地验收基线为每个目标 107 通过、0 失败，后续按实际改动更新。 -->

| 环境 | 实际版本 |
| --- | --- |
| 操作系统与架构 | 待填写 |
| moon / moonc / moonrun | 待填写 |

| 检查 | 结果或通过 / 失败数量 | 证据与说明 |
| --- | --- | --- |
| `moon info && moon fmt` | pending | |
| `moon fmt --check` | pending | |
| `moon check` | pending | |
| `moon build` | pending | |
| `moon test --target wasm` | pending | |
| `moon test --target wasm-gc` | pending | |
| `moon test --target js` | pending | |
| `moon test --target native` | pending | |
| `git diff --check` | pending | |
| 远程 CI，当前 PR 提交 | pending | 填写 Actions 运行链接及对应 commit |

## 支持状态与限制

<!-- 写明 IMPLEMENTED / PARTIAL / NOT_IMPLEMENTED 的实际范围与错误行为。Bootstrap 的 Generic 和 Ctap2Canonical 整体均为 PARTIAL，float、tag、indefinite-length 的当前限制需与 docs/LIMITATIONS.md 一致。 -->

- 当前支持范围
- 已知限制及 unsupported 行为
- 安全、兼容性或破坏性 API 影响
- 解析、签名验证、信任评估与认证结论的实际完成状态

## 标准依据与测试来源

<!-- 提供规范固定版本、章节与仓库映射位置。外部 fixture 写明来源、许可和 NOTICE，项目合成输入及派生变异标明类别和生成方式。 -->

- 标准依据与映射
- 测试向量来源及许可

## 后续计划

<!-- Bootstrap PR 说明 Phase 3 的计划目标、边界与预期测试，并按后续独立 Phase 分支 / PR 推进。 -->

- 下一 Phase 的范围
- 待补证据与验证计划

## 合并确认

- [ ] 已审阅 diff，提交符合 Conventional Commits 并按逻辑改动组织
- [ ] 已检查公开接口变化、标准映射、限制与变更记录
- [ ] 已附实际测试报告，失败与 pending 项已明确记录
- [ ] 当前 PR 提交的 CI 全部通过，可申请合并
- [ ] 用户已明确授权合并，授权依据已记录在 PR 或对应对话中

<!-- CI 通过后再申请合并。收到用户明确合并授权后，按授权范围执行。 -->
