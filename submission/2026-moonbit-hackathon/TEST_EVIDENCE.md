# 测试与运行证据

记录日期为 2026-11-12。功能冻结基线为 `582de401fba9b1ec816f1c26003395bae7589ea5`。本页汇总已有基线实测与本次参赛整理的针对性复验。

## 独立用例口径

| 套件 | 独立用例 | 已保存结果 |
| --- | ---: | --- |
| MoonBit Core | 491 | native/js/wasm/wasm-gc 各通过 491 |
| CLI | 7 | 四目标各通过 7，独立数量只计一次 |
| Reference RP 与 HTTPS preflight | 57 | 57 通过 |
| Dashboard 与报告校验 | 26 | 26 通过 |
| Ubuntu/Nginx 部署 | 50 | 50 个叶用例通过 |
| **合计** | **631** | **491 + 7 + 57 + 26 + 50** |

部署套件的 Node TAP 汇总为 51 项，其中一个父测试汇总七个 Nginx 子测试。因此部署独立叶用例为 50，不能将 TAP 的 51 再与既有 581 相加。四目标重复执行同一 Core/CLI 用例也不重复累计。详细历史记录见 [开发记录](../../docs/DEVELOPMENT.md) 和 [P7.2 实际验证](../../deploy/ubuntu-nginx/VALIDATION.md)。

## 工具链与本地结果

固定 MoonBit/compiler/core 为 `0.10.20+65efd5b93`，MoonCrypt 为 `0.4.16`，Node 为 `24.18.0`。P7.2 记录四目标 info/check/test/build/run、`moon fmt --check`、Dashboard 类型检查与生产构建、历史脱敏报告检查均通过。Ubuntu 22.04.5 arm64 隔离虚拟机实际运行 Nginx 1.18.0、ShellCheck 0.8.0、systemd 249，部署 51 TAP 项全部通过且零跳过，RP57 和 Dashboard26 另在 Ubuntu 复验通过。macOS 缺 Nginx 时的跳过结果没有作为 Ubuntu 运行证据。[本地完整验证与环境摘要](../../deploy/ubuntu-nginx/VALIDATION.md)

原始验证保留两项工具提示。npm 报告可选 fsevents 安装脚本未获许可，后续检查及构建通过。systemd-analyze 对镜像已有 snapd unit 的 RestartMode 输出提示，项目 unit 校验 exit0。详见原始验证记录。

## 历史 CI 快照

| 提交与范围 | 状态与链接 |
| --- | --- |
| P7.1 `6e4136bac9f18dd88359e5b783ccdd9ee160636c` | 六项 SUCCESS，四个 MoonBit 目标、RP、Dashboard。[运行 43164703998](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43164703998) |
| P7.2 `582de40` | 本地 Ubuntu 结果已记录，该基线尚无对应远程运行证据 |

该表记录历史基线。PR #8 已合入 main，PR #9 已合入 P7.1 分支，当前核验见下节。

## 已核实的合并记录与修订前 CI

2026-11-12 通过 GitHub API 核验 run 的 `head_sha`、状态以及全部六个 job。下表固定本次修订提交创建前的快照，四个 MoonBit 目标、Reference RP and concurrency、Vue dashboard 均 completed/success。

| 提交与范围 | 实际核验结果 |
| --- | --- |
| 功能分支 `85e63f3c48c43ae7d6303a6807697dcf4d91761e` | PR #9 的 head，六项 success。[运行 43199498333](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43199498333) |
| main `6947564bccd421bccef8e3337ff5bab4db6347cc` | PR #8 的 merge commit，六项 success。[运行 43204987911](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43204987911) |
| 本次最终材料修订的核对入口 | 按新 PR 的完整 head SHA 核对六项检查，固定运行链接记录在其验收说明中。[分支 Actions](https://github.com/Ksuserkqy/moonpasskey-lab/actions?query=branch%3Afeat%2Fp7-2-ubuntu-nginx-deployment) |

PR #8 于 `2026-11-12T10:58:03Z` 合入 main，head 为 `6e4136bac9f18dd88359e5b783ccdd9ee160636c`。PR #9 于 `2026-11-12T11:00:31Z` 合入 `feat/p7-1-interoperability-closure`，merge commit 为 `e944fd1cf8f7026ed8bed2489b70e02b36162084`。最终修订的完整 SHA 与 CI 结果在新 PR 创建及运行后记录到该 PR 的验收说明中。[PR #8](https://github.com/Ksuserkqy/moonpasskey-lab/pull/8) · [PR #9](https://github.com/Ksuserkqy/moonpasskey-lab/pull/9)

现有 CI 覆盖四目标与 RP/Dashboard 六个 job。部署套件的 Ubuntu22 实测来自本地隔离环境，631 独立用例的组成与口径保持上表记录。每个绿色运行仅证明其列明提交的对应 CI 通过。

## 参赛整理的实际复验

本次修改限于 Dashboard 的说明与输入来源展示、演示脚本及公开夹具、项目元数据和文档资产。Core 源码及已有测试文件的差异为空。独立测试数量继续为 631，演示调用次数单独记录。

| 验证 | 本次实际结果 |
| --- | --- |
| Dashboard 类型检查 / 26 项现有测试 / 生产构建 | PASS |
| 项目元数据修改后的 JS `moon check --deny-warn` | PASS |
| `bash -n scripts/demo.sh` | PASS |
| 七个 SYNTHETIC 场景的文本与 JSON CLI | 14 次调用全部匹配状态、退出码、检查及错误类型 |
| 错误字节位置演示 | 单字节 AuthenticatorData 返回 UnexpectedEnd / authData.rpIdHash / offset=0，exit2 |
| 本地 Dashboard / 会话 / 实际 Core HTTP | 页面200、UV required、导入有效夹具 PASS / signatureValid=true |
| 干净源码副本 | 排除项目依赖与构建产物后，实际 npm ci、构建、14 次 CLI 与 HTTP/Core 验证通过，复用宿主缓存及依赖索引 |
| 历史报告检查 | 通过，原 Safari 报告 SHA-256 与基线一致 |
| 本地 Markdown 文件链接 / SVG XML / diff 空白 | 通过 |

截图取自实际 Safari 界面。CLI 图展示实际 stdout 的浏览器排版页，输出原文一并保存。新增导入展示标记说明输入来源，验证结果继续来自 Core。干净源码副本的依赖安装提示和具体范围见演示稿。[演示记录](DEMO_SCRIPT.md) · [截图来源](assets/README.md)

## 最终修订的本地复验

2026-11-12，针对 main 快速开始、PR 状态说明、完整验签输入措辞及图片扩展名完成以下复验。修订后的远程四目标结果按上方新 PR 核对入口查证。

| 检查 | 实际结果 |
| --- | --- |
| README 文件关系与命令 | README.md 继续链接 README.mbt.md，clone 明确使用 main |
| 图片格式及字节 | 三张 JPEG 魔数 FFD8FF，改名为 .jpg，逐文件 SHA-256 与原文件一致 |
| 文档引用 | 38 份 Markdown、143 个相对引用、4 个锚点通过 |
| CLI 演示 | 七组 SYNTHETIC 输入、十四次普通 CLI 调用全部匹配预期 |
| 干净源码启动 | 排除依赖及构建产物后，moon update、Core/CLI 构建、npm ci、Dashboard 构建、本地 HTTP200 及真实 Core 导入验证通过 |
| 部署本机回归 | TAP 43 PASS、0 FAIL、1 组 SKIP，该组对应 7 个 Nginx 运行叶用例 |
| 格式、Shell 与报告 | moon fmt --check、Bash 语法、ShellCheck、历史报告检查、git diff --check 通过 |

干净副本复用了宿主 MoonBit 索引、包缓存和 npm 缓存/配置。CommonJS 声明仅支持 ESM 的工具提示及可选 fsevents 安装脚本提示保留，构建成功。本机缺少 Nginx；部署代码的 Ubuntu 22.04 虚拟机历史完整实测见上方 P7.2 记录。

## 真实设备与合成测试

保存了一份 Safari/macOS 平台 Passkey 真实测试注册与 Assertion 成功记录。实际请求 UV 为 preferred，响应 UP/UV/BE/BS 均为 true，signCount 为 0，DER 有效，Core 12 项 PASS。provider 来源为维护者选择。旧导出没有版本级事务字段，规范化后为 UNKNOWN。报告 SHA-256 为 `0f27841c5fcf6d84927a7b53b66a9f6b24aa2fa0feb84f7caa711cd13311c9af`。[设备记录](../../docs/ASSERTION-INTEROP.md) · [原始脱敏导出](../../docs/interop/safari-macos-2026-11-12.redacted.json)

UV Required 新设备流程、iPhone、Chrome、Windows Hello、USB/NFC 设备均待执行或因 HTTPS 入口缺项阻塞。Node/OpenSSL 合成签名、数据库竞争与 Nginx 合成 TLS 的结果按各自测试范围记录。公网部署、真实 DNS、Let's Encrypt 证书与手机访问尚未执行。[人工矩阵](../../docs/ASSERTION-INTEROP.md#phase-71-设备验收矩阵) · [部署范围](../../deploy/ubuntu-nginx/VALIDATION.md)

## 复验入口

在固定工具链、依赖已安装的仓库根目录执行。

```sh
moon fmt --check
for target in native js wasm wasm-gc; do
  moon info --target "$target"
  moon check --target "$target" --deny-warn
  moon test --target "$target" --deny-warn
  moon build --target "$target" --deny-warn
  moon run cmd/main --target "$target" --deny-warn
  CLI_TARGET="$target" node --test cmd/main/cli.test.mjs
done
npm --prefix reference-rp test
npm --prefix dashboard run check
npm --prefix dashboard test
npm --prefix dashboard run build
node --experimental-strip-types scripts/check-interop-reports.mjs
# Ubuntu 22.04，需实际 Nginx、ShellCheck、systemd-analyze
bash deploy/ubuntu-nginx/tests/validate-ubuntu22.sh
git diff --check
```

`moon info` 后核对生成接口差异。上述列表提供复验入口，实际执行结果需按提交保存。
