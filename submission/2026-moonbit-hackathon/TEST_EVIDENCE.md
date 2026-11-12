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

## 远程 CI

| 提交与范围 | 状态与链接 |
| --- | --- |
| P7.1 `6e4136bac9f18dd88359e5b783ccdd9ee160636c` | 六项 SUCCESS，四个 MoonBit 目标、RP、Dashboard。[运行 43164703998](https://github.com/Ksuserkqy/moonpasskey-lab/actions/runs/43164703998) |
| P7.2 `582de40` | 本地 Ubuntu 结果已记录，该基线尚无对应远程运行证据 |
| 参赛材料分支 | 按 `git rev-parse HEAD` 核对对应六个 job。[分支 Actions 记录](https://github.com/Ksuserkqy/moonpasskey-lab/actions?query=branch%3Afeat%2Fp7-2-ubuntu-nginx-deployment)；最终提交链接和核验结果记录在该分支的堆叠 Draft PR 中 |

现有 CI 为四目标与 RP/Dashboard 六个 job，部署套件的实际 Ubuntu22 验证来自本地隔离环境。最终提交 CI 必须对应实际提交 SHA，P7.1 的绿色检查只对应上表固定旧 SHA。

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
