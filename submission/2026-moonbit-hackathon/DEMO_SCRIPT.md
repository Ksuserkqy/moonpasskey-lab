# MoonPasskey Lab：约 4 分 40 秒中文演示稿

## 演示前准备（不计入讲解时长）

在仓库根目录操作。干净环境需先安装 Node.js **24.18.0**、MoonBit **0.10.20+65efd5b93**，确认 `node`、`npm`、`moon`、`moonc` 在 PATH 中，再执行一次 `moon update` 初始化依赖索引。隔离安装还需把 `MOON_HOME` 指向对应 MoonBit 安装目录；脚本会优先使用该目录的 `bin`，并拒绝其他 Node/moonc 版本。

```sh
./scripts/demo.sh
```

脚本构建 `analysis` 和 `cmd/main` 的 JS 目标；Dashboard 缺少 Vite 安装时执行 `npm ci`，随后构建页面并启动 Node 参考 RP。默认地址为 [http://localhost:8787](http://localhost:8787)，只监听 loopback，数据库为内存，UV required，counter report-only，停止即丢弃本次会话数据。若端口占用，使用 `DEMO_PORT=8790 ./scripts/demo.sh` 并打开相应端口。已有部署环境变量不会把这个脚本切换为远程服务或持久数据库。

首次安装需要网络和依赖下载。预热后可把“约 30 秒内启动”作为现场准备目标，但尚未做专门计时，不能把它作为已测性能承诺。录屏前先确认页面已经加载，CLI 已完成一次校验，不在讲解中等待首次安装。

本次本机验证使用的隔离工具链命令是：

```sh
export MOON_HOME=/tmp/moonpasskey-p5-toolchain-0.10.20
export PATH=/tmp/node-v24.18.0-darwin-arm64/bin:/tmp/moonpasskey-p5-toolchain-0.10.20/bin:$PATH
DEMO_PORT=8790 ./scripts/demo.sh
```

这些 `/tmp` 路径只是本次验证环境，不是项目要求的安装位置。另开一个终端，保持相同工具链环境。窗口建议左侧终端、右侧浏览器；示例文件都位于 `submission/2026-moonbit-hackathon/demo/`。

## 0:00–0:25：开场与边界

操作：展示 Dashboard 顶部本地服务配置与测试用途提示。

讲解：“这是 MoonPasskey Lab，一个以纯 MoonBit Core 为中心的 WebAuthn ES256 解析与验证实验室。今天用 CLI 和 Dashboard 两个入口观察同一套验证结果。CLI 与 Import assertion 输入都明确标为 SYNTHETIC，只含公开测试字节与公钥，不含私钥，也不代表真实设备的互操作认证。”

## A · 0:25–1:25：CLI 从字节解析到完整验证

操作：运行完整演示；输出依次包含人类可读文本和机器可读 JSON，可滚动停在前三个 PASS 场景。

```sh
./scripts/demo.sh cli
```

如需逐项停顿，使用普通入口：

```sh
moon run cmd/main --target js -- --input submission/2026-moonbit-hackathon/demo/client-data.json
moon run cmd/main --target js -- --input submission/2026-moonbit-hackathon/demo/authenticator-data.json --json
moon run cmd/main --target js -- --input submission/2026-moonbit-hackathon/demo/verify-valid.json --json
```

需要展示字节错误位置时，可另外生成一个单字节 SYNTHETIC 输入并执行。预期退出码为 2，报告为 `UnexpectedEnd`、`authData.rpIdHash`、`offset=0`，此路径已实际运行。

```sh
printf '%s\n' '{"command":"authenticator-data","authenticatorData":"AQ","_fixture":{"classification":"SYNTHETIC"}}' > /tmp/moonpasskey-truncated.json
moon run cmd/main --target js --deny-warn -- --input /tmp/moonpasskey-truncated.json
```

讲解：“第一步保留原始 ClientDataJSON 字节，读取 type、origin 和字段位置。第二步解析 AuthenticatorData，看到 UP、UV 和计数器。单独解析时，未执行的策略或签名检查会明确写为 NOT_PERFORMED。第三个输入是已有测试复用的有效 ES256 签名，完整验证返回 PASS，签名检查和策略检查都有自己的状态。报告隐藏完整 challenge、凭证 ID、userHandle、公钥编码及签名字节。”

## B · 1:25–2:35：Dashboard 导入同一输入

操作：打开 Import，选择 `verify-assertion`，载入 `demo/verify-valid.json` 并点击运行分析。页面的命令选择会覆盖文件中的 `command`，因此要选择匹配的命令。展示 SYNTHETIC 来源、PASS、Checks、flags、counter 与脱敏字段；再展示报告导出入口。

讲解：“网页把同一个请求发给本机参考 RP，再调用刚构建的 MoonBit Core，没有在前端重新实现验签。这里的合成断言使用 rp.test 策略，顶部 localhost 则是本地服务配置，不能混为一次真实登录。原始输入不会因为导入就登记为账户凭证。这个样本 UP 为真、UV 为假，preferred 策略下仍可通过。计数器为零且报告 NOT_SUPPORTED，不能据此宣称具备克隆检测能力。导出的是脱敏分析报告，便于复核和交流。”

## C · 2:35–4:15：四个负例说明失败原因

操作：在 Import 保持 `verify-assertion`，依次载入以下四个文件并运行。每项停留约 20 秒，指向错误类型与对应失败检查。CLI 完整脚本已逐项断言同样结果；手动运行负例的正常退出码是 **2**。

| 输入文件 | 屏幕上应看到 | 讲解重点 |
| --- | --- | --- |
| `verify-invalid-signature.json` | FAIL / `InvalidSignature` | “只翻转一个签名字节，结构仍合法，但密码学验证失败。” |
| `verify-wrong-challenge.json` | FAIL / `ChallengeMismatch` | “签名仍是原来的有效签名，可信 challenge 对不上，验证必须拒绝。” |
| `verify-wrong-origin.json` | FAIL / `OriginNotAllowed` | “原始 origin 不在可信白名单，拒绝的是策略，而不是用改坏签名冒充来源检查。” |
| `verify-uv-required.json` | FAIL / `UserVerificationRequired` | “只把策略改成 required；样本本来没有 UV，因此不能通过。不会改写已签名 flags 来制造这个负例。” |

讲解：“Core 在错误处短路，其他 NOT_PERFORMED 表示尚未执行，不能当成成功。脚本只容忍这些已知失败的退出码，并继续核对状态、错误类型和失败检查；任何意外结果都会让演示脚本自身失败。”

## 4:15–4:40：归档设备报告回看与收尾

操作：前约 20 秒运行下列检查器，并只读打开三份归档 JSON，指向 `configuration.userVerification`、`authenticatorData.flags` 和 `databaseTransaction`。最后 5 秒停止本地服务。此段执行报告结构与脱敏契约检查，展示的 Core 结果和签名状态来自导出时保存的报告。

```sh
node --experimental-strip-types scripts/check-interop-reports.mjs
```

| 归档报告 | 导出中保存的结果 |
| --- | --- |
| [测试登记](../../docs/interop/local-uv-required-registration-2026-11-12.redacted.json) | PASS，UP/UV=true，COMMITTED null→0，signature / attestation_trust 为 NOT_PERFORMED |
| [第一次认证](../../docs/interop/local-uv-required-assertion-1-2026-11-12.redacted.json) | Core 12 项 PASS，DER 签名有效，COMMITTED 0→1，counter=0 / NOT_SUPPORTED |
| [重复认证](../../docs/interop/local-uv-required-assertion-2-2026-11-12.redacted.json) | Core 12 项 PASS，DER 签名有效，COMMITTED 1→2，counter=0 / NOT_SUPPORTED |

三份报告记录 MacBookAir、MacOS 27.2、Google Chrome 157.0.8103.39，策略为 UV required。维护者已确认使用 Chrome。provider 字段保留 `1Password`，`providerSource` 保留 `UNKNOWN`。

讲解：“最后回看已归档的 Chrome 设备报告。Required 下 UP、UV 为真，两次认证签名有效，事务版本从零推进到一、二。计数器均为零并报告 NOT_SUPPORTED。provider 来源保留 UNKNOWN。”

## 本次实际验证记录

- Node `v24.18.0`、moonc `v0.10.20+65efd5b93`；Darwin arm64。
- `bash -n scripts/demo.sh` 通过。
- `./scripts/demo.sh cli` 通过：七个输入分别运行文本和 JSON 输出，共十四次普通 CLI 调用；全部匹配预期退出码、状态、关键检查及错误类型。
- `DEMO_PORT=8790 ./scripts/demo.sh` 完成 Core/CLI JS 构建和 Dashboard 生产构建，成功启动本地服务，启动诊断为 UV required、counter report-only。
- 实际 HTTP 检查通过：Dashboard 200；会话配置为 localhost / UV required；携带本地会话与 CSRF 的 `/api/analyze` 调用真实 Core，`verify-valid.json` 返回 PASS、脱敏报告、`signatureValid=true`。
- 本次已有 Dashboard 依赖可复用，未重复执行缺失依赖时的 `npm ci` 分支；未进行真实设备 ceremony，未作启动时长基准。

沙箱环境最初禁止本地端口监听与 HTTP 访问，授权本机 loopback 后上述服务验证通过；这不改变脚本在正常终端中的启动方式。

### 追加的干净源码复现检查

本次另将工作区源码复制到临时目录，排除 `.git`、`.mooncakes`、`node_modules`、`_build` 和 `dashboard/dist`，保留提交材料及合成输入。使用相同固定 Node/MoonBit 工具链和已有 MoonBit 安装内的依赖索引，`./scripts/demo.sh cli` 的十四次调用全部通过。

随后在副本执行 `DEMO_PORT=8791 ./scripts/demo.sh`，实际进入缺少 Dashboard 依赖的 `npm ci` 分支，安装 52 个包，审计 53 个包并报告 0 个漏洞。npm 提示 `fsevents@2.3.3` 的安装脚本尚未列入 allowScripts，命令仍成功退出，Dashboard 生产构建完成。该检查使用了宿主 npm 缓存与 registry 配置，因此只证明源码和项目内依赖目录可从零构建。

8791 的 Dashboard 返回 HTTP 200，会话配置为 localhost / UV required；携带会话与 CSRF 的合成有效断言导入调用真实 Core，返回 PASS、脱敏报告和 `signatureValid=true`。检查后向该端口的独立 Node 进程发送 SIGTERM，服务正常退出；再次确认 8791 已停止，原有 8790 服务仍返回 HTTP 200。
