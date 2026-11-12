# 本地 Reference RP

这是用于开发和互操作验证的 TEST ONLY 服务。注册适配器完成最小 none-attestation 测试登记，支持 ES256。完整 attestation 信任、生产账户认证与恢复、凭证管理授权和生产部署仍待实现。

## 启动

使用 Node.js 24.18.0 和项目固定 MoonBit 工具链，在仓库根目录运行。

```sh
moon build analysis --target js --deny-warn
npm --prefix dashboard ci
npm --prefix dashboard run check
npm --prefix dashboard run build
node reference-rp/start.mjs
```

打开 `http://localhost:8787`。默认监听127.0.0.1，RP ID 为 localhost。Dashboard 显示当前 secure-context 和 WebAuthn 能力，点击注册后由使用者完成系统 Passkey 提示，再点击验证 assertion 完成第二次系统确认。

localhost 的开发 HTTP origin 可被浏览器视为 potentially trustworthy。实际设备记录还需观察 secure-context 状态。自定义域名使用具有受信任证书的 HTTPS，并配置精确 RP ID 和 Origin。服务始终限制 loopback 监听。跨设备测试需由维护者配置受保护的本地 HTTPS 访问路径，移动设备的 localhost 指向移动设备自身。[Secure Contexts 2023-11-10 §3.1、§5.2](https://www.w3.org/TR/2023/CRD-secure-contexts-20231110/#is-origin-trustworthy)

| 环境变量 | 默认或作用 |
| --- | --- |
| `REFERENCE_RP_PORT` | 8787 |
| `REFERENCE_RP_ORIGIN` | http://localhost:8787 |
| `REFERENCE_RP_ID` | localhost |
| `REFERENCE_RP_UV` | preferred，可配置 required/discouraged |
| `REFERENCE_RP_COUNTER` | report-only，可配置 reject |
| `REFERENCE_RP_DB` | 未设置时内存库，显式文件路径启用本地持久化 |
| `REFERENCE_RP_CORE` | 默认已构建 analysis.js |
| `REFERENCE_RP_TLS_CERT`、`REFERENCE_RP_TLS_KEY` | 成对指定受信任 TLS 证书和私钥文件 |

测试凭证私钥由系统 provider 管理。服务保存登记后的公开 COSE key、credential ID、临时账户句柄和计数状态。原始 clientDataJSON、authenticatorData、attestationObject 和签名仅用于当次验证。报告脱敏后保存于当前数据库，默认随进程退出清除。显式文件持久化需由使用者管理保留期限。

## HTTP 接口

| 方法与路径 | 行为 |
| --- | --- |
| GET `/api/session` | 建立临时账户与 HttpOnly SameSite=Strict cookie，返回 CSRF token 和公开配置 |
| POST `/api/challenges` | 接收 purpose=registration/assertion，生成服务器挑战和浏览器 options |
| POST `/api/register` | 接收原始响应传输字段，经 MoonBit 测试注册验证后原子登记 |
| POST `/api/assertions` | 从会话账户选择可信记录，完整 Core 验证并原子提交 |
| GET `/api/state` | 当前会话账户的凭证计数、BE/BS 和 version |
| GET `/api/reports` | 当前账户最近100份脱敏报告 |
| POST `/api/analyze` | 调用 MoonBit 公开脱敏分析入口，分析导入 JSON |

POST 需要精确 Origin、JSON Content-Type 和 X-CSRF-Token。服务核对 Host、Origin、Sec-Fetch-Site、会话有效期和账户归属。HTTP body 上限2 MiB，先严格解码 UTF-8，header/request 超时有界。错误返回 FAIL 与可区分的 kind，日志仅输出启动 origin 和策略。

注册和 assertion body 包含 type、rawId、clientDataJSON、challengeId、challenge。注册另外包含 attestationObject。Assertion 另外包含 authenticatorData、DER signature 和 nullable userHandle。所有二进制字段使用无 padding Base64URL。

服务端构造可信 policy、expectedChallenge 和 credential，调用 `analysis.run_host_json`。前端仅转换 ArrayBuffer 与传输编码并调用原生 `navigator.credentials.create/get`。原始 clientDataJSON 保持其返回字节，签名消息构造及全部协议检查在 MoonBit 执行。[WebAuthn Level 3 REC 2026-08-25 §7.1、§7.2](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)

## Dashboard

Vue 3、TypeScript、Vite 与本地打包的 Inter 字体提供页面。展示 Core 返回的 ClientData、flags、逐项状态、ES256/P-256、DER 和 counter 结果。导入分析使用服务器上的同一 MoonBit Core。页面默认内存保存数据，导出前删除敏感认证字段，HTML 和静态资源使用同源 CSP。协议验证代码集中在 MoonBit。

## 测试与边界

```sh
npm --prefix reference-rp test
npm --prefix dashboard test
node --test cmd/main/cli.test.mjs
```

Host HTTP 集成测试使用临时生成的合成 P-256 key 和签名，经真实编译 Core 执行注册、验签与负例。私钥只存在于测试进程内存。竞争测试使用真实 SQLite 多连接。实际 Safari/设备流程的执行结果单独记录于互操作文档。

Node 24.18 的内置 node:sqlite 标记为 Stability 1.2 Release candidate。参考服务为单进程本地工具，未建立生产级账户、分布式协调、全面流量限制、长期清理、审计或运维体系。MoonCrypt 的独立审计限制沿用 P5/P6 记录。[Node.js 24.18 SQLite](https://nodejs.org/download/release/v24.18.0/docs/api/sqlite.html) · [当前限制](LIMITATIONS.md) · [挑战事务](CHALLENGE-LIFECYCLE.md)

## Phase 7.1 验收接口

注册和 Assertion 成功响应增加 databaseTransaction 对象，status=COMMITTED，包含 previousVersion 和 version。注册 version为0，previousVersion为null；Assertion 使用成功CAS的旧版本与旧版本加一。该对象在事务成功后返回，失败或回滚响应没有 COMMITTED。报告省略credential ID和report ID，Dashboard只保留非身份事务元数据。

HTTPS配置现在启动前拒绝空TLS对象及缺少cert/key的情况。实际HTTPS测试使用运行时生成的合成证书，客户端只为该次请求显式提供CA并验证TLS名称及证书。测试不改变系统证书信任。Required、Preferred、Discouraged的选项和实际UV响应均通过真实编译Core验证。

```sh
REFERENCE_RP_PORT=8789 REFERENCE_RP_UV=required node reference-rp/start.mjs
node reference-rp/interop-preflight.mjs
node --experimental-strip-types scripts/check-interop-reports.mjs
```

preflight是离线配置与证书检查，只读取维护者通过环境变量明确提供的TLS路径，检查完整NodeTLS输入、SAN、时效和密钥配对。REFERENCE_RP_TLS_CA是可选的origin CA PEM文件，仅供预检和连接器显式信任配置使用，start.mjs不借此信任转发头。链信任、代理Host/Origin、外部Access/JWT和手机可达性保留人工验收状态。

P7.1当前工程准备可运行，真实required、iPhone和跨设备HTTPS的执行状态见设备矩阵。受保护HTTPS方案保持后端loopback、精确Host/Origin/session/CSRF。基础设施激活由维护者批准并执行。[跨设备HTTPS](INTEROP-HTTPS.md) · [设备矩阵](ASSERTION-INTEROP.md)
