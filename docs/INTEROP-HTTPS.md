# 跨设备 HTTPS 互操作环境

## 状态与操作边界

Phase 7.1 提供安全拓扑、占位配置和本地预检。实际测试域名、证书、Access 应用、Tunnel 及 iPhone Safari 验收由维护者准备并确认。跨设备 HTTPS 访问与 iPhone 真实注册、assertion 的状态为 `NOT_PERFORMED`，在获得实际结果后更新互操作矩阵。[互操作矩阵](ASSERTION-INTEROP.md)

本文的 `passkey-test.<owned-test-domain>` 是需替换的占位符。维护者需使用自己控制的专用测试域名，并在所有配置中填写同一个固定 hostname。实际 iPhone 地址需在部署及访问控制验证完成后填写。域名、基础设施权限或可信证书尚未就绪时，将该次设备测试记录为 `BLOCKED` 并记录具体缺项。

Codex 的工作范围为代码分析、设计、模板、测试和文档。创建公网 Tunnel、DNS 变更、路由器端口、防火墙、根证书信任、服务对外发布及生产域名使用均受本阶段维护者授权边界约束。下文基础设施准备与激活步骤由维护者在批准后执行。工程准备期间的本地预检保持离线。

## HTTPS 拓扑

```text
iPhone Safari / macOS Safari / Chrome
  HTTPS, fixed test hostname, browser-trusted certificate
    → Cloudflare edge + Access identity authorization, every path
      → authenticated named Tunnel connection
        → cloudflared validates the Access application JWT
          → verified HTTPS to 127.0.0.1:8787
            → Reference RP + MoonBit Core + SQLite + built Dashboard
```

Tunnel 由 Mac 上的 connector 建立出站连接。后端继续监听 `127.0.0.1`，使用独立的 TLS 连接。访问控制覆盖 Dashboard 静态文件及全部 `/api/` 路径。此设计选用一个固定 hostname 和一个受保护 ingress，末尾使用 `http_status:404` 兜底。[Cloudflare Tunnel 连接模型](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)

### 固定身份与传输参数

| 参数 | 精确值或约束 |
| --- | --- |
| 浏览器地址 | `https://passkey-test.<owned-test-domain>/` |
| `REFERENCE_RP_ORIGIN` | `https://passkey-test.<owned-test-domain>`，使用默认 HTTPS 端口，末尾无 `/` |
| `REFERENCE_RP_ID` | `passkey-test.<owned-test-domain>`，仅 hostname |
| 浏览器到边缘 | HTTPS 443，证书对设备可信并覆盖该 hostname |
| connector 到后端 | `https://127.0.0.1:8787`，校验证书链、有效期和名称 |
| 后端 TLS 名称 / SNI | 固定测试 hostname，由 `originServerName` 指定 |
| 后端 HTTP Host | 固定测试 hostname，由 `httpHostHeader` 指定，省略后端的 `:8787` |
| HTTP Origin | 浏览器实际发出的精确 origin，原样传递 |
| 服务监听地址 | `127.0.0.1:8787` |
| 后端 HTTP 协议 | HTTP/1.1 over TLS，`http2Origin: false` |

RP ID 确定凭证作用域。Origin 包含 scheme、hostname 和非默认端口。本文模板使用边缘443；如果维护者选用非默认边缘端口，须同步修改云端路由、httpHostHeader、Origin和下文curl的连接端口。预检会输出externalPort，并将实际代理Host/Origin一致性留待人工验证。后端监听端口与浏览器访问端口分开配置。`localhost` 下的凭证需要在固定测试 RP ID 下重新登记。WebAuthn 依赖无 TLS 错误的 secure context，并要求验证客户端返回的 origin。[WebAuthn Level 3 §5.1、§13.4.9](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#rp-id)

现有 `reference-rp/server.mjs` 对 HTTPS origin 要求配置 TLS。`start.mjs` 加载成对证书与私钥。该服务比较实际 HTTP `Host` 与已配置 origin 的 host，比较请求 `Origin`，并检查 session、CSRF 和 `Sec-Fetch-Site`。该拓扑让这些检查使用原有配置与请求头。应用直接使用明确的 `REFERENCE_RP_ORIGIN` 与 `REFERENCE_RP_ID`，代理传入的 `Forwarded`、`X-Forwarded-Host` 和 `X-Forwarded-Proto` 不参与信任配置。[Reference RP](REFERENCE-RP.md)

## 维护者准备条件

1. 选择专用固定测试 hostname，确认域名控制权、Cloudflare 区域和账户权限。为此次测试准备命名 Tunnel 及其本地凭据。部署操作需在维护者确认授权之后进行。[Cloudflare 自托管应用准备条件](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)
2. 为这个**精确 hostname**创建 Access 自托管应用，Path 留空以覆盖全部路径。检查同 hostname 下更具体的应用和路径规则，确保每个路径都受同样身份要求保护。保持一个 hostname 的全部路径使用同一个访问边界。[Access 路径覆盖与优先级](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/)
3. 配置经过 IdP 验证的维护者明确身份 Allow 列表，使用适合测试窗口的短会话时长。检查 Allow、Bypass、Service Auth 和其他应用策略，确保只有获准测试者能够进入本服务。服务现有 session 提供临时测试账户，外部身份授权由 Access 层承担。[Access 策略](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
4. 确认边缘证书处于 active 状态、SAN 覆盖固定 hostname、设备时间正确，目标 Safari / Chrome 能正常验证其信任链。浏览器证书错误时暂停验收并修复证书或链。[Cloudflare 浏览器兼容性](https://developers.cloudflare.com/ssl/reference/browser-compatibility/)
5. 在 Mac 私有目录准备后端完整 PEM 证书链、对应私钥和用于 connector 验证的明确 CA bundle。后端证书的 SAN 覆盖同一固定 hostname，且处于有效期内。可使用已有受信 CA 证书，或使用仅通过 `caPool` 指定信任的 origin CA。浏览器验证边缘证书，connector 验证后端证书。Cloudflare Origin CA 证书的用途限于后端链路。[Cloudflare Origin CA](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)
6. 准备并记录所用 `cloudflared --version`，按当前官方文档验证实际版本支持模板字段。connector 配置的 `caPool` 引用已审核的 CA 文件，`originServerName` 绑定证书名称，`noTLSVerify` 保持 `false`，`httpHostHeader` 设置精确应用 host。[Tunnel origin 参数](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)
7. 在**该 ingress 内部**配置 `access.required: true`、正确的 team name 和 Access 应用 AUD。connector 校验签名 JWT 后才转发。仅存在 `Cf-Access-Jwt-Assertion` 或身份邮件请求头不足以证明已授权。JWT 的来源、签名、发行者、audience 和有效期需要由 connector 的 Access 校验处理。[Access JWT 验证](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)

Reference RP 仍然是 TEST ONLY 工具。云端代理会处理浏览器请求和短期认证响应，维护者应确认此次测试允许使用该服务商处理测试数据。本机进程可访问 loopback，受信任 Mac 的本地用户和进程属于此部署的主机边界。Reference RP 本身没有实现 Access JWT 校验，也没有生产身份账户管理。上述 connector 校验和边缘身份策略是外部访问链路的必要部署条件。

## 配置模板

仓库提供两个占位文件。

- [Reference RP 环境变量模板](interop/https/reference-rp.env.example)
- [cloudflared 本地管理配置模板](interop/https/cloudflared.yml.example)

将模板复制到维护者选定的私有目录后再编辑。替换所有 `<...>` 和 `/absolute/private/path/...`。凭据 JSON、TLS 私钥、CA 文件、真实环境配置及 SQLite 文件按本地保留策略管理，私钥和凭据文件使用仅维护者可读的权限。仓库的 `reference-rp/data/` 已被忽略，可用于本阶段 SQLite 测试库。模板中的 `REFERENCE_RP_TLS_CA` 供离线预检使用，connector 的 `caPool` 需指向同一已审核 CA bundle。

模板的 ingress 使用根路径转发，浏览器发起的 `/api/session`、`/api/challenges`、`/api/register`、`/api/assertions`、`/api/state`、`/api/reports` 与静态资源路径保持原有路径。请求中的 Origin、cookie 和 CSRF header 按应用协议传递。所有路径都经过 Access，代理无需添加 CORS 允许来源或重写 Origin。配置文件的 ingress 校验只验证规则结构，实际授权与证书验证仍需在部署后确认。[Tunnel 配置文件与 ingress 校验](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)

维护者替换私有副本后，在仓库根目录执行以下离线检查。这里的路径也需要替换为私有副本的实际路径。

```sh
. /absolute/private/path/reference-rp.env
node reference-rp/interop-preflight.mjs
cloudflared --version
cloudflared tunnel --config /absolute/private/path/interop-cloudflared.yml ingress validate
cloudflared tunnel --config /absolute/private/path/interop-cloudflared.yml ingress rule "${REFERENCE_RP_ORIGIN}/"
cloudflared tunnel --config /absolute/private/path/interop-cloudflared.yml ingress rule "${REFERENCE_RP_ORIGIN}/api/session"
cloudflared tunnel --config /absolute/private/path/interop-cloudflared.yml ingress rule https://unmatched.invalid/
```

预期固定 hostname 的任一路径匹配受保护的第一个 ingress，其他 hostname 匹配 404 兜底。离线预检检查 HTTPS 配置、RP ID 与 hostname、证书 SAN 与有效期、证书和私钥配对以及完整后端TLS证书输入和所提供CA PEM的语法。证书链信任、外部 DNS、边缘证书、Access / JWT 运行状态和设备连通性仍需取得实际证据。模板原样包含占位符，预检应报告缺少有效配置。

## 启动与本地 TLS 验证

维护者完成上述配置后，使用项目固定 MoonBit 和 Node.js 24.18.0 工具链，在仓库根目录构建并启动服务。

```sh
moon build analysis --target js --deny-warn
npm --prefix dashboard ci
npm --prefix dashboard run check
npm --prefix dashboard run build
mkdir -p reference-rp/data
. /absolute/private/path/reference-rp.env
node reference-rp/interop-preflight.mjs
REFERENCE_RP_UV=required node reference-rp/start.mjs
```

环境模板将 UV 设置为 `required`、counter 设置为 `report-only`。Dashboard 展示的配置及导出报告中的请求策略需与本次实际启动一致。更换 UV 策略后重启服务，并在新测试会话中重新登记和认证。后续重复认证在同一个浏览器测试会话中执行，以验证既有 credential 的数据库状态更新。

在第二个终端加载同一环境配置。以下连接只访问本机，`--connect-to` 将 TCP 连接指向 loopback，同时保留 URL hostname、TLS SNI、证书名称验证和 HTTP Host。`--cacert` 仅为该次客户端校验指定 CA 文件。响应体被丢弃以避免在终端打印 session 和 CSRF 内容。[curl 连接目标控制](https://curl.se/docs/manpage.html#--connect-to) · [curl 证书校验](https://curl.se/docs/sslcerts.html)

```sh
. /absolute/private/path/reference-rp.env
lsof -nP -iTCP:8787 -sTCP:LISTEN
curl --noproxy '*' --silent --show-error --max-time 10 \
  --cacert "$REFERENCE_RP_TLS_CA" \
  --connect-to "${REFERENCE_RP_ID}:443:127.0.0.1:${REFERENCE_RP_PORT}" \
  --output /dev/null --write-out '%{http_code}\n' \
  "${REFERENCE_RP_ORIGIN}/api/session"
curl --noproxy '*' --silent --show-error --max-time 10 \
  --cacert "$REFERENCE_RP_TLS_CA" \
  --connect-to "${REFERENCE_RP_ID}:443:127.0.0.1:${REFERENCE_RP_PORT}" \
  --header 'Host: wrong.invalid' \
  --output /dev/null --write-out '%{http_code}\n' \
  "${REFERENCE_RP_ORIGIN}/api/session"
curl --noproxy '*' --silent --show-error --max-time 10 \
  --cacert "$REFERENCE_RP_TLS_CA" \
  --connect-to "${REFERENCE_RP_ID}:443:127.0.0.1:${REFERENCE_RP_PORT}" \
  --header 'Origin: https://wrong.invalid' \
  --output /dev/null --write-out '%{http_code}\n' \
  "${REFERENCE_RP_ORIGIN}/api/session"
```

预期监听结果仅为 `127.0.0.1:8787`。三个请求预期依次为 200、403、403，且全部完成 TLS 验证。错误 Host / Origin 验证在本机直接测试后端，以便精确检查应用拒绝逻辑。外部代理会固定设置后端 Host，因此外部伪造 Host 的请求还需由云端 hostname 路由和 Access 边界处理。

## 维护者激活与访问控制验收

只有在维护者已批准并准备基础设施、完成本地检查且审核 Access 配置后，才启动已有命名 Tunnel。该命令会建立对外服务链路，属于人工部署步骤。

```sh
cloudflared tunnel --config /absolute/private/path/interop-cloudflared.yml run
```

维护者在目标设备上逐项记录实际结果。

1. 从没有 Access 登录状态的浏览器会话访问固定测试地址和 `/api/session`，确认到达 Access 登录或拒绝页面，后端 Dashboard / session 数据不可获取。随后验证一个未在 Allow 列表中的身份被拒绝。记录状态和时间，省略认证 cookie 与 JWT。
2. 使用获准维护者身份登录，确认 Dashboard、静态资源和 API 全部可用。确认 Access 的实际保护对象包含整个 hostname，以及 connector 使用该应用的正确 team name / AUD。
3. 检查运行中的 connector 确实加载了私有配置中的 per-ingress Access JWT 校验和严格 TLS 校验，且仅存在这一个受保护后端路由。检查缺失或无效 Access 认证不能到达 RP。仅看到边缘登录页还不足以完成 connector 配置验收。
4. 在 iPhone Safari 访问固定 HTTPS 地址，确认无证书错误、Dashboard 的 secure-context 为 true、WebAuthn 可用，页面显示正确 RP ID / origin / UV。记录实际 iPhone 型号、OS / Safari 版本、时间和实际地址。
5. 记录可信 HTTPS、未授权拒绝、获准身份访问和后端 loopback 的实际验收结果。在这些检查完成之前，矩阵的 HTTPS 实际访问保持 `NOT_PERFORMED` 或具体阻塞状态。

Access 登录会话在外部 IdP 页面完成，回到原始固定测试 origin 后再执行 WebAuthn。访问令牌到期会导致 API 被 Access 拦截或跳转。重新登录后启动新的服务器挑战，再继续本次操作。

## iPhone Safari 与 UV Required 人工验收

维护者在同一个 iPhone Safari 测试会话中完成以下流程。Mac 与 iPhone 的浏览器 cookie 分别建立各自的临时账户，iPhone 需先登记自己的测试 credential。

1. 打开部署验收通过的实际 `https://passkey-test.<owned-test-domain>/`，完成 Access 身份登录。
2. 在设备记录中填写真实型号、OS、浏览器版本和手动选择的 provider。若系统界面明确选择了 iCloud Keychain / platform passkey，将 provider 来源记为 `MAINTAINER_SELECTED`。无法确认时使用 `UNKNOWN`。[互操作记录字段](ASSERTION-INTEROP.md)
3. 点击 `Register test passkey`，由维护者操作系统 Passkey 界面完成创建。确认注册结果来自服务器、Core 状态及 SQLite 登记结果，并导出该次脱敏报告。
4. 点击 `Verify with passkey`，由维护者完成系统身份验证。Dashboard 使用实际 `clientDataJSON`、`authenticatorData` 和 DER signature 的服务器验证结果展示检查状态。
5. 查看实际返回 AuthenticatorData 的 UP、UV、BE、BS 和 signCount，记录 DER 验签、Core 最终状态、事务结果。UV Required 验收需要实际 UP=true、UV=true 和完整验证成功。请求配置中的 `required` 单独记录。[WebAuthn 注册与 assertion 验证](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)
6. 在相同会话中再次发起新的 assertion，比较数据库 credential version、计数和备份状态更新，记录第二次真实结果。
7. 点击 `Export safe report` 导出实际注册与 assertion 报告。维护者回传通过结构及白名单校验的文件，以及 HTTPS 访问、身份拒绝和所用版本的脱敏记录。新导出以`.redacted.json`结尾，合入 `docs/interop/` 后执行 `node scripts/check-interop-reports.mjs` 校验；也可在命令后传入尚在Downloads中的实际文件路径。[报告与矩阵](ASSERTION-INTEROP.md)

设备无法完成 UV、浏览器取消、超时、策略拒绝或其他错误时，保留真实状态和可脱敏错误原因。实际系统 provider 选择由维护者确认。提供者身份的独立证据需按报告结构单独记录。

## Chrome / Google Password Manager 人工验收

使用同一受保护 HTTPS origin，在 macOS Chrome 建立独立测试会话。明确在系统界面选择 Google Password Manager，然后分别完成新测试 passkey 的注册、assertion、UV Required 和重复认证流程，按同一结构导出报告。记录 Chrome、macOS 和 provider 的实际版本与选择来源。无法选择该 provider 时记录可复现原因。测试尚未执行时使用 `NOT_PERFORMED`。

## 关闭与清理

1. 导出并校验实际脱敏报告，记录本次环境参数和结束时间。
2. 先停止 `cloudflared`，确认该 connector 及此次测试的其他副本均已退出，对外测试入口停止提供 RP 内容。
3. 停止 Reference RP，确认 loopback 监听已消失。保留需要用于复核的测试库至维护者决定的期限。
4. 维护者按已批准的运维范围撤销临时 DNS / Tunnel 路由和 Access 会话，清理临时 Tunnel 凭据与证书材料。复用的域名或应用按实际保留计划处理。
5. 由维护者删除 provider 中本次创建的测试 passkey，清除浏览器测试站点数据。测试数据库及其 SQLite sidecar 按本地保留策略清理。

## 常见错误

| 现象 | 检查与处理 |
| --- | --- |
| iPhone 打开 localhost 失败 | 使用部署验证通过的固定 HTTPS 测试地址，localhost 指向手机本机 |
| Safari 证书错误或 secure-context=false | 检查边缘证书 SAN、有效期、完整链、设备时间及浏览器兼容性，修复后重新验收 |
| HTTPS requires a certificate and key | 为 RP 提供 `REFERENCE_RP_TLS_CERT` 和 `REFERENCE_RP_TLS_KEY`，connector 连接 HTTPS 后端 |
| connector x509 错误 | 校对 origin SAN、`originServerName`、完整链和 `caPool`，修复验证失败 |
| HostMismatch | 确认 `httpHostHeader` 等于浏览器 origin 的 host，标准 443 场景省略 `:8787` |
| OriginMismatch / OriginRequired | 核对 scheme、hostname、端口与尾部 `/`，确认浏览器 Origin 原样传递及请求来自实际页面 |
| Access 拒绝或循环登录 | 核对 IdP 身份 Allow 列表、会话、精确 hostname 和 Path，检查 connector team name / AUD |
| 未登录可进入 Dashboard 或 `/api/session` | 立即停止 connector，修复整个 hostname 的 Access 保护与 JWT 验证后重新验收 |
| `SecurityError` 或 RP ID Hash 失败 | 核对实际 origin 与 RP ID，在固定测试 RP ID 下重新登记 credential |
| CredentialNotFound | 在当前设备当前浏览器会话先完成登记，再发起 assertion |
| SessionRequired / CSRF 错误 | 保持同一浏览器站点会话并重新获取服务器会话与挑战 |
| UV 检查失败 | 记录请求策略及实际 flags，检查 provider 的用户验证能力与系统配置 |
| ChallengeExpired / 重放拒绝 | 用当前会话获取新挑战，记录实际失败原因及后续新流程结果 |

## 证据边界

自动化的 HTTPS、Host / Origin、UV 策略和报告检查结果归入自动化测试记录。真实设备结果由维护者实际注册、认证和导出产生。模板与离线预检不能确认 DNS、边缘证书、Access 运行策略或 iPhone 行为。Phase 7.1 的跨设备 HTTPS 与真实设备最终状态见持续维护的矩阵。[互操作矩阵](ASSERTION-INTEROP.md)
