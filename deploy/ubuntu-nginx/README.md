# Ubuntu 22.04 / Nginx 部署准备

本目录供维护者在后续授权阶段部署 TEST ONLY Reference RP。当前交付为本地工程化准备，真实服务器、DNS、Let's Encrypt 和设备验收结果由各自实际执行记录确认。P7.1 的历史报告与未完成设备项保留原状态。

## 固定拓扑与目录

```text
Browser
  → https://passkey-test.ksuser.cn:443  Nginx + Basic Auth + Let's Encrypt
    → https://127.0.0.1:8787  Node 24.18.0
      → compiled MoonBit Core → SQLite
```

RP ID 为 `passkey-test.ksuser.cn`，Origin 为 `https://passkey-test.ksuser.cn`，UV 为 required，Counter 为 report-only。Nginx 校验内部 CA、后端证书有效期、SAN 和 SNI，应用继续校验实际 Host、Origin、会话和 CSRF。Nginx 在边缘验证 Basic Auth，转发时去除 Authorization 和所有未列入白名单的代理请求头。[Nginx upstream TLS](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify) · [Basic Auth](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html)

| 路径 | 用途与权限 |
| --- | --- |
| `/opt/node-v24.18.0/` | 官方对应 CPU 的 Node，root 所有，服务只读 |
| `/opt/moonbit-0.10.20/` | 固定 MoonBit 工具链，构建与离线预检使用 |
| `/opt/moonpasskey/releases/<release>/` | 构建后的项目，root 所有，服务只读 |
| `/opt/moonpasskey/current` | 指向维护者选定 release 的符号链接 |
| `/var/lib/moonpasskey/` | moonpasskey:moonpasskey，0700，SQLite 与 WAL/SHM |
| `/etc/moonpasskey/reference-rp.env` | root:root，0600，systemd PID1 读取 |
| `/etc/moonpasskey/tls/ca/` | root:root，0700，CA key 0600 |
| `/etc/moonpasskey/tls/backend/` | root:moonpasskey，0750，leaf key/cert 0640 |
| `/etc/moonpasskey/tls/backend-ca.crt` | root:root，0644，指定的公开 CA |
| `/etc/nginx/moonpasskey.htpasswd` | root:www-data，0640，独立 Basic Auth 用户库 |
| `/var/www/moonpasskey-acme/` | 本站 ACME webroot，root 所有，可公开读取 challenge |

下列服务器命令属于未来维护者操作手册，所有代码块在 Bash 中执行，变更步骤使用 set -eu 让前置检查失败时停止。本阶段实际运行范围见 [本地验收记录](VALIDATION.md)。现有虚拟主机保持各自配置文件，新增本站两个独立片段，配置检查通过后由维护者执行明确的服务操作。

## 1. Ubuntu 与固定工具链

在未来目标服务器的授权控制台执行。确认系统确为 Ubuntu 22.04，架构为 amd64 或 arm64，先查看已有监听端口和 Nginx 虚拟主机安排。

```sh
set -eu
cat /etc/os-release
uname -m
sudo ss -ltnp '( sport = :80 or sport = :443 or sport = :8787 )'
sudo apt-get update
sudo apt-get install --no-install-recommends nginx openssl ca-certificates curl xz-utils git clang unzip apache2-utils certbot shellcheck
```

安装 Node 24.18.0。下载版本化官方归档，对照官方 SHA256SUMS 校验。目录已存在时先检查版本，由维护者决定复用或处理。

```sh
set -eu
case "$(dpkg --print-architecture)" in
  amd64) node_arch=x64 ;;
  arm64) node_arch=arm64 ;;
  *) printf 'Unsupported CPU architecture\n' >&2; exit 1 ;;
esac
tool_stage=$(mktemp -d)
cd "$tool_stage"
curl --fail --show-error --silent --location --retry 3 \
  "https://nodejs.org/dist/v24.18.0/node-v24.18.0-linux-${node_arch}.tar.xz" -o node.tar.xz
curl --fail --show-error --silent --location --retry 3 \
  https://nodejs.org/dist/v24.18.0/SHASUMS256.txt -o SHASUMS256.txt
expected=$(awk -v file="node-v24.18.0-linux-${node_arch}.tar.xz" '$2 == file {print $1}' SHASUMS256.txt)
test -n "$expected"
printf '%s  node.tar.xz\n' "$expected" | sha256sum --check -
test ! -e /opt/node-v24.18.0
test ! -L /opt/node-v24.18.0
tar -xJf node.tar.xz
sudo mv "node-v24.18.0-linux-${node_arch}" /opt/node-v24.18.0
sudo chown -R root:root /opt/node-v24.18.0
/opt/node-v24.18.0/bin/node --version
```

安装固定 MoonBit。使用官方版本化归档，URL中的加号编码为%2B。已有工具链目录先核对并由维护者处理。安装后核对compiler完整build hash，CLI自身的0.1...版本不同于compiler版本。

```sh
set -eu
case "$(uname -m)" in
  x86_64) moon_target=linux-x86_64 ;;
  aarch64) moon_target=linux-aarch64 ;;
  *) printf 'Unsupported CPU architecture\n' >&2; exit 1 ;;
esac
moon_stage=$(mktemp -d)
cd "$moon_stage"
curl --fail --show-error --silent --location --retry 3 \
  "https://cli.moonbitlang.com/binaries/0.10.20%2B65efd5b93/moonbit-${moon_target}.tar.gz" -o moonbit.tar.gz
curl --fail --show-error --silent --location --retry 3 \
  'https://cli.moonbitlang.com/cores/core-0.10.20%2B65efd5b93.tar.gz' -o core.tar.gz
sudo test ! -e /opt/moonbit-0.10.20
sudo test ! -L /opt/moonbit-0.10.20
sudo install -d -o root -g root -m 0755 /opt/moonbit-0.10.20
sudo tar -xzf moonbit.tar.gz -C /opt/moonbit-0.10.20
sudo tar -xzf core.tar.gz -C /opt/moonbit-0.10.20/lib
sudo find /opt/moonbit-0.10.20/bin -type f -exec chmod a+x {} +
sudo ln -sf moon /opt/moonbit-0.10.20/bin/moonx
sudo env MOON_HOME=/opt/moonbit-0.10.20 PATH=/opt/moonbit-0.10.20/bin:/usr/bin:/bin \
  /opt/moonbit-0.10.20/bin/moon -C /opt/moonbit-0.10.20/lib/core bundle --warn-list -a --all
env MOON_HOME=/opt/moonbit-0.10.20 PATH=/opt/moonbit-0.10.20/bin:/usr/bin:/bin /opt/moonbit-0.10.20/bin/moon version --all
/opt/moonbit-0.10.20/bin/moonc -v
```

期望 compiler/core 为 `0.10.20+65efd5b93`。构建依赖仍为 MoonCrypt 0.4.16。[Node 24.18.0 官方归档](https://nodejs.org/dist/v24.18.0/) · [MoonBit 安装](https://docs.moonbitlang.com/en/latest/download.html)

## 2. 源码与构建

本阶段分支尚未推送。维护者审核选定提交后，可从其本地 checkout 导出受版本管理的源码包，经批准的文件传输流程放入目标构建目录。`git archive` 自动排除本地未跟踪维护文件、node_modules 和运行数据库。

```sh
set -eu
# 在已审核的 Phase 7.2 checkout 中执行
git status --short
git rev-parse HEAD
git archive --format=tar.gz --output=/tmp/moonpasskey-source.tar.gz HEAD
sha256sum /tmp/moonpasskey-source.tar.gz
```

在服务器以普通构建账户解包到新目录，并记录传输前后的摘要。以下假设已通过批准流程将文件放在 `/tmp/moonpasskey-source.tar.gz`。

```sh
set -eu
mkdir -p "$HOME/moonpasskey-build"
cd "$HOME/moonpasskey-build"
tar -xzf /tmp/moonpasskey-source.tar.gz
export MOON_HOME=/opt/moonbit-0.10.20
export PATH="/opt/node-v24.18.0/bin:$MOON_HOME/bin:$PATH"
moon update
moon info
moon fmt --check
for target in native js wasm wasm-gc; do
  moon check --target "$target" --deny-warn
  moon test --target "$target" --deny-warn
done
moon build analysis --target js --release --deny-warn
moon build analysis --target js --deny-warn
npm --prefix reference-rp test
npm --prefix dashboard ci
npm --prefix dashboard run check
npm --prefix dashboard test
npm --prefix dashboard run build
node --experimental-strip-types scripts/check-interop-reports.mjs
MOONPASSKEY_REQUIRE_NGINX=1 node --test deploy/ubuntu-nginx/tests/*.test.mjs
shellcheck -x deploy/ubuntu-nginx/scripts/*.sh
# 隔离Ubuntu 22.04验证机上的完整部署检查入口
bash deploy/ubuntu-nginx/tests/validate-ubuntu22.sh
```

部署运行只需要编译 Core 和 Dashboard 产物及 RP 源码，Node 服务不在启动时进行包安装或构建。MoonCrypt 全部通过 MoonBit 构建产物使用。

## 3. 账户和 release 文件

从构建根目录执行。release 标识采用人工确认的构建日期和提交短 hash，例如通过下面命令生成。建立新目录时拒绝覆盖既有 release。

```sh
set -eu
getent group moonpasskey || sudo groupadd --system moonpasskey
id moonpasskey || sudo useradd --system --gid moonpasskey --home-dir /nonexistent --shell /usr/sbin/nologin moonpasskey
sudo install -d -o root -g root -m 0755 /opt/moonpasskey/releases /etc/moonpasskey /etc/moonpasskey/tls
sudo install -d -o moonpasskey -g moonpasskey -m 0700 /var/lib/moonpasskey
release_id=$(date -u +%Y%m%dT%H%M%SZ)
release_dir="/opt/moonpasskey/releases/$release_id"
sudo test ! -e "$release_dir"
sudo test ! -L "$release_dir"
sudo install -d -o root -g root -m 0755 "$release_dir"
sudo cp -a reference-rp deploy "$release_dir/"
sudo install -d -m 0755 "$release_dir/_build/js/release/build/analysis" "$release_dir/dashboard"
sudo cp _build/js/release/build/analysis/analysis.js "$release_dir/_build/js/release/build/analysis/analysis.js"
sudo cp -a dashboard/dist "$release_dir/dashboard/"
sudo chown -R root:root "$release_dir"
sudo chmod -R a+rX,go-w "$release_dir"
sudo test ! -e /opt/moonpasskey/current
sudo test ! -L /opt/moonpasskey/current
sudo ln -s "$release_dir" /opt/moonpasskey/current
```

首次部署使用上述 current 检查。升级已有 current 时先按 [回滚与 release 切换](ROLLBACK.md) 记录旧目标，由维护者在停机窗口切换。

## 4. 内部 CA 和后端 TLS

在本次源码构建目录运行。生成器默认只操作 `/etc/moonpasskey/tls`，已有 CA 或 leaf 目录会拒绝覆盖。生成失败清理自身临时目录，生产 CA key 仅 root 可读。

```sh
set -eu
sudo bash deploy/ubuntu-nginx/scripts/generate-backend-ca.sh
sudo bash deploy/ubuntu-nginx/scripts/generate-backend-cert.sh
sudo test ! -e /etc/moonpasskey/tls/backend-ca.crt
sudo test ! -L /etc/moonpasskey/tls/backend-ca.crt
sudo install -o root -g root -m 0644 \
  /etc/moonpasskey/tls/ca/ca.crt /etc/moonpasskey/tls/backend-ca.crt
sudo openssl verify -no-CApath -no-CAstore -purpose sslserver \
  -CAfile /etc/moonpasskey/tls/backend-ca.crt -verify_hostname passkey-test.ksuser.cn \
  /etc/moonpasskey/tls/backend/backend.crt
sudo -u moonpasskey test -r /etc/moonpasskey/tls/backend/backend.key
sudo -u moonpasskey test ! -r /etc/moonpasskey/tls/ca/ca.key
```

后端证书 SAN 为 DNS:passkey-test.ksuser.cn。内部 CA 不安装到系统或浏览器 trust store，Nginx 仅通过本站 `proxy_ssl_trusted_certificate` 引用它。Node 配置仅使用 leaf cert/key，签发 CA key 不进入服务可访问范围。[证书生命周期与权限](tls/README.md)

## 5. 环境与 systemd

```sh
set -eu
sudo test ! -e /etc/moonpasskey/reference-rp.env
sudo test ! -L /etc/moonpasskey/reference-rp.env
sudo install -o root -g root -m 0600 deploy/ubuntu-nginx/config/reference-rp.env.example /etc/moonpasskey/reference-rp.env
sudo test ! -e /etc/systemd/system/moonpasskey-rp.service
sudo test ! -L /etc/systemd/system/moonpasskey-rp.service
sudo install -o root -g root -m 0644 deploy/ubuntu-nginx/systemd/moonpasskey-rp.service /etc/systemd/system/moonpasskey-rp.service
sudo systemd-analyze verify /etc/systemd/system/moonpasskey-rp.service
```

EnvironmentFile 使用字面 `KEY=value`，没有 shell export、source 或插值。systemd 先以管理器身份读取 root0600 环境，再以 moonpasskey 用户运行 Node。`ProtectSystem=strict` 配合 `ReadWritePaths=/var/lib/moonpasskey`，持久写入限定为 SQLite 目录。PrivateTmp 提供隔离的临时命名空间。NoNewPrivileges、ProtectHome 和 InaccessiblePaths 进一步约束 CA、边缘证书和 Basic Auth 凭据。[Ubuntu 22.04 systemd.exec](https://manpages.ubuntu.com/manpages/jammy/en/man5/systemd.exec.5.html)

## 6. 独立 HTTP 站点与 DNS

在 DNS 控制台由维护者将 `passkey-test.ksuser.cn` 的 A 记录指向未来目标公网 IPv4。只有确认 IPv6 已正确监听和路由时才配置 AAAA，避免 ACME 请求命中错误目标。先验证 DNS，再审核目标端口及安全组。此步骤由未来部署授权单独覆盖。

```sh
set -eu
getent ahosts passkey-test.ksuser.cn
sudo install -d -o root -g root -m 0755 /var/www/moonpasskey-acme/.well-known/acme-challenge
sudo test ! -e /etc/nginx/sites-available/moonpasskey-http.conf
sudo test ! -L /etc/nginx/sites-available/moonpasskey-http.conf
sudo install -o root -g root -m 0644 deploy/ubuntu-nginx/nginx/moonpasskey-http.conf /etc/nginx/sites-available/moonpasskey-http.conf
sudo test ! -e /etc/nginx/sites-enabled/moonpasskey-http.conf
sudo test ! -L /etc/nginx/sites-enabled/moonpasskey-http.conf
sudo ln -s /etc/nginx/sites-available/moonpasskey-http.conf /etc/nginx/sites-enabled/moonpasskey-http.conf
sudo nginx -t
# 以下为未来维护者激活命令
sudo systemctl reload nginx
```

HTTP 只为该 server_name 的 ACME challenge 返回文件，其余路径固定跳转 HTTPS。现有 nginx.conf 与其他站点文件不需要改动。HTTPS 片段在公网证书就绪后再启用。

## 7. Let's Encrypt 与 Basic Auth

维护者确认公网80可达、DNS正确并授权证书申请后，交互执行 webroot 申请，按真实邮箱和条款提示填写。使用 certonly 避免自动重写虚拟主机。

```sh
set -eu
sudo certbot certonly --webroot --webroot-path /var/www/moonpasskey-acme \
  --domain passkey-test.ksuser.cn --cert-name passkey-test.ksuser.cn
sudo test ! -e /etc/nginx/moonpasskey.htpasswd
sudo test ! -L /etc/nginx/moonpasskey.htpasswd
sudo htpasswd -cB /etc/nginx/moonpasskey.htpasswd maintainer
sudo chown root:www-data /etc/nginx/moonpasskey.htpasswd
sudo chmod 0640 /etc/nginx/moonpasskey.htpasswd
```

Basic Auth 密码通过交互提示输入，使用独立测试凭据。HTTPS 的 Dashboard、assets 和全部 API 均要求认证，Authorization 不转发到 Node。HTTP ACME 路径不受 Basic Auth 阻断。[Certbot webroot](https://eff-certbot.readthedocs.io/en/stable/using.html#webroot)

## 8. 预检与服务激活

```sh
set -eu
sudo bash deploy/ubuntu-nginx/scripts/preflight.sh --check-dns --json
sudo test ! -e /etc/nginx/sites-available/moonpasskey-https.conf
sudo test ! -L /etc/nginx/sites-available/moonpasskey-https.conf
sudo install -o root -g root -m 0644 deploy/ubuntu-nginx/nginx/moonpasskey-https.conf /etc/nginx/sites-available/moonpasskey-https.conf
sudo test ! -e /etc/nginx/sites-enabled/moonpasskey-https.conf
sudo test ! -L /etc/nginx/sites-enabled/moonpasskey-https.conf
sudo ln -s /etc/nginx/sites-available/moonpasskey-https.conf /etc/nginx/sites-enabled/moonpasskey-https.conf
sudo nginx -t
sudo systemd-analyze verify /etc/systemd/system/moonpasskey-rp.service
# 通过所有预检并取得本次真实部署授权后，由维护者执行
sudo systemctl daemon-reload
sudo systemctl enable --now moonpasskey-rp.service
sudo systemctl reload nginx
```

预检默认离线、只读。DNS 只在 `--check-dns` 时查询，HTTPS 请求只在 verifier 的 `--network` 时发送。它检查 Ubuntu/CPU、Node及完整 compiler hash、Nginx 状态、80/443/8787占用、环境、证书链/名称/时效/配对及权限。首次部署 Nginx inactive 和空闲端口可接受，failed 状态拒绝。私有CA目录和CA key的隔离另由生成器、unit限制及第4节的人工读取拒绝检查验证。Unix 权限位检查不代替真实 systemd/AppArmor/ACL 运行验收。

## 9. 部署后验证与证书续期

```sh
set -eu
sudo systemctl status moonpasskey-rp.service --no-pager
sudo journalctl -u moonpasskey-rp.service --since '-10 minutes' --no-pager
sudo ss -ltnp '( sport = :80 or sport = :443 or sport = :8787 )'
sudo bash deploy/ubuntu-nginx/scripts/verify-deployment.sh --json
```

8787应只监听127.0.0.1。HTTPS verifier 需要显式网络参数和 root0600 的独立 `username:password` 单行文件。维护者通过编辑器在私有目录准备该文件，不将密码放进命令行、日志或仓库。

```sh
set -eu
sudo install -o root -g root -m 0600 /dev/null /root/moonpasskey-verification.credentials
sudoedit /root/moonpasskey-verification.credentials
sudo bash deploy/ubuntu-nginx/scripts/verify-deployment.sh --network \
  --credentials-file /root/moonpasskey-verification.credentials --json
```

期待后端 TLS成功，错误Host/Origin为403，公网未授权为401，Basic Auth通过后页面为200。脚本只请求静态首页及拒绝路径，不创建挑战、会话或测试账号。随后由维护者在真实浏览器执行注册、Assertion、required UV和重复认证，导出实际脱敏报告并按 P7.1 检查器验收。

Certbot 的 webroot 续期保留HTTP challenge通道。维护者单独批准后可执行实际续期与测试。

```sh
set -eu
sudo certbot renew --cert-name passkey-test.ksuser.cn --dry-run
sudo certbot renew --cert-name passkey-test.ksuser.cn
sudo nginx -t && sudo systemctl reload nginx
systemctl list-timers certbot.timer --all
```

自动续期需要在维护者审核后配置本站 deploy hook，在续期成功后运行 `nginx -t`，成功才 reload。若服务器已有统一 hook，应使用既有运维流程，避免重复 reload。没有统一 hook 时，可建立只响应本站续期的独立文件。

```sh
set -eu
sudo test ! -e /etc/letsencrypt/renewal-hooks/deploy/moonpasskey-nginx
sudo test ! -L /etc/letsencrypt/renewal-hooks/deploy/moonpasskey-nginx
hook_stage=$(mktemp)
cat > "$hook_stage" <<'HOOK'
#!/bin/sh
set -eu
case " ${RENEWED_DOMAINS:-} " in
  *' passkey-test.ksuser.cn '*) /usr/sbin/nginx -t && /bin/systemctl reload nginx ;;
esac
HOOK
sudo install -o root -g root -m 0755 "$hook_stage" /etc/letsencrypt/renewal-hooks/deploy/moonpasskey-nginx
rm "$hook_stage"
```

内部 CA 和后端 leaf 不由 Certbot 管理，其轮换步骤见 TLS 文档。公网 Let's Encrypt 证书目录由其既有机制管理。

## 10. 故障排查

| 现象 | 检查 |
| --- | --- |
| nginx -t 找不到公网证书 | 先仅启用HTTP片段完成ACME，再启用HTTPS片段 |
| 401 | 核对本站htpasswd、浏览器Basic Auth和文件www-data读取权限 |
| 444或空响应 | 实际Host必须是passkey-test.ksuser.cn，使用域名访问 |
| 502且证书错误 | 内部CA、SAN、时效、proxy_ssl_name/SNI与Node实际leaf检查，修复后保持校验开启 |
| OriginMismatch / CSRF | Origin原样传递，页面与配置scheme/host/port须相同，保持当前cookie/CSRF |
| service读取TLS失败 | 检查root:moonpasskey0750/0640、全部父目录遍历与unit沙箱 |
| SQLite无法写入 | /var/lib/moonpasskey归moonpasskey、0700，DB0600，检查磁盘和AppArmor |
| 服务启动错误 | 核对Node绝对版本路径、CORE release产物、EnvironmentFile格式和journal |
| 端口被其他进程占用 | 停止激活计划，先与维护者确认已有服务用途 |
| ACME失败 | DNS A/AAAA、HTTP80可达、challenge webroot及独立vhost匹配 |

回滚只操作本站链接和服务，数据库与签发材料保留至维护者决定。[回滚手册](ROLLBACK.md)
