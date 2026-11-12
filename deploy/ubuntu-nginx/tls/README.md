# Nginx → Node 后端 TLS

这里的独立私有根 CA 只用于 Nginx 验证 `127.0.0.1:8787` 上的 Node HTTPS。浏览器仍验证 Nginx 的公有证书；本 CA 不安装进操作系统或浏览器信任库，也不替代 Let's Encrypt 证书。

| 路径 | 所有者 / 权限 | 使用者 |
| --- | --- | --- |
| `/etc/moonpasskey/tls` | `root:root` / `0755` | 受保护的父目录 |
| `ca/` | `root:root` / `0700` | 仅管理员 |
| `ca/ca.key` | `root:root` / `0600` | 仅管理员签发时读取 |
| `ca/ca.crt` | `root:root` / `0644`，父目录不可遍历 | 管理员导出公有 CA 证书 |
| `backend/` | `root:moonpasskey` / `0750` | Node 读取叶证书与密钥 |
| `backend/backend.crt`、`backend/backend.key` | `root:moonpasskey` / `0640` | Node；不授予 CA 私钥访问权 |
| `backend-ca.crt` | `root:root` / `0644` | Nginx 的显式上游信任锚 |

## 首次生成

在 Ubuntu 22.04 上安装 `openssl`（OpenSSL 3），先按主运行手册创建 `moonpasskey` 系统用户和组。在仓库根目录由 root 执行：

```sh
sudo install -d -o root -g root -m 0755 /etc/moonpasskey /etc/moonpasskey/tls
sudo bash deploy/ubuntu-nginx/scripts/generate-backend-ca.sh
sudo bash deploy/ubuntu-nginx/scripts/generate-backend-cert.sh
sudo install -o root -g root -m 0644 \
  /etc/moonpasskey/tls/ca/ca.crt /etc/moonpasskey/tls/backend-ca.crt
sudo openssl verify -no-CApath -no-CAstore -x509_strict -purpose sslserver \
  -CAfile /etc/moonpasskey/tls/backend-ca.crt \
  -verify_hostname passkey-test.ksuser.cn \
  /etc/moonpasskey/tls/backend/backend.crt
```

CA 与叶证书分别生成独立的 P-256 私钥。CA 有效期为 3650 天，带 `CA:TRUE,pathlen:0`；叶证书有效期为 365 天，包含唯一的 `DNS:passkey-test.ksuser.cn` SAN、`CA:FALSE` 和 `serverAuth`。序列号为随机 128 位值，签发不创建或修改 CA 的串号状态文件。

Node 启动仅读取 `REFERENCE_RP_TLS_CERT` 和 `REFERENCE_RP_TLS_KEY` 两个叶凭据。同一 EnvironmentFile 另设 `REFERENCE_RP_TLS_CA` 供离线预检读取公开 CA。Nginx 使用 `proxy_ssl_trusted_certificate /etc/moonpasskey/tls/backend-ca.crt`、`proxy_ssl_verify on`、`proxy_ssl_server_name on`、`proxy_ssl_name passkey-test.ksuser.cn` 验证证书链与名称；连接目的地址仍为回环 IP。不能关闭上游验证或改信任叶证书。

## 失败、权限与续签

两个脚本都拒绝相对路径、`.` / `..` 路径组件、路径中的符号链接、不安全权限和已有输出，包括空目录或悬空链接。叶签发还检查 CA 目录与文件所有者、权限、硬链接、私钥结构、CA 证书及剩余有效期。生产调用必须为 root，父目录必须由 root 持有且不可被组或其他用户写入。

每次签发先取得该输出的目录锁，在同一受保护父目录的私有临时目录中生成并验证完整凭据，最后一次目录重命名发布。普通失败和可捕获信号会清理临时目录和锁，已有 CA 不会被改写。断电或 `SIGKILL` 后可能留下隐藏的临时目录或锁：先确认没有生成进程，再由 root 检查并清理；不要将未完成的临时文件投入使用。

`ca/` 和 `backend/` 均禁止覆盖。续签前停止 RP，将现有 `backend/` 移入管理员的 `0700` 备份目录，重新执行叶签发，验证后重启并按主运行手册验收；失败时恢复原目录。CA 私钥需要单独安全备份；不要为普通叶续签删除或重建 CA。更换 CA 必须同时规划 Nginx 信任锚更新与回滚，属于管理员显式操作。

## 离线测试

```sh
node --test deploy/ubuntu-nginx/tests/tls.test.mjs
```

测试只使用临时目录，不读取或写入真实 `/etc`、系统信任库、DNS 或 ACME 服务。脚本的 `--test-directory ABSOLUTE_EXISTING_DIRECTORY` 选项要求调用者持有、模式为 `0700` 的现有目录；生成其下的 `ca/` 和 `backend/`，组使用当前用户主组，允许非 root 测试。该选项不会执行生产用户配置或部署。测试覆盖权限、独立 CA、SAN、密钥匹配、正确与错误主机名的真实 OpenSSL 链验证、拒绝覆盖、不安全路径 / CA 输入，以及中途失败的清理。

实现依据：[OpenSSL 3 req](https://docs.openssl.org/3.0/man1/openssl-req/)、[x509](https://docs.openssl.org/3.0/man1/openssl-x509/) 与[证书验证选项](https://docs.openssl.org/3.0/man1/openssl-verification-options/)。这些离线测试不能代替目标 Ubuntu 主机上的 `nginx -t`、服务权限与真实反向代理连通性验收。
