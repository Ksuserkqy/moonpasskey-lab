# 本站回滚与保留

本手册的操作范围为 MoonPasskey 专属服务、两条本站 Nginx 链接和 current release。现有网站、全局 Nginx 配置、SQLite 和证书材料保留。执行前由维护者确认真实服务器操作授权和实际故障范围。

## 仅停用本站入口

先记录当前版本和 unit 状态。进入原部署源码目录后执行默认 dry-run，它只列出将停用的本站链接。

```sh
set -eu
readlink /opt/moonpasskey/current
systemctl status moonpasskey-rp.service --no-pager
sudo bash deploy/ubuntu-nginx/scripts/rollback-site.sh
```

脚本只接受 sites-enabled 中名称为 moonpasskey-http.conf 和 moonpasskey-https.conf、且目标精确等于对应 sites-available 路径的符号链接。任何普通文件、意外目标或符号链接父目录都会拒绝，在校验全部候选后才删除。脚本不调用systemctl或reload，不删除sites-available内容。

维护者审核 dry-run 后手动应用，再做配置检查。若检查失败，保持现有 Nginx进程，修复或恢复本站链接后重新检查，通过才reload。

```sh
set -eu
sudo bash deploy/ubuntu-nginx/scripts/rollback-site.sh --apply
sudo nginx -t
# 仅在上一条成功且维护者确认后执行
sudo systemctl reload nginx
sudo systemctl stop moonpasskey-rp.service
sudo systemctl disable moonpasskey-rp.service
```

停止本站HTTP片段后，相关ACME续期路径也停止提供服务。维护者须同步暂停或安排本站续期，保留其他域名既有Certbot配置。

## 恢复上一 release

先选择已验收的真实历史路径。下面通过交互读取路径，验证该目录位于本站 releases 内，再在停止本站 Node 服务后切换 current。配置、数据格式或历史版本不兼容时，维护者先评估恢复步骤。

```sh
set -eu
read -r -p '已验收的完整 release 路径: ' previous_release
case "$previous_release" in /opt/moonpasskey/releases/*) ;; *) exit 1 ;; esac
case "$previous_release" in *"/../"*|*"/./"*) exit 1 ;; esac
test -d "$previous_release"
test "$(readlink -f "$previous_release")" = "$previous_release"
test -f "$previous_release/reference-rp/start.mjs"
test -f "$previous_release/_build/js/release/build/analysis/analysis.js"
sudo systemctl stop moonpasskey-rp.service
sudo test -L /opt/moonpasskey/current
sudo test ! -e /opt/moonpasskey/current.rollback
sudo test ! -L /opt/moonpasskey/current.rollback
sudo ln -sT "$previous_release" /opt/moonpasskey/current.rollback
sudo mv -Tf /opt/moonpasskey/current.rollback /opt/moonpasskey/current
sudo systemctl start moonpasskey-rp.service
sudo systemctl status moonpasskey-rp.service --no-pager
```

恢复已经保留的站点文件时只重建本站链接，先核对保留配置与证书仍有效。

```sh
set -eu
for site in moonpasskey-http.conf moonpasskey-https.conf; do
  sudo test -f "/etc/nginx/sites-available/$site"
  sudo test ! -e "/etc/nginx/sites-enabled/$site"
  sudo test ! -L "/etc/nginx/sites-enabled/$site"
done
for site in moonpasskey-http.conf moonpasskey-https.conf; do
  sudo ln -sT "/etc/nginx/sites-available/$site" "/etc/nginx/sites-enabled/$site"
done
sudo nginx -t
# 通过配置检查并由维护者确认后执行
sudo systemctl reload nginx
```

回滚脚本可重复执行，测试证明其他合成站点链接、文件和数据库不会被删除。

## 数据与密钥

SQLite恢复前先停止本站Node，按维护者批准的备份方案保留DB、WAL和SHM一致快照。不得只复制运行中DB文件而忽略WAL。内部CA key、leaf、htpasswd、公网证书和日志的保留或销毁由独立授权流程决定，本站回滚脚本没有这些删除功能。
