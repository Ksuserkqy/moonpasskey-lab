# P7.2 本地验证记录

2026-11-12，部署工程准备状态为 `PASS_WITH_WARNINGS`。真实服务器部署、公网域名访问、DNS变更、Let's Encrypt申请/续期和新设备验收均为 `NOT_PERFORMED`。本阶段仅创建本地worktree及本地隔离验证环境。

## 基线与文件边界

- source commit为 `6e4136bac9f18dd88359e5b783ccdd9ee160636c`。
- 分支为 `feat/p7-2-ubuntu-nginx-deployment`，独立worktree通过Codex worktree工具创建。
- 所有新增内容位于 `deploy/ubuntu-nginx/`，原有Core、RP、Dashboard、P7.1报告及证据文件没有改动。
- 原checkout仍在指定commit且工作区干净，PR #8只读核验为Draft/OPEN，head保持该commit。
- 原Safari报告SHA-256保持 `0f27841c5fcf6d84927a7b53b66a9f6b24aa2fa0feb84f7caa711cd13311c9af`。

## macOS 原有完整回归

使用隔离MoonBit `0.10.20+65efd5b93` 与官方Node `24.18.0`，MoonCrypt保持 `0.4.16`。

| 目标 | Core | CLI | info/check/build/run |
| --- | --- | --- | --- |
| native | 491/491 | 7/7 | PASS |
| js | 491/491 | 7/7 | PASS |
| wasm | 491/491 | 7/7 | PASS |
| wasm-gc | 491/491 | 7/7 | PASS |

RP57/57、Dashboard26/26、类型检查、Dashboard构建和既有报告校验全部通过。独立基线581项完整保留。moon info、moon fmt、moon fmt --check、所有目标deny-warn检查/测试/构建/运行和git diff --check通过。新worktree的npm ci报告macOS可选fsevents安装脚本未获许可，后续类型检查/测试/构建均成功。固定MoonBit首次生成CommonJS产物时提示仅ESM生成TypeScript declaration，实际JS入口通过既有测试。

## Ubuntu 22.04 实际环境

通过本机QEMU/HVF启动独立Ubuntu arm64虚拟机。没有SSH连接、宿主端口转发或真实服务器操作。源码来自功能worktree的只读9p共享，测试副本写入虚拟机的 `/opt/p72-project`。系统包安装时设置policy-rc.d禁止包安装脚本自动启动Nginx。实际Nginx验证由测试在临时目录启动独立进程，使用临时端口、合成TLS和认证材料。

| 工具 | 实际版本 |
| --- | --- |
| OS | Ubuntu 22.04.5 LTS，aarch64 |
| Kernel | 5.15.0-203-generic |
| QEMU | 11.1.3，HVF |
| Nginx | 1.18.0-6ubuntu14.22 |
| systemd | 249.11-0ubuntu3.23 |
| OpenSSL | 3.0.2-0ubuntu1.30 |
| ShellCheck | 0.8.0-2 |
| Node | 官方Linux arm64 24.18.0 |
| moon/moonrun | 0.1.20261104，940aa18 |
| moonc/core | 0.10.20+65efd5b93 |

Ubuntu镜像固定为20261106 daily，SHA256与官方SHA256SUMS一致。Node归档同样按官方SHA256SUMS核对。MoonBit使用官方版本化归档，URL中的加号编码为%2B；未编码的加号请求曾返回403，编码后的归档下载、解包和core bundle成功。

| 归档 | SHA-256 |
| --- | --- |
| jammy-server-cloudimg-arm64.img | 7fc0212296c65f8e20f8e9af89aaab9500ea4ec73cfb245afa0f2b509bb90785 |
| node-v24.18.0-linux-arm64.tar.xz | 58c9520501f6ae2b52d5b210444e24b9d0c029a58c5011b797bc1fe7105886f6 |
| moonbit-linux-aarch64.tar.gz | 8eaf1e2bd633bc6ab480d86ebeeef2d40248b7c8b5317dc287d77ad01f165727 |

MoonBit归档摘要为本次下载的记录值，完整compiler版本通过实际执行核对。[Ubuntu固定镜像](https://cloud-images.ubuntu.com/jammy/20261106/) · [Ubuntu官方摘要](https://cloud-images.ubuntu.com/jammy/20261106/SHA256SUMS) · [Node官方摘要](https://nodejs.org/dist/v24.18.0/SHASUMS256.txt)

## 实际执行结果

```sh
bash deploy/ubuntu-nginx/tests/validate-ubuntu22.sh
```

该入口强制要求Ubuntu22.04、固定Node和实际Nginx，缺少Nginx时失败。它执行Bash语法、ShellCheck、systemd-analyze verify和部署测试。

最终部署套件按Node统计为51/51、0失败、0跳过，其中1个父测试汇总7项实际Nginx子测试。新增独立叶用例为50项，与既有581项合计631项。组成分别为配置6项、预检与verifier25项、回滚6项、TLS生成6项、Nginx运行7项。宿主macOS缺少Nginx时该运行组明确跳过，最终验收采用Ubuntu上的强制运行结果。

| 检查 | 实际结果 |
| --- | --- |
| Nginx -t，独立临时prefix，两个vhost | PASS |
| 实际HTTP ACME、固定HTTPS跳转与Host拒绝 | PASS |
| 全部应用路径Basic Auth与凭据不转发 | PASS |
| Origin/Cookie/CSRF/body与响应原样传输 | PASS |
| 上游正确SAN/SNI、指定CA验证 | PASS |
| 上游错误SAN、不受信CA、过期证书 | 均拒绝，502 |
| Bash脚本语法及Ubuntu ShellCheck0.8 | PASS |
| systemd-analyze verify，本项目unit | exit0 |
| 最终部署套件 | 51/51，0跳过 |
| 原有RP57项在Ubuntu额外复验 | 57/57 |
| 原有Dashboard/报告26项在Ubuntu额外复验 | 26/26 |

systemd校验还输出镜像既有 `/lib/systemd/system/snapd.service` 的 `RestartMode` 未知key提示，项目unit没有该设置。该外部提示未隐藏，verify返回0。第一次ShellCheck0.8发现三处SC2015，已改为显式if并在同一Ubuntu环境重跑通过。

Nginx运行测试替换监听端口、证书、认证文件和ACME路径到临时测试资源，实际执行checked-in配置的处理规则。它证明合成环境中的代理行为，实际Let's Encrypt证书、真实公网路由、既有多站点环境和浏览器验收仍待部署阶段确认。

另在虚拟机中执行了两个生成器的默认生产路径分支。CA/key为root:root0700/0600，backend目录/key为root:moonpasskey0750/0640，公开CA为root:root0644。实际runuser检查证明moonpasskey可读leaf key并无法读取CA key，OpenSSL指定CA及hostname验证通过。所有这些材料均在临时虚拟机内合成，不进入仓库。

## 预检与未完成项

离线预检自动化覆盖环境文件、精确RP策略、版本、目录权限、release Core存在/读取及受控父路径、独立CA/leaf、证书SAN/时效/配对、默认无网络和无数据库探针写入。Ubuntu中另用实际moonpasskey身份核对了root持有的编译Core读取权限，检查过程中没有执行该产物。网络verifier测试只访问动态loopback合成HTTPS，包含Basic Auth、Host/Origin拒绝、错误CA与敏感凭据文件权限。

真实主机完整preflight需要真实安装路径、环境、服务账户、数据目录和Let's Encrypt证书，当前未对真实主机执行。公网DNS查询及域名HTTPS验证未执行。Unix权限位检查不建立AppArmor/ACL或实际systemd服务运行证据，相关步骤由部署手册交给维护者验收。

本机为该验证安装了QEMU、ShellCheck及Homebrew依赖，其中若干既有依赖由Homebrew升级。版本化Node和MoonBit均使用独立目录。实际生成的证书、密钥、密码和数据库只存在于临时测试资源。当前阶段的远程CI、推送和PR创建不在授权操作范围内。
