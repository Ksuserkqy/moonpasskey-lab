# 图像来源

图像于 2026-11-12 在本地参赛工作区生成。PNG 为实际 Safari 窗口截图，未合成结果或修改界面中的验证状态。

| 文件 | 来源与范围 |
| --- | --- |
| `dashboard.png` | `DEMO_PORT=8790 ./scripts/demo.sh` 启动后的首页，等待测试注册，无本次设备认证结果 |
| `verification-result.png` | 导入公开 `demo/verify-valid.json`，实际 MoonBit Core 返回 PASS，界面保留 SYNTHETIC import、UV=0 和 NOT_SUPPORTED |
| `cli-demo.png` | 两次普通 CLI 执行的 stdout 在本地 HTML 中排版后由 Safari 截图，完整输出见 `cli-output.txt`；截图为输出阅读页 |
| `architecture.svg` | 本项目手工编写的架构示意图，实线为当前调用路径，虚线为部署准备入口 |

CLI 的有效输入来自已有公开 SYNTHETIC fixture。错误定位输入可按下列命令重建，退出码 2 为预期拒绝。

```sh
printf '%s\n' '{"command":"authenticator-data","authenticatorData":"AQ","_fixture":{"classification":"SYNTHETIC"}}' > /tmp/moonpasskey-truncated.json
moon run cmd/main --target js --deny-warn -- --input /tmp/moonpasskey-truncated.json
```

实际输出为 `UnexpectedEnd`、`authData.rpIdHash`、`offset=0`。这些截图记录本地合成演示。真实 Safari/macOS 设备证据见仓库已有历史报告，其原始字节单独保存。
