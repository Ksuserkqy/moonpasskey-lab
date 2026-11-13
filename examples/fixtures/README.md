# SYNTHETIC 演示输入

这里全部是可公开的项目合成输入，不包含真实用户、真实设备采集记录或私钥。有效断言逐字节复用 `analysis/fixtures_test.mbt` 的 `bridge_fixture("verify")`。每个 JSON 的 `_fixture.classification` 均为 `SYNTHETIC`；该字段仅标注输入来源，Core 会忽略它，不影响验证结果。

| 文件 | Core 预期结果 | 变化 |
| --- | --- | --- |
| `client-data.json` | PASS，`json` PASS | 单独解析原始 ClientDataJSON |
| `authenticator-data.json` | PASS，`authenticator_data` PASS | 单独解析原始 AuthenticatorData |
| `verify-valid.json` | PASS，`signature` PASS | 原始有效 ES256 合成断言，策略 UV preferred |
| `verify-invalid-signature.json` | FAIL，`InvalidSignature` | 仅翻转 DER 签名最后一个字节，保留 DER 结构 |
| `verify-wrong-challenge.json` | FAIL，`ChallengeMismatch` | 仅修改可信 `expectedChallenge`，保留签名和协议原始字节 |
| `verify-wrong-origin.json` | FAIL，`OriginNotAllowed` | 仅修改可信 Origin 白名单，保留签名和协议原始字节 |
| `verify-uv-required.json` | FAIL，`UserVerificationRequired` | 仅把策略改为 UV required；原始已签名 flags 为 UP=true、UV=false |

输入中的 `rp.test` / `https://rp.test` 是离线夹具的合成策略值。Dashboard 顶部显示的 `localhost` 是运行中的本地参考 RP 配置，两者用途不同。Import 对请求内携带的策略执行分析，不会将该夹具登记为本地账户凭证，也不会证明真实设备互操作成功。

独立解析成功只说明格式可解析；未执行的验签与策略检查保持 `NOT_PERFORMED`。完整验证在错误处短路，负例中其他 `NOT_PERFORMED` 项目不能解释成通过。运行 `./scripts/demo.sh cli` 会实际调用普通 CLI，逐一核对七组场景的文本/JSON 退出码、JSON 状态、关键检查和错误类型。
