# Analysis CLI

Phase 7 扩展已有 `cmd/main`。CLI、参考 RP 和 Dashboard 共用纯 MoonBit `analysis` 包及 P1–P6 验证入口。工具链固定为 `0.10.20+65efd5b93`，MoonCrypt 固定为 `0.4.16`。文件读取使用已存在于依赖树的 `moonbitlang/x@0.5.7`，该版本现列为直接依赖。

## 运行

在仓库根目录准备 UTF-8 JSON 请求文件，再执行命令。请求中的二进制字段均使用严格、无 padding 的 Base64URL 编码，保留原始字节。

```sh
moon run cmd/main -- --input request.json
moon run cmd/main --target js -- --input request.json --json
moon run cmd/main --target native -- --help
```

无参数和 `--help` 输出帮助并退出0。默认输出可读文本，`--json` 输出单个机器可读对象。完整输入只通过文件读取，报告隐藏完整 challenge、credential ID、userHandle、公钥编码、签名和原始认证字节。

| 退出码 | 含义 |
| --- | --- |
| 0 | PASS 或帮助 |
| 2 | Core 输入、解析、策略或验签失败 |
| 64 | 参数错误或缺少输入文件 |
| 70 | 内部报告契约错误 |
| 74 | 文件读取失败 |

## 请求

ClientData 独立分析使用下面的项目合成输入。其 Base64URL 内容是原始 JSON 字节。

```json
{"command":"client-data","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVEiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIn0"}
```

| command | 必需字段 |
| --- | --- |
| `client-data` | `clientDataJSON` |
| `authenticator-data` | `authenticatorData` |
| `analyze-assertion` | `clientDataJSON`、`authenticatorData`、`signature`、`publicKey` |
| `verify-assertion` | `clientDataJSON`、`authenticatorData`、`signature`、`credentialId`、`expectedChallenge`、`credential`、`policy` |
| `register-test` | `clientDataJSON`、`attestationObject`、`credentialId`、`userHandle`、`expectedChallenge`、`policy` |

`publicKey` 是完整 COSE CBOR 编码。`analyze-assertion` 解析输入并检查该公钥与 DER 签名，安全策略检查状态保持 `NOT_PERFORMED`。`verify-assertion` 调用 P6 的完整 ES256 Assertion 验证入口。

```json
{
  "command": "verify-assertion",
  "clientDataJSON": "<base64url>",
  "authenticatorData": "<base64url>",
  "signature": "<base64url DER>",
  "credentialId": "<base64url>",
  "userHandle": null,
  "expectedChallenge": "<base64url>",
  "userIdentification": "identified",
  "credential": {
    "credentialId": "<base64url>",
    "userHandle": "<base64url>",
    "publicKey": "<base64url COSE CBOR>",
    "signCount": 0,
    "backupEligible": true
  },
  "policy": {
    "rpId": "localhost",
    "allowedOrigins": ["http://localhost:8787"],
    "uv": "preferred",
    "counterPolicy": "report-only",
    "allowCrossOrigin": false,
    "allowedTopOrigins": [],
    "allowedCredentialIds": []
  }
}
```

`userIdentification` 可为 `identified` 或 `discoverable`，默认 identified。UV 支持 preferred、required、discouraged，默认 preferred。Counter 支持 report-only、reject，默认 report-only。已登记 BE 未知时使用 null。参考 RP 从可信数据库构造这些字段。

`register-test` 仅用于测试登记，要求 `fmt=none` 和空 statement Map，验证 challenge、origin、RP ID hash、UP/UV、AT、RFU、BE/BS、凭证 ID 和 ES256 公钥曲线点。其公开报告隐藏内部存储记录。完整 attestation 信任评估尚未实现。

## 报告与资源边界

`status` 是 PASS 或 FAIL，`checks` 包含逐步状态，错误包含类型、静态 context 和适用的 offset。独立解析成功时，尚未执行的策略检查保持 NOT_PERFORMED。UV preferred 时 PASS 表示满足策略，实际 UV 值见 flags。Counter WARNING 表示非递增风险。P6 在错误处短路，无法从错误确认的其他步骤保守报告 NOT_PERFORMED。

JSON envelope 限制4,194,304个 UTF-16 code units，深度32并拒绝重复键。二进制字段复用1 MiB限制和已有 CBOR/JSON预算。CLI 读取原始文件字节并严格解码 UTF-8，非法字节返回 InvalidInputUtf8。文件 API 先读取整个文件，再执行 Core envelope 检查。处理不可信大文件的宿主应另设文件大小与进程资源限制。

`analysis.run_json` 返回脱敏报告。`analysis.run_host_json` 额外返回服务端登记记录，属于可信宿主内部接口。参考 RP 在 HTTP 输出和报告保存前再次过滤。两者均有黑盒测试。

```sh
moon build analysis --target js --deny-warn
node --test cmd/main/cli.test.mjs
CLI_TARGET=wasm-gc node --test cmd/main/cli.test.mjs
```

JS CommonJS 模块位于 `_build/js/debug/build/analysis/analysis.js`。固定工具链会提示 CommonJS 不生成 TypeScript declaration，JS 导出和四目标 MoonBit 接口通过各自测试验证。
