# MoonPasskey Lab

MoonBit WebAuthn / Passkey 协议分析与 ES256 Assertion 验证工具。固定 MoonBit `0.10.20+65efd5b93`、MoonCrypt `0.4.16`。

```sh
moon run cmd/main -- --help
moon test --target wasm --deny-warn
moon build analysis --target js --deny-warn
npm --prefix dashboard ci
npm --prefix dashboard run build
node reference-rp/start.mjs
```

参考 RP 和 Dashboard 默认仅本地测试使用，打开 `http://localhost:8787`。协议与密码学验证由 MoonBit Core 执行，登记流程限定 none attestation。

[CLI 使用](docs/CLI.md) · [本地 RP](docs/REFERENCE-RP.md) · [挑战事务](docs/CHALLENGE-LIFECYCLE.md) · [设备互操作](docs/ASSERTION-INTEROP.md) · [当前限制](docs/LIMITATIONS.md) · [开发与测试记录](docs/DEVELOPMENT.md)
