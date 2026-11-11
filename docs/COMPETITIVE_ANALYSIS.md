# 与 simple-webauthn.mbt 的比较

## 审阅范围

2026-11-11 审阅 `f4ah6o/simple-webauthn.mbt`，固定 commit 为 `1f973d3381522d21acd20dffdc1205c1337beba4`。其模块版本为 `0.2.0`，首选编译目标为 JavaScript，提供注册和认证选项、验证函数及浏览器 ceremony API。[模块元数据](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/moon.mod)

## 可核实差异

| 维度 | simple-webauthn.mbt 固定版本 | MoonPasskey Lab Phase 1 |
| --- | --- | --- |
| 目标 | WebAuthn 注册和认证流程 API | 协议分析、安全诊断与互操作测试，当前已实现基础字节工具 |
| Base64URL | 使用 x/codec/base64，补齐输入 padding，移除输出 padding | 使用 core/encoding/base64，验证原始 URL-safe 字符和输入上限，返回明确 Result |
| 二进制读取 | helpers 提供 bytes 和 offset 参数的整数读取函数 | ByteReader 持有游标，失败不推进，支持完整 UInt32 |
| 协议能力 | 已有注册、认证和 attestation 处理代码 | 尚未实现 WebAuthn 结构和认证校验 |
| 密码学 | SHA-256 使用 x/crypto，ES256 使用 WebCrypto 或 Node crypto | 密码学组件待审阅选型 |
| 展示和报告 | 本次核验聚焦 server、helpers 和 crypto 源码 | 协议树、字节证据、规则报告均为规划 |

Base64URL 和字节工具差异来自公开包装函数的实际实现。对其公开 Base64URL wrapper 的审阅未发现大小上限。[Base64URL 源码](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/src/helpers/base64url.mbt) [字节工具源码](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/src/helpers/bytes.mbt)

同步 ES256 路径实际调用 Node `crypto.verify`，异步路径通过 WebCrypto FFI。后续选择本项目密码学组件时，需要核验实现、算法支持、输入验证和后端行为。[同步 ES256 源码](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/src/crypto/ecdsa_es256.mbt) [WebCrypto FFI](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/src/crypto/webcrypto_ffi.mbt) [SHA-256 源码](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/src/crypto/sha256.mbt)

## 文档与实现状态

该版本 README 的同步验签 stub 和 packed 未实现说明与源码存在差异。注册验证代码包含 packed ES256 self-attestation 路径。其他部分格式分支调用 `verify_attestation_has_required_fields`，其工作是检查必要字段并返回布尔值，证书路径与信任锚栈仍列于待实现范围。能力判断应结合具体调用路径与测试。[注册验证源码](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/src/server/verify_registration.mbt) [兼容矩阵](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/docs/upstream.md)

## 依赖和许可

竞品声明 `moonbitlang/async@0.22.4`、`moonbitlang/x@0.5.5`、`mizchi/js_core@0.13.0`，模块许可字段为 `Apache-2.0 AND MIT`，NOTICE 记录 vendored CBOR 来自 MIT 许可的 mizchi/cbor.mbt。本阶段仅进行源码比较，项目新增实现通过 MoonBit 标准库和本地代码完成。[模块元数据](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/moon.mod) [NOTICE](https://github.com/f4ah6o/simple-webauthn.mbt/blob/1f973d3381522d21acd20dffdc1205c1337beba4/NOTICE)
