// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "Ksuserkqy/moonpasskey_lab"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/Ksuserkqy/moonpasskey-lab"

license = "Apache-2.0"

keywords = [ "webauthn", "passkey", "es256", "cbor" ]

preferred_target = "wasm"

description = "WebAuthn / Passkey protocol analysis and ES256 verification toolkit"

import {
  "moonbitstack/mooncrypt@0.4.16",
  "moonbitlang/x@0.5.7",
}
