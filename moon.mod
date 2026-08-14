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

name = "moonredact/moonredact"

version = "0.1.0"

readme = "README.md"

repository = ""

license = "Apache-2.0"

keywords = [ "privacy", "redaction", "pii", "security", "audit" ]

preferred_target = "wasm-gc"

description = "Deterministic sensitive-text detection, policy redaction, and disclosure auditing for MoonBit"

import {
  "moonbitlang/x@0.4.49",
}
