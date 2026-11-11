# Project Agents.md Guide

This is a [MoonBit](https://docs.moonbitlang.com) project.

You can browse and install extra skills here:
<https://github.com/moonbitlang/skills>

## Project Structure

- MoonBit packages are organized per directory; each directory contains a
  `moon.pkg` file listing its dependencies. Each package has its files and
  blackbox test files (ending in `_test.mbt`) and whitebox test files (ending in
  `_wbtest.mbt`).

- In the toplevel directory, there is a `moon.mod` file listing module
  metadata.

## Coding convention

- MoonBit code is organized in block style, each block is separated by `///|`,
  the order of each block is irrelevant. In some refactorings, you can process
  block by block independently.

- Try to keep deprecated blocks in file called `deprecated.mbt` in each
  directory.

## Tooling

- `moon fmt` is used to format your code properly.

- `moon ide` provides project navigation helpers like `peek-def`, `outline`, and
  `find-references`. See $moonbit-agent-guide for details.

- `moon info` is used to update the generated interface of the package, each
  package has a generated interface file `.mbti`, it is a brief formal
  description of the package. If nothing in `.mbti` changes, this means your
  change does not bring the visible changes to the external package users, it is
  typically a safe refactoring.

- In the last step, run `moon info && moon fmt` to update the interface and
  format the code. Check the diffs of `.mbti` file to see if the changes are
  expected.

- Run `moon test` to check tests pass. MoonBit supports snapshot testing; when
  changes affect outputs, run `moon test --update` to refresh snapshots.

- Prefer `assert_eq` or `assert_true(pattern is Pattern(...))` for results that
  are stable or very unlikely to change. For snapshot tests that record
  structured debugging output, derive `Debug` and use `debug_inspect`, rather
  than deriving `Show` for debugging. For solid, well-defined results (e.g.
  scientific computations), prefer assertion tests. You can use
  `moon coverage analyze > uncovered.log` to see which parts of your code are
  not covered by tests.


# AGENTS.md — MoonPasskey Lab

## 1. Project Identity

**Project:** MoonPasskey Lab

**Description:** A MoonBit-native WebAuthn / Passkey protocol analyzer, security diagnostic toolkit, and interoperability testing framework.

**GitHub:** https://github.com/Ksuserkqy/moonpasskey-lab

**License:** Apache-2.0

**Primary language:** MoonBit

**Frontend:** Vue 3 + TypeScript + Vite

**Primary standard:** W3C Web Authentication Level 3

### Project Mission

Make WebAuthn protocol data:

- Parseable
- Inspectable
- Verifiable
- Explainable
- Testable

MoonPasskey Lab is NOT another WebAuthn authentication SDK.

Its main value is protocol analysis, security diagnostics, byte-level inspection, test vectors, and interoperability testing.

## 2. Mandatory Engineering Principles

The following requirements are mandatory.

1. Core protocol parsing MUST be implemented in MoonBit.
2. Security rules MUST be implemented in MoonBit.
3. Cryptographic verification MUST be implemented through verified MoonBit cryptographic components.
4. TypeScript MUST NOT independently reimplement core protocol validation.
5. The frontend MUST consume actual MoonBit Core results.
6. Every supported feature MUST have automated tests.
7. Every security rule MUST have a documented technical basis.
8. Unsupported functionality MUST be explicitly reported.
9. Parsing success MUST NOT be interpreted as authentication success.
10. Never claim complete WebAuthn Level 3 compliance without evidence.

Correctness and security take priority over feature count and visual appearance.

## 3. Development Environment

The primary development environment is:

- Apple Silicon macOS
- MoonBit Toolchain: initially 0.1.20261104
- MoonC: initially v0.10.20
- Node.js: 24.x
- npm: 12.x
- Git
- VS Code / Codex

Do not assume these versions remain unchanged.

Always inspect the actual environment before diagnosing toolchain problems.

Do not reinstall or upgrade working dependencies without a technical reason.

## 4. Repository Protection

Before making changes, inspect:

- git status
- git branch
- git remote -v
- git log -5 --oneline
- Existing project files
- Existing MoonBit module configuration

Rules:

- NEVER delete the existing .git directory.
- NEVER execute `moon new` again in an already initialized project.
- NEVER overwrite existing user work without permission.
- NEVER use `git push --force`.
- NEVER change the GitHub remote.
- NEVER commit credentials, tokens, API keys, or personal secrets.
- NEVER publish a release or Mooncakes package without explicit authorization.
- Do not push changes unless explicitly requested.

Use a feature branch for substantial implementation work.

Preserve the existing MoonBit module identity and generated project structure.

## Git Workflow Policy

- Develop each subsequent Phase on its own feature branch and open a separate Pull Request targeting `main`.
- Use descriptive branch names under `feat/` or `codex/`.
- Use Conventional Commits and organize each commit around actual functionality or a coherent maintenance change.
- Stage explicit paths or reviewed hunks and inspect `git diff --cached` before every commit.
- Keep each commit buildable and testable where its dependencies permit, and document any unavoidable dependency between commits.
- Include the scope, architecture, test commands and results, target compatibility, security boundaries, limitations, fixture provenance, and follow-up work in each Pull Request.
- Request merge approval after CI passes for the current PR head.
- Merge requires the user's explicit approval. Keep `main` buildable and testable.
- Preserve real author information, timestamps, test evidence, and development history. Record deferred or externally blocked checks accurately.
- Changes to repository Rulesets or branch protection require the user's explicit approval.
- The user-authorized P1/P2 Bootstrap PR is a one-time integration of already accepted work. Its logical P1, P2, and repository-workflow commits are recorded together on `feat/v0.1-core`; later Phases follow the per-Phase branch and PR policy above.

## 5. Technical Architecture

The project has four logical layers.

### Layer A: MoonBit Core

Responsible for:

- Base64URL
- Binary reading
- CBOR decoding
- ClientDataJSON parsing
- AuthenticatorData parsing
- AttestationObject parsing
- COSE key parsing
- Cryptographic verification
- Security rules
- Analysis orchestration
- Report generation

This layer must not depend on the Vue frontend.

### Layer B: CLI

Provides local developer tools.

Responsibilities:

- Read input files
- Validate input format
- Invoke MoonBit Core
- Export diagnostic reports
- Return meaningful process exit codes

CLI must not duplicate core validation logic.

### Layer C: Web Dashboard

Technology:

- Vue 3
- TypeScript
- Vite

Responsibilities:

- JSON input
- File import
- Example selection
- Protocol tree visualization
- Byte-level inspection
- Security result presentation
- Report download

The frontend must invoke MoonBit Core through a verified integration mechanism.

Do not simulate analysis results.

If MoonBit JavaScript or WebAssembly integration is not yet reliable, implement the CLI first and investigate integration separately.

### Layer D: Test Infrastructure

Contains:

- Unit tests
- Integration tests
- Positive fixtures
- Negative fixtures
- Standards-based test vectors
- Compatibility tests
- Regression tests

Clearly distinguish official test vectors from synthetic fixtures.

Record source and licensing information for external fixtures.

## 6. Module Responsibilities

The following are logical modules. Adapt physical directories and package declarations to the actual MoonBit project conventions.

### Base64URL

- URL-safe encoding and decoding
- Padding handling
- Invalid character detection
- Input length validation

### ByteReader

- Read u8
- Read big-endian u16
- Read big-endian u32
- Read exact-length byte slices
- Track current offset
- Track remaining bytes
- Detect out-of-bounds reads

### ClientDataJSON

- Parse type
- Parse challenge
- Parse origin
- Parse crossOrigin
- Parse topOrigin
- Preserve original JSON bytes

CRITICAL:

The SHA-256 digest must be calculated from the original clientDataJSON bytes.

Never parse and reserialize JSON before calculating the digest.

### CBOR

Support the CBOR types required by WebAuthn:

- Unsigned integers
- Negative integers
- Byte strings
- Text strings
- Arrays
- Maps
- Required simple values

Requirements:

- Bounds checking
- Duplicate map key detection
- Maximum nesting depth
- Maximum input size
- Clear unsupported-type errors
- Preserve source byte ranges where practical

Apply CTAP2 canonical encoding requirements only in the appropriate protocol contexts.

Do not blindly apply one encoding policy to every CBOR document.

### AuthenticatorData

Parse:

- rpIdHash
- flags
- signCount
- AAGUID
- credentialIdLength
- credentialId
- credentialPublicKey
- extensions

Respect the conditional structure controlled by AT and ED flags.

### AttestationObject

Parse:

- fmt
- authData
- attStmt

Initially support complete structural parsing and the none format.

Clearly distinguish:

- Structural parsing
- Attestation signature verification
