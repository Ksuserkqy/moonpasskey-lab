# Cryptographic verification fixture attribution

`crypto_vectors_test.mbt` and `crypto_der_vectors_wbtest.mbt` contain public verification data from the sources below. The test code, source-range assertions, API error expectations and input mutations were added by MoonPasskey Lab. The existing strict hexadecimal test decoder and unchanged P3 W3C registration and assertion byte fixtures are reused by the blackbox suite. The separately compiled whitebox suite has a local hexadecimal fixture decoder.

| Selection | Cases | Expected outcomes |
| --- | ---: | --- |
| Wycheproof P-256 SHA-256 P1363 complete file | 262 | 173 valid, 89 invalid |
| Wycheproof P-256 SHA-256 DER complete file | 484 | 174 valid, 310 invalid |
| NIST CAVS P-256 SHA-256 SigVer complete group | 15 | 3 valid, 12 invalid |
| NIST CAVS P-256 PKV complete group | 12 | 4 valid, 8 invalid |
| SHA-256 reference inputs | 13 | 12 published digests, 1 generated reference |
| W3C ES256 assertion examples | 3 | 3 valid |

These 789 input cases are exercised by 20 named tests. The two complete Wycheproof files include overlapping mathematical test cases in their respective signature encodings. Additional mutations exercise error and integration behavior. Verification inputs contain public keys, messages, signatures and expected hashes. Passing these tests supplies evidence for the selected implementation and inputs. CAVP validation, a security audit and full WebAuthn conformance each require their own evidence.

## Project Wycheproof

The complete `testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json` file is pinned to C2SP/Wycheproof commit `65ca494727a52944c204441c860b039e6786b99b`, dated 11 November 2026. All 262 `tcId` values, message bytes and signature bytes are retained. All 112 public-key groups use their published 65-byte SEC1 uncompressed encoding. Each coordinate remains exactly 32 bytes, including leading zeros. This avoids ambiguity in the variable-width signed `wx` and `wy` text representations. [Pinned source](https://github.com/C2SP/wycheproof/blob/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json)

The source file SHA-256 is `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986`. Upstream classifies 173 signatures as valid and 89 as invalid. The API expectations refine the invalid cases into 21 length errors, 50 scalar-range errors and 18 well-formed signatures that fail verification. R is checked before S. The suite includes leading-zero scalars, high-S signatures, public-key edge cases and arithmetic edge cases. The unsigned scalar bytes retain their original values.

Wycheproof is distributed under Apache License 2.0. The pinned upstream license is reproduced in `fixtures/WYCHEPROOF-LICENSE.txt`. The original source file has no separate copyright header. [Pinned license](https://github.com/C2SP/wycheproof/blob/65ca494727a52944c204441c860b039e6786b99b/LICENSE)

The complete `testvectors_v1/ecdsa_secp256r1_sha256_test.json` DER suite is pinned to the same commit. All 484 `tcId` values, message bytes and signature bytes are retained across all 113 published public-key groups. Its source file SHA-256 is `182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332`. [Pinned DER source](https://github.com/C2SP/wycheproof/blob/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1/ecdsa_secp256r1_sha256_test.json)

The DER whitebox test exercises the private strict DER decoder, followed by the public raw64 primitive on each published original message. The arbitrary messages in this suite directly exercise message-based ECDSA verification. The W3C examples separately exercise the standard assertion entry point and its `authenticatorData || SHA256(clientDataJSON)` construction. The DER suite expects 174 successful verifications, 23 well-formed signatures that fail verification, 229 encoding errors and 58 scalar-range errors. R accounts for 44 scalar-range errors and S for 14. The API checks canonical structure and nonnegative INTEGER encodings before scalar ranges, checks R before S and rejects inputs outside the 8–72-byte ES256 DER envelope. Canonical positive integers exceeding the P-256 order produce scalar-range errors. The preserved oversized, BER, malformed-length, negative, nonminimal and wrong-type cases exercise these distinctions.

## NIST ECDSA CAVS data

The NIST CAVP FIPS 186-4 ECDSA archive supplies `SigVer.rsp` and `PKV.rsp`. Their headers identify CAVS 11.0 and generation on 16 March 2011. The archive README records its update on 5 May 2015. The archive is identified by SHA-256 `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752`. [NIST source page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures), [NIST archive](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip)

| Archive member | Selected group | Member SHA-256 |
| --- | --- | --- |
| `186-4ecdsatestvectors/SigVer.rsp` | `[P-256,SHA-256]` | `e9841c3d12e323042751460d0b8ef4bc59c2640105ec7da4852775f80ab10191` |
| `186-4ecdsatestvectors/PKV.rsp` | `[P-256]` | `1d33551c1a199b1fc2b0e4075cdfd52d4830503ef37e6b16f04ce617d524f3f1` |

The complete selected SigVer group contains three valid signatures and three failures in each published category of changed message, R, S and Q. The published R and S integers are each encoded as 32 unsigned big-endian bytes and concatenated into raw64. All 15 public points pass independent OpenSSL public-key checks. OpenSSL also independently reproduces every published verification result.

The complete selected PKV group contains four valid points, four off-curve points and four out-of-range points. Coordinates are copied as unsigned integer hex. Four coordinates have 65 hex digits. A leading zero nibble encodes those same integers in 33 bytes. The existing P4 coordinate-length check rejects those inputs before backend import. Off-curve inputs pass the P4 parameter checks and fail the P5 point import. The test indices preserve the order within each selected group.

NIST permits copying and distributing its site information except material marked as copyrighted, and requests source attribution. The selected response files and archive README contain no separate copyright notice. The National Institute of Standards and Technology is the source of these verification data. These are informal implementation checks using the published CAVP data. NIST's source page explains that the vectors do not replace CAVP validation. [NIST copyright and disclaimer policy](https://www.nist.gov/copyrights-disclaimers), [NIST CAVP guidance](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures)

## SHA-256 references

Nine byte-oriented CAVS 11.0 cases are copied from NIST's SHA archive, generated on 15 March 2011. `SHA256ShortMsg.rsp` supplies bit lengths 0, 8, 24, 440, 448, 456, 504 and 512. `SHA256LongMsg.rsp` supplies bit length 1304. `Len = 0` denotes an empty message and its `Msg = 00` placeholder contributes zero bytes. The archive SHA-256 is `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`. [NIST secure-hashing source page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing), [NIST SHA byte-oriented archive](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip)

| Archive member | Member SHA-256 |
| --- | --- |
| `shabytetestvectors/SHA256ShortMsg.rsp` | `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c` |
| `shabytetestvectors/SHA256LongMsg.rsp` | `6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974` |

NIST's SHA-256 example document supplies the `abc` and 56-byte `abcdbc...nopq` examples. RFC 6234 section 8.5 supplies the SHA-256 result for one million ASCII `a` bytes. All 12 published message/digest pairs were independently checked with Python `hashlib`. The NIST information policy above applies to the NIST data. [NIST SHA-256 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf), [RFC 6234 section 8.5](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5)

The 65-byte input `00` through `40` and its SHA-256 digest are a project-generated boundary case. Python `hashlib` independently computed the reference digest `4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781`. This case is labeled generated in its test name.

Copyright (c) 2011 IETF Trust and the persons identified as the document authors. All rights reserved. RFC 6234 is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents in effect on its publication date. Only published test input and digest values are reused. [RFC 6234 copyright notice](https://www.rfc-editor.org/rfc/rfc6234.html), [IETF Trust legal provisions](https://trustee.ietf.org/license-info/)

## W3C assertion examples

The unchanged P3 fixture functions supply the registration objects, assertion `authenticatorData` and exact original `clientDataJSON` bytes for WebAuthn Level 3, Recommendation 25 August 2026, sections 16.2, 16.4 and 16.5. The new tests additionally copy each published assertion signature in its original ASN.1 DER encoding, of length 72, 72 and 71 bytes respectively. The standard WebAuthn assertion entry point consumes those exact signatures. [Section 16.2](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256), [Section 16.4](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-crossOrigin), [Section 16.5](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-topOrigin)

Each derived raw64 signature contains the same unsigned R and S integers, padded separately to 32 bytes. This test-only conversion independently exercises the raw64 primitive. The copied DER signatures also test rejection by the raw64 primitive, and the raw64 signatures test rejection by the standard DER assertion entry point. The exact original DER signatures independently verify with OpenSSL using the corresponding registration public key over `authenticatorData || SHA256(original clientDataJSON)`. Expected hashes were independently computed with Python `hashlib`. The three standard DER integration tests additionally cover changed JSON, authenticator data and signature bytes, JSON property reordering with equal parsed objects, empty inputs, truncated and appended signature encodings and an incorrect registered public key.

This software includes material copied from Web Authentication Level 3, https://www.w3.org/TR/2026/REC-webauthn-3-20260825/. Copyright © 2026 World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/

Copyright © 2026 World Wide Web Consortium. All Rights Reserved. This work is distributed under the W3C Software and Document License in the hope that it will be useful, but WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. The full W3C Software and Document License 2023 notice is reproduced in the adjacent `W3C-NOTICE.md` and applies to the copied W3C material here. Test additions and the described conversion were made by MoonPasskey Lab on 12 November 2026. [W3C Software and Document License 2023](https://www.w3.org/copyright/software-license-2023/)
