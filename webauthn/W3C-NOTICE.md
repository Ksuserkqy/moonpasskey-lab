# W3C WebAuthn protocol test-vector attribution

`w3c_vectors_test.mbt` includes exact published byte sequences from the informative test vectors in **Web Authentication: An API for accessing Public Key Credentials — Level 3**, W3C Recommendation, **25 August 2026**:

- [§16.2 ES256 Credential with No Attestation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256).
- [§16.4 ES256 Credential with `"crossOrigin": true` in clientDataJSON](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-crossOrigin).
- [§16.5 ES256 Credential with `"topOrigin"` in clientDataJSON](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-topOrigin).

Only registration and assertion `clientDataJSON`, registration `attestationObject`, and assertion `authenticatorData` are copied. The byte sequences are unchanged: published hexadecimal encodings are split into adjacent source strings and decoded by a test-only helper. JSON is never reconstructed or reserialized. Expected public AAGUID, credential ID, challenge, flags, lengths and field values are derived from these same examples. Private-key, signature, certificate and trust-root fields are omitted. Test code and assertions are additions by MoonPasskey Lab. These official examples are separate from the project-generated synthetic and malformed fixtures in the other test files. Passing them supplies structural parsing evidence; it does not establish cryptographic verification, interoperability certification or full WebAuthn conformance.

| Source | Registration clientDataJSON | Registration attestationObject | Assertion clientDataJSON | Assertion authenticatorData |
| --- | ---: | ---: | ---: | ---: |
| §16.2 | 255 bytes | 194 bytes | 132 bytes | 37 bytes |
| §16.4 | 254 bytes | 194 bytes | 251 bytes | 37 bytes |
| §16.5 | 168 bytes | 194 bytes | 285 bytes | 37 bytes |

Each registration object contains a 164-byte `authData` payload, a 32-byte credential ID and a 77-byte ES256 credential-public-key CBOR map. The source's `client_data_gen_flags` and `auth_data_UV_BE_BS` values are fixture-generation seeds; assertions use the actual wire flags. All copied fields were extracted from the fixed-version HTML's corresponding `<pre>` blocks and independently checked with Python hexadecimal decoding, JSON decoding and a small CBOR field reader. No fixture-generation or extraction scripts are runtime dependencies.

This software includes material copied from Web Authentication Level 3, https://www.w3.org/TR/2026/REC-webauthn-3-20260825/. Copyright © 2026 World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/

Copyright © 2026 World Wide Web Consortium. All Rights Reserved. This work is distributed under the W3C Software and Document License in the hope that it will be useful, but WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. [W3C Software and Document License 2023](https://www.w3.org/copyright/software-license-2023/)

## W3C Software and Document License 2023 notice

This work is being provided by the copyright holders under the following license.

By obtaining and/or copying this work, you (the licensee) agree that you have read, understood, and will comply with the following terms and conditions.

Permission to copy, modify, and distribute this work, with or without modification, for any purpose and without fee or royalty is hereby granted, provided that you include the following on ALL copies of the work or portions thereof, including modifications:

- The full text of this NOTICE in a location viewable to users of the redistributed or derivative work.
- Any pre-existing intellectual property disclaimers, notices, or terms and conditions. If none exist, the W3C software and document short notice should be included.
- Notice of any changes or modifications, through a copyright statement on the new code or document such as "This software or document includes material copied from or derived from [title and URI of the W3C document]. Copyright © [$year-of-document] World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/"

THIS WORK IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS MAKE NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE OR DOCUMENT WILL NOT INFRINGE ANY THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.

COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE SOFTWARE OR DOCUMENT.

The name and trademarks of copyright holders may NOT be used in advertising or publicity pertaining to the work without specific, written prior permission. Title to copyright in this work will at all times remain with copyright holders.
