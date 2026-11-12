# Assertion interoperability procedure

Phase 6 supplies a reproducible manual capture procedure and a MoonBit Core verification adapter. Real browser and device interoperability has status **NOT_PERFORMED**. The automated suites use published vectors and project-generated fixtures. No browser, operating-system authenticator, cloud passkey provider or physical security key was exercised for this document.

| Browser and authenticator | Actual OS / browser / device versions | Capture | Core verification |
| --- | --- | --- | --- |
| Safari with iCloud Keychain or a platform passkey | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |
| Chrome with Google Password Manager | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |
| Chrome with Windows Hello | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |
| Browser with a USB or NFC FIDO2 security key | NOT_RECORDED | NOT_PERFORMED | NOT_PERFORMED |

Each completed run should record its date, operating-system version, browser version, selected provider or security-key model, transport, requested UV preference, actual parsed flags, Core test commands and results. A browser user-agent string supplies supplementary information. Record the actual software versions separately.

## Capture a temporary test credential

Use a fresh temporary test credential and an isolated test page. The following capture retains public protocol messages and the temporary account handle in browser memory. Authenticator private keys remain managed by the authenticator. Avoid production accounts and production authentication responses.

1. Start a local server in an empty directory.

   ```sh
   mkdir -p /tmp/moonpasskey-p6-interop
   python3 -m http.server 8000 --bind 127.0.0.1 --directory /tmp/moonpasskey-p6-interop
   ```

2. Open `http://localhost:8000` in the browser under test. Open its developer console and confirm `window.isSecureContext` is `true` and `navigator.credentials` is available. WebAuthn permits the localhost HTTP development case. The expected origin for this run is exactly `http://localhost:8000`, and the RP ID is exactly `localhost`. [WebAuthn RP ID definition](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#rp-id)

3. Paste the capture script below into the console. Complete the browser's registration and authentication prompts using the authenticator being evaluated. The default request identifies the temporary account before authentication and requests UV as `preferred`.

   ```js
   const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
   const base64url = buffer => {
     const bytes = new Uint8Array(buffer);
     let binary = "";
     for (const byte of bytes) binary += String.fromCharCode(byte);
     return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
   };

   const rpId = location.hostname;
   const origin = location.origin;
   const userHandle = randomBytes(32);
   const registrationChallenge = randomBytes(32);
   const uv = "preferred";

   const registration = await navigator.credentials.create({
     publicKey: {
       rp: { id: rpId, name: "MoonPasskey Lab interoperability" },
       user: {
         id: userHandle,
         name: `temporary-${crypto.randomUUID()}@example.invalid`,
         displayName: "Temporary interoperability account"
       },
       challenge: registrationChallenge,
       pubKeyCredParams: [{ type: "public-key", alg: -7 }],
       authenticatorSelection: { userVerification: uv },
       attestation: "none",
       timeout: 60000
     }
   });
   if (registration === null || registration.type !== "public-key" ||
       !(registration.response instanceof AuthenticatorAttestationResponse)) {
     throw new Error("Expected a public-key registration response");
   }

   const assertionChallenge = randomBytes(32);
   const assertion = await navigator.credentials.get({
     publicKey: {
       rpId,
       challenge: assertionChallenge,
       allowCredentials: [{ type: "public-key", id: registration.rawId }],
       userVerification: uv,
       timeout: 60000
     }
   });
   if (assertion === null || assertion.type !== "public-key" ||
       !(assertion.response instanceof AuthenticatorAssertionResponse)) {
     throw new Error("Expected a public-key assertion response");
   }

   const capture = {
     capturedAt: new Date().toISOString(),
     userAgent: navigator.userAgent,
     expectedRpId: rpId,
     expectedOrigin: origin,
     userVerification: uv,
     accountUserHandle: base64url(userHandle),
     expectedChallenge: base64url(assertionChallenge),
     registration: {
       type: registration.type,
       rawId: base64url(registration.rawId),
       clientDataJSON: base64url(registration.response.clientDataJSON),
       attestationObject: base64url(registration.response.attestationObject)
     },
     assertion: {
       type: assertion.type,
       rawId: base64url(assertion.rawId),
       clientDataJSON: base64url(assertion.response.clientDataJSON),
       authenticatorData: base64url(assertion.response.authenticatorData),
       signature: base64url(assertion.response.signature),
       userHandle: assertion.response.userHandle === null
         ? null
         : base64url(assertion.response.userHandle)
     }
   };
   console.log(JSON.stringify(capture, null, 2));
   ```

4. Copy the emitted JSON into a local test record. Preserve every encoded field exactly. Record the provider or device selected during each prompt. Record failures, cancellations and unavailable provider choices with their actual browser error name and message.

5. Check both response `type` values are `public-key` before constructing the Core request. Decode transport fields through the existing Base64URL package. The signature field contains the original authenticator signature. The Core Assertion API accepts strict ASN.1 DER for ES256. [WebAuthn signature formats](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-signature-attestation-types)

The browser-generated random challenges in this isolated harness are fixed expectations for the local experiment. A deployed RP must generate challenges in its trusted server environment, retain ceremony state, enforce expiry and atomically consume each challenge after successful authentication. Core verifies the supplied expectation. [WebAuthn cryptographic challenges](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-cryptographic-challenges)

The registration object supplies the public key and initial counter and BE values for this test. Phase 6's assertion verification consumes a trusted credential/account record. Production registration trust and account enrollment require their own completed process.

## Verify the capture through MoonBit Core

Place a local blackbox test in `webauthn/local_interop_test.mbt`. Populate the placeholders below from the captured JSON. Preserve a nullable assertion userHandle as `None` when its captured value is `null`. All other captured binary fields use `interop_decode`. The test uses the existing package imports and public APIs.

```moonbit
///|
fn interop_decode(value : String) -> Bytes raise {
  match @base64url.decode(value) {
    Ok(bytes) => bytes
    Err(error) => fail("capture transport encoding: \{error.to_repr()}")
  }
}

///|
test "local temporary browser assertion interoperability" {
  let registration_raw_id = interop_decode("<registration.rawId>")
  let registration_object = interop_decode("<registration.attestationObject>")
  let account_handle = interop_decode("<accountUserHandle>")
  let client = interop_decode("<assertion.clientDataJSON>")
  let auth = interop_decode("<assertion.authenticatorData>")
  let signature = interop_decode("<assertion.signature>")
  let response_raw_id = interop_decode("<assertion.rawId>")
  let expected_challenge = interop_decode("<expectedChallenge>")
  let response_handle : BytesView? = None
  // For a non-null capture use Some(interop_decode("<assertion.userHandle>")) instead.

  let object = match @webauthn.parse_attestation_object(registration_object) {
    Ok(value) => value
    Err(error) => fail("registration structure: \{error.to_repr()}")
  }
  let attested = match object.auth_data.attested {
    Some(value) => value
    None => fail("registration lacks attested credential data")
  }
  assert_eq(attested.credential_id, registration_raw_id[:])
  let parameters = match attested.validate_es256() {
    Ok(value) => value
    Err(error) => fail("registration COSE parameters: \{error.to_repr()}")
  }
  let public_key = match @webauthn.import_es256_public_key(parameters) {
    Ok(value) => value
    Err(error) => fail("registration public point: \{error.to_repr()}")
  }
  let record : @webauthn.AssertionCredentialRecord = {
    credential_id: registration_raw_id,
    user_handle: account_handle,
    public_key,
    sign_count: object.auth_data.sign_count,
    backup_eligible: Some(object.auth_data.flags.be),
  }
  let request : @webauthn.AssertionVerificationRequest = {
    client_data_json: client,
    authenticator_data: auth,
    signature,
    credential_id: response_raw_id,
    user_handle: response_handle,
    expected_challenge,
    user_identification: @webauthn.Identified,
  }
  let policy = @webauthn.AssertionVerificationPolicy::new(
    "localhost", ["http://localhost:8000"],
    user_verification=@webauthn.Preferred,
    allowed_credential_ids=[registration_raw_id],
  )
  let verified = match @webauthn.verify_webauthn_es256_assertion(request, record, policy) {
    Ok(value) => value
    Err(error) => fail("browser assertion verification: \{error.to_repr()}")
  }
  assert_eq(verified.client_data.raw, client[:])
  assert_eq(verified.authenticator_data.raw, auth[:])
  assert_true(verified.authenticator_data.flags.up)
  assert_eq(verified.client_data.origin, "http://localhost:8000")
  assert_eq(verified.credential_update.credential_id, registration_raw_id[:])
}
```

The exact MoonBit template above passed a compile-only check with toolchain `0.10.20+65efd5b93`, using `moon test <test-file> --target wasm --build-only --deny-warn`. This confirms its API and syntax compatibility. Real-device capture and verification remain **NOT_PERFORMED**. Replace every placeholder before executing the test.

Run the populated test with the project-pinned toolchain for all four targets. Retain the exact commands, results and capture metadata in the run record.

```sh
moon test webauthn/local_interop_test.mbt --target native --deny-warn
moon test webauthn/local_interop_test.mbt --target js --deny-warn
moon test webauthn/local_interop_test.mbt --target wasm --deny-warn
moon test webauthn/local_interop_test.mbt --target wasm-gc --deny-warn
```

Confirm that the original capture succeeds. Repeat verification after changing one expected challenge byte, removing the allowed origin, using another RP ID, and changing one signed authenticator-data byte. Record the specific `AssertionVerificationError` for every negative case. Inspect the actual UP, UV, BE, BS and counter status through the Core result. Signature verification covers the original client JSON bytes, including their property order and whitespace.

For a second capture with UV `required`, set `uv = "required"` in the browser script and use `Required` in the Core policy. For a discoverable credential run, request `residentKey: "required"` during registration, omit `allowCredentials` during authentication, resolve the captured non-null userHandle to the temporary account, and use `Discoverable` in the Core request. The caller establishes that account-to-credential association before invoking Core. Cross-origin iframe testing additionally requires an intentionally configured embedding page, browser permissions policy and exact Core origin/top-origin allowlists. Record these configurations with the resulting capture. [WebAuthn account binding and assertion checks](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion)

The result's credential update remains a proposal. This harness keeps no persistent account store. A deployed caller must atomically recheck the credential snapshot, consume the challenge and apply accepted state updates. After the experiment, remove the temporary test credential from the selected provider or authenticator and handle the local capture according to the tester's retention policy.
