///|
fn bridge_object(value : Json) -> Map[String, Json] raise {
  match value {
    Json::Object(fields) => fields
    _ => fail("expected report object")
  }
}

///|
fn bridge_field(value : Json, name : String) -> Json raise {
  match bridge_object(value).get(name) {
    Some(field) => field
    None => fail("missing field " + name)
  }
}

///|
fn bridge_run(value : Json, host~ : Bool = false) -> Json raise {
  @json.parse(
    if host {
      @analysis.run_host_json(value.stringify())
    } else {
      @analysis.run_json(value.stringify())
    },
  )
}

///|
fn bridge_encode(bytes : BytesView) -> Json raise {
  match @base64url.encode(bytes) {
    Ok(value) => Json::string(value)
    Err(_) => fail("invalid test encoding")
  }
}

///|
fn bridge_fail(
  value : Json,
  kind : String,
  context : String,
  host~ : Bool = false,
) -> Json raise {
  let report = bridge_run(value, host~)
  assert_eq(bridge_field(report, "status"), Json::string("FAIL"))
  let error = bridge_field(report, "error")
  assert_eq(bridge_field(error, "kind"), Json::string(kind))
  assert_eq(bridge_field(error, "context"), Json::string(context))
  assert_false(bridge_object(report).contains("credentialUpdate"))
  assert_false(bridge_object(report).contains("record"))
  report
}

///|
test "bridge client data analysis redacts challenge and preserves optional fields" {
  let source = bridge_fixture("verify")
  let report = bridge_run(
    Json::object({
      "command": Json::string("client-data"),
      "clientDataJSON": bridge_field(source, "clientDataJSON"),
    }),
  )
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  let client = bridge_field(report, "clientData")
  assert_eq(bridge_field(client, "type"), Json::string("webauthn.get"))
  assert_eq(bridge_field(client, "origin"), Json::string("https://rp.test"))
  assert_eq(bridge_field(client, "crossOrigin"), Json::boolean(false))
  assert_eq(bridge_field(client, "topOrigin"), Json::null())
  assert_eq(
    bridge_field(bridge_field(client, "challenge"), "redacted"),
    Json::boolean(true),
  )
  assert_false(report.stringify().contains("Y2hhbGxlbmdl"))
  assert_eq(
    bridge_field(bridge_field(report, "checks"), "signature"),
    Json::string("NOT_PERFORMED"),
  )
}

///|
test "bridge auth data analysis exposes flags count hash and length" {
  let source = bridge_fixture("verify")
  let report = bridge_run(
    Json::object({
      "command": Json::string("authenticator-data"),
      "authenticatorData": bridge_field(source, "authenticatorData"),
    }),
  )
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  let auth = bridge_field(report, "authenticatorData")
  assert_eq(bridge_field(auth, "length"), Json::number(37.0))
  assert_eq(bridge_field(auth, "signCount"), Json::number(0.0))
  assert_eq(
    bridge_field(bridge_field(auth, "flags"), "up"),
    Json::boolean(true),
  )
  assert_eq(bridge_field(bridge_field(auth, "flags"), "rfu"), Json::number(0.0))
}

///|
test "bridge analyze assertion verifies DER with policy checks skipped" {
  let report = bridge_run(bridge_fixture("analyze"))
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  assert_eq(
    bridge_field(bridge_field(report, "crypto"), "signatureValid"),
    Json::boolean(true),
  )
  assert_eq(
    bridge_field(bridge_field(report, "checks"), "challenge"),
    Json::string("NOT_PERFORMED"),
  )
}

///|
test "bridge complete assertion uses actual Core and reports zero counter" {
  let report = bridge_run(bridge_fixture("verify"))
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  assert_eq(
    bridge_field(bridge_field(report, "counter"), "status"),
    Json::string("NOT_SUPPORTED"),
  )
  for (name, value) in bridge_object(bridge_field(report, "checks")) {
    if name != "counter" {
      assert_eq(value, Json::string("PASS"))
    }
  }
}

///|
test "bridge successful report omits original binary fields and identity" {
  let source = bridge_fixture("verify")
  let output = bridge_run(source).stringify()
  for
    name in [
      "clientDataJSON", "authenticatorData", "signature", "credentialId", "userHandle",
      "expectedChallenge",
    ] {
    let value = match bridge_field(source, name) {
      Json::String(value) => value
      _ => fail("expected binary string")
    }
    assert_false(output.contains(value))
  }
  assert_false(output.contains("publicKey\":\""))
}

///|
test "bridge test registration redacts record in public entry" {
  let report = bridge_run(bridge_fixture("register"))
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  assert_eq(bridge_field(report, "testOnly"), Json::boolean(true))
  assert_false(bridge_object(report).contains("record"))
  assert_eq(
    bridge_field(bridge_field(report, "checks"), "attestation_trust"),
    Json::string("NOT_PERFORMED"),
  )
}

///|
test "bridge trusted host receives validated public registration record" {
  let source = bridge_fixture("register")
  let report = bridge_run(source, host=true)
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  assert_eq(bridge_field(report, "redacted"), Json::boolean(false))
  assert_eq(bridge_field(report, "internal"), Json::boolean(true))
  let record = bridge_field(report, "record")
  assert_eq(
    bridge_field(record, "credentialId"),
    bridge_field(source, "credentialId"),
  )
  assert_eq(
    bridge_field(record, "userHandle"),
    bridge_field(source, "userHandle"),
  )
  assert_eq(bridge_field(record, "signCount"), Json::number(0.0))
  assert_eq(bridge_field(record, "backupEligible"), Json::boolean(false))
  assert_true(bridge_object(record).contains("publicKey"))
}

///|
test "bridge responseMode input cannot reveal a public registration record" {
  let source = bridge_fixture("register")
  bridge_object(source).set("responseMode", Json::string("internal"))
  assert_false(bridge_object(bridge_run(source)).contains("record"))
}

///|
test "bridge duplicate decoded keys fail without echoing property values" {
  let report = @json.parse(
    @analysis.run_json(
      "{\"command\":\"secret-one\",\"comm\\u0061nd\":\"secret-two\"}",
    ),
  )
  assert_eq(
    bridge_field(bridge_field(report, "error"), "kind"),
    Json::string("DuplicateField"),
  )
  assert_false(report.stringify().contains("secret-"))
}

///|
test "bridge malformed JSON is a distinct transport error" {
  for input in ["", "{", "[", "{\"command\":true,}"] {
    let report = @json.parse(@analysis.run_json(input))
    assert_eq(
      bridge_field(bridge_field(report, "error"), "kind"),
      Json::string("InvalidJson"),
    )
  }
}

///|
test "bridge deep JSON is bounded before recursive processing" {
  let input = String::make(33, '[') + "0" + String::make(33, ']')
  let report = @json.parse(@analysis.run_json(input))
  assert_eq(
    bridge_field(bridge_field(report, "error"), "kind"),
    Json::string("ResourceLimit"),
  )
}

///|
test "bridge envelope length is bounded" {
  let report = @json.parse(@analysis.run_json(String::make(4_194_305, ' ')))
  assert_eq(
    bridge_field(bridge_field(report, "error"), "kind"),
    Json::string("ResourceLimit"),
  )
}

///|
test "bridge object envelope and command are required" {
  bridge_fail(Json::array([]), "WrongType", "input") |> ignore
  bridge_fail(Json::object(Map([])), "MissingField", "input.command") |> ignore
  bridge_fail(
    Json::object({ "command": Json::number(1.0) }),
    "WrongType",
    "input.command",
  )
  |> ignore
  bridge_fail(
    Json::object({ "command": Json::string("secret-unknown") }),
    "UnknownCommand",
    "input.command",
  )
  |> ignore
}

///|
test "bridge binary transports reject padding alphabet and unused bits" {
  for encoded in ["e30=", "e31", "+/8", "a", "é", " e30", "e30\n"] {
    bridge_fail(
      Json::object({
        "command": Json::string("client-data"),
        "clientDataJSON": Json::string(encoded),
      }),
      "InvalidBase64URL",
      "input.clientDataJSON",
    )
    |> ignore
  }
}

///|
test "bridge missing and mistyped binary field paths are explicit" {
  bridge_fail(
    Json::object({ "command": Json::string("client-data") }),
    "MissingField",
    "input.clientDataJSON",
  )
  |> ignore
  bridge_fail(
    Json::object({
      "command": Json::string("authenticator-data"),
      "authenticatorData": Json::boolean(false),
    }),
    "WrongType",
    "input.authenticatorData",
  )
  |> ignore
}

///|
test "bridge nested parser errors retain source offsets" {
  let report = bridge_fail(
    Json::object({
      "command": Json::string("authenticator-data"),
      "authenticatorData": Json::string("AA"),
    }),
    "UnexpectedEnd",
    "authData.rpIdHash",
  )
  assert_eq(
    bridge_field(bridge_field(report, "error"), "offset"),
    Json::number(0.0),
  )
}

///|
test "bridge JSON parser failure never exposes duplicate member text" {
  let raw = b"{\"sensitive-member\":0,\"sensitive-member\":1}"
  let report = bridge_run(
    Json::object({
      "command": Json::string("client-data"),
      "clientDataJSON": bridge_encode(raw),
    }),
  )
  assert_eq(
    bridge_field(bridge_field(report, "error"), "kind"),
    Json::string("DuplicateMember"),
  )
  assert_false(report.stringify().contains("sensitive-member"))
}

///|
test "bridge assertion warning retains count high water" {
  let source = bridge_fixture("verify")
  bridge_object(bridge_field(source, "credential")).set(
    "signCount",
    Json::number(5.0),
  )
  let report = bridge_run(source)
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  assert_eq(
    bridge_field(bridge_field(report, "counter"), "status"),
    Json::string("WARNING"),
  )
  assert_eq(
    bridge_field(bridge_field(report, "credentialUpdate"), "signCount"),
    Json::number(5.0),
  )
}

///|
test "bridge explicit Reject counter policy prevents update proposal" {
  let source = bridge_fixture("verify")
  bridge_object(bridge_field(source, "credential")).set(
    "signCount",
    Json::number(5.0),
  )
  bridge_object(bridge_field(source, "policy")).set(
    "counterPolicy",
    Json::string("reject"),
  )
  bridge_fail(source, "CounterNonIncreasing", "authData.signCount") |> ignore
}

///|
test "bridge uint32 counter transport rejects fractional and overflow" {
  for value in [-1.0, 1.5, 4294967296.0] {
    let source = bridge_fixture("verify")
    bridge_object(bridge_field(source, "credential")).set(
      "signCount",
      Json::number(value),
    )
    bridge_fail(source, "InvalidInteger", "input.credential.signCount")
    |> ignore
  }
}

///|
test "bridge maximum uint32 counter remains unsigned" {
  let source = bridge_fixture("verify")
  bridge_object(bridge_field(source, "credential")).set(
    "signCount",
    Json::number(4294967295.0),
  )
  let report = bridge_run(source)
  assert_eq(
    bridge_field(bridge_field(report, "credentialUpdate"), "signCount"),
    Json::number(4294967295.0),
  )
}

///|
test "bridge wrong challenge reports policy error and no update" {
  let source = bridge_fixture("verify")
  bridge_object(source).set("expectedChallenge", bridge_encode(b"other"))
  bridge_fail(source, "ChallengeMismatch", "clientDataJSON.challenge") |> ignore
}

///|
test "bridge origin allowlist is exact" {
  let source = bridge_fixture("verify")
  bridge_object(bridge_field(source, "policy")).set(
    "allowedOrigins",
    Json::array([Json::string("https://rp.test.evil")]),
  )
  bridge_fail(source, "OriginNotAllowed", "clientDataJSON.origin") |> ignore
}

///|
test "bridge RP hash uses trusted exact configuration" {
  let source = bridge_fixture("verify")
  bridge_object(bridge_field(source, "policy")).set(
    "rpId",
    Json::string("other.test"),
  )
  bridge_fail(source, "RpIdHashMismatch", "authData.rpIdHash") |> ignore
}

///|
test "bridge UV required policy is forwarded to Core" {
  let source = bridge_fixture("verify")
  bridge_object(bridge_field(source, "policy")).set(
    "uv",
    Json::string("required"),
  )
  bridge_fail(source, "UserVerificationRequired", "authData.flags.uv") |> ignore
}

///|
test "bridge identity binding is forwarded to Core" {
  let source = bridge_fixture("verify")
  bridge_object(source).set("credentialId", bridge_encode(b"other-credential"))
  bridge_fail(source, "CredentialIdMismatch", "request.credential_id") |> ignore
}

///|
test "bridge malformed DER and wrong signatures remain distinct" {
  let source = bridge_fixture("verify")
  bridge_object(source).set("signature", bridge_encode(b""))
  bridge_fail(source, "Crypto.InvalidSignatureEncoding", "signature") |> ignore
  bridge_object(source).set(
    "signature",
    bridge_encode(b"\x30\x06\x02\x01\x01\x02\x01\x01"),
  )
  bridge_fail(source, "InvalidSignature", "signature") |> ignore
}

///|
test "bridge wrong public key point fails before assertion verification" {
  let source = bridge_fixture("verify")
  let key = b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" +
    Bytes::make(32, b'\x00') +
    b"\x22\x58\x20" +
    Bytes::make(32, b'\x00')
  bridge_object(bridge_field(source, "credential")).set(
    "publicKey",
    bridge_encode(key),
  )
  bridge_fail(source, "InvalidPublicKey", "credential.publicKey") |> ignore
}

///|
test "bridge invalid policy enum values have schema paths" {
  for (name, value) in [("uv", "unexpected"), ("counterPolicy", "unexpected")] {
    let source = bridge_fixture("verify")
    bridge_object(bridge_field(source, "policy")).set(name, Json::string(value))
    bridge_fail(source, "InvalidConfiguration", "input.policy." + name)
    |> ignore
  }
}

///|
test "bridge registration requires create type" {
  let source = bridge_fixture("register")
  bridge_object(source).set(
    "clientDataJSON",
    bridge_field(bridge_fixture("verify"), "clientDataJSON"),
  )
  bridge_fail(source, "InvalidClientDataType", "clientDataJSON.type", host=true)
  |> ignore
}

///|
test "bridge registration challenge mismatch produces no stored record" {
  let source = bridge_fixture("register")
  bridge_object(source).set("expectedChallenge", bridge_encode(b"other"))
  bridge_fail(
    source,
    "ChallengeMismatch",
    "clientDataJSON.challenge",
    host=true,
  )
  |> ignore
}

///|
test "bridge registration origin mismatch produces no stored record" {
  let source = bridge_fixture("register")
  bridge_object(bridge_field(source, "policy")).set(
    "allowedOrigins",
    Json::array([Json::string("https://other.test")]),
  )
  bridge_fail(source, "OriginNotAllowed", "clientDataJSON.origin", host=true)
  |> ignore
}

///|
test "bridge registration RP hash mismatch produces no stored record" {
  let source = bridge_fixture("register")
  bridge_object(bridge_field(source, "policy")).set(
    "rpId",
    Json::string("other.test"),
  )
  bridge_fail(source, "RpIdHashMismatch", "authData.rpIdHash", host=true)
  |> ignore
}

///|
test "bridge registration credential ID must match attested ID" {
  let source = bridge_fixture("register")
  bridge_object(source).set("credentialId", bridge_encode(b"different"))
  bridge_fail(source, "CredentialIdMismatch", "credentialId", host=true)
  |> ignore
}

///|
test "bridge registration user handle bounds are enforced" {
  for handle in [b"", Bytes::make(65, b'a')] {
    let source = bridge_fixture("register")
    bridge_object(source).set("userHandle", bridge_encode(handle))
    bridge_fail(source, "InvalidUserHandle", "userHandle", host=true) |> ignore
  }
}

///|
test "bridge registration UV policy is enforced" {
  let source = bridge_fixture("register")
  bridge_object(bridge_field(source, "policy")).set(
    "uv",
    Json::string("required"),
  )
  bridge_fail(
    source,
    "UserVerificationRequired",
    "authData.flags.uv",
    host=true,
  )
  |> ignore
}

///|
test "bridge registration rejects RP URL configuration" {
  let source = bridge_fixture("register")
  bridge_object(bridge_field(source, "policy")).set(
    "rpId",
    Json::string("https://rp.test:443"),
  )
  bridge_fail(source, "InvalidConfiguration", "policy", host=true) |> ignore
}

///|
fn bridge_binary(value : Json) -> Bytes raise {
  match value {
    Json::String(text) =>
      match @base64url.decode(text) {
        Ok(bytes) => bytes
        Err(_) => fail("fixture binary invalid")
      }
    _ => fail("expected binary fixture")
  }
}

///|
fn bridge_registration_flags(flags : Byte) -> Json raise {
  let source = bridge_fixture("register")
  let raw = bridge_binary(bridge_field(source, "attestationObject"))
  bridge_object(source).set(
    "attestationObject",
    bridge_encode(
      raw[:62].to_owned() + Bytes::from_array([flags]) + raw[63:].to_owned(),
    ),
  )
  source
}

///|
test "bridge registration requires user presence" {
  bridge_fail(
    bridge_registration_flags(b'\x40'),
    "UserPresenceRequired",
    "authData.flags.up",
    host=true,
  )
  |> ignore
}

///|
test "bridge registration retains multidevice backed state" {
  let report = bridge_run(bridge_registration_flags(b'\x59'), host=true)
  assert_eq(bridge_field(report, "status"), Json::string("PASS"))
  assert_eq(
    bridge_field(bridge_field(report, "record"), "backupEligible"),
    Json::boolean(true),
  )
  assert_eq(
    bridge_field(
      bridge_field(bridge_field(report, "authenticatorData"), "flags"),
      "bs",
    ),
    Json::boolean(true),
  )
}

///|
test "bridge registration rejects BS without BE" {
  bridge_fail(
    bridge_registration_flags(b'\x51'),
    "InvalidFlags",
    "attestationObject.authData.flags",
    host=true,
  )
  |> ignore
}

///|
test "bridge registration rejects reserved authenticator bits" {
  for flags in [b'\x43', b'\x61'] {
    bridge_fail(
      bridge_registration_flags(flags),
      "InvalidAssertionFlags",
      "authData.flags.reserved",
      host=true,
    )
    |> ignore
  }
}

///|
test "bridge registration validates the actual curve point" {
  let source = bridge_fixture("register")
  let raw = bridge_binary(bridge_field(source, "attestationObject"))
  let zero_key = b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" +
    Bytes::make(32, b'\x00') +
    b"\x22\x58\x20" +
    Bytes::make(32, b'\x00')
  bridge_object(source).set(
    "attestationObject",
    bridge_encode(raw[:95].to_owned() + zero_key),
  )
  bridge_fail(source, "InvalidPublicKey", "credential.publicKey", host=true)
  |> ignore
}

///|
test "bridge registration accepts none format only" {
  let source = bridge_fixture("register")
  let raw = bridge_binary(bridge_field(source, "attestationObject"))
  // Replace the four-byte fmt value while preserving canonical CBOR shape.
  bridge_object(source).set(
    "attestationObject",
    bridge_encode(raw[:6].to_owned() + b"test" + raw[10:].to_owned()),
  )
  bridge_fail(
    source,
    "UnsupportedTestAttestation",
    "attestationObject.fmt",
    host=true,
  )
  |> ignore
}

///|
test "bridge registration rejects malformed attestation CBOR" {
  let source = bridge_fixture("register")
  bridge_object(source).set("attestationObject", bridge_encode(b"\xa3"))
  let report = bridge_run(source, host=true)
  assert_eq(bridge_field(report, "status"), Json::string("FAIL"))
  assert_eq(
    bridge_field(bridge_field(report, "error"), "kind"),
    Json::string("Cbor.UnexpectedEnd"),
  )
  assert_false(bridge_object(report).contains("record"))
}

///|
test "bridge registration cross origin defaults to disabled" {
  let source = bridge_fixture("register")
  let client = b"{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"https://rp.test\",\"crossOrigin\":true}"
  bridge_object(source).set("clientDataJSON", bridge_encode(client))
  bridge_fail(
    source,
    "CrossOriginNotAllowed",
    "clientDataJSON.crossOrigin",
    host=true,
  )
  |> ignore
  bridge_object(bridge_field(source, "policy")).set(
    "allowCrossOrigin",
    Json::boolean(true),
  )
  assert_eq(
    bridge_field(bridge_run(source, host=true), "status"),
    Json::string("PASS"),
  )
}

///|
test "bridge registration validates present top origin separately" {
  let source = bridge_fixture("register")
  let client = b"{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"https://rp.test\",\"crossOrigin\":true,\"topOrigin\":\"https://top.test\"}"
  bridge_object(source).set("clientDataJSON", bridge_encode(client))
  let policy = bridge_object(bridge_field(source, "policy"))
  policy.set("allowCrossOrigin", Json::boolean(true))
  bridge_fail(
    source,
    "TopOriginNotAllowed",
    "clientDataJSON.topOrigin",
    host=true,
  )
  |> ignore
  policy.set(
    "allowedTopOrigins",
    Json::array([Json::string("https://top.test")]),
  )
  assert_eq(
    bridge_field(bridge_run(source, host=true), "status"),
    Json::string("PASS"),
  )
}

///|
test "bridge registration rejects inconsistent optional origin fields" {
  let source = bridge_fixture("register")
  let client = b"{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"https://rp.test\",\"topOrigin\":\"https://top.test\"}"
  bridge_object(source).set("clientDataJSON", bridge_encode(client))
  bridge_fail(
    source,
    "InconsistentTopOrigin",
    "clientDataJSON.topOrigin",
    host=true,
  )
  |> ignore
}

///|
test "bridge registration rejects padded and empty challenges" {
  for
    (challenge, kind) in [
      ("Y2hhbGxlbmdl=", "InvalidChallengeEncoding"),
      ("", "EmptyChallenge"),
    ] {
    let source = bridge_fixture("register")
    let client = "{\"type\":\"webauthn.create\",\"challenge\":\"" +
      challenge +
      "\",\"origin\":\"https://rp.test\"}"
    bridge_object(source).set(
      "clientDataJSON",
      bridge_encode(@utf8.encode(client)),
    )
    bridge_fail(source, kind, "clientDataJSON.challenge", host=true) |> ignore
  }
}
