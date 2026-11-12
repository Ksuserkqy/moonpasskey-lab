///|
// Synthetic policy inputs share the signed fixtures in assertion_fixtures_test.
// Changed fields that fail a policy check deliberately retain the old signature.
fn policy_client(
  type_~ : String = "webauthn.get",
  challenge~ : String = "Y2hhbGxlbmdl",
  origin~ : String = "https://rp.test",
  suffix~ : String = ",\"crossOrigin\":false",
) -> Bytes {
  @utf8.encode(
    "{\"type\":\"" +
    type_ +
    "\",\"challenge\":\"" +
    challenge +
    "\",\"origin\":\"" +
    origin +
    "\"" +
    suffix +
    "}",
  )
}

///|
fn policy_field_error(
  request : @webauthn.AssertionVerificationRequest,
  record : @webauthn.AssertionCredentialRecord,
  policy : @webauthn.AssertionVerificationPolicy,
  field : String,
  kind : @webauthn.AssertionVerificationErrorKind,
) -> Unit raise {
  let client = match @webauthn.parse_client_data(request.client_data_json) {
    Ok(value) => value
    Err(error) => fail("policy fixture must parse: \{error.to_repr()}")
  }
  let mut offset : Int32? = None
  for entry in client.members {
    if entry.name == field {
      offset = Some(entry.value_range.start)
    }
  }
  assert_true(offset is Some(_))
  assertion_error(
    request,
    record,
    policy,
    kind,
    "clientDataJSON." + field,
    offset~,
  )
}

///|
test "assertion policy defaults use exact origins and report counter risks" {
  let policy = @webauthn.AssertionVerificationPolicy::new("rp.test", [
    "https://rp.test",
  ])
  assert_eq(policy.expected_rp_id, "rp.test")
  assert_eq(policy.allowed_origins, ["https://rp.test"])
  assert_eq(policy.user_verification, @webauthn.Preferred)
  assert_false(policy.allow_cross_origin)
  assert_eq(policy.allowed_top_origins, [])
  assert_eq(policy.allowed_credential_ids, [])
  assert_eq(policy.counter_risk, @webauthn.ReportOnly)
  let result = assertion_ok(
    assertion_request(assertion_fixture()),
    assertion_record(),
    policy,
  )
  assert_eq(result.client_data.challenge, "Y2hhbGxlbmdl")
}

///|
test "assertion policy requires the authentication client data type" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for type_ in ["webauthn.create", "WebAuthn.get", "webauthn.get.extra", ""] {
    policy_field_error(
      { ..request, client_data_json: policy_client(type_~), },
      record,
      assertion_policy(),
      "type",
      @webauthn.InvalidClientDataType,
    )
  }
}

///|
test "assertion policy compares the complete outstanding challenge bytes" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    expected_challenge in [
      b"challengf", b"challeng", b"challenge!", b"other ceremony",
    ] {
    policy_field_error(
      { ..request, expected_challenge, },
      record,
      assertion_policy(),
      "challenge",
      @webauthn.ChallengeMismatch,
    )
  }
  let result = assertion_ok(request, record, assertion_policy())
  assert_eq(result.client_data.raw, request.client_data_json)
}

///|
test "assertion policy rejects an empty outstanding or received challenge" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  assertion_error(
    { ..request, expected_challenge: b"", },
    record,
    assertion_policy(),
    @webauthn.EmptyChallenge,
    "request.expected_challenge",
  )
  policy_field_error(
    { ..request, client_data_json: policy_client(challenge=""), },
    record,
    assertion_policy(),
    "challenge",
    @webauthn.EmptyChallenge,
  )
}

///|
test "assertion policy rejects padding and noncanonical Base64URL challenges" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    challenge in [
      "YQ==", "YQ=", "Y2hhbGxlbmdl=", "YR", "Y", "YQ+", "YQ/", "YQ ", "=YQ",
    ] {
    policy_field_error(
      { ..request, client_data_json: policy_client(challenge~), },
      record,
      assertion_policy(),
      "challenge",
      @webauthn.InvalidChallengeEncoding,
    )
  }
}

///|
test "assertion policy reports different canonical challenge content" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for challenge in ["YQ", "Y2hhbGxlbmdm", "Y2hhbGxlbmdlIQ", "AA"] {
    policy_field_error(
      { ..request, client_data_json: policy_client(challenge~), },
      record,
      assertion_policy(),
      "challenge",
      @webauthn.ChallengeMismatch,
    )
  }
}

///|
test "assertion policy rejects unlisted origins using exact string equality" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    origin in [
      "https://evil.test", "https://rp.test.evil.test", "https://login.rp.test",
      "http://rp.test", "https://rp.test:443", "https://rp.test:8443", "https://RP.test",
      "https://rp.test/", "https://rp.test@evil.test", "https://rp.test?x", "null",
      "",
    ] {
    policy_field_error(
      { ..request, client_data_json: policy_client(origin~), },
      record,
      assertion_policy(),
      "origin",
      @webauthn.OriginNotAllowed,
    )
  }
}

///|
test "assertion policy accepts each explicitly configured allowed origin" {
  let policy = {
    ..assertion_policy(),
    allowed_origins: ["https://login.rp.test", "https://rp.test"],
  }
  let record = assertion_record()
  for client in ["base", "origin_alt"] {
    let fixture = assertion_fixture(client~)
    let result = assertion_ok(assertion_request(fixture), record, policy)
    assert_eq(result.client_data.raw, fixture.client[:])
  }
}

///|
test "assertion policy supports absent and explicit false crossOrigin" {
  let record = assertion_record()
  for client in ["base", "cross_missing"] {
    let fixture = assertion_fixture(client~)
    let result = assertion_ok(
      assertion_request(fixture),
      record,
      assertion_policy(),
    )
    assert_false(result.client_data.cross_origin == Some(true))
  }
}

///|
test "assertion policy requires explicit trust for cross-origin assertions" {
  let request = assertion_request(assertion_fixture(client="cross_true"))
  let record = assertion_record()
  policy_field_error(
    request,
    record,
    assertion_policy(),
    "crossOrigin",
    @webauthn.CrossOriginNotAllowed,
  )
  let policy = { ..assertion_policy(), allow_cross_origin: true, }
  let result = assertion_ok(request, record, policy)
  assert_eq(result.client_data.cross_origin, Some(true))
  assert_eq(result.client_data.top_origin, None)
}

///|
test "assertion policy validates optional topOrigin against its own allowlist" {
  let request = assertion_request(assertion_fixture(client="top_true"))
  let record = assertion_record()
  let policy = { ..assertion_policy(), allow_cross_origin: true, }
  policy_field_error(
    request,
    record,
    policy,
    "topOrigin",
    @webauthn.TopOriginNotAllowed,
  )
  let allowed = {
    ..policy,
    allowed_top_origins: ["https://another-top.test", "https://top.test"],
  }
  let result = assertion_ok(request, record, allowed)
  assert_eq(result.client_data.top_origin, Some("https://top.test"))
}

///|
test "assertion policy topOrigin allowlist does not enable cross-origin trust" {
  let request = assertion_request(assertion_fixture(client="top_true"))
  let policy = {
    ..assertion_policy(),
    allowed_top_origins: ["https://top.test"],
  }
  policy_field_error(
    request,
    assertion_record(),
    policy,
    "crossOrigin",
    @webauthn.CrossOriginNotAllowed,
  )
}

///|
test "assertion policy rejects topOrigin with absent or false crossOrigin" {
  let request = assertion_request(assertion_fixture())
  let policy = {
    ..assertion_policy(),
    allow_cross_origin: true,
    allowed_top_origins: ["https://top.test"],
  }
  for
    suffix in [
      ",\"topOrigin\":\"https://top.test\"", ",\"crossOrigin\":false,\"topOrigin\":\"https://top.test\"",
    ] {
    policy_field_error(
      { ..request, client_data_json: policy_client(suffix~), },
      assertion_record(),
      policy,
      "topOrigin",
      @webauthn.InconsistentTopOrigin,
    )
  }
}

///|
test "assertion policy topOrigin matching preserves scheme host and port" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  let policy = {
    ..assertion_policy(),
    allow_cross_origin: true,
    allowed_top_origins: ["https://top.test"],
  }
  for
    top in [
      "http://top.test", "https://top.test:443", "https://top.test:8443", "https://TOP.test",
      "https://top.test.evil.test", "https://sub.top.test", "",
    ] {
    let suffix = ",\"crossOrigin\":true,\"topOrigin\":\"" + top + "\""
    policy_field_error(
      { ..request, client_data_json: policy_client(suffix~), },
      record,
      policy,
      "topOrigin",
      @webauthn.TopOriginNotAllowed,
    )
  }
}

///|
test "assertion policy rejects RP ID URL port path and malformed configuration" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    expected_rp_id in [
      "", "https://rp.test", "http://rp.test", "rp.test:443", "rp.test/path", "rp.test?x",
      "rp.test#fragment", "rp@test", "rp test", ".rp.test", "rp..test", "-rp.test",
      "rp-.test", "rp.test.", "é.test",
    ] {
    assertion_error(
      request,
      record,
      { ..assertion_policy(), expected_rp_id, },
      @webauthn.InvalidConfiguration,
      "policy.expected_rp_id",
    )
  }
}

///|
test "assertion policy hashes the exact trusted RP ID without case folding" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for expected_rp_id in ["other.test", "RP.test", "RP.TEST"] {
    assertion_error(
      request,
      record,
      { ..assertion_policy(), expected_rp_id, },
      @webauthn.RpIdHashMismatch,
      "authData.rpIdHash",
      offset=Some(0),
    )
  }
}

///|
test "assertion policy rejects empty origin lists and empty configured entries" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  assertion_error(
    request,
    record,
    { ..assertion_policy(), allowed_origins: [], },
    @webauthn.InvalidConfiguration,
    "policy.allowed_origins",
  )
  assertion_error(
    request,
    record,
    { ..assertion_policy(), allowed_origins: [""], },
    @webauthn.InvalidConfiguration,
    "policy.allowed_origins[0]",
  )
  assertion_error(
    request,
    record,
    { ..assertion_policy(), allowed_top_origins: [""], },
    @webauthn.InvalidConfiguration,
    "policy.allowed_top_origins[0]",
  )
}

///|
test "assertion policy binds response raw credential ID to its trusted record" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    credential_id in [
      b"other", b"Credential", b"credentia", b"credential!", b"credential\x00",
    ] {
    assertion_error(
      { ..request, credential_id, },
      record,
      assertion_policy(),
      @webauthn.CredentialIdMismatch,
      "request.credential_id",
    )
  }
  assertion_error(
    request,
    { ..record, credential_id: b"other", },
    assertion_policy(),
    @webauthn.CredentialIdMismatch,
    "request.credential_id",
  )
}

///|
test "assertion policy enforces credential allowCredentials independently" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  let policy = {
    ..assertion_policy(),
    allowed_credential_ids: [b"other", b"credential"],
  }
  assertion_ok(request, record, policy) |> ignore
  assertion_error(
    request,
    record,
    { ..policy, allowed_credential_ids: [b"other"], },
    @webauthn.CredentialNotAllowed,
    "request.credential_id",
  )
}

///|
test "assertion policy rejects empty or oversized credential identifiers" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for credential_id in [b"", Bytes::make(1024, b'c')] {
    assertion_error(
      { ..request, credential_id, },
      record,
      assertion_policy(),
      @webauthn.InvalidCredentialId,
      "request.credential_id",
    )
    assertion_error(
      request,
      { ..record, credential_id, },
      assertion_policy(),
      @webauthn.InvalidCredentialId,
      "record.credential_id",
    )
    assertion_error(
      request,
      record,
      { ..assertion_policy(), allowed_credential_ids: [credential_id], },
      @webauthn.InvalidConfiguration,
      "policy.allowed_credential_ids[0]",
    )
  }
}

///|
test "assertion policy validates present userHandle against the account record" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  assertion_ok({ ..request, user_handle: None, }, record, assertion_policy())
  |> ignore
  assertion_ok(
    { ..request, user_handle: Some(b"account"), },
    record,
    assertion_policy(),
  )
  |> ignore
  for handle in [b"other", b"Account", b"accoun", b"account!", b"account\x00"] {
    assertion_error(
      { ..request, user_handle: Some(handle), },
      record,
      assertion_policy(),
      @webauthn.UserHandleMismatch,
      "request.user_handle",
    )
  }
}

///|
test "assertion policy discoverable mode requires a matched caller-resolved handle" {
  let request = {
    ..assertion_request(assertion_fixture()),
    user_identification: @webauthn.Discoverable,
  }
  let record = assertion_record()
  assertion_ok(
    { ..request, user_handle: Some(b"account"), },
    record,
    assertion_policy(),
  )
  |> ignore
  assertion_error(
    { ..request, user_handle: None, },
    record,
    assertion_policy(),
    @webauthn.UserHandleRequired,
    "request.user_handle",
  )
  assertion_error(
    { ..request, user_handle: Some(b"another account"), },
    record,
    assertion_policy(),
    @webauthn.UserHandleMismatch,
    "request.user_handle",
  )
}

///|
test "assertion policy bounds account and response userHandle lengths" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for user_handle in [b"", Bytes::make(65, b'a')] {
    assertion_error(
      { ..request, user_handle: Some(user_handle), },
      record,
      assertion_policy(),
      @webauthn.InvalidUserHandle,
      "request.user_handle",
    )
    assertion_error(
      request,
      { ..record, user_handle, },
      assertion_policy(),
      @webauthn.InvalidUserHandle,
      "record.user_handle",
    )
  }
  let maximum = Bytes::make(64, b'a')
  assertion_ok(
    { ..request, user_handle: Some(maximum), },
    { ..record, user_handle: maximum, },
    assertion_policy(),
  )
  |> ignore
}

///|
test "assertion policy retains raw bytes after JSON field reordering" {
  let fixture = assertion_fixture(client="reordered")
  let request = assertion_request(fixture)
  let result = assertion_ok(request, assertion_record(), assertion_policy())
  assert_eq(result.client_data.raw, fixture.client[:])
  assert_eq(result.authenticator_data.raw, fixture.auth[:])
}

///|
fn policy_limited_error(
  request : @webauthn.AssertionVerificationRequest,
  record : @webauthn.AssertionCredentialRecord,
  policy : @webauthn.AssertionVerificationPolicy,
  limits : @cbor.Limits,
  kind : @webauthn.AssertionVerificationErrorKind,
  context : String,
  offset~ : Int32? = None,
) -> Unit raise {
  match
    @webauthn.verify_webauthn_es256_assertion(request, record, policy, limits~) {
    Err(error) => {
      assert_eq(error.kind, kind)
      assert_eq(error.context, context)
      assert_eq(error.offset, offset)
    }
    Ok(_) => fail("expected bounded verification error")
  }
}

///|
test "assertion policy rejects invalid parser limit configuration" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    (limits, name, value) in [
      (@cbor.Limits::new(max_input_bytes=-1), "max_input_bytes", -1),
      (@cbor.Limits::new(max_string_bytes=-1), "max_string_bytes", -1),
      (@cbor.Limits::new(max_array_items=-1), "max_array_items", -1),
      (@cbor.Limits::new(max_map_pairs=-1), "max_map_pairs", -1),
      (@cbor.Limits::new(max_depth=-1), "max_depth", -1),
      (@cbor.Limits::new(max_values=-1), "max_values", -1),
      (@cbor.Limits::new(max_depth=65), "max_depth", 65),
    ] {
    policy_limited_error(
      request,
      record,
      assertion_policy(),
      limits,
      @webauthn.Parse({
        offset: 0,
        context: "assertion.limits",
        kind: @webauthn.InvalidLimit(name~, value~),
      }),
      "assertion.limits",
    )
  }
}

///|
test "assertion policy bounds each untrusted raw response before parsing" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  let length = request.client_data_json.length()
  policy_limited_error(
    request,
    record,
    assertion_policy(),
    @cbor.Limits::new(max_input_bytes=length - 1),
    @webauthn.ResourceLimit(limit=length - 1, actual=length),
    "request.client_data_json",
  )
  policy_limited_error(
    { ..request, authenticator_data: Bytes::make(length + 1, b'a'), },
    record,
    assertion_policy(),
    @cbor.Limits::new(max_input_bytes=length),
    @webauthn.ResourceLimit(limit=length, actual=length + 1),
    "request.authenticator_data",
  )
}

///|
test "assertion policy bounds outstanding challenge and existing key encoding" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  policy_limited_error(
    { ..request, expected_challenge: Bytes::make(1025, b'c'), },
    record,
    assertion_policy(),
    @cbor.Limits::new(max_input_bytes=1024),
    @webauthn.ResourceLimit(limit=1024, actual=1025),
    "request.expected_challenge",
  )
  policy_limited_error(
    { ..request, client_data_json: b"{}", authenticator_data: b"", },
    record,
    assertion_policy(),
    @cbor.Limits::new(max_input_bytes=76),
    @webauthn.ResourceLimit(limit=76, actual=77),
    "record.public_key",
  )
}

///|
test "assertion policy challenge size remains bounded by the shared Base64URL limit" {
  let request = assertion_request(assertion_fixture())
  policy_limited_error(
    {
      ..request,
      expected_challenge: Bytes::make(@base64url.MAX_BYTES + 1, b'c'),
    },
    assertion_record(),
    assertion_policy(),
    @cbor.Limits::new(max_input_bytes=@base64url.MAX_BYTES + 1),
    @webauthn.ResourceLimit(
      limit=@base64url.MAX_BYTES,
      actual=@base64url.MAX_BYTES + 1,
    ),
    "request.expected_challenge",
  )
}

///|
test "assertion policy budgets credential and userHandle bytes before identity comparison" {
  let request = {
    ..assertion_request(assertion_fixture()),
    client_data_json: b"{}",
    authenticator_data: b"",
  }
  let record = assertion_record()
  let limits = @cbor.Limits::new(max_input_bytes=10)
  let large = Bytes::make(11, b'a')
  for
    (candidate_request, candidate_record, context) in [
      ({ ..request, credential_id: large, }, record, "request.credential_id"),
      (request, { ..record, credential_id: large, }, "record.credential_id"),
      (request, { ..record, user_handle: large, }, "record.user_handle"),
      ({ ..request, user_handle: Some(large), }, record, "request.user_handle"),
    ] {
    policy_limited_error(
      candidate_request,
      candidate_record,
      assertion_policy(),
      limits,
      @webauthn.ResourceLimit(limit=10, actual=11),
      context,
    )
  }
}

///|
test "assertion policy bounds origin and credential allowlist cardinality" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  let origins = assertion_policy()
  policy_limited_error(
    request,
    record,
    origins,
    @cbor.Limits::new(max_array_items=0),
    @webauthn.ResourceLimit(limit=0, actual=1),
    "policy.allowed_origins",
  )
  policy_limited_error(
    request,
    record,
    {
      ..origins,
      allowed_top_origins: ["https://one.test", "https://two.test"],
    },
    @cbor.Limits::new(max_array_items=1),
    @webauthn.ResourceLimit(limit=1, actual=2),
    "policy.allowed_top_origins",
  )
  policy_limited_error(
    request,
    record,
    { ..origins, allowed_credential_ids: [b"credential", b"other"], },
    @cbor.Limits::new(max_array_items=1),
    @webauthn.ResourceLimit(limit=1, actual=2),
    "policy.allowed_credential_ids",
  )
}

///|
test "assertion policy counts configured string limits in UTF8 bytes" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  policy_limited_error(
    request,
    record,
    assertion_policy(),
    @cbor.Limits::new(max_string_bytes=14),
    @webauthn.ResourceLimit(limit=14, actual=15),
    "policy.allowed_origins[0]",
  )
  policy_limited_error(
    request,
    record,
    { ..assertion_policy(), expected_rp_id: "x", allowed_origins: ["😀"], },
    @cbor.Limits::new(max_string_bytes=3),
    @webauthn.ResourceLimit(limit=3, actual=4),
    "policy.allowed_origins[0]",
  )
  policy_limited_error(
    request,
    record,
    { ..assertion_policy(), allowed_top_origins: ["https://top.test"], },
    @cbor.Limits::new(max_string_bytes=15),
    @webauthn.ResourceLimit(limit=15, actual=16),
    "policy.allowed_top_origins[0]",
  )
}

///|
test "assertion policy preserves all nested client parser resource errors" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    limits in [
      @cbor.Limits::new(max_values=0),
      @cbor.Limits::new(max_values=8),
      @cbor.Limits::new(max_map_pairs=3),
      @cbor.Limits::new(max_depth=0),
    ] {
    let nested = match
      @webauthn.parse_client_data(request.client_data_json, limits~) {
      Err(error) => error
      Ok(_) => fail("resource fixture must exhaust its parser limit")
    }
    policy_limited_error(
      request,
      record,
      assertion_policy(),
      limits,
      @webauthn.Parse(nested),
      "clientDataJSON",
      offset=Some(nested.offset),
    )
  }
}

///|
test "assertion policy preserves malformed JSON and UTF8 parser locations" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for client_data_json in [b"{}", b"\xff", b"{", b"[]"] {
    let nested = match @webauthn.parse_client_data(client_data_json) {
      Err(error) => error
      Ok(_) => fail("malformed client fixture must fail its parser")
    }
    assertion_error(
      { ..request, client_data_json, },
      record,
      assertion_policy(),
      @webauthn.Parse(nested),
      "clientDataJSON",
      offset=Some(nested.offset),
    )
  }
}

///|
test "assertion policy RP ID label and total length boundaries are explicit" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  let label = String::make(63, 'a')
  let longest = label + "." + label + "." + label + "." + String::make(61, 'a')
  assert_eq(longest.length(), 253)
  for expected_rp_id in [String::make(64, 'a'), longest + "a"] {
    assertion_error(
      request,
      record,
      { ..assertion_policy(), expected_rp_id, },
      @webauthn.InvalidConfiguration,
      "policy.expected_rp_id",
    )
  }
  for expected_rp_id in [label, longest, "localhost", "xn--bcher-kva.test"] {
    assertion_error(
      request,
      record,
      { ..assertion_policy(), expected_rp_id, },
      @webauthn.RpIdHashMismatch,
      "authData.rpIdHash",
      offset=Some(0),
    )
  }
}

///|
test "assertion policy accepts opaque binary credential IDs through 1023 bytes" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for credential_id in [b"\x00", b"\x00\xffid", Bytes::make(1023, b'c')] {
    let result = assertion_ok(
      { ..request, credential_id, },
      { ..record, credential_id, },
      { ..assertion_policy(), allowed_credential_ids: [credential_id], },
    )
    assert_eq(result.credential_update.credential_id, credential_id[:])
  }
}

///|
test "assertion policy handles bounded subviews without surrounding bytes" {
  let fixture = assertion_fixture()
  let request = assertion_request(fixture)
  let record = assertion_record()
  let client = b"prefix" + fixture.client + b"suffix"
  let auth = b"prefix" + fixture.auth + b"suffix"
  let signature = b"prefix" + fixture.signature + b"suffix"
  let id = b"prefixcredentialsuffix"
  let handle = b"prefixaccountsuffix"
  let challenge = b"prefixchallengesuffix"
  let result = assertion_ok(
    {
      ..request,
      client_data_json: client[6:6 + fixture.client.length()],
      authenticator_data: auth[6:6 + fixture.auth.length()],
      signature: signature[6:6 + fixture.signature.length()],
      credential_id: id[6:16],
      user_handle: Some(handle[6:13]),
      expected_challenge: challenge[6:15],
    },
    { ..record, credential_id: id[6:16], user_handle: handle[6:13], },
    assertion_policy(),
  )
  assert_eq(result.client_data.raw, fixture.client[:])
  assert_eq(result.authenticator_data.raw, fixture.auth[:])
}

///|
test "assertion policy rejects malformed trusted UTF16 origin configuration" {
  let request = assertion_request(assertion_fixture())
  let record = assertion_record()
  for
    origin in [
      String::from_array([(0xd800).unsafe_to_char()]),
      String::from_array([(0xdc00).unsafe_to_char()]),
      String::from_array([(0xd800).unsafe_to_char(), 'a']),
    ] {
    assertion_error(
      request,
      record,
      { ..assertion_policy(), allowed_origins: [origin], },
      @webauthn.InvalidConfiguration,
      "policy.allowed_origins[0]",
    )
    assertion_error(
      request,
      record,
      { ..assertion_policy(), allowed_top_origins: [origin], },
      @webauthn.InvalidConfiguration,
      "policy.allowed_top_origins[0]",
    )
  }
}

///|
test "assertion policy source offsets remain relative to a client subview" {
  let request = assertion_request(assertion_fixture())
  let client = policy_client(challenge="YQ")
  let wrapped = b"prefix" + client + b"suffix"
  assertion_error(
    { ..request, client_data_json: wrapped[6:6 + client.length()], },
    assertion_record(),
    assertion_policy(),
    @webauthn.ChallengeMismatch,
    "clientDataJSON.challenge",
    offset=Some(35),
  )
}
