///|
// All P3 fixtures here are project-generated synthetic inputs, not official
// vectors. Tiny CBOR constructors are test-only and use hand-derived heads.
fn att_head(major : Int32, size : Int32) -> Bytes {
  if size < 24 {
    Bytes::from_array([(major * 32 + size).to_byte()])
  } else if size < 256 {
    Bytes::from_array([(major * 32 + 24).to_byte(), size.to_byte()])
  } else {
    Bytes::from_array([
      (major * 32 + 25).to_byte(),
      (size >> 8).to_byte(),
      size.to_byte(),
    ])
  }
}

///|
fn att_auth(extensions~ : Bool = false) -> Bytes {
  Bytes::make(32, b'\x00') +
  (if extensions { b"\xc0" } else { b"\x40" }) +
  Bytes::make(20, b'\x00') +
  b"\x00\x02id\xa1\x01\x02" +
  (if extensions { b"\xa1\x61x\xf5" } else { b"" })
}

///|
fn att_object(
  auth : Bytes,
  fmt~ : Bytes = b"\x64none",
  stmt~ : Bytes = b"\xa0",
) -> Bytes {
  b"\xa3\x63fmt" +
  fmt +
  b"\x67attStmt" +
  stmt +
  b"\x68authData" +
  att_head(2, auth.length()) +
  auth
}

///|
fn att_parsed(input : BytesView) -> @webauthn.AttestationObject raise {
  match @webauthn.parse_attestation_object(input) {
    Ok(value) => value
    Err(error) => fail("unexpected attestation error: \{error.to_repr()}")
  }
}

///|
fn att_error(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @webauthn.ParseError raise {
  match @webauthn.parse_attestation_object(input, limits~) {
    Err(error) => error
    Ok(_) => fail("expected invalid attestation object")
  }
}

///|
test "attestation none retains raw map and exact field encoding ranges" {
  let auth = att_auth()
  let input = att_object(auth)
  let parsed = att_parsed(input)
  assert_eq(parsed.raw, input[:])
  assert_eq(parsed.fmt, "none")
  assert_eq(parsed.statement_status, @webauthn.NoneStructureChecked)
  assert_eq(parsed.fmt_range, { start: 5, end: 10, })
  assert_eq(parsed.att_stmt.range, { start: 18, end: 19, })
  assert_eq(parsed.auth_data_range, { start: 28, end: input.length(), })
  assert_eq(parsed.auth_data_payload_range, { start: 30, end: input.length(), })
  assert_eq(parsed.auth_data.raw, auth[:])
  assert_true(
    parsed.att_stmt.kind is @cbor.Map(entries) && entries.length() == 0,
  )
}

///|
test "attestation integration parses AT and ED without crossing CBOR boundaries" {
  let parsed = att_parsed(att_object(att_auth(extensions=true)))
  let attested = match parsed.auth_data.attested {
    Some(value) => value
    None => fail("missing AT")
  }
  assert_eq(attested.credential_id, b"id"[:])
  assert_eq(attested.credential_public_key.range, { start: 57, end: 60, })
  assert_eq(attested.credential_public_key_raw, b"\xa1\x01\x02"[:])
  assert_true(attested.credential_public_key.kind is @cbor.Map(_))
  match parsed.auth_data.extensions {
    Some(value) => {
      assert_eq(value.range, { start: 60, end: 64, })
      assert_true(value.kind is @cbor.Map(_))
      let start = parsed.auth_data_payload_range.start + value.range.start
      assert_eq(
        parsed.raw[start:start + value.encoded_length()],
        b"\xa1\x61x\xf5"[:],
      )
    }
    None => fail("missing ED")
  }
}

///|
test "attestation unknown formats retain statement and explicitly lack validation" {
  for fmt in [b"\x66packed", b"\x66future"] {
    let parsed = att_parsed(
      att_object(att_auth(), fmt~, stmt=b"\xa1\x63sig\x41x"),
    )
    assert_eq(parsed.statement_status, @webauthn.FormatNotValidated)
    assert_true(
      parsed.att_stmt.kind is @cbor.Map(entries) && entries.length() == 1,
    )
  }
}

///|
test "attestation each required member missing reports named field" {
  let auth = att_auth()
  let bytes = att_head(2, auth.length()) + auth
  for
    (input, field) in [
      (b"\xa2\x67attStmt\xa0\x68authData" + bytes, "fmt"),
      (b"\xa2\x63fmt\x64none\x68authData" + bytes, "attStmt"),
      (b"\xa2\x63fmt\x64none\x67attStmt\xa0", "authData"),
    ] {
    let error = att_error(input)
    assert_eq(error.kind, @webauthn.MissingField(field))
    assert_eq(error.context, "attestationObject." + field)
  }
}

///|
test "attestation rejects each wrong field type" {
  for
    (input, context, offset) in [
      (att_object(att_auth(), fmt=b"\x00"), "fmt", 5),
      (att_object(att_auth(), stmt=b"\x80"), "attStmt", 18),
      (b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x60", "authData", 28),
    ] {
    let error = att_error(input)
    assert_eq(error.offset, offset)
    assert_eq(error.context, "attestationObject." + context)
    assert_true(error.kind is @webauthn.WrongType(_))
  }
}

///|
test "attestation rejects scalar and array top levels" {
  for input in [b"\x00", b"\x80", b"\x40", b"\xf6"] {
    let error = att_error(input)
    assert_eq(error.offset, 0)
    assert_eq(error.kind, @webauthn.WrongType(expected="CBOR map"))
  }
}

///|
test "attestation rejects duplicate required keys before field extraction" {
  for
    input in [
      b"\xa2\x63fmt\x64none\x63fmt\x64none", b"\xa2\x67attStmt\xa0\x67attStmt\xa0",
      b"\xa2\x68authData\x40\x68authData\x40",
    ] {
    assert_true(
      att_error(input).kind is @webauthn.Cbor(@cbor.DuplicateMapKey(_)),
    )
  }
}

///|
test "attestation rejects noncanonical outer encoding and order" {
  let valid = att_object(att_auth())
  let nonminimal = b"\xb8\x03" + valid[1:].to_owned()
  assert_true(
    att_error(nonminimal).kind is @webauthn.Cbor(@cbor.NonMinimalEncoding),
  )
  assert_true(
    att_error(b"\xa2\x67attStmt\xa0\x63fmt\x64none").kind
    is @webauthn.Cbor(@cbor.UnsortedMapKey(_)),
  )
}

///|
test "attestation rejects malformed CBOR and every truncation of a valid fixture" {
  for input in [b"\xff", b"\x1c", b"\xbf\xff"] {
    assert_true(att_error(input).kind is @webauthn.Cbor(_))
  }
  let input = att_object(att_auth(extensions=true))
  for size in 0..<input.length() {
    let error = att_error(input[:size])
    assert_true(error.offset >= 0 && error.offset <= size)
  }
}

///|
test "attestation rejects trailing data with exact offset" {
  let input = att_object(att_auth())
  let error = att_error(input + b"\x00\x01")
  assert_eq(error.offset, input.length())
  assert_eq(error.kind, @webauthn.Cbor(@cbor.TrailingData(remaining=2)))
}

///|
test "attestation authData truncation preserves outer offset and read sizes" {
  let error = att_error(att_object(Bytes::make(36, b'\x00')))
  assert_eq(error.offset, 30 + 33)
  assert_eq(error.context, "attestationObject.authData.signCount")
  assert_eq(error.kind, @webauthn.UnexpectedEnd(expected=4, remaining=3))
}

///|
test "attestation requires AT in its authenticator data context" {
  let error = att_error(att_object(Bytes::make(37, b'\x00')))
  assert_eq(error.offset, 30 + 32)
  assert_eq(error.kind, @webauthn.MissingField("attestedCredentialData"))
}

///|
test "attestation rejects nonempty none statement" {
  let error = att_error(att_object(att_auth(), stmt=b"\xa1\x61x\x00"))
  assert_eq(error.offset, 18)
  assert_eq(error.kind, @webauthn.InvalidNoneStatement)
}

///|
test "attestation rejects nontext outer keys and statement keys" {
  assert_eq(att_error(b"\xa1\x00\x00").context, "attestationObject.key")
  let error = att_error(
    att_object(att_auth(), fmt=b"\x66future", stmt=b"\xa1\x00\x00"),
  )
  assert_eq(error.context, "attestationObject.attStmt.key")
  assert_eq(error.kind, @webauthn.WrongType(expected="text string"))
}

///|
test "attestation keeps unknown fields in the raw structured map" {
  let valid = att_object(att_auth())
  // Same encoded key length: 'fmt' sorts before 'new'.
  let input = b"\xa4" +
    valid[1:10].to_owned() +
    b"\x63new\x01" +
    valid[10:].to_owned()
  let parsed = att_parsed(input)
  assert_true(parsed.cbor.kind is @cbor.Map(entries) && entries.length() == 4)
  assert_eq(parsed.raw, input[:])
}

///|
test "attestation shares node budget across outer map key and ED" {
  let input = att_object(att_auth(extensions=true))
  assert_true(
    @webauthn.parse_attestation_object(
      input,
      limits=@cbor.Limits::new(max_values=13),
    )
    is Ok(_),
  )
  let error = att_error(input, limits=@cbor.Limits::new(max_values=12))
  assert_true(error.context.contains("extensions"))
  assert_true(
    error.kind is @webauthn.Cbor(@cbor.ResourceLimit(name="max_values", ..)),
  )
}

///|
test "attestation input budget includes all encoded bytes" {
  let input = att_object(att_auth())
  assert_true(
    @webauthn.parse_attestation_object(
      input,
      limits=@cbor.Limits::new(max_input_bytes=input.length()),
    )
    is Ok(_),
  )
  assert_true(
    att_error(
      input,
      limits=@cbor.Limits::new(max_input_bytes=input.length() - 1),
    ).kind
    is @webauthn.Cbor(@cbor.ResourceLimit(name="max_input_bytes", ..)),
  )
  assert_true(
    att_error(Bytes::make(1_048_577, b'\x00')).kind
    is @webauthn.Cbor(@cbor.ResourceLimit(name="max_input_bytes", ..)),
  )
}

///|
test "attestation applies string map array and depth budgets to statement" {
  let input = att_object(
    att_auth(),
    fmt=b"\x66future",
    stmt=b"\xa1\x61x\x81\x81\x00",
  )
  for
    limits in [
      @cbor.Limits::new(max_string_bytes=59), // authData is 60 bytes
      @cbor.Limits::new(max_map_pairs=2),
      @cbor.Limits::new(max_array_items=0),
      @cbor.Limits::new(max_depth=3),
    ] {
    assert_true(
      att_error(input, limits~).kind is @webauthn.Cbor(@cbor.ResourceLimit(_)),
    )
  }
}

///|
test "attestation invalid limits fail before decoding" {
  for
    limits in [
      @cbor.Limits::new(max_depth=65),
      @cbor.Limits::new(max_values=-1),
    ] {
    let error = att_error(b"", limits~)
    assert_eq(error.offset, 0)
    assert_eq(error.context, "attestationObject.limits")
    assert_true(error.kind is @webauthn.InvalidLimit(_))
  }
}

///|
test "attestation nested duplicate-key secondary offset is also rebased" {
  let auth = att_auth()[0:57].to_owned() + b"\xa2\x01\x02\x01\x03"
  let error = att_error(att_object(auth))
  assert_eq(error.offset, 30 + 60)
  assert_eq(
    error.kind,
    @webauthn.Cbor(@cbor.DuplicateMapKey(first_offset=30 + 58)),
  )
}

///|
test "attestation nested unsorted-key secondary offset is also rebased" {
  let auth = att_auth()[0:57].to_owned() + b"\xa2\x03\x02\x01\x03"
  let error = att_error(att_object(auth))
  assert_eq(error.offset, 30 + 60)
  assert_eq(
    error.kind,
    @webauthn.Cbor(@cbor.UnsortedMapKey(previous_offset=30 + 58)),
  )
}

///|
test "attestation sliced input keeps offsets relative to supplied view" {
  let input = att_object(att_auth())
  let wrapped = b"prefix" + input + b"suffix"
  let parsed = att_parsed(wrapped[6:6 + input.length()])
  assert_eq(parsed.fmt_range.start, 5)
  assert_eq(parsed.auth_data_payload_range.start, 30)
  assert_eq(parsed.raw, input[:])
}

///|
test "attestation format identifier uses WebAuthn ASCII and octet limits" {
  for name in [" ", "bad\"", "bad\\", "名", String::make(33, 'x')] {
    let bytes = @utf8.encode(name)
    let error = att_error(
      att_object(att_auth(), fmt=att_head(3, bytes.length()) + bytes),
    )
    assert_eq(error.offset, 5)
    assert_eq(error.kind, @webauthn.InvalidFormatIdentifier)
  }
  let bytes = @utf8.encode(String::make(32, 'x'))
  let parsed = att_parsed(att_object(att_auth(), fmt=att_head(3, 32) + bytes))
  assert_eq(parsed.statement_status, @webauthn.FormatNotValidated)
}
