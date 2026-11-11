///|
// All fixtures in this file are synthetic wire encodings constructed for this
// project from WebAuthn §6.1/6.5.1 and CBOR major types; no device vectors.
fn auth_fixed(flags : Byte, count~ : Bytes = b"\x00\x00\x00\x00") -> Bytes {
  Bytes::make(32, b'\x7f') + Bytes::from_array([flags]) + count
}

///|
fn auth_at(key~ : Bytes = b"\xa0", id~ : Bytes = b"\x01") -> Bytes {
  let length = id.length()
  Bytes::make(16, b'\xab') +
  Bytes::from_array([(length >> 8).to_byte(), (length & 255).to_byte()]) +
  id +
  key
}

///|
fn auth_parsed(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @webauthn.AuthenticatorData raise {
  match @webauthn.parse_authenticator_data(input, limits~) {
    Ok(value) => value
    Err(error) => {
      debug_inspect(error)
      fail("unexpected authData error")
    }
  }
}

///|
fn auth_error(
  input : BytesView,
  offset : Int32,
  context : String,
  kind : @webauthn.ErrorKind,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> Unit raise {
  match @webauthn.parse_authenticator_data(input, limits~) {
    Err(error) => {
      assert_eq(error.offset, offset)
      assert_eq(error.context, context)
      assert_eq(error.kind, kind)
    }
    Ok(_) => fail("expected authData error")
  }
}

///|
test "authData minimal fixed structure preserves bytes and ranges" {
  let input = auth_fixed(b'\x00')
  let value = auth_parsed(input)
  assert_eq(value.raw, input[:])
  assert_eq(value.rp_id_hash, input[:32])
  assert_eq(value.rp_id_hash_range, { start: 0, end: 32, })
  assert_eq(value.flags_range, { start: 32, end: 33, })
  assert_eq(value.sign_count_range, { start: 33, end: 37, })
  assert_eq(value.sign_count, 0U)
  assert_eq(value.attested, None)
  assert_eq(value.extensions, None)
  assert_eq(value.extensions_raw, None)
}

///|
test "authData unsigned counter maximum and big endian ordering" {
  assert_eq(
    auth_parsed(auth_fixed(b'\x01', count=b"\xff\xff\xff\xff")).sign_count,
    4294967295U,
  )
  assert_eq(
    auth_parsed(auth_fixed(b'\x01', count=b"\x12\x34\x56\x78")).sign_count,
    0x12345678U,
  )
}

///|
test "authData every fixed prefix truncation identifies the missing field" {
  let input = auth_fixed(b'\x00')
  for length in 0..<32 {
    auth_error(
      input[:length],
      0,
      "authData.rpIdHash",
      @webauthn.UnexpectedEnd(expected=32, remaining=length),
    )
  }
  auth_error(
    input[:32],
    32,
    "authData.flags",
    @webauthn.UnexpectedEnd(expected=1, remaining=0),
  )
  for length in 33..<37 {
    auth_error(
      input[:length],
      33,
      "authData.signCount",
      @webauthn.UnexpectedEnd(expected=4, remaining=length - 33),
    )
  }
}

///|
test "authData exact 37 byte input budget succeeds" {
  let value = auth_parsed(
    auth_fixed(b'\x01'),
    limits=@cbor.Limits::new(max_input_bytes=37),
  )
  assert_true(value.flags.up)
}

///|
test "authData input budget checked before reading" {
  auth_error(
    auth_fixed(b'\x00'),
    0,
    "authData",
    @webauthn.ResourceLimit(name="max_input_bytes", limit=36, actual=37UL),
    limits=@cbor.Limits::new(max_input_bytes=36),
  )
}

///|
test "authData oversized input rejects before processing attacker flags" {
  auth_error(
    Bytes::make(1_048_577, b'\xff'),
    0,
    "authData",
    @webauthn.ResourceLimit(
      name="max_input_bytes",
      limit=1_048_576,
      actual=1_048_577UL,
    ),
  )
}

///|
test "authData reserved bits are exposed without assigning security meaning" {
  let flags = auth_parsed(auth_fixed(b'\x22')).flags
  assert_eq(flags.raw, b'\x22')
  assert_eq(flags.reserved, b'\x22')
  assert_false(flags.up)
  assert_false(flags.uv)
  assert_false(flags.be)
  assert_false(flags.bs)
  assert_false(flags.at)
  assert_false(flags.ed)
}

///|
test "authData UV alone is structurally accepted" {
  let flags = auth_parsed(auth_fixed(b'\x04')).flags
  assert_true(flags.uv)
  assert_false(flags.up)
}

///|
test "authData every flag combination enforces BS implies BE" {
  for bits in 0..<256 {
    let fixed = auth_fixed(bits.to_byte())
    if (bits & 0x10) != 0 && (bits & 0x08) == 0 {
      auth_error(
        fixed,
        32,
        "authData.flags",
        @webauthn.InvalidFlags(bits.to_byte()),
      )
    } else {
      let at = if (bits & 0x40) != 0 { auth_at() } else { b"" }
      let ed = if (bits & 0x80) != 0 { b"\xa0" } else { b"" }
      let flags = auth_parsed(fixed + at + ed).flags
      assert_eq(flags.up, (bits & 0x01) != 0)
      assert_eq(flags.uv, (bits & 0x04) != 0)
      assert_eq(flags.be, (bits & 0x08) != 0)
      assert_eq(flags.bs, (bits & 0x10) != 0)
      assert_eq(flags.at, (bits & 0x40) != 0)
      assert_eq(flags.ed, (bits & 0x80) != 0)
      assert_eq(flags.reserved, (bits & 0x22).to_byte())
    }
  }
}

///|
test "authData attested fields and key retain exact original ranges" {
  let input = auth_fixed(b'\x41') + auth_at(key=b"\xa1\x01\x02", id=b"abc")
  let value = auth_parsed(input)
  guard value.attested is Some(attested) else { fail("missing AT") }
  assert_eq(attested.raw, input[37:])
  assert_eq(attested.range, { start: 37, end: 61, })
  assert_eq(attested.aaguid, Bytes::make(16, b'\xab')[:])
  assert_eq(attested.aaguid_range, { start: 37, end: 53, })
  assert_eq(attested.credential_id_length, 3U)
  assert_eq(attested.credential_id_length_range, { start: 53, end: 55, })
  assert_eq(attested.credential_id, b"abc"[:])
  assert_eq(attested.credential_id_range, { start: 55, end: 58, })
  assert_eq(attested.credential_public_key.range, { start: 58, end: 61, })
  assert_eq(attested.credential_public_key_raw, b"\xa1\x01\x02"[:])
  assert_true(attested.credential_public_key.kind is @cbor.Map(_))
  assert_eq(value.extensions, None)
}

///|
test "authData structural zero credential ID length remains explicit" {
  let value = auth_parsed(auth_fixed(b'\x40') + auth_at(id=b""))
  guard value.attested is Some(attested) else { fail("missing AT") }
  assert_eq(attested.credential_id_length, 0U)
  assert_eq(attested.credential_id, b""[:])
  assert_eq(attested.credential_id_range, { start: 55, end: 55, })
  assert_eq(attested.credential_public_key.range.start, 55)
}

///|
test "authData credential ID exact maximum 1023 bytes succeeds" {
  let id = Bytes::make(1023, b'\xff')
  let value = auth_parsed(auth_fixed(b'\x40') + auth_at(id~))
  guard value.attested is Some(attested) else { fail("missing AT") }
  assert_eq(attested.credential_id_length, 1023U)
  assert_eq(attested.credential_id, id[:])
  assert_eq(attested.credential_public_key.range.start, 1078)
}

///|
test "authData credential ID lengths above 1023 reject before allocation" {
  for length in [1024, 32768, 65535] {
    let input = auth_fixed(b'\x40') +
      Bytes::make(16, b'\x00') +
      Bytes::from_array([(length >> 8).to_byte(), (length & 255).to_byte()])
    auth_error(
      input,
      53,
      "authData.attested.credentialIdLength",
      @webauthn.InvalidCredentialIdLength(length.reinterpret_as_uint()),
    )
  }
}

///|
test "authData truncated AAGUID never advances past input" {
  for remaining in 0..<16 {
    auth_error(
      auth_fixed(b'\x40') + Bytes::make(remaining, b'\x00'),
      37,
      "authData.attested.aaguid",
      @webauthn.UnexpectedEnd(expected=16, remaining~),
    )
  }
}

///|
test "authData truncated credential ID length identifies two byte read" {
  for remaining in [0, 1] {
    auth_error(
      auth_fixed(b'\x40') + Bytes::make(16 + remaining, b'\x00'),
      53,
      "authData.attested.credentialIdLength",
      @webauthn.UnexpectedEnd(expected=2, remaining~),
    )
  }
}

///|
test "authData credential ID declared length exceeds remaining bytes" {
  let input = auth_fixed(b'\x40') + Bytes::make(16, b'\x00') + b"\x00\x03ab"
  auth_error(
    input,
    55,
    "authData.attested.credentialId",
    @webauthn.UnexpectedEnd(expected=3, remaining=2),
  )
}

///|
test "authData missing public key identifies start of its encoding" {
  auth_error(
    auth_fixed(b'\x40') + auth_at(key=b""),
    56,
    "authData.attested.credentialPublicKey.root",
    @webauthn.Cbor(@cbor.UnexpectedEnd(expected=1, remaining=0)),
  )
}

///|
test "authData truncated public key retains nested CBOR location" {
  auth_error(
    auth_fixed(b'\x40') + auth_at(key=b"\xa1\x01"),
    58,
    "authData.attested.credentialPublicKey.root.map[0].value",
    @webauthn.Cbor(@cbor.UnexpectedEnd(expected=1, remaining=0)),
  )
}

///|
test "authData public key requires CBOR map" {
  for key in [b"\x00", b"\x80", b"\x40"] {
    auth_error(
      auth_fixed(b'\x40') + auth_at(key~),
      56,
      "authData.attested.credentialPublicKey",
      @webauthn.WrongType(expected="CBOR map"),
    )
  }
}

///|
test "authData public key canonical constraint rejects nonminimal header" {
  auth_error(
    auth_fixed(b'\x40') + auth_at(key=b"\xb8\x00"),
    56,
    "authData.attested.credentialPublicKey.root",
    @webauthn.Cbor(@cbor.NonMinimalEncoding),
  )
}

///|
test "authData public key duplicate map members reject" {
  auth_error(
    auth_fixed(b'\x40') + auth_at(key=b"\xa2\x01\x02\x01\x03"),
    59,
    "authData.attested.credentialPublicKey.root.map[1].key",
    @webauthn.Cbor(@cbor.DuplicateMapKey(first_offset=57)),
  )
}

///|
test "authData ED without AT preserves extension map encoding" {
  let input = auth_fixed(b'\x80') + b"\xa1\x61x\xf5"
  let value = auth_parsed(input)
  assert_eq(value.attested, None)
  guard value.extensions is Some(extensions) else { fail("missing ED") }
  assert_eq(extensions.range, { start: 37, end: 41, })
  assert_eq(value.extensions_raw, Some(b"\xa1\x61x\xf5"[:]))
  guard extensions.kind is @cbor.Map(entries) else { fail("extension map") }
  assert_eq(entries[0].0.kind, @cbor.TextString("x"))
  assert_eq(entries[0].1.kind, @cbor.Boolean(true))
  assert_eq(entries[0].0.range, { start: 38, end: 40, })
}

///|
test "authData AT and ED consume separate adjacent CBOR objects" {
  let input = auth_fixed(b'\xc0') +
    auth_at(key=b"\xa1\x01\x02") +
    b"\xa1\x61x\xf5"
  let value = auth_parsed(input)
  guard value.attested is Some(attested) else { fail("missing AT") }
  guard value.extensions is Some(extensions) else { fail("missing ED") }
  assert_eq(attested.credential_public_key.range, { start: 56, end: 59, })
  assert_eq(attested.range.end, 59)
  assert_eq(extensions.range, { start: 59, end: 63, })
  assert_eq(value.extensions_raw, Some(input[59:63]))
}

///|
test "authData missing extension object reports exact next offset" {
  auth_error(
    auth_fixed(b'\x80'),
    37,
    "authData.extensions.root",
    @webauthn.Cbor(@cbor.UnexpectedEnd(expected=1, remaining=0)),
  )
}

///|
test "authData truncated extension reports nested CBOR value" {
  auth_error(
    auth_fixed(b'\x80') + b"\xa1\x61x",
    40,
    "authData.extensions.root.map[0].value",
    @webauthn.Cbor(@cbor.UnexpectedEnd(expected=1, remaining=0)),
  )
}

///|
test "authData extensions require map and text keys" {
  auth_error(
    auth_fixed(b'\x80') + b"\x80",
    37,
    "authData.extensions",
    @webauthn.WrongType(expected="CBOR map"),
  )
  auth_error(
    auth_fixed(b'\x80') + b"\xa1\x01\x02",
    38,
    "authData.extensions.key",
    @webauthn.InvalidExtensionKey,
  )
}

///|
test "authData extension identifiers check ASCII syntax and 32 octet limit" {
  for
    key in [
      b"\x61 ",
      b"\x61\x22",
      b"\x61\x5c",
      b"\x62\xc3\xa9",
      b"\x78\x21" + Bytes::make(33, b'a'),
    ] {
    auth_error(
      auth_fixed(b'\x80') + b"\xa1" + key + b"\xf5",
      38,
      "authData.extensions.key",
      @webauthn.InvalidExtensionKey,
    )
  }
  let value = auth_parsed(
    auth_fixed(b'\x80') + b"\xa1\x78\x20" + Bytes::make(32, b'a') + b"\xf5",
  )
  assert_true(value.extensions is Some(_))
}

///|
test "authData unknown extension values are retained without semantic validation" {
  let value = auth_parsed(auth_fixed(b'\x80') + b"\xa1\x61x\x82\x01\xf6")
  guard value.extensions is Some(extensions) else { fail("missing ED") }
  guard extensions.kind is @cbor.Map(entries) else { fail("map") }
  assert_true(entries[0].1.kind is @cbor.Array(_))
}

///|
test "authData extensions enforce canonical CBOR and duplicate rejection" {
  auth_error(
    auth_fixed(b'\x80') + b"\xb8\x00",
    37,
    "authData.extensions.root",
    @webauthn.Cbor(@cbor.NonMinimalEncoding),
  )
  auth_error(
    auth_fixed(b'\x80') + b"\xa2\x61x\xf5\x61x\xf4",
    41,
    "authData.extensions.root.map[1].key",
    @webauthn.Cbor(@cbor.DuplicateMapKey(first_offset=38)),
  )
}

///|
test "authData absent conditional flags cannot hide trailing objects" {
  auth_error(
    auth_fixed(b'\x00') + b"\xa0",
    37,
    "authData.trailing",
    @webauthn.TrailingData(remaining=1),
  )
  auth_error(
    auth_fixed(b'\x40') + auth_at() + b"\xa0",
    57,
    "authData.trailing",
    @webauthn.TrailingData(remaining=1),
  )
  auth_error(
    auth_fixed(b'\x80') + b"\xa0\xa0",
    38,
    "authData.trailing",
    @webauthn.TrailingData(remaining=1),
  )
}

///|
test "authData AT and ED reject third trailing item" {
  auth_error(
    auth_fixed(b'\xc0') + auth_at() + b"\xa0\x00",
    58,
    "authData.trailing",
    @webauthn.TrailingData(remaining=1),
  )
}

///|
test "authData node budget shared by public key and extensions" {
  let input = auth_fixed(b'\xc0') + auth_at(key=b"\xa1\x01\x02") + b"\xa0"
  assert_true(
    auth_parsed(input, limits=@cbor.Limits::new(max_values=4)).extensions
    is Some(_),
  )
  auth_error(
    input,
    59,
    "authData.extensions.root",
    @webauthn.Cbor(@cbor.ResourceLimit(name="max_values", limit=0, actual=1UL)),
    limits=@cbor.Limits::new(max_values=3),
  )
}

///|
test "authData zero node budget rejects CBOR fields" {
  auth_error(
    auth_fixed(b'\x80') + b"\xa0",
    37,
    "authData.extensions.root",
    @webauthn.Cbor(@cbor.ResourceLimit(name="max_values", limit=0, actual=1UL)),
    limits=@cbor.Limits::new(max_values=0),
  )
  assert_eq(
    auth_parsed(auth_fixed(b'\x00'), limits=@cbor.Limits::new(max_values=0)).sign_count,
    0U,
  )
}

///|
test "authData nested depth budget applies within CBOR extensions" {
  let input = auth_fixed(b'\x80') + b"\xa1\x61x\x80"
  assert_true(
    auth_parsed(input, limits=@cbor.Limits::new(max_depth=2)).extensions
    is Some(_),
  )
  auth_error(
    input,
    40,
    "authData.extensions.root.map[0].value",
    @webauthn.Cbor(@cbor.ResourceLimit(name="max_depth", limit=1, actual=2UL)),
    limits=@cbor.Limits::new(max_depth=1),
  )
}

///|
test "authData map pair and string budgets reach embedded objects" {
  let input = auth_fixed(b'\x80') + b"\xa1\x61x\xf5"
  auth_error(
    input,
    37,
    "authData.extensions.root",
    @webauthn.Cbor(
      @cbor.ResourceLimit(name="max_map_pairs", limit=0, actual=1UL),
    ),
    limits=@cbor.Limits::new(max_map_pairs=0),
  )
  auth_error(
    input,
    38,
    "authData.extensions.root.map[0].key",
    @webauthn.Cbor(
      @cbor.ResourceLimit(name="max_string_bytes", limit=0, actual=1UL),
    ),
    limits=@cbor.Limits::new(max_string_bytes=0),
  )
}

///|
test "authData invalid budgets rejected even without conditional fields" {
  auth_error(
    auth_fixed(b'\x00'),
    0,
    "authData.limits",
    @webauthn.InvalidLimit(name="max_values", value=-1),
    limits=@cbor.Limits::new(max_values=-1),
  )
  auth_error(
    auth_fixed(b'\x00'),
    0,
    "authData.limits",
    @webauthn.InvalidLimit(name="max_depth", value=65),
    limits=@cbor.Limits::new(max_depth=65),
  )
}

///|
test "authData input subview offsets are relative to supplied view" {
  let auth = auth_fixed(b'\xc0') + auth_at() + b"\xa0"
  let wrapped = b"prefix" + auth + b"suffix"
  let value = auth_parsed(wrapped[6:6 + auth.length()])
  assert_eq(value.raw, auth[:])
  guard value.attested is Some(attested) else { fail("missing AT") }
  assert_eq(attested.credential_public_key.range.start, 56)
  guard value.extensions is Some(extensions) else { fail("missing ED") }
  assert_eq(extensions.range.start, 57)
}

///|
test "authData every suffix truncation returns an error for AT plus ED" {
  let input = auth_fixed(b'\xc0') +
    auth_at(key=b"\xa1\x01\x02") +
    b"\xa1\x61x\x82\x01\xf5"
  for length in 37..<input.length() {
    assert_true(@webauthn.parse_authenticator_data(input[:length]) is Err(_))
  }
  assert_true(@webauthn.parse_authenticator_data(input) is Ok(_))
}

///|
test "authData extension arrays obey caller item budget" {
  let input = auth_fixed(b'\x80') + b"\xa1\x61x\x81\x00"
  auth_error(
    input,
    40,
    "authData.extensions.root.map[0].value",
    @webauthn.Cbor(
      @cbor.ResourceLimit(name="max_array_items", limit=0, actual=1UL),
    ),
    limits=@cbor.Limits::new(max_array_items=0),
  )
  assert_true(
    auth_parsed(input, limits=@cbor.Limits::new(max_array_items=1)).extensions
    is Some(_),
  )
}

///|
test "authData cannot raise CTAP container depth above four" {
  let four = auth_fixed(b'\x80') + b"\xa1\x61x\x81\x81\x81\x00"
  assert_true(auth_parsed(four).extensions is Some(_))
  let five = auth_fixed(b'\x80') + b"\xa1\x61x\x81\x81\x81\x80"
  auth_error(
    five,
    43,
    "authData.extensions.root.map[0].value.array[0].array[0].array[0]",
    @webauthn.Cbor(
      @cbor.ResourceLimit(name="ctap2_container_depth", limit=4, actual=5UL),
    ),
    limits=@cbor.Limits::new(max_depth=64),
  )
}

///|
test "authData malicious maximum CBOR length is rejected without narrowing" {
  let input = auth_fixed(b'\x80') +
    b"\xa1\x61x\x5b\xff\xff\xff\xff\xff\xff\xff\xff"
  auth_error(
    input,
    40,
    "authData.extensions.root.map[0].value",
    @webauthn.Cbor(
      @cbor.ResourceLimit(
        name="max_string_bytes",
        limit=1_048_576,
        actual=18446744073709551615UL,
      ),
    ),
  )
}

///|
test "authData unsupported CBOR stays explicit in protocol errors" {
  auth_error(
    auth_fixed(b'\x80') + b"\xa1\x61x\xf9\x3e\x00",
    40,
    "authData.extensions.root.map[0].value",
    @webauthn.Cbor(@cbor.UnsupportedFloat(width=2)),
  )
  auth_error(
    auth_fixed(b'\x80') + b"\xbf",
    37,
    "authData.extensions.root",
    @webauthn.Cbor(@cbor.IndefiniteLengthNotAllowed),
  )
}
