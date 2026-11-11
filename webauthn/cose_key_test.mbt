///|
// All fixtures here are synthetic and hand-derived from CBOR/COSE labels.
// Coordinates deliberately exercise parameter checks, not curve membership.
// The official W3C example remains in the existing official-vector fixtures.
fn cose_bstr(value : Bytes) -> Bytes {
  let length = value.length()
  if length < 24 {
    Bytes::from_array([(0x40 + length).to_byte()]) + value
  } else {
    Bytes::from_array([b'\x58', length.to_byte()]) + value
  }
}

///|
fn cose_fixture(
  kty~ : Bytes = b"\x02",
  alg~ : Bytes = b"\x26",
  crv~ : Bytes = b"\x01",
  x~ : Bytes = b"\x58\x20" + Bytes::make(32, b'\x01'),
  y~ : Bytes = b"\x58\x20" + Bytes::make(32, b'\x02'),
) -> Bytes {
  b"\xa5\x01" + kty + b"\x03" + alg + b"\x20" + crv + b"\x21" + x + b"\x22" + y
}

///|
fn cose_fields(fields : Array[(Bytes, Bytes)]) -> Bytes {
  let mut bytes = Bytes::from_array([(0xa0 + fields.length()).to_byte()])
  for (key, value) in fields {
    bytes = bytes + key + value
  }
  bytes
}

///|
fn cose_parsed(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @webauthn.Es256PublicKeyParameters raise {
  match @webauthn.validate_es256_credential_public_key(input, limits~) {
    Ok(value) => value
    Err(error) => fail("unexpected COSE error: \{error.to_repr()}")
  }
}

///|
fn cose_error(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @webauthn.ParseError raise {
  match @webauthn.validate_es256_credential_public_key(input, limits~) {
    Err(error) => error
    Ok(_) => fail("expected COSE parameter error")
  }
}

///|
fn cose_expect_field(
  input : BytesView,
  field : String,
  offset : Int32,
  kind : @webauthn.ErrorKind,
) -> Unit raise {
  let error = cose_error(input)
  assert_eq(error.offset, offset)
  assert_eq(error.context, "credentialPublicKey." + field)
  assert_eq(error.kind, kind)
}

///|
fn cose_auth_fixture(key : Bytes, extensions~ : Bool = false) -> Bytes {
  Bytes::make(32, b'\x00') +
  (if extensions { b"\xc0" } else { b"\x40" }) +
  Bytes::make(20, b'\x00') +
  b"\x00\x02id" +
  key +
  (if extensions { b"\xa1\x61x\xf5" } else { b"" })
}

///|
fn cose_auth_parsed(input : BytesView) -> @webauthn.AuthenticatorData raise {
  match @webauthn.parse_authenticator_data(input) {
    Ok(value) => value
    Err(error) =>
      fail("unexpected authData structure error: \{error.to_repr()}")
  }
}

///|
test "cose positive typed ES256 parameters retain complete raw bytes" {
  let input = cose_fixture()
  let parameters = cose_parsed(input)
  assert_eq(parameters.raw, input[:])
  assert_eq(parameters.range, { start: 0, end: 77, })
  assert_eq(parameters.kty, 2U)
  assert_eq(parameters.alg, -7)
  assert_eq(parameters.crv, 1U)
  assert_eq(parameters.x, Bytes::make(32, b'\x01')[:])
  assert_eq(parameters.y, Bytes::make(32, b'\x02')[:])
  assert_eq(parameters.point_validation, @webauthn.NotPerformed)
}

///|
test "cose positive all field ranges include their original value encodings" {
  let input = cose_fixture()
  let parameters = cose_parsed(input)
  assert_eq(parameters.kty_range, { start: 2, end: 3, })
  assert_eq(parameters.alg_range, { start: 4, end: 5, })
  assert_eq(parameters.crv_range, { start: 6, end: 7, })
  assert_eq(parameters.x_range, { start: 8, end: 42, })
  assert_eq(parameters.y_range, { start: 43, end: 77, })
  assert_eq(
    input[parameters.x_range.start:parameters.x_range.end],
    (b"\x58\x20" + parameters.x.to_owned())[:],
  )
  assert_eq(
    input[parameters.y_range.start:parameters.y_range.end],
    (b"\x58\x20" + parameters.y.to_owned())[:],
  )
}

///|
test "cose positive leading coordinate zeros are preserved without conversion" {
  let x = b"\x00\x00" + Bytes::make(30, b'\x11')
  let y = b"\x00" + Bytes::make(31, b'\x22')
  let parameters = cose_parsed(cose_fixture(x=cose_bstr(x), y=cose_bstr(y)))
  assert_eq(parameters.x, x[:])
  assert_eq(parameters.y, y[:])
  assert_eq(parameters.x.length(), 32)
  assert_eq(parameters.y.length(), 32)
}

///|
test "cose positive zero off-curve coordinates are parameter-only results" {
  let zero = Bytes::make(32, b'\x00')
  let parameters = cose_parsed(
    cose_fixture(x=cose_bstr(zero), y=cose_bstr(zero)),
  )
  assert_eq(parameters.x, zero[:])
  assert_eq(parameters.y, zero[:])
  assert_eq(parameters.point_validation, @webauthn.NotPerformed)
}

///|
test "cose positive maximum in-field coordinates p minus one are accepted" {
  let below = b"\xff\xff\xff\xff\x00\x00\x00\x01" +
    Bytes::make(12, b'\x00') +
    Bytes::make(11, b'\xff') +
    b"\xfe"
  assert_eq(below.length(), 32)
  let parameters = cose_parsed(
    cose_fixture(x=cose_bstr(below), y=cose_bstr(below)),
  )
  assert_eq(parameters.x, below[:])
  assert_eq(parameters.y, below[:])
  assert_eq(parameters.point_validation, @webauthn.NotPerformed)
}

///|
test "cose positive subviews keep raw bytes and ranges relative to the view" {
  let input = cose_fixture()
  let wrapped = b"prefix" + input + b"suffix"
  let parameters = cose_parsed(wrapped[6:6 + input.length()])
  assert_eq(parameters.raw, input[:])
  assert_eq(parameters.range, { start: 0, end: 77, })
  assert_eq(parameters.x_range.start, 8)
  assert_eq(parameters.y_range.start, 43)
}

///|
test "cose negative each required parameter must be present" {
  let fields = [
    (b"\x01", b"\x02", "kty"),
    (b"\x03", b"\x26", "alg"),
    (b"\x20", b"\x01", "crv"),
    (b"\x21", cose_bstr(Bytes::make(32, b'\x01')), "x"),
    (b"\x22", cose_bstr(Bytes::make(32, b'\x02')), "y"),
  ]
  for missing in 0..<fields.length() {
    let included : Array[(Bytes, Bytes)] = []
    for index, (key, value, _) in fields {
      if index != missing {
        included.push((key, value))
      }
    }
    let name = fields[missing].2
    cose_expect_field(
      cose_fields(included),
      name,
      0,
      @webauthn.MissingField(name),
    )
  }
}

///|
test "cose negative algorithm must be an integer rather than a name or scalar" {
  for algorithm in [b"\x65ES256", b"\xf5", b"\x40", b"\xf6", b"\x80"] {
    cose_expect_field(
      cose_fixture(alg=algorithm),
      "alg",
      4,
      @webauthn.WrongType(expected="integer"),
    )
  }
}

///|
test "cose negative unsupported algorithm values never identify as ES256" {
  for
    algorithm in [
      b"\x00", b"\x07", b"\x20", b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff", b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff",
    ] {
    cose_expect_field(
      cose_fixture(alg=algorithm),
      "alg",
      4,
      @webauthn.UnsupportedAlgorithm,
    )
  }
}

///|
test "cose negative ES384 ES512 RS256 PS256 and EdDSA are unsupported" {
  for
    (kty, algorithm) in [
      (b"\x02", b"\x38\x22"), // ES384 -35
      (b"\x02", b"\x38\x23"), // ES512 -36
      (b"\x03", b"\x39\x01\x00"), // RS256 -257
      (b"\x03", b"\x38\x24"), // PS256 -37
      (b"\x01", b"\x27"), // EdDSA -8
    ] {
    cose_expect_field(
      cose_fixture(kty~, alg=algorithm),
      "alg",
      4,
      @webauthn.UnsupportedAlgorithm,
    )
  }
}

///|
test "cose negative alternate algorithm keys do not require ES256 fields" {
  // Minimal public OKP and RSA shapes lack the EC2 y coordinate.
  let okp = b"\xa4\x01\x01\x03\x27\x20\x06\x21" +
    cose_bstr(Bytes::make(32, b'\x01'))
  let rsa = b"\xa4\x01\x03\x03\x39\x01\x00\x20\x41n\x21\x43\x01\x00\x01"
  for input in [okp, rsa] {
    cose_expect_field(input, "alg", 4, @webauthn.UnsupportedAlgorithm)
  }
}

///|
test "cose negative ES256 requires EC2 key type" {
  for
    kty in [
      b"\x00", b"\x01", b"\x03", b"\x20", b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff",
    ] {
    cose_expect_field(
      cose_fixture(kty~),
      "kty",
      2,
      @webauthn.UnsupportedKeyType,
    )
  }
}

///|
test "cose negative key type must be an integer" {
  for kty in [b"\x63EC2", b"\xf4", b"\xf6", b"\x40", b"\xa0"] {
    cose_expect_field(
      cose_fixture(kty~),
      "kty",
      2,
      @webauthn.WrongType(expected="integer"),
    )
  }
}

///|
test "cose negative ES256 rejects non P256 curves" {
  for
    crv in [
      b"\x00", b"\x02", b"\x03", b"\x20", b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff",
    ] {
    cose_expect_field(cose_fixture(crv~), "crv", 6, @webauthn.InvalidCurve)
  }
}

///|
test "cose negative curve must be an integer" {
  for crv in [b"\x65P-256", b"\xf5", b"\xf6", b"\x40", b"\x80"] {
    cose_expect_field(
      cose_fixture(crv~),
      "crv",
      6,
      @webauthn.WrongType(expected="integer"),
    )
  }
}

///|
test "cose negative x coordinate requires exactly 32 bytes" {
  for length in [0, 1, 31, 33] {
    cose_expect_field(
      cose_fixture(x=cose_bstr(Bytes::make(length, b'\x01'))),
      "x",
      8,
      @webauthn.InvalidCoordinateLength(expected=32, actual=length),
    )
  }
}

///|
test "cose negative y coordinate requires exactly 32 bytes" {
  for length in [0, 1, 31, 33] {
    cose_expect_field(
      cose_fixture(y=cose_bstr(Bytes::make(length, b'\x01'))),
      "y",
      43,
      @webauthn.InvalidCoordinateLength(expected=32, actual=length),
    )
  }
}

///|
test "cose negative x coordinate rejects non byte strings" {
  for coordinate in [b"\x00", b"\x60", b"\xf5", b"\xf6", b"\x80", b"\xa0"] {
    cose_expect_field(
      cose_fixture(x=coordinate),
      "x",
      8,
      @webauthn.WrongType(expected="byte string"),
    )
  }
}

///|
test "cose negative y coordinate rejects non byte strings" {
  for coordinate in [b"\x00", b"\x60", b"\xf6", b"\x80", b"\xa0"] {
    cose_expect_field(
      cose_fixture(y=coordinate),
      "y",
      43,
      @webauthn.WrongType(expected="byte string"),
    )
  }
}

///|
test "cose negative Boolean y compressed point encodings are forbidden" {
  for coordinate in [b"\xf4", b"\xf5"] {
    cose_expect_field(
      cose_fixture(y=coordinate),
      "y",
      43,
      @webauthn.CompressedPointNotAllowed,
    )
  }
}

///|
test "cose negative x and y reject p p plus one and maximum 32 byte values" {
  let prime = b"\xff\xff\xff\xff\x00\x00\x00\x01" +
    Bytes::make(12, b'\x00') +
    Bytes::make(12, b'\xff')
  let above = b"\xff\xff\xff\xff\x00\x00\x00\x01" +
    Bytes::make(11, b'\x00') +
    b"\x01" +
    Bytes::make(12, b'\x00')
  for coordinate in [prime, above, Bytes::make(32, b'\xff')] {
    assert_eq(coordinate.length(), 32)
    cose_expect_field(
      cose_fixture(x=cose_bstr(coordinate)),
      "x",
      8,
      @webauthn.InvalidCoordinate,
    )
    cose_expect_field(
      cose_fixture(y=cose_bstr(coordinate)),
      "y",
      43,
      @webauthn.InvalidCoordinate,
    )
  }
}

///|
test "cose negative private d parameter is distinct and never echoed in errors" {
  let ordinary = cose_fixture()
  let input = b"\xa6" + ordinary[1:].to_owned() + b"\x23\x50SENSITIVE_MARKER"
  let error = cose_error(input)
  assert_eq(error.kind, @webauthn.PrivateKeyMaterialNotAllowed)
  assert_eq(error.offset, 77)
  assert_eq(error.context, "credentialPublicKey.parameter[5]")
  assert_false(error.to_repr().to_string().contains("SENSITIVE_MARKER"))
}

///|
test "cose negative kid key ops and base IV have explicit forbidden labels" {
  let ordinary = cose_fixture()
  for
    (label, value, position, index) in [
      (2, b"\x41k", 3, 1),
      (4, b"\x81\x02", 5, 2),
      (5, b"\x41i", 5, 2),
    ] {
    let input = b"\xa6" +
      ordinary[1:position].to_owned() +
      Bytes::from_array([label.to_byte()]) +
      value +
      ordinary[position:].to_owned()
    let error = cose_error(input)
    assert_eq(error.kind, @webauthn.ForbiddenCoseParameter(label~))
    assert_eq(error.offset, position)
    assert_eq(error.context, "credentialPublicKey.parameter[\{index}]")
  }
}

///|
test "cose negative unknown integer parameters include the entire CBOR domain" {
  let ordinary = cose_fixture()
  for label in [b"\x06", b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff"] {
    let input = b"\xa6" +
      ordinary[1:5].to_owned() +
      label +
      b"\x00" +
      ordinary[5:].to_owned()
    let error = cose_error(input)
    assert_eq(error.kind, @webauthn.UnsupportedCoseParameter)
    assert_eq(error.offset, 5)
    assert_eq(error.context, "credentialPublicKey.parameter[2]")
  }
  for label in [b"\x24", b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff"] {
    let error = cose_error(b"\xa6" + ordinary[1:].to_owned() + label + b"\x00")
    assert_eq(error.kind, @webauthn.UnsupportedCoseParameter)
    assert_eq(error.offset, 77)
    assert_eq(error.context, "credentialPublicKey.parameter[5]")
  }
}

///|
test "cose negative unsupported text COSE labels are reported explicitly" {
  let ordinary = cose_fixture()
  let error = cose_error(b"\xa6" + ordinary[1:].to_owned() + b"\x66future\x00")
  assert_eq(error.kind, @webauthn.UnsupportedCoseParameter)
  assert_eq(error.offset, 77)
  assert_eq(error.context, "credentialPublicKey.parameter[5]")
}

///|
test "cose negative labels other than integer or text have precise type errors" {
  let ordinary = cose_fixture()
  for label in [b"\x40", b"\x80", b"\xa0", b"\xf5", b"\xf6"] {
    let input = b"\xa6" + ordinary[1:].to_owned() + label + b"\x00"
    let error = cose_error(input)
    assert_eq(
      error.kind,
      @webauthn.WrongType(expected="integer or text COSE label"),
    )
    assert_eq(error.offset, 77)
    assert_eq(error.context, "credentialPublicKey.parameter[5]")
  }
}

///|
test "cose negative key input must be a CBOR map" {
  for input in [b"\x00", b"\x40", b"\x60", b"\x80", b"\xf4", b"\xf6"] {
    let error = cose_error(input)
    assert_eq(error.kind, @webauthn.WrongType(expected="CBOR map"))
    assert_eq(error.offset, 0)
    assert_eq(error.context, "credentialPublicKey")
  }
}

///|
test "cose negative duplicate labels preserve CBOR primary and first offsets" {
  let input = b"\xa2\x01\x02\x01\x02"
  let error = cose_error(input)
  assert_eq(error.offset, 3)
  assert_eq(error.kind, @webauthn.Cbor(@cbor.DuplicateMapKey(first_offset=1)))
  assert_true(error.context.contains("map[1].key"))
}

///|
test "cose negative noncanonical heads and integer fields cannot bypass CBOR" {
  let ordinary = cose_fixture()
  for
    input in [
      b"\xb8\x05" + ordinary[1:].to_owned(),
      cose_fixture(kty=b"\x18\x02"),
      cose_fixture(alg=b"\x38\x06"),
    ] {
    assert_true(
      cose_error(input).kind is @webauthn.Cbor(@cbor.NonMinimalEncoding),
    )
  }
}

///|
test "cose negative noncanonical label order retains CBOR location" {
  let error = cose_error(b"\xa2\x03\x26\x01\x02")
  assert_eq(error.offset, 3)
  assert_eq(error.kind, @webauthn.Cbor(@cbor.UnsortedMapKey(previous_offset=1)))
}

///|
test "cose negative every truncation returns bounded source offsets" {
  let input = cose_fixture()
  for length in 0..<input.length() {
    let error = cose_error(input[:length])
    assert_true(error.kind is @webauthn.Cbor(_))
    assert_true(error.offset >= 0 && error.offset <= length)
  }
}

///|
test "cose negative trailing data is never part of a validated key" {
  let input = cose_fixture()
  let error = cose_error(input + b"\x00")
  assert_eq(error.offset, 77)
  assert_eq(error.kind, @webauthn.Cbor(@cbor.TrailingData(remaining=1)))
}

///|
test "cose negative unsupported CBOR and invalid UTF8 remain CBOR errors" {
  for
    input in [
      b"\xff", b"\xbf\xff", b"\xc0\xa0", b"\xa1\x61\xff\x00", b"\xa1\x01\xf9\x3e\x00",
    ] {
    assert_true(cose_error(input).kind is @webauthn.Cbor(_))
  }
}

///|
test "cose positive exact caller budgets suffice for the full key" {
  let input = cose_fixture()
  let parameters = cose_parsed(
    input,
    limits=@cbor.Limits::new(
      max_input_bytes=77,
      max_string_bytes=32,
      max_map_pairs=5,
      max_depth=1,
      max_values=11,
    ),
  )
  assert_eq(parameters.x.length(), 32)
  assert_eq(parameters.y.length(), 32)
}

///|
test "cose negative caller limits apply before parameter validation" {
  let input = cose_fixture()
  for
    limits in [
      @cbor.Limits::new(max_input_bytes=76),
      @cbor.Limits::new(max_string_bytes=31),
      @cbor.Limits::new(max_map_pairs=4),
      @cbor.Limits::new(max_depth=0),
      @cbor.Limits::new(max_values=10),
    ] {
    assert_true(
      cose_error(input, limits~).kind is @webauthn.Cbor(@cbor.ResourceLimit(_)),
    )
  }
}

///|
test "cose negative invalid budgets retain explicit errors" {
  for
    limits in [
      @cbor.Limits::new(max_values=-1),
      @cbor.Limits::new(max_depth=65),
    ] {
    assert_true(
      cose_error(cose_fixture(), limits~).kind is @webauthn.InvalidLimit(_),
    )
  }
}

///|
test "cose negative subview errors remain relative to that input view" {
  let input = cose_fixture(y=b"\xf5")
  let wrapped = b"prefix" + input + b"suffix"
  cose_expect_field(
    wrapped[6:6 + input.length()],
    "y",
    43,
    @webauthn.CompressedPointNotAllowed,
  )
}

///|
test "cose integration authenticator data provides opt in ES256 validation" {
  let input = cose_auth_fixture(cose_fixture(), extensions=true)
  let auth = cose_auth_parsed(input)
  guard auth.attested is Some(attested) else { fail("missing AT") }
  match attested.validate_es256() {
    Ok(parameters) => {
      assert_eq(parameters.range, { start: 57, end: 134, })
      assert_eq(parameters.kty_range, { start: 59, end: 60, })
      assert_eq(parameters.x_range, { start: 65, end: 99, })
      assert_eq(parameters.y_range, { start: 100, end: 134, })
      assert_eq(parameters.x, Bytes::make(32, b'\x01')[:])
      assert_eq(parameters.raw, attested.credential_public_key_raw)
      assert_eq(parameters.point_validation, @webauthn.NotPerformed)
    }
    Err(error) => fail("unexpected opt in error: \{error.to_repr()}")
  }
  assert_true(auth.extensions is Some(_))
  assert_eq(auth.raw, input[:])
}

///|
test "cose integration semantic errors use authenticator data coordinates" {
  let auth = cose_auth_parsed(cose_auth_fixture(cose_fixture(y=b"\xf5")))
  guard auth.attested is Some(attested) else { fail("missing AT") }
  match attested.validate_es256() {
    Err(error) => {
      assert_eq(error.offset, 100)
      assert_eq(error.context, "authData.attested.credentialPublicKey.y")
      assert_eq(error.kind, @webauthn.CompressedPointNotAllowed)
    }
    Ok(_) => fail("compressed point must not pass opt in validation")
  }
}

///|
test "cose integration alternate algorithms retain prior structure parser behavior" {
  for
    (kty, algorithm) in [
      (b"\x02", b"\x38\x22"),
      (b"\x02", b"\x38\x23"),
      (b"\x03", b"\x39\x01\x00"),
      (b"\x03", b"\x38\x24"),
      (b"\x01", b"\x27"),
    ] {
    let key = cose_fixture(kty~, alg=algorithm)
    let auth_input = cose_auth_fixture(key)
    let auth = cose_auth_parsed(auth_input)
    guard auth.attested is Some(attested) else { fail("missing AT") }
    assert_eq(attested.credential_public_key_raw, key[:])
    match attested.validate_es256() {
      Err(error) => {
        assert_eq(error.kind, @webauthn.UnsupportedAlgorithm)
        assert_eq(error.offset, 61)
      }
      Ok(_) => fail("alternate algorithm must not identify as ES256")
    }
    let object = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData" +
      cose_bstr(auth_input)
    match @webauthn.parse_attestation_object(object) {
      Ok(parsed) => {
        assert_eq(parsed.statement_status, @webauthn.NoneStructureChecked)
        guard parsed.auth_data.attested is Some(nested) else {
          fail("missing nested AT")
        }
        assert_eq(nested.credential_public_key_raw, key[:])
        assert_true(nested.validate_es256() is Err(_))
      }
      Err(error) =>
        fail("existing structure parser rejected algorithm: \{error.to_repr()}")
    }
  }
}

///|
test "cose integration private or optional parameters remain structurally inspectable" {
  let ordinary = cose_fixture()
  let input = b"\xa6" + ordinary[1:].to_owned() + b"\x23\x41s"
  let auth = cose_auth_parsed(cose_auth_fixture(input))
  guard auth.attested is Some(attested) else { fail("missing AT") }
  assert_eq(attested.credential_public_key_raw, input[:])
  match attested.validate_es256() {
    Err(error) => {
      assert_eq(error.kind, @webauthn.PrivateKeyMaterialNotAllowed)
      assert_eq(error.offset, 134)
    }
    Ok(_) => fail("private parameter must be rejected by validation")
  }
}
