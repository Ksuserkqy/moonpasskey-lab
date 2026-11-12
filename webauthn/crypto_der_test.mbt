///|
// Synthetic ASN.1 DER fixtures. Arbitrary in-range scalar pairs are expected
// to fail verification while passing DER and scalar-format validation.
fn crypto_der_integer(content : Bytes) -> Bytes {
  b"\x02" + Bytes::from_array([content.length().to_byte()]) + content
}

///|
fn crypto_der_body(body : Bytes) -> Bytes {
  b"\x30" + Bytes::from_array([body.length().to_byte()]) + body
}

///|
fn crypto_der_pair(r : Bytes, s : Bytes) -> Bytes {
  crypto_der_body(crypto_der_integer(r) + crypto_der_integer(s))
}

///|
fn crypto_der_verify(
  signature : BytesView,
) -> Result[Bool, @webauthn.CryptoError] raise {
  @webauthn.verify_webauthn_es256_assertion_signature(
    crypto_imported(crypto_parameters_fixture()),
    b"auth",
    b"client",
    signature,
  )
}

///|
test "crypto DER accepts minimal short positive scalar encodings" {
  for content in [b"\x01", b"\x7f", b"\x01\x00", Bytes::make(31, b'\x01')] {
    assert_eq(crypto_der_verify(crypto_der_pair(content, b"\x01")), Ok(false))
    assert_eq(crypto_der_verify(crypto_der_pair(b"\x01", content)), Ok(false))
  }
}

///|
test "crypto DER accepts necessary sign padding for short and full width scalars" {
  for
    content in [
      b"\x00\x80",
      b"\x00\xff",
      b"\x00\x80" + Bytes::make(31, b'\x00'),
    ] {
    assert_eq(crypto_der_verify(crypto_der_pair(content, b"\x01")), Ok(false))
    assert_eq(crypto_der_verify(crypto_der_pair(b"\x01", content)), Ok(false))
  }
}

///|
test "crypto DER accepts maximum encoded width and high S scalar range" {
  let below = b"\x00" + crypto_order()[:31].to_owned() + b"\x50"
  let signature = crypto_der_pair(below, below)
  assert_eq(signature.length(), 72)
  assert_eq(crypto_der_verify(signature), Ok(false))
}

///|
test "crypto DER valid 64 byte sequence is parsed according to its DER structure" {
  let signature = crypto_der_pair(
    Bytes::make(28, b'\x01'),
    Bytes::make(30, b'\x01'),
  )
  assert_eq(signature.length(), 64)
  assert_eq(crypto_der_verify(signature), Ok(false))
}

///|
test "crypto DER zero scalar encoding has precise R and S errors" {
  for
    (r, s, component) in [
      (b"\x00", b"\x01", "R"),
      (b"\x01", b"\x00", "S"),
      (b"\x00", b"\x00", "R"),
    ] {
    assert_eq(
      crypto_der_verify(crypto_der_pair(r, s)),
      Err(@webauthn.InvalidSignatureScalar(component~)),
    )
  }
}

///|
test "crypto DER group order and greater scalar values retain component errors" {
  let order = crypto_order()
  let above = order[:31].to_owned() + b"\x52"
  for scalar in [order, above, Bytes::make(32, b'\xff')] {
    let content = b"\x00" + scalar
    assert_eq(
      crypto_der_verify(crypto_der_pair(content, b"\x01")),
      Err(@webauthn.InvalidSignatureScalar(component="R")),
    )
    assert_eq(
      crypto_der_verify(crypto_der_pair(b"\x01", content)),
      Err(@webauthn.InvalidSignatureScalar(component="S")),
    )
  }
}

///|
test "crypto DER sequence requires exact SEQUENCE tag" {
  let body = b"\x06\x02\x01\x01\x02\x01\x01"
  for tag in [b'\x10', b'\x31', b'\x04', b'\xa0', b'\xff'] {
    assert_eq(
      crypto_der_verify(Bytes::from_array([tag]) + body),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER R and S require INTEGER tags" {
  for tag in [b'\x04', b'\x03', b'\x22', b'\xa2', b'\xff'] {
    let other = Bytes::from_array([tag]) + b"\x01\x01"
    assert_eq(
      crypto_der_verify(crypto_der_body(other + b"\x02\x01\x01")),
      Err(@webauthn.InvalidSignatureEncoding),
    )
    assert_eq(
      crypto_der_verify(crypto_der_body(b"\x02\x01\x01" + other)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER empty INTEGER content is rejected in both positions" {
  assert_eq(
    crypto_der_verify(crypto_der_pair(b"", b"\x01")),
    Err(@webauthn.InvalidSignatureEncoding),
  )
  assert_eq(
    crypto_der_verify(crypto_der_pair(b"\x01", b"")),
    Err(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "crypto DER negative INTEGER content is rejected in both positions" {
  for content in [b"\x80", b"\xff", b"\x80\x00", Bytes::make(32, b'\xff')] {
    assert_eq(
      crypto_der_verify(crypto_der_pair(content, b"\x01")),
      Err(@webauthn.InvalidSignatureEncoding),
    )
    assert_eq(
      crypto_der_verify(crypto_der_pair(b"\x01", content)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER redundant positive sign padding is rejected in both positions" {
  for
    content in [
      b"\x00\x01",
      b"\x00\x7f",
      b"\x00\x00",
      b"\x00\x00\x80",
      b"\x00" + Bytes::make(32, b'\x01'),
    ] {
    assert_eq(
      crypto_der_verify(crypto_der_pair(content, b"\x01")),
      Err(@webauthn.InvalidSignatureEncoding),
    )
    assert_eq(
      crypto_der_verify(crypto_der_pair(b"\x01", content)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER positive magnitudes wider than 32 bytes have component errors" {
  for
    content in [
      Bytes::make(33, b'\x01'),
      b"\x00\x80" + Bytes::make(32, b'\x00'),
    ] {
    assert_eq(
      crypto_der_verify(crypto_der_pair(content, b"\x01")),
      Err(@webauthn.InvalidSignatureScalar(component="R")),
    )
    assert_eq(
      crypto_der_verify(crypto_der_pair(b"\x01", content)),
      Err(@webauthn.InvalidSignatureScalar(component="S")),
    )
  }
}

///|
test "crypto DER rejects long form and indefinite sequence lengths" {
  let body = b"\x02\x01\x01\x02\x01\x01"
  for prefix in [b"\x30\x81\x06", b"\x30\x82\x00\x06", b"\x30\x80", b"\x30\xff"] {
    assert_eq(
      crypto_der_verify(prefix + body),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
  assert_eq(
    crypto_der_verify(b"\x30\x80" + body + b"\x00\x00"),
    Err(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "crypto DER rejects long form and indefinite INTEGER lengths" {
  for
    integer in [
      b"\x02\x81\x01\x01", b"\x02\x82\x00\x01\x01", b"\x02\x80\x01\x00\x00", b"\x02\xff\x01",
    ] {
    assert_eq(
      crypto_der_verify(crypto_der_body(integer + b"\x02\x01\x01")),
      Err(@webauthn.InvalidSignatureEncoding),
    )
    assert_eq(
      crypto_der_verify(crypto_der_body(b"\x02\x01\x01" + integer)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER every truncated prefix is an encoding error" {
  let signature = crypto_der_pair(
    b"\x00\x80" + Bytes::make(31, b'\x00'),
    b"\x00\x80" + Bytes::make(31, b'\x00'),
  )
  for length in 0..<signature.length() {
    assert_eq(
      crypto_der_verify(signature[:length]),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER declared sequence length must match the entire input" {
  let body = b"\x02\x01\x01\x02\x01\x01"
  for length in [0, 1, 5, 7, 127] {
    let signature = b"\x30" + Bytes::from_array([length.to_byte()]) + body
    assert_eq(
      crypto_der_verify(signature),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER INTEGER length cannot exceed its available sequence content" {
  for
    body in [
      b"\x02\x07\x01\x02\x01\x01", b"\x02\x01\x01\x02\x02\x01", b"\x02\x01\x01\x02",
    ] {
    assert_eq(
      crypto_der_verify(crypto_der_body(body)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER trailing bytes and extra sequence members are rejected" {
  let signature = crypto_der_pair(b"\x01", b"\x01")
  for suffix in [b"\x00", b"\x00\x00", b"\x02\x01\x01"] {
    assert_eq(
      crypto_der_verify(signature + suffix),
      Err(@webauthn.InvalidSignatureEncoding),
    )
    let body = signature[2:].to_owned() + suffix
    assert_eq(
      crypto_der_verify(crypto_der_body(body)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER sequence requires exactly two INTEGER members" {
  for body in [b"", b"\x02\x01\x01", b"\x02\x01\x01\x02\x01\x01\x02\x01\x01"] {
    assert_eq(
      crypto_der_verify(crypto_der_body(body)),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER entry rejects a raw scalar pair lacking a DER envelope" {
  let one = Bytes::make(31, b'\x00') + b"\x01"
  assert_eq(
    crypto_der_verify(one + one),
    Err(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "crypto DER entry respects signature subview boundaries" {
  let signature = crypto_der_pair(b"\x01", b"\x01")
  let wrapped = b"prefix" + signature + b"suffix"
  assert_eq(crypto_der_verify(wrapped[6:6 + signature.length()]), Ok(false))
  assert_eq(wrapped, b"prefix" + signature + b"suffix")
}

///|
test "crypto DER checks both INTEGER encodings before scalar semantics" {
  for invalid_s in [b"\x04\x01\x01", b"\x02\x02\x00\x01", b"\x02\x01\x80"] {
    let signature = crypto_der_body(b"\x02\x01\x00" + invalid_s)
    assert_eq(
      crypto_der_verify(signature),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}

///|
test "crypto DER rejects inputs beyond the maximum P256 DER envelope" {
  for length in [73, 4096] {
    assert_eq(
      crypto_der_verify(Bytes::make(length, b'\x30')),
      Err(@webauthn.InvalidSignatureEncoding),
    )
  }
}
