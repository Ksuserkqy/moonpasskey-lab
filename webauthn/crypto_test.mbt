///|
// Project synthetic crypto regression fixtures. The default point is the
// published SEC 2 P-256 generator. Additional leading-zero public points were
// generated with Node.js 24.18.0/OpenSSL using fixed public test scalars.
// These tests store public coordinates only and claim no official vectors.
fn crypto_parameters_fixture(
  x~ : Bytes = b"\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96",
  y~ : Bytes = b"\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5",
) -> Bytes {
  b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" + x + b"\x22\x58\x20" + y
}

///|
fn crypto_parameters(
  input : BytesView,
) -> @webauthn.Es256PublicKeyParameters raise {
  match @webauthn.validate_es256_credential_public_key(input) {
    Ok(parameters) => parameters
    Err(error) => fail("unexpected parameter error \{error.to_repr()}")
  }
}

///|
fn crypto_imported(
  input : BytesView,
) -> @webauthn.ValidatedEs256PublicKey raise {
  match @webauthn.import_es256_public_key(crypto_parameters(input)) {
    Ok(key) => key
    Err(error) => fail("unexpected public key import error \{error.to_repr()}")
  }
}

///|
fn crypto_order() -> Bytes {
  b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51"
}

///|
test "crypto public key import retains P4 bytes coordinates and ranges" {
  let input = crypto_parameters_fixture()
  let parameters = crypto_parameters(input)
  let key = crypto_imported(input)
  assert_eq(key.parameters(), parameters)
  assert_eq(key.parameters().raw, input[:])
  assert_eq(key.parameters().range, { start: 0, end: 77, })
  assert_eq(key.parameters().x_range, { start: 8, end: 42, })
  assert_eq(key.parameters().y_range, { start: 43, end: 77, })
}

///|
test "crypto public key import rejects zero off-curve coordinates" {
  let zero = Bytes::make(32, b'\x00')
  let parameters = crypto_parameters(crypto_parameters_fixture(x=zero, y=zero))
  assert_eq(parameters.point_validation, @webauthn.NotPerformed)
  assert_true(
    @webauthn.import_es256_public_key(parameters)
    is Err(@webauthn.InvalidPublicKey),
  )
}

///|
test "crypto public key import rejects in-field p minus one off-curve pair" {
  let below = b"\xff\xff\xff\xff\x00\x00\x00\x01" +
    Bytes::make(12, b'\x00') +
    Bytes::make(11, b'\xff') +
    b"\xfe"
  let parameters = crypto_parameters(
    crypto_parameters_fixture(x=below, y=below),
  )
  assert_true(
    @webauthn.import_es256_public_key(parameters)
    is Err(@webauthn.InvalidPublicKey),
  )
}

///|
test "crypto public key import rejects altered generator coordinates" {
  let input = crypto_parameters_fixture()
  let altered = input[:76].to_owned() + b"\xf4"
  let parameters = crypto_parameters(altered)
  assert_true(
    @webauthn.import_es256_public_key(parameters)
    is Err(@webauthn.InvalidPublicKey),
  )
}

///|
test "crypto upstream issue 1 noncanonical coordinates stop at P4 guard" {
  // Synthetic reproduction documented in the backend's public issue.
  // https://github.com/moonbitstack/mooncrypt/issues/1
  let prime = b"\xff\xff\xff\xff\x00\x00\x00\x01" +
    Bytes::make(12, b'\x00') +
    Bytes::make(12, b'\xff')
  let congruent_y = b"\x66\x48\x5c\x78\x0e\x2f\x83\xd7\x24\x33\xbd\x5d\x84\xa0\x6b\xb6\x54\x1c\x2a\xf3\x1d\xae\x87\x17\x28\xbf\x85\x6a\x17\x4f\x93\xf4"
  match
    @webauthn.validate_es256_credential_public_key(
      crypto_parameters_fixture(x=prime, y=congruent_y),
    ) {
    Err(error) => {
      assert_eq(error.offset, 8)
      assert_eq(error.context, "credentialPublicKey.x")
      assert_eq(error.kind, @webauthn.InvalidCoordinate)
    }
    Ok(_) => fail("noncanonical field coordinates must stop before key import")
  }
}

///|
test "crypto public key import preserves valid leading zero x and y coordinates" {
  let points = [
    (
      b"\x00\x55\x43\x89\x4a\xf3\xd0\x0e\xd7\xd7\x40\xab\xdb\xd7\x5c\x96\xb0\x68\x77\xb7\x87\xdb\x5f\x70\xee\xa7\x8b\x90\xa8\xd7\xc0\x0a",
      b"\xbb\x4c\x85\xa3\xd8\xea\x29\xef\xaa\xfa\x24\x40\x69\x12\xdd\x84\xd5\xb1\x4d\xc3\x2b\xf6\x56\xef\x6c\x6b\xd5\x8a\x5d\x94\x3f\x92",
    ),
    (
      b"\x98\x6a\xe2\x50\x6f\x1f\xf1\x04\xd0\x42\x30\x86\x1d\x8f\x4b\x49\x8f\x4b\xc4\xc6\xd0\x09\xb3\x0f\x75\x44\xdc\x12\x9b\x82\xd2\x8d",
      b"\x00\x3c\xcc\xc0\xa6\x46\x0e\x0a\xe3\x28\xa4\xd9\x7d\x3c\x7b\x61\xd8\x6f\xc6\x28\x9c\x18\x9f\x25\x25\x11\x0c\x44\x1b\xb0\x7e\x97",
    ),
  ]
  for (x, y) in points {
    let key = crypto_imported(crypto_parameters_fixture(x~, y~))
    assert_eq(key.parameters().x, x[:])
    assert_eq(key.parameters().y, y[:])
    assert_eq(key.parameters().x.length(), 32)
    assert_eq(key.parameters().y.length(), 32)
  }
}

///|
test "crypto public key import preserves nested AT source ranges" {
  let key_bytes = crypto_parameters_fixture()
  let auth_bytes = Bytes::make(32, b'\x00') +
    b"\x40" +
    Bytes::make(20, b'\x00') +
    b"\x00\x02id" +
    key_bytes
  let auth = match @webauthn.parse_authenticator_data(auth_bytes) {
    Ok(auth) => auth
    Err(error) => fail("unexpected authData error \{error.to_repr()}")
  }
  guard auth.attested is Some(attested) else { fail("missing AT") }
  let parameters = match attested.validate_es256() {
    Ok(parameters) => parameters
    Err(error) => fail("unexpected AT parameters error \{error.to_repr()}")
  }
  let key = match @webauthn.import_es256_public_key(parameters) {
    Ok(key) => key
    Err(error) => fail("unexpected AT point error \{error.to_repr()}")
  }
  assert_eq(key.parameters().range, { start: 57, end: 134, })
  assert_eq(key.parameters().x_range, { start: 65, end: 99, })
  assert_eq(key.parameters().y_range, { start: 100, end: 134, })
  assert_eq(key.parameters().raw, key_bytes[:])
}

///|
test "crypto signature lengths reject before scalar checks" {
  let key = crypto_imported(crypto_parameters_fixture())
  for length in [0, 1, 31, 32, 63, 65, 72] {
    assert_eq(
      @webauthn.verify_es256_signature(
        key,
        b"message",
        Bytes::make(length, b'\x00'),
      ),
      Err(@webauthn.InvalidSignatureLength(expected=64, actual=length)),
    )
  }
}

///|
test "crypto signature zero R zero S and zero pair have component errors" {
  let key = crypto_imported(crypto_parameters_fixture())
  let zero = Bytes::make(32, b'\x00')
  let one = Bytes::make(31, b'\x00') + b"\x01"
  for
    (signature, component) in [
      (zero + one, "R"),
      (one + zero, "S"),
      (zero + zero, "R"),
    ] {
    assert_eq(
      @webauthn.verify_es256_signature(key, b"message", signature),
      Err(@webauthn.InvalidSignatureScalar(component~)),
    )
  }
}

///|
test "crypto signature scalar n n plus one and maximum bytes reject on both sides" {
  let key = crypto_imported(crypto_parameters_fixture())
  let order = crypto_order()
  let above = order[:31].to_owned() + b"\x52"
  let one = Bytes::make(31, b'\x00') + b"\x01"
  for invalid in [order, above, Bytes::make(32, b'\xff')] {
    assert_eq(
      @webauthn.verify_es256_signature(key, b"message", invalid + one),
      Err(@webauthn.InvalidSignatureScalar(component="R")),
    )
    assert_eq(
      @webauthn.verify_es256_signature(key, b"message", one + invalid),
      Err(@webauthn.InvalidSignatureScalar(component="S")),
    )
  }
}

///|
test "crypto signature legal scalar bounds return false for invalid signatures" {
  let key = crypto_imported(crypto_parameters_fixture())
  let one = Bytes::make(31, b'\x00') + b"\x01"
  let below = crypto_order()[:31].to_owned() + b"\x50"
  for signature in [one + one, below + one, one + below, below + below] {
    assert_eq(
      @webauthn.verify_es256_signature(key, b"message", signature),
      Ok(false),
    )
  }
}

///|
test "crypto signature legal encoding supports empty message without format error" {
  let key = crypto_imported(crypto_parameters_fixture())
  let one = Bytes::make(31, b'\x00') + b"\x01"
  assert_eq(@webauthn.verify_es256_signature(key, b"", one + one), Ok(false))
}

///|
test "crypto signature reads only supplied signature and message views" {
  let key = crypto_imported(crypto_parameters_fixture())
  let one = Bytes::make(31, b'\x00') + b"\x01"
  let signature = one + one
  let wrapped_signature = b"prefix" + signature + b"suffix"
  let wrapped_message = b"prefixmessagesuffix"
  assert_eq(
    @webauthn.verify_es256_signature(
      key,
      wrapped_message[6:13],
      wrapped_signature[6:70],
    ),
    Ok(false),
  )
  assert_eq(wrapped_signature, b"prefix" + signature + b"suffix")
  assert_eq(wrapped_message, b"prefixmessagesuffix")
}

///|
test "crypto SHA256 leaves original bytes and sliced views intact" {
  let input = b"prefixabcsuffix"
  let before = input[:].to_owned()
  let view = input[6:9]
  assert_eq(
    @webauthn.sha256(view),
    b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
  )
  assert_eq(input, before)
  assert_eq(view, b"abc"[:])
  assert_eq(@webauthn.sha256(view).length(), 32)
}

///|
test "crypto signed data appends one client hash to unchanged authenticator data" {
  let auth = b"\x00\x01\x7f\x80\xff"
  let client = b"abc"
  let expected_hash = b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"
  assert_eq(
    @webauthn.build_webauthn_assertion_signed_data(auth, client),
    Ok(auth + expected_hash),
  )
  assert_eq(auth, b"\x00\x01\x7f\x80\xff")
  assert_eq(client, b"abc")
}

///|
test "crypto signed data accepts empty authenticator and client byte inputs" {
  let empty_hash = b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"
  assert_eq(
    @webauthn.build_webauthn_assertion_signed_data(b"", b""),
    Ok(empty_hash),
  )
  assert_eq(
    @webauthn.build_webauthn_assertion_signed_data(b"auth", b""),
    Ok(b"auth" + empty_hash),
  )
  assert_eq(
    @webauthn.build_webauthn_assertion_signed_data(b"", b"abc"),
    Ok(@webauthn.sha256(b"abc")),
  )
}

///|
test "crypto signed data respects both input subview boundaries" {
  let auth = b"prefixauthsuffix"
  let client = b"prefixabcsuffix"
  assert_eq(
    @webauthn.build_webauthn_assertion_signed_data(auth[6:10], client[6:9]),
    Ok(b"auth" + @webauthn.sha256(b"abc")),
  )
  assert_eq(auth, b"prefixauthsuffix")
  assert_eq(client, b"prefixabcsuffix")
}

///|
test "crypto signed data hashes original JSON order whitespace and escapes" {
  let variants = [
    b"{\"type\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"https://rp.test\"}",
    b"{\"origin\":\"https://rp.test\",\"challenge\":\"a\",\"type\":\"webauthn.get\"}",
    b"{ \"type\":\"webauthn.get\",\"challenge\":\"a\",\"origin\":\"https://rp.test\" }",
    b"{\"type\":\"webauthn.get\",\"challenge\":\"\\u0061\",\"origin\":\"https://rp.test\"}",
  ]
  let auth = b"auth"
  for index, client in variants {
    let parsed = match @webauthn.parse_client_data(client) {
      Ok(parsed) => parsed
      Err(error) => fail("unexpected client JSON error \{error.to_repr()}")
    }
    assert_eq(parsed.challenge, "a")
    assert_eq(parsed.raw, client[:])
    assert_eq(
      @webauthn.build_webauthn_assertion_signed_data(auth, parsed.raw),
      Ok(auth + @webauthn.sha256(client)),
    )
    for other in 0..<index {
      assert_true(@webauthn.sha256(client) != @webauthn.sha256(variants[other]))
    }
  }
}
