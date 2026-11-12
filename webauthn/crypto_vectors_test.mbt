///|
// Public verification fixtures. Exact source versions, byte selections and
// licenses are recorded in CRYPTO-VECTORS-NOTICE.md. No private key material.
// The existing strict w3c_hex test decoder is shared across fixture suites.
struct CryptoSignatureCase {
  id : Int32
  message_hex : String
  signature_hex : String
  expected : Result[Bool, @webauthn.CryptoError]
}

///|
struct CryptoSignatureGroup {
  public_point_hex : String
  cases : Array[CryptoSignatureCase]
}

///|
fn crypto_vector_import(
  point : Bytes,
) -> @webauthn.ValidatedEs256PublicKey raise {
  assert_eq(point.length(), 65)
  assert_eq(point[0], b'\x04')
  let cose = b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" +
    point[1:33].to_owned() +
    b"\x22\x58\x20" +
    point[33:65].to_owned()
  let parameters = match @webauthn.validate_es256_credential_public_key(cose) {
    Ok(value) => value
    Err(error) =>
      fail("public vector COSE parameters failed: \{error.to_repr()}")
  }
  let key = match @webauthn.import_es256_public_key(parameters) {
    Ok(value) => value
    Err(error) => fail("public vector point import failed: \{error.to_repr()}")
  }
  assert_eq(key.parameters(), parameters)
  assert_eq(key.parameters().x, point[1:33])
  assert_eq(key.parameters().y, point[33:65])
  assert_eq(key.parameters().point_validation, @webauthn.NotPerformed)
  key
}

///|
fn crypto_check_signature_groups(
  source : String,
  groups : Array[CryptoSignatureGroup],
  expected_cases : Int32,
  expected_valid : Int32,
) -> Unit raise {
  let mut count = 0
  let mut valid = 0
  for group in groups {
    let key = crypto_vector_import(w3c_hex(group.public_point_hex, 65))
    for vector in group.cases {
      let message = w3c_hex(vector.message_hex, vector.message_hex.length() / 2)
      let signature = w3c_hex(
        vector.signature_hex,
        vector.signature_hex.length() / 2,
      )
      let actual = @webauthn.verify_es256_signature(key, message, signature)
      assert_eq(actual, vector.expected, msg="\{source} case \{vector.id}")
      if vector.expected == Ok(true) {
        valid = valid + 1
      }
      count = count + 1
    }
  }
  assert_eq(count, expected_cases)
  assert_eq(valid, expected_valid)
}

///|
// Complete pinned Wycheproof P-256/SHA-256 P1363 suite, all 112 key groups.
// Exact 65-byte SEC1 uncompressed public keys avoid signed wx/wy text forms.
fn crypto_wycheproof_groups() -> Array[CryptoSignatureGroup] {
  [
    {
      public_point_hex: "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c7328" +
      "38c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e734151" +
      "3e",
      cases: [
        {
          id: 1,
          message_hex: "313233343030",
          signature_hex: "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18" +
          "4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
          expected: Ok(true),
        },
        {
          id: 2,
          message_hex: "313233343030",
          signature_hex: "012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf53" +
          "6900b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b491568" +
          "47db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=66),
          ),
        },
        {
          id: 3,
          message_hex: "313233343030",
          signature_hex: "01002ba3a7be6b94d6ec80a6d9d1190a432be6dfbb2cb98d6d4d72972df62081" +
          "7f180000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49" +
          "156847db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=68),
          ),
        },
        {
          id: 4,
          message_hex: "313233343030",
          signature_hex: "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739" +
          "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
          expected: Ok(false),
        },
        {
          id: 5,
          message_hex: "313233343030",
          signature_hex: "012ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e" +
          "1800b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b491568" +
          "47db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=66),
          ),
        },
        {
          id: 6,
          message_hex: "313233343030",
          signature_hex: "0100000000000000002ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee8" +
          "59b8cc6af9bd5c2e18000000000000000000b329f479a2bbd0a5c384ee1493b1" +
          "f5186a87139cac5df4087c134b49156847db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=82),
          ),
        },
        {
          id: 7,
          message_hex: "313233343030",
          signature_hex: "01b329f478a2bbd0a6c384ee1493b1f518276e0e4a5375928d6fcd160c11cb6d" +
          "2c00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b491568" +
          "47db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=66),
          ),
        },
        {
          id: 8,
          message_hex: "313233343030",
          signature_hex: "0100b329f379a2bbd1a5c384ee1493b1f4d55181c143c3fc78fc35de0e45788d" +
          "98db0000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49" +
          "156847db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=68),
          ),
        },
        {
          id: 9,
          message_hex: "313233343030",
          signature_hex: "01b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847" +
          "db00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b491568" +
          "47db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=66),
          ),
        },
        {
          id: 10,
          message_hex: "313233343030",
          signature_hex: "010000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4" +
          "087c134b49156847db000000000000000000b329f479a2bbd0a5c384ee1493b1" +
          "f5186a87139cac5df4087c134b49156847db",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=82),
          ),
        },
        {
          id: 11,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 12,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 13,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 14,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 15,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 16,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 17,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000000" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 18,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 19,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Ok(false),
        },
        {
          id: 20,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 21,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Ok(false),
        },
        {
          id: 22,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 23,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 24,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 25,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 26,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 27,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 28,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 29,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 30,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 31,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 32,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 33,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Ok(false),
        },
        {
          id: 34,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 35,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Ok(false),
        },
        {
          id: 36,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 37,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 38,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
        {
          id: 39,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 40,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 41,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 42,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 43,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 44,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 45,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 46,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 47,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 48,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 49,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 50,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 51,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 52,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 53,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 54,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 55,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 56,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 57,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 58,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 59,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000001000000000000000000000000" +
          "ffffffff00000001000000000000000000000001000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
        {
          id: 60,
          message_hex: "3639383139",
          signature_hex: "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e" +
          "6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
          expected: Ok(true),
        },
        {
          id: 61,
          message_hex: "343236343739373234",
          signature_hex: "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266" +
          "252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
          expected: Ok(true),
        },
        {
          id: 62,
          message_hex: "37313338363834383931",
          signature_hex: "9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882" +
          "093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
          expected: Ok(true),
        },
        {
          id: 63,
          message_hex: "3130333539333331363638",
          signature_hex: "73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa43" +
          "2f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
          expected: Ok(true),
        },
        {
          id: 64,
          message_hex: "33393439343031323135",
          signature_hex: "bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3dd" +
          "bdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
          expected: Ok(true),
        },
        {
          id: 65,
          message_hex: "31333434323933303739",
          signature_hex: "204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd" +
          "51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
          expected: Ok(true),
        },
        {
          id: 66,
          message_hex: "33373036323131373132",
          signature_hex: "ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa03" +
          "99ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
          expected: Ok(true),
        },
        {
          id: 67,
          message_hex: "333433363838373132",
          signature_hex: "060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b" +
          "8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
          expected: Ok(true),
        },
        {
          id: 68,
          message_hex: "31333531353330333730",
          signature_hex: "9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831d" +
          "b26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
          expected: Ok(true),
        },
        {
          id: 69,
          message_hex: "36353533323033313236",
          signature_hex: "a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b7" +
          "20aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
          expected: Ok(true),
        },
        {
          id: 70,
          message_hex: "31353634333436363033",
          signature_hex: "fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db9" +
          "3df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
          expected: Ok(true),
        },
        {
          id: 71,
          message_hex: "34343239353339313137",
          signature_hex: "b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675" +
          "d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
          expected: Ok(true),
        },
        {
          id: 72,
          message_hex: "3130393533323631333531",
          signature_hex: "3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a8" +
          "4c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
          expected: Ok(true),
        },
        {
          id: 73,
          message_hex: "35393837333530303431",
          signature_hex: "30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf" +
          "47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
          expected: Ok(true),
        },
        {
          id: 74,
          message_hex: "33343633303036383738",
          signature_hex: "38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52" +
          "067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
          expected: Ok(true),
        },
        {
          id: 75,
          message_hex: "39383137333230323837",
          signature_hex: "44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf" +
          "2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
          expected: Ok(true),
        },
        {
          id: 76,
          message_hex: "33323232303431303436",
          signature_hex: "2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e9" +
          "7d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
          expected: Ok(true),
        },
        {
          id: 77,
          message_hex: "36363636333037313034",
          signature_hex: "bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8f" +
          "f6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
          expected: Ok(true),
        },
        {
          id: 78,
          message_hex: "31303335393531383938",
          signature_hex: "50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6" +
          "d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
          expected: Ok(true),
        },
        {
          id: 79,
          message_hex: "31383436353937313935",
          signature_hex: "f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d" +
          "3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
          expected: Ok(true),
        },
        {
          id: 80,
          message_hex: "33313336303436313839",
          signature_hex: "9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7a" +
          "c60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
          expected: Ok(true),
        },
        {
          id: 81,
          message_hex: "32363633373834323534",
          signature_hex: "bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d" +
          "9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
          expected: Ok(true),
        },
        {
          id: 82,
          message_hex: "31363532313030353234",
          signature_hex: "2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e" +
          "7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
          expected: Ok(true),
        },
        {
          id: 83,
          message_hex: "35373438303831363936",
          signature_hex: "54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c59" +
          "2ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
          expected: Ok(true),
        },
        {
          id: 84,
          message_hex: "36333433393133343638",
          signature_hex: "5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c9466" +
          "65d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
          expected: Ok(true),
        },
        {
          id: 85,
          message_hex: "31353431313033353938",
          signature_hex: "207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107" +
          "cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
          expected: Ok(true),
        },
        {
          id: 86,
          message_hex: "3130343738353830313238",
          signature_hex: "6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728" +
          "aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
          expected: Ok(true),
        },
        {
          id: 87,
          message_hex: "3130353336323835353638",
          signature_hex: "a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfc" +
          "e99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
          expected: Ok(true),
        },
        {
          id: 88,
          message_hex: "393533393034313035",
          signature_hex: "975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf" +
          "7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
          expected: Ok(true),
        },
        {
          id: 89,
          message_hex: "393738383438303339",
          signature_hex: "5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e" +
          "0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
          expected: Ok(true),
        },
        {
          id: 90,
          message_hex: "33363130363732343432",
          signature_hex: "a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba6" +
          "5e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
          expected: Ok(true),
        },
        {
          id: 91,
          message_hex: "31303534323430373035",
          signature_hex: "614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88" +
          "737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
          expected: Ok(true),
        },
        {
          id: 92,
          message_hex: "35313734343438313937",
          signature_hex: "bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa" +
          "6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
          expected: Ok(true),
        },
        {
          id: 93,
          message_hex: "31393637353631323531",
          signature_hex: "499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad2" +
          "42c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
          expected: Ok(true),
        },
        {
          id: 94,
          message_hex: "33343437323533333433",
          signature_hex: "08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b2" +
          "9d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
          expected: Ok(true),
        },
        {
          id: 95,
          message_hex: "333638323634333138",
          signature_hex: "be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8" +
          "e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
          expected: Ok(true),
        },
        {
          id: 96,
          message_hex: "33323631313938363038",
          signature_hex: "15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443" +
          "e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
          expected: Ok(true),
        },
        {
          id: 97,
          message_hex: "39363738373831303934",
          signature_hex: "352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad" +
          "1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
          expected: Ok(true),
        },
        {
          id: 98,
          message_hex: "34393538383233383233",
          signature_hex: "4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb" +
          "3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
          expected: Ok(true),
        },
        {
          id: 99,
          message_hex: "383234363337383337",
          signature_hex: "eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e96" +
          "7451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
          expected: Ok(true),
        },
        {
          id: 100,
          message_hex: "3131303230383333373736",
          signature_hex: "2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052" +
          "ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
          expected: Ok(true),
        },
        {
          id: 101,
          message_hex: "313333383731363438",
          signature_hex: "ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b3300219" +
          "79938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
          expected: Ok(true),
        },
        {
          id: 102,
          message_hex: "333232313434313632",
          signature_hex: "81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8" +
          "cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
          expected: Ok(true),
        },
        {
          id: 103,
          message_hex: "3130363836363535353436",
          signature_hex: "dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808" +
          "048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
          expected: Ok(true),
        },
        {
          id: 104,
          message_hex: "3632313535323436",
          signature_hex: "ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a5762" +
          "93320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
          expected: Ok(true),
        },
        {
          id: 105,
          message_hex: "37303330383138373734",
          signature_hex: "ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883" +
          "f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
          expected: Ok(true),
        },
        {
          id: 106,
          message_hex: "35393234353233373434",
          signature_hex: "677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f7" +
          "6b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
          expected: Ok(true),
        },
        {
          id: 107,
          message_hex: "31343935353836363231",
          signature_hex: "479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0" +
          "918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
          expected: Ok(true),
        },
        {
          id: 108,
          message_hex: "34303035333134343036",
          signature_hex: "43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a3" +
          "1dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
          expected: Ok(true),
        },
        {
          id: 109,
          message_hex: "33303936343537353132",
          signature_hex: "5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff11" +
          "45b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
          expected: Ok(true),
        },
        {
          id: 110,
          message_hex: "32373834303235363230",
          signature_hex: "5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06f" +
          "b1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
          expected: Ok(true),
        },
        {
          id: 111,
          message_hex: "32363138373837343138",
          signature_hex: "0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32e" +
          "db1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
          expected: Ok(true),
        },
        {
          id: 112,
          message_hex: "31363432363235323632",
          signature_hex: "7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a" +
          "3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
          expected: Ok(true),
        },
        {
          id: 113,
          message_hex: "36383234313839343336",
          signature_hex: "7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5" +
          "249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
          expected: Ok(true),
        },
        {
          id: 114,
          message_hex: "343834323435343235",
          signature_hex: "914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348" +
          "fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe1" +
      "03c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba" +
      "5e",
      cases: [
        {
          id: 115,
          message_hex: "313233343030",
          signature_hex: "000000000000000000000000000000004319055358e8617b0c46353d039cdaab" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(true),
        },
        {
          id: 116,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
      ],
    },
    {
      public_point_hex: "04ab05fd9d0de26b9ce6f4819652d9fc69193d0aa398f0fba8013e09c5822045" +
      "5419235271228c786759095d12b75af0692dd4103f19f6a8c32f49435a1e9b8d" +
      "45",
      cases: [
        {
          id: 117,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0480984f39a1ff38a86a68aa4201b6be5dfbfecf876219710b07badf6fdd4c6c" +
      "5611feb97390d9826e7a06dfb41871c940d74415ed3cac2089f1445019bb55ed" +
      "95",
      cases: [
        {
          id: 118,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "044201b4272944201c3294f5baa9a3232b6dd687495fcc19a70a95bc602b4f7c" +
      "0595c37eba9ee8171c1bb5ac6feaf753bc36f463e3aef16629572c0c0a8fb080" +
      "0e",
      cases: [
        {
          id: 119,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9" +
      "575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e87229" +
      "6b",
      cases: [
        {
          id: 120,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000005" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Ok(true),
        },
        {
          id: 121,
          message_hex: "313233343030",
          signature_hex: "0501",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "046627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b15" +
      "726170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694" +
      "a5",
      cases: [
        {
          id: 122,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000005" +
          "0000000000000000000000000000000000000000000000000000000000000003",
          expected: Ok(true),
        },
        {
          id: 123,
          message_hex: "313233343030",
          signature_hex: "0503",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "045a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5" +
      "bfef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f8" +
      "13",
      cases: [
        {
          id: 124,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000005" +
          "0000000000000000000000000000000000000000000000000000000000000005",
          expected: Ok(true),
        },
        {
          id: 125,
          message_hex: "313233343030",
          signature_hex: "0505",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "04cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c7" +
      "3770af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8" +
      "c1",
      cases: [
        {
          id: 126,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000005" +
          "0000000000000000000000000000000000000000000000000000000000000006",
          expected: Ok(true),
        },
        {
          id: 127,
          message_hex: "313233343030",
          signature_hex: "0506",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "042ef747671c97d9c7f9cb2f6a30d678c3d84757ba241ef7183d51a29f52d87c" +
      "2ea8fb2ea635b761baefc1c4ded2099281b844e13e044c328553bbbafa337d8a" +
      "76",
      cases: [
        {
          id: 128,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000006" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Ok(true),
        },
        {
          id: 129,
          message_hex: "313233343030",
          signature_hex: "0601",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "04931cc49cda4d87d25b1601c56c3b83b4f45e44971998f2d3e7d3c55152214e" +
      "df058dc140abbba42fc1ddbf30dab8eb9b46ee7338b3f7ee96242bf45e1df5e9" +
      "95",
      cases: [
        {
          id: 130,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000006" +
          "0000000000000000000000000000000000000000000000000000000000000003",
          expected: Ok(true),
        },
        {
          id: 131,
          message_hex: "313233343030",
          signature_hex: "0603",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "04899a4af61867e3f3c190dbb48f8bc9fc74b70a467a4a1f06477b3af2f39ab8" +
      "ed47ac000f9ea8a3034939bf48ad5d061a69fc8495ae4df2dbec7effa03a0062" +
      "b3",
      cases: [
        {
          id: 132,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000006" +
          "0000000000000000000000000000000000000000000000000000000000000006",
          expected: Ok(true),
        },
        {
          id: 133,
          message_hex: "313233343030",
          signature_hex: "0606",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
      ],
    },
    {
      public_point_hex: "04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3" +
      "c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf" +
      "46",
      cases: [
        {
          id: 134,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000006" +
          "0000000000000000000000000000000000000000000000000000000000000007",
          expected: Ok(true),
        },
        {
          id: 135,
          message_hex: "313233343030",
          signature_hex: "0607",
          expected: Err(@webauthn.InvalidSignatureLength(expected=64, actual=2)),
        },
        {
          id: 136,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632557" +
          "0000000000000000000000000000000000000000000000000000000000000007",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
      ],
    },
    {
      public_point_hex: "043a72476291571193b4d109b2c37b59f2807e8fe9cffd804eacded903e77ca0" +
      "da592dbc74fee0ca7508cc7bc282b0c51a143286ff53c60131668e7a0929e4ed" +
      "04",
      cases: [
        {
          id: 137,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000006" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
      ],
    },
    {
      public_point_hex: "04d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890" +
      "d9971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89c" +
      "c1",
      cases: [
        {
          id: 138,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000100" +
          "8f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "044838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce0" +
      "5ffa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c" +
      "6b",
      cases: [
        {
          id: 139,
          message_hex: "313233343030",
          signature_hex: "000000000000000000000000000000000000000000000000002d9b4d347952d6" +
          "ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "047393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f" +
      "64e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b18575" +
      "26",
      cases: [
        {
          id: 140,
          message_hex: "313233343030",
          signature_hex: "000000000000000000000000000000000000001033e67e37b32b445580bf4eff" +
          "8b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "045ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcd" +
      "c5fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c" +
      "0b",
      cases: [
        {
          id: 141,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000100" +
          "ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "041d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c415" +
      "09dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8" +
      "c9",
      cases: [
        {
          id: 142,
          message_hex: "313233343030",
          signature_hex: "00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25" +
          "ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e" +
      "99915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d761633791" +
      "1e",
      cases: [
        {
          id: 143,
          message_hex: "313233343030",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5" +
          "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04e075effd9607d08d5f34e3652f64cfa3bd6d20c58d0a232f058491260ab212" +
      "a4cc61760ac8b0680c1b644c03cc628ba9dc4a3c0561368489c692bd40f43aa3" +
      "ca",
      cases: [
        {
          id: 144,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000009c44febf31c3594f" +
          "000000000000000000000000000000000000000000000000839ed28247c2b06b",
          expected: Ok(true),
        },
        {
          id: 145,
          message_hex: "313233343030",
          signature_hex: "9c44febf31c3594f839ed28247c2b06b",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=16),
          ),
        },
      ],
    },
    {
      public_point_hex: "04cffb758c3073ea3c08efd9f7f17a85b6ae385c5a140c146ad5f1f5a826718b" +
      "c8dfdc6bebc894144c6d418ac5d97339726ad2ae925df868426e5628e9f4e623" +
      "42",
      cases: [
        {
          id: 146,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd" +
          "000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a",
          expected: Ok(true),
        },
        {
          id: 147,
          message_hex: "313233343030",
          signature_hex: "09df8b682430beef6f5fd7c7cd0fd0a62e13778f4222a0d61c8a",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=26),
          ),
        },
      ],
    },
    {
      public_point_hex: "04b98740e69e61a325d5f772e3b5c4f67fb7150b16a9afeca9ddc4afcbb6fa05" +
      "49c446e814138e4ebc82dbf86a390056d4595dcf45e381fef217a4597d7bd514" +
      "98",
      cases: [
        {
          id: 148,
          message_hex: "313233343030",
          signature_hex: "000000000000000000000000000000008a598e563a89f526c32ebec8de26367c" +
          "0000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf",
          expected: Ok(true),
        },
        {
          id: 149,
          message_hex: "313233343030",
          signature_hex: "8a598e563a89f526c32ebec8de26367c84f633e2042630e99dd0f1e16f7a04bf",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=32),
          ),
        },
      ],
    },
    {
      public_point_hex: "0484536a270c3932bb2084732adf2c768efc6d3977e5220229ea9a44888b8f9d" +
      "7b1766398cdac2fc8000017b29a7ba15a58f196037f35f7008ed4286ddff00fd" +
      "46",
      cases: [
        {
          id: 150,
          message_hex: "313233343030",
          signature_hex: "000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0bdf" +
          "000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9",
          expected: Ok(true),
        },
        {
          id: 151,
          message_hex: "313233343030",
          signature_hex: "aa6eeb5823f7fa31b466bb473797f0d0314c0bdfe2977c479e6d25703cebbc6b" +
          "d561938cc9d1bfb9",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=40),
          ),
        },
      ],
    },
    {
      public_point_hex: "048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e193738" +
      "7405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf57" +
      "6d",
      cases: [
        {
          id: 152,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "0000000000000000000000000000000000000000000000000000000000000001",
          expected: Ok(true),
        },
        {
          id: 153,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "0000000000000000000000000000000000000000000000000000000000000000",
          expected: Err(@webauthn.InvalidSignatureScalar(component="S")),
        },
      ],
    },
    {
      public_point_hex: "0461722eaba731c697c7a9ba4d0afdbb5713d8aa12b0eab601bb33dbaf792c5a" +
      "dc272cd993b2b663aba5b3a26c101182ff178684945e83879e71598b95fe647d" +
      "fc",
      cases: [
        {
          id: 154,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "02f676969f451a8ccafa4c4f09791810e6d632dbd60b1d5540f3284fbe1889b0",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04c4c91981e720e20d7e478ff19d09b95a98f58c0f469b72801a8ce844a34731" +
      "6594afcd4188182e7779889b3258d0368ece1e66797fe7c648c6f0b9e26bd718" +
      "71",
      cases: [
        {
          id: 155,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "4e260962e33362ef0046126d2d5a4edc6947ab20e19b8ec19cf79e5908b6e628",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d58d47bf49bc8f416641f6f760fcbca80aa52a814e56a5fa40bab44fd6f631" +
      "7216deaa84d45d8e0e29cc9ecf5653f8ee6444750813becae8deb42b04ba07a6" +
      "34",
      cases: [
        {
          id: 156,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "077ed0d8f20f697d8fc591ac64dd5219c7932122b4f9b9ec6441e44a0092cf21",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0491e305822e5e44f3fdb616e2ef42cd98f241b86e9f68815bc4dba6a945e4ee" +
      "fb3c5937e2ac1d9466f6d65e49b35fc8d75ffc22e1fe2f32af42f5fa3c26f9b4" +
      "b0",
      cases: [
        {
          id: 157,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "3e0292a67e181c6c0105ee35e956e78e9bdd033c6e71ae57884039a245e4175f",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0424a0bc4d16dbbd40d2fd81a7c3f8d8ec741607d5bb406a0611cc60d0e683bd" +
      "46b575cad039c15f7f3dffcfc007b4b0f743c871ecc76a504a32672fd84526d8" +
      "61",
      cases: [
        {
          id: 158,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "13d22b06d6b8f5d97e0c64962b4a3bae30f668ca6217ef5b35d799f159e23ebe",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d24dd06745cafb39186d22a92aa0e58169a79ab69488628a9da5ed3ef74726" +
      "9b7e9209d98faeb95355948adae61d5291c6015d3ee9513486d886fb05cbd25c" +
      "6a",
      cases: [
        {
          id: 159,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "4523ce342e4994bb8968bf6613f60c06c86111f15a3a389309e72cd447d5dd99",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "048200f148e7eab1581bcd1e23946f8a9b8191d9641f9560341721f9d3fec3d6" +
      "3ece795669e0481e035de8623d716a6984d0a4809d6c65519443ee55260f7f3d" +
      "cb",
      cases: [
        {
          id: 160,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "37d765be3c9c78189ad30edb5097a4db670de11686d01420e37039d4677f4809",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04a8a69c5ed33b150ce8d37ac197070ed894c05d47258a80c9041d9248662202" +
      "4de85997c9666b60a393568efede8f4ca0167c1e10f626e62fc1b8c8e9c6ba6e" +
      "d7",
      cases: [
        {
          id: 161,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "44237823b54e0c74c2bf5f759d9ac5f8cb897d537ffa92effd4f0bb6c9acd860",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04ed0587e75b3b9a1dd0794f41d1729fcd432b2436cbf51c230d8bc727327318" +
      "1735a57f09c7873d3964aa8102c9e25fa53070cd924cb7e3a459174740b8b71c" +
      "34",
      cases: [
        {
          id: 162,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "266d30a485385906054ca86d46f5f2b17e7f4646a3092092ad92877126538111",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04077091d99004a99ee08224e59a46a70495e6fba4eff681c3ce42127e588681" +
      "ef4f1c16c77dfa440dde18245c9de76243d8f2fd9dea3f2782d6c04974d02f25" +
      "dc",
      cases: [
        {
          id: 163,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "538c7b3798e84d0ce90340165806348971ed44db8f0c674f5f215968390f92ee",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04616a8b8e57d82c11678f5827911024cd23a16cb52a65f230fb554a7b110c35" +
      "a5bb466660be5cab3e4b587c12b45bd998bd56c7d66c2f94d03a1a6d2028d8a1" +
      "54",
      cases: [
        {
          id: 164,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "6fef0ef15d1688e15e704c4e6bb8bb7f40d52d3af5c661bb78c4ed9b408699b3",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0471dc92b2b1baa7612c4a53427a0d2dfe548fa9cf829bb6b248f736a5eb30b5" +
      "13f91c7dff1144cb36057c2b859f35bd666a7961833b06de0f45159fbae208e3" +
      "26",
      cases: [
        {
          id: 165,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "6f44275e9aeb1331efcb8d58f35c0252791427e403ad84daad51d247cc2a64c6",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04662f43ae614bd9c90ff3fcded25cf0ef186b6967a47aa6aa7ae7f396594df9" +
      "31f5f94a525edd50d3738f7a28d03d7a2a70095c8f89de9bb2c645fea8d8bac9" +
      "e0",
      cases: [
        {
          id: 166,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "21323755b103d2f9da6ab83eccab9ad8598bcf625652f10e7a3eeee3c3945fb3",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04dff107959bd2f7386497a5624430a0ab35e552c1a4e4dc9c298caeb9635317" +
      "0dcb5065d7947a676c76287ca8e430324f8a534b0ba6f21200e033c4b88852a3" +
      "cc",
      cases: [
        {
          id: 167,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "6c50acfe76de1289e7a5edb240f1c2a7879db6873d5d931f3c6ac467a6eac171",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04bd0862b0bfba85036922e06f5458754aafc3075b603a814b3ac75659bf24d7" +
      "528258a607ffca2cfe05a300cb4c3c4e1963bbb1bc54d320e16969f85aad2433" +
      "85",
      cases: [
        {
          id: 168,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "755b7fffb0b17ad57dca50fcefb7fe297b029df25e5ccb5069e8e70c2742c2a6",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f2" +
      "871b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe" +
      "47",
      cases: [
        {
          id: 169,
          message_hex: "313233343030",
          signature_hex: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8" +
          "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04f50d371b91bfb1d7d14e1323523bc3aa8cbf2c57f9e284de628c8b4536787b" +
      "86f94ad887ac94d527247cd2e7d0c8b1291c553c9730405380b14cbb209f5fa2" +
      "dd",
      cases: [
        {
          id: 170,
          message_hex: "313233343030",
          signature_hex: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9" +
          "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0468ec6e298eafe16539156ce57a14b04a7047c221bafc3a582eaeb0d857c4d9" +
      "4697bed1af17850117fdb39b2324f220a5698ed16c426a27335bb385ac8ca6fb" +
      "30",
      cases: [
        {
          id: 171,
          message_hex: "313233343030",
          signature_hex: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9" +
          "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0469da0364734d2e530fece94019265fefb781a0f1b08f6c8897bdf6557927c8" +
      "b866d2d3c7dcd518b23d726960f069ad71a933d86ef8abbcce8b20f71e2a8470" +
      "02",
      cases: [
        {
          id: 172,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d8adc00023a8edc02576e2b63e3e30621a471e2b2320620187bf067a1ac1ff" +
      "3233e2b50ec09807accb36131fff95ed12a09a86b4ea9690aa32861576ba2362" +
      "e1",
      cases: [
        {
          id: 173,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "043623ac973ced0a56fa6d882f03a7d5c7edca02cfc7b2401fab3690dbe75ab7" +
      "858db06908e64b28613da7257e737f39793da8e713ba0643b92e9bb3252be7f8" +
      "fe",
      cases: [
        {
          id: 174,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04cf04ea77e9622523d894b93ff52dc3027b31959503b6fa3890e5e04263f922" +
      "f1e8528fb7c006b3983c8b8400e57b4ed71740c2f3975438821199bedeaecab2" +
      "e9",
      cases: [
        {
          id: 175,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04db7a2c8a1ab573e5929dc24077b508d7e683d49227996bda3e9f78dbeff773" +
      "504f417f3bc9a88075c2e0aadd5a13311730cf7cc76a82f11a36eaf08a6c99a2" +
      "06",
      cases: [
        {
          id: 176,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "e91e1ba60fdedb76a46bcb51dc0b8b4b7e019f0a28721885fa5d3a8196623397",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04dead11c7a5b396862f21974dc4752fadeff994efe9bbd05ab413765ea80b6e" +
      "1f1de3f0640e8ac6edcf89cff53c40e265bb94078a343736df07aa0318fc7fe1" +
      "ff",
      cases: [
        {
          id: 177,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "fdea5843ffeb73af94313ba4831b53fe24f799e525b1e8e8c87b59b95b430ad9",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d0bc472e0d7c81ebaed3a6ef96c18613bb1fea6f994326fbe80e00dfde67c7" +
      "e9986c723ea4843d48389b946f64ad56c83ad70ff17ba85335667d1bb9fa619e" +
      "fd",
      cases: [
        {
          id: 178,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "03ffcabf2f1b4d2a65190db1680d62bb994e41c5251cd73b3c3dfc5e5bafc035",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04a0a44ca947d66a2acb736008b9c08d1ab2ad03776e02640f78495d458dd51c" +
      "326337fe5cf8c4604b1f1c409dc2d872d4294a4762420df43a30a2392e40426a" +
      "dd",
      cases: [
        {
          id: 179,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "4dfbc401f971cd304b33dfdb17d0fed0fe4c1a88ae648e0d2847f74977534989",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04c9c2115290d008b45fb65fad0f602389298c25420b775019d42b62c3ce8a96" +
      "b73877d25a8080dc02d987ca730f0405c2c9dbefac46f9e601cc3f06e9713973" +
      "fd",
      cases: [
        {
          id: 180,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "bc4024761cd2ffd43dfdb17d0fed112b988977055cd3a8e54971eba9cda5ca71",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "045eca1ef4c287dddc66b8bccf1b88e8a24c0018962f3c5e7efa83bc1a5ff603" +
      "3e5e79c4cb2c245b8c45abdce8a8e4da758d92a607c32cd407ecaef22f1c934a" +
      "71",
      cases: [
        {
          id: 181,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "788048ed39a5ffa77bfb62fa1fda2257742bf35d128fb3459f2a0c909ee86f91",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "045caaa030e7fdf0e4936bc7ab5a96353e0a01e4130c3f8bf22d473e317029a4" +
      "7adeb6adc462f7058f2a20d371e9702254e9b201642005b3ceda926b42b178be" +
      "f9",
      cases: [
        {
          id: 182,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "476d9131fd381bd917d0fed112bc9e0a5924b5ed5b11167edd8b23582b3cb15e",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04c2fd20bac06e555bb8ac0ce69eb1ea20f83a1fc3501c8a66469b1a31f619b0" +
      "986237050779f52b615bd7b8d76a25fc95ca2ed32525c75f27ffc87ac397e6cb" +
      "af",
      cases: [
        {
          id: 183,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "8374253e3e21bd154448d0a8f640fe46fafa8b19ce78d538f6cc0a19662d3601",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "043fd6a1ca7f77fb3b0bbe726c372010068426e11ea6ae78ce17bedae4bba86c" +
      "ed03ce5516406bf8cfaab8745eac1cd69018ad6f50b5461872ddfc56e0db3c8f" +
      "f4",
      cases: [
        {
          id: 184,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "357cfd3be4d01d413c5b9ede36cba5452c11ee7fe14879e749ae6a2d897a52d6",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "049cb8e51e27a5ae3b624a60d6dc32734e4989db20e9bca3ede1edf7b0869111" +
      "14b4c104ab3c677e4b36d6556e8ad5f523410a19f2e277aa895fc57322b44275" +
      "44",
      cases: [
        {
          id: 185,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "29798c5c0ee287d4a5e8e6b799fd86b8df5225298e6ffc807cd2f2bc27a0a6d8",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04a3e52c156dcaf10502620b7955bc2b40bc78ef3d569e1223c262512d8f4960" +
      "2a4a2039f31c1097024ad3cc86e57321de032355463486164cf192944977df14" +
      "7f",
      cases: [
        {
          id: 186,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "0b70f22c781092452dca1a5711fa3a5a1f72add1bf52c2ff7cae4820b30078dd",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04f19b78928720d5bee8e670fb90010fb15c37bf91b58a5157c3f3c059b2655e" +
      "88cf701ec962fb4a11dcf273f5dc357e58468560c7cfeb942d074abd43292605" +
      "09",
      cases: [
        {
          id: 187,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "16e1e458f021248a5b9434ae23f474b43ee55ba37ea585fef95c90416600f1ba",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0483a744459ecdfb01a5cf52b27a05bb7337482d242f235d7b4cb89345545c90" +
      "a8c05d49337b9649813287de9ffe90355fd905df5f3c32945828121f37cc50de" +
      "6e",
      cases: [
        {
          id: 188,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "2252d6856831b6cf895e4f0535eeaf0e5e5809753df848fe760ad86219016a97",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04dd13c6b34c56982ddae124f039dfd23f4b19bbe88cee8e528ae51e5d6f3a21" +
      "d7bfad4c2e6f263fe5eb59ca974d039fc0e4c3345692fb5320bdae4bd3b42a45" +
      "ff",
      cases: [
        {
          id: 189,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "81ffe55f178da695b28c86d8b406b15dab1a9e39661a3ae017fbe390ac0972c3",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0467e6f659cdde869a2f65f094e94e5b4dfad636bbf95192feeed01b0f3deb74" +
      "60a37e0a51f258b7aeb51dfe592f5cfd5685bbe58712c8d9233c62886437c38b" +
      "a0",
      cases: [
        {
          id: 190,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "042eb6412505aec05c6545f029932087e490d05511e8ec1f599617bb367f9eca" +
      "af805f51efcc4803403f9b1ae0124890f06a43fedcddb31830f6669af292895c" +
      "b0",
      cases: [
        {
          id: 191,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "b62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0484db645868eab35e3a9fd80e056e2e855435e3a6b68d75a50a854625fe0d7f" +
      "356d2589ac655edc9a11ef3e075eddda9abf92e72171570ef7bf43a2ee39338c" +
      "fe",
      cases: [
        {
          id: 192,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "bb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0491b9e47c56278662d75c0983b22ca8ea6aa5059b7a2ff7637eb2975e386ad6" +
      "6349aa8ff283d0f77c18d6d11dc062165fd13c3c0310679c1408302a16854ecf" +
      "bd",
      cases: [
        {
          id: 193,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04f3ec2f13caf04d0192b47fb4c5311fb6d4dc6b0a9e802e5327f7ec5ee8e483" +
      "4df97e3e468b7d0db867d6ecfe81e2b0f9531df87efdb47c1338ac321fefe5a4" +
      "32",
      cases: [
        {
          id: 194,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d92b200aefcab6ac7dafd9acaf2fa10b3180235b8f46b4503e4693c670fccc" +
      "885ef2f3aebf5b317475336256768f7c19efb7352d27e4cccadc85b6b8ab922c" +
      "72",
      cases: [
        {
          id: 195,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "ab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "040a88361eb92ecca2625b38e5f98bbabb96bf179b3d76fc48140a3bcd881523" +
      "cde6bdf56033f84a5054035597375d90866aa2c96b86a41ccf6edebf47298ad4" +
      "89",
      cases: [
        {
          id: 196,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "ca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d0fb17ccd8fafe827e0c1afc5d8d80366e2b20e7f14a563a2ba50469d84375" +
      "e868612569d39e2bb9f554355564646de99ac602cc6349cf8c1e236a7de7637d" +
      "93",
      cases: [
        {
          id: 197,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "bfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04836f33bbc1dc0d3d3abbcef0d91f11e2ac4181076c9af0a22b1e4309d3edb2" +
      "769ab443ff6f901e30c773867582997c2bec2b0cb8120d760236f3a95bbe881f" +
      "75",
      cases: [
        {
          id: 198,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0492f99fbe973ed4a299719baee4b432741237034dec8d72ba5103cb33e55fee" +
      "b8033dd0e91134c734174889f3ebcf1b7a1ac05767289280ee7a794cebd6e696" +
      "97",
      cases: [
        {
          id: 199,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "bfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04d35ba58da30197d378e618ec0fa7e2e2d12cffd73ebbb2049d130bba434af0" +
      "9eff83986e6875e41ea432b7585a49b3a6c77cbb3c47919f8e82874c794635c1" +
      "d2",
      cases: [
        {
          id: 200,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "bfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "048651ce490f1b46d73f3ff475149be29136697334a519d7ddab0725c8d07932" +
      "24e11c65bd8ca92dc8bc9ae82911f0b52751ce21dd9003ae60900bd825f590cc" +
      "28",
      cases: [
        {
          id: 201,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "046d8e1b12c831a0da8795650ff95f101ed921d9e2f72b15b1cdaca9826b9cfc" +
      "6def6d63e2bc5c089570394a4bc9f892d5e6c7a6a637b20469a58c106ad486bf" +
      "37",
      cases: [
        {
          id: 202,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "040ae580bae933b4ef2997cbdbb0922328ca9a410f627a0f7dff24cb4d920e15" +
      "428911e7f8cc365a8a88eb81421a361ccc2b99e309d8dcd9a98ba83c3949d893" +
      "e3",
      cases: [
        {
          id: 203,
          message_hex: "313233343030",
          signature_hex: "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd" +
          "5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc469" +
      "63838a40f2a36092e9004e92d8d940cf5638550ce672ce8b8d4e15eba5499249" +
      "e9",
      cases: [
        {
          id: 204,
          message_hex: "313233343030",
          signature_hex: "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569" +
          "bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc469" +
      "637c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db6" +
      "16",
      cases: [
        {
          id: 205,
          message_hex: "313233343030",
          signature_hex: "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569" +
          "bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "046adda82b90261b0f319faa0d878665a6b6da497f09c903176222c34acfef72" +
      "a647e6f50dcc40ad5d9b59f7602bb222fad71a41bf5e1f9df4959a364c62e488" +
      "d9",
      cases: [
        {
          id: 206,
          message_hex: "313233343030",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000001" +
          "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "042fca0d0a47914de77ed56e7eccc3276a601120c6df0069c825c8f6a01c9f38" +
      "2065f3450a1d17c6b24989a39beb1c7decfca8384fbdc294418e5d807b3c6ed7" +
      "de",
      cases: [
        {
          id: 207,
          message_hex: "313233343030",
          signature_hex: "0100000000000000000000000000000000000000000000000000000000000000" +
          "00003333333300000000333333333333333325c7cbbc549e52e763f1f55a327a" +
          "3aa9",
          expected: Err(
            @webauthn.InvalidSignatureLength(expected=64, actual=66),
          ),
        },
      ],
    },
    {
      public_point_hex: "04dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d2" +
      "5045d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18" +
      "f7",
      cases: [
        {
          id: 208,
          message_hex: "313233343030",
          signature_hex: "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70" +
          "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "044fea55b32cb32aca0c12c4cd0abfb4e64b0f5a516e578c016591a93f5a0fbc" +
      "c5d7d3fd10b2be668c547b212f6bb14c88f0fecd38a8a4b2c785ed3be62ce4b2" +
      "80",
      cases: [
        {
          id: 209,
          message_hex: "313233343030",
          signature_hex: "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" +
          "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04c6a771527024227792170a6f8eee735bf32b7f98af669ead299802e32d7c31" +
      "07bc3b4b5e65ab887bbd343572b3e5619261fe3a073e2ffd78412f726867db58" +
      "9e",
      cases: [
        {
          id: 210,
          message_hex: "313233343030",
          signature_hex: "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" +
          "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04851c2bbad08e54ec7a9af99f49f03644d6ec6d59b207fec98de85a7d15b956" +
      "efcee9960283045075684b410be8d0f7494b91aa2379f60727319f10ddeb0fe9" +
      "d6",
      cases: [
        {
          id: 211,
          message_hex: "313233343030",
          signature_hex: "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" +
          "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04f6417c8a670584e388676949e53da7fc55911ff68318d1bf3061205acb19c4" +
      "8f8f2b743df34ad0f72674acb7505929784779cd9ac916c3669ead43026ab6d4" +
      "3f",
      cases: [
        {
          id: 212,
          message_hex: "313233343030",
          signature_hex: "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" +
          "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04501421277be45a5eefec6c639930d636032565af420cf3373f557faa7f8a06" +
      "438673d6cb6076e1cfcdc7dfe7384c8e5cac08d74501f2ae6e89cad195d0aa13" +
      "71",
      cases: [
        {
          id: 213,
          message_hex: "313233343030",
          signature_hex: "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" +
          "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "040d935bf9ffc115a527735f729ca8a4ca23ee01a4894adf0e3415ac84e808bb" +
      "343195a3762fea29ed38912bd9ea6c4fde70c3050893a4375850ce61d82eba33" +
      "c5",
      cases: [
        {
          id: 214,
          message_hex: "313233343030",
          signature_hex: "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" +
          "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "045e59f50708646be8a589355014308e60b668fb670196206c41e748e64e4dca" +
      "215de37fee5c97bcaf7144d5b459982f52eeeafbdf03aacbafef38e213624a01" +
      "de",
      cases: [
        {
          id: 215,
          message_hex: "313233343030",
          signature_hex: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
          "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04169fb797325843faff2f7a5b5445da9e2fd6226f7ef90ef0bfe924104b02db" +
      "8e7bbb8de662c7b9b1cf9b22f7a2e582bd46d581d68878efb2b861b131d8a1d6" +
      "67",
      cases: [
        {
          id: 216,
          message_hex: "313233343030",
          signature_hex: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
          "b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04271cd89c000143096b62d4e9e4ca885aef2f7023d18affdaf8b7b548981487" +
      "540a1c6e954e32108435b55fa385b0f76481a609b9149ccb4b02b2ca47fe8e4d" +
      "a5",
      cases: [
        {
          id: 217,
          message_hex: "313233343030",
          signature_hex: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
          "cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "043d0bc7ed8f09d2cb7ddb46ebc1ed799ab1563a9ab84bf524587a220afe499c" +
      "12e22dc3b3c103824a4f378d96adb0a408abf19ce7d68aa6244f78cb216fa3f8" +
      "df",
      cases: [
        {
          id: 218,
          message_hex: "313233343030",
          signature_hex: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
          "3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04a6c885ade1a4c566f9bb010d066974abb281797fa701288c721bcbd23663a9" +
      "b72e424b690957168d193a6096fc77a2b004a9c7d467e007e1f2058458f98af3" +
      "16",
      cases: [
        {
          id: 219,
          message_hex: "313233343030",
          signature_hex: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
          "49249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "048d3c2c2c3b765ba8289e6ac3812572a25bf75df62d87ab7330c3bdbad9ebfa" +
      "5c4c6845442d66935b238578d43aec54f7caa1621d1af241d4632e0b780c423f" +
      "5d",
      cases: [
        {
          id: 220,
          message_hex: "313233343030",
          signature_hex: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
          "16a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2" +
      "964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51" +
      "f5",
      cases: [
        {
          id: 221,
          message_hex: "313233343030",
          signature_hex: "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023" +
          "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
          expected: Ok(false),
        },
        {
          id: 222,
          message_hex: "313233343030",
          signature_hex: "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e" +
          "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2" +
      "96b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae" +
      "0a",
      cases: [
        {
          id: 223,
          message_hex: "313233343030",
          signature_hex: "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023" +
          "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
          expected: Ok(false),
        },
        {
          id: 224,
          message_hex: "313233343030",
          signature_hex: "44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e" +
          "249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fa" +
      "d587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d52" +
      "5d",
      cases: [
        {
          id: 225,
          message_hex: "",
          signature_hex: "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a" +
          "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
          expected: Ok(true),
        },
        {
          id: 226,
          message_hex: "4d7367",
          signature_hex: "530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23" +
          "d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9",
          expected: Ok(true),
        },
        {
          id: 227,
          message_hex: "313233343030",
          signature_hex: "a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388" +
          "f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
          expected: Ok(true),
        },
        {
          id: 228,
          message_hex: "0000000000000000000000000000000000000000",
          signature_hex: "986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb71" +
          "3dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd8169000000" +
      "00ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d6" +
      "85",
      cases: [
        {
          id: 229,
          message_hex: "4d657373616765",
          signature_hex: "d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f1" +
          "9b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
          expected: Ok(true),
        },
        {
          id: 230,
          message_hex: "4d657373616765",
          signature_hex: "0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b" +
          "500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
          expected: Ok(true),
        },
        {
          id: 231,
          message_hex: "4d657373616765",
          signature_hex: "bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3" +
          "541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049" +
      "3584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde800000" +
      "00",
      cases: [
        {
          id: 232,
          message_hex: "4d657373616765",
          signature_hex: "664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a" +
          "59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
          expected: Ok(true),
        },
        {
          id: 233,
          message_hex: "4d657373616765",
          signature_hex: "4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b43" +
          "9638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
          expected: Ok(true),
        },
        {
          id: 234,
          message_hex: "4d657373616765",
          signature_hex: "e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04" +
          "a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049" +
      "357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffff" +
      "ff",
      cases: [
        {
          id: 235,
          message_hex: "4d657373616765",
          signature_hex: "1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830" +
          "228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
          expected: Ok(true),
        },
        {
          id: 236,
          message_hex: "4d657373616765",
          signature_hex: "b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d" +
          "3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
          expected: Ok(true),
        },
        {
          id: 237,
          message_hex: "4d657373616765",
          signature_hex: "b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86" +
          "ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffff" +
      "ffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb922" +
      "2e",
      cases: [
        {
          id: 238,
          message_hex: "4d657373616765",
          signature_hex: "d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b4" +
          "3dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
          expected: Ok(true),
        },
        {
          id: 239,
          message_hex: "4d657373616765",
          signature_hex: "5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af78" +
          "2c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
          expected: Ok(true),
        },
        {
          id: 240,
          message_hex: "4d657373616765",
          signature_hex: "96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28" +
          "f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4" +
      "f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd" +
      "73",
      cases: [
        {
          id: 241,
          message_hex: "4d657373616765",
          signature_hex: "766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6" +
          "402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
          expected: Ok(true),
        },
        {
          id: 242,
          message_hex: "4d657373616765",
          signature_hex: "c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9" +
          "edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
          expected: Ok(true),
        },
        {
          id: 243,
          message_hex: "4d657373616765",
          signature_hex: "d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84" +
          "feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba74" +
      "8e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e" +
      "71",
      cases: [
        {
          id: 244,
          message_hex: "4d657373616765",
          signature_hex: "b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7" +
          "b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
          expected: Ok(true),
        },
        {
          id: 245,
          message_hex: "4d657373616765",
          signature_hex: "6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f7" +
          "5939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
          expected: Ok(true),
        },
        {
          id: 246,
          message_hex: "4d657373616765",
          signature_hex: "efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361" +
          "f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af0" +
      "15000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193b" +
      "c2",
      cases: [
        {
          id: 247,
          message_hex: "4d657373616765",
          signature_hex: "31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb07" +
          "0f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
          expected: Ok(true),
        },
        {
          id: 248,
          message_hex: "4d657373616765",
          signature_hex: "caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743" +
          "cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
          expected: Ok(true),
        },
        {
          id: 249,
          message_hex: "4d657373616765",
          signature_hex: "7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed800185945" +
          "9450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af0" +
      "15fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c4" +
      "3d",
      cases: [
        {
          id: 250,
          message_hex: "4d657373616765",
          signature_hex: "d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b356" +
          "89c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
          expected: Ok(true),
        },
        {
          id: 251,
          message_hex: "4d657373616765",
          signature_hex: "341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b34" +
          "72b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
          expected: Ok(true),
        },
        {
          id: 252,
          message_hex: "4d657373616765",
          signature_hex: "70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67" +
          "aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04264d796a0dab9b376d34eea6fe297dde1c7b73e53944bc96c8f1e8a6850bb6" +
      "c9cf5308020eed460c649ddae61d4ef8bb79958113f106befaf4f18876d12a5e" +
      "64",
      cases: [
        {
          id: 253,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000005" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04add76677e54a92e79bbee36a70e1754838273ec4b39295e4018a587290a7fc" +
      "73f240d625642c943e610d80d953c5c6b8a12760a624ba3b90a0b7902755e1ae" +
      "79",
      cases: [
        {
          id: 254,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000006" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04264d796a0dab9b376d34eea6fe297dde1c7b73e53944bc96c8f1e8a6850bb6" +
      "c9cf5308020eed460c649ddae61d4ef8bb79958113f106befaf4f18876d12a5e" +
      "64",
      cases: [
        {
          id: 255,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Err(@webauthn.InvalidSignatureScalar(component="R")),
        },
      ],
    },
    {
      public_point_hex: "04e7e49dd82812432744fefe723f7f69663214ad1b85c02b2650b4ca0354743a" +
      "325223c51c415f457aec69cb019bbe3d27585b38f8b79c39dfea6c27c2f0d814" +
      "6a",
      cases: [
        {
          id: 256,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04ce24c99032d52ac6ead23c0ae3ec68ef41e51a281fd457808c83136d7dcce9" +
      "0e8f7a154b551e9f39c59279357aa491b2a62bdebc2bb78613883fc72936c057" +
      "e0",
      cases: [
        {
          id: 257,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000003" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04c981c75ddfd3910387eb147098fe5658c43aaaa34c681cd6d514b6ad5b6baa" +
      "6d14fbddb53a6e6db18e90602bc60f2e736d625765f7f2cca4be76f4eeccf12c" +
      "18",
      cases: [
        {
          id: 258,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "0000000000000000000000000000000000000000000000000000000000000004" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "040ec505bc19b14a43e05678cccf07a443d3e871a2e19b68a4da91859a0650f3" +
      "2477300e4f64e9982d94dff5d294428bb37cc9be66117cae9c389d2d495f68b9" +
      "87",
      cases: [
        {
          id: 259,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "000000000000000000000000000000004319055358e8617b0c46353d039cdab3" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04d42ce21e730f3d2a84e949828574b4dceeb77d4f89556735f34fba03028ee3" +
      "ed32daf8bfd3f0a7a0821170840f4e032056722386b35d9bdd4f4f450696f4fb" +
      "52",
      cases: [
        {
          id: 260,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdab4" +
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "046955a72c0dad4ed60356f7692649b951fa8ea474bf1cc9549b96c68de4782d" +
      "fae012ffc24e92c72be71ff2622ee7e549dcb59e7b708f6921c4d4ea29512e2a" +
      "ba",
      cases: [
        {
          id: 261,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "5f6d3aa0d327c13702513d4299f297ab182fcf670f96291fab19572e7a6e01c4" +
          "0000000000000000000000000000000100000000000000000000000000000000",
          expected: Ok(true),
        },
        {
          id: 262,
          message_hex: "68656c6c6f2c20776f726c64",
          signature_hex: "5f6d3aa0d327c13702513d4299f297ab182fcf670f96291fab19572e7a6e01c4" +
          "ffffffff00000000fffffffffffffffebce6faada7179e84f3b9cac2fc632551",
          expected: Ok(true),
        },
      ],
    },
  ]
}

///|
test "Wycheproof pinned complete P256 SHA256 raw suite 262 cases" {
  let groups = crypto_wycheproof_groups()
  assert_eq(groups.length(), 112)
  crypto_check_signature_groups("Wycheproof tcId", groups, 262, 173)
}

///|
// Complete P-256/SHA-256 group from the NIST CAVS 11.0 SigVer response file.
// R and S are unsigned 32-byte integers concatenated into RFC 9053 raw64.
fn crypto_nist_signature_groups() -> Array[CryptoSignatureGroup] {
  [
    {
      public_point_hex: "0487f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad415" +
      "55e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205" +
      "e9",
      cases: [
        // Published result F (3 - S changed)
        {
          id: 1,
          message_hex: "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d" +
          "9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19" +
          "fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c" +
          "24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
          signature_hex: "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0" +
          "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "045cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7" +
      "d2ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a" +
      "85",
      cases: [
        // Published result F (2 - R changed)
        {
          id: 2,
          message_hex: "069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d6" +
          "83877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae187300" +
          "4565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b" +
          "3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e",
          signature_hex: "dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693" +
          "d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "042ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244" +
      "cb5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a" +
      "64",
      cases: [
        // Published result F (4 - Q changed)
        {
          id: 3,
          message_hex: "df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d" +
          "8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af7149598" +
          "96858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd861" +
          "28cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de",
          signature_hex: "9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8" +
          "9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf" +
      "3c970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee9" +
      "27",
      cases: [
        // Published result P (0 )
        {
          id: 4,
          message_hex: "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45f" +
          "d75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217" +
          "ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce4" +
          "70a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
          signature_hex: "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f" +
          "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d28" +
      "647f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f2" +
      "2a",
      cases: [
        // Published result P (0 )
        {
          id: 5,
          message_hex: "73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730f" +
          "b68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f226" +
          "63bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a" +
          "6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08",
          signature_hex: "1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407" +
          "cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a",
          expected: Ok(true),
        },
      ],
    },
    {
      public_point_hex: "04a849bef575cac3c6920fbce675c3b787136209f855de19ffe2e8d29b31a5ad" +
      "86bf5fe4f7858f9b805bd8dcc05ad5e7fb889de2f822f3d8b41694e6c55c16b4" +
      "71",
      cases: [
        // Published result F (2 - R changed)
        {
          id: 6,
          message_hex: "666036d9b4a2426ed6585a4e0fd931a8761451d29ab04bd7dc6d0c5b9e38e6c2" +
          "b263ff6cb837bd04399de3d757c6c7005f6d7a987063cf6d7e8cb38a4bf0d74a" +
          "282572bd01d0f41e3fd066e3021575f0fa04f27b700d5b7ddddf50965993c3f9" +
          "c7118ed78888da7cb221849b3260592b8e632d7c51e935a0ceae15207bedd548",
          signature_hex: "25acc3aa9d9e84c7abf08f73fa4195acc506491d6fc37cb9074528a7db87b9d6" +
          "9b21d5b5259ed3f2ef07dfec6cc90d3a37855d1ce122a85ba6a333f307d31537",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "043dfb6f40f2471b29b77fdccba72d37c21bba019efa40c1c8f91ec405d7dcc5" +
      "dff22f953f1e395a52ead7f3ae3fc47451b438117b1e04d613bc8555b7d6e6d1" +
      "bb",
      cases: [
        // Published result F (4 - Q changed)
        {
          id: 7,
          message_hex: "7e80436bce57339ce8da1b5660149a20240b146d108deef3ec5da4ae256f8f89" +
          "4edcbbc57b34ce37089c0daa17f0c46cd82b5a1599314fd79d2fd2f446bd5a25" +
          "b8e32fcf05b76d644573a6df4ad1dfea707b479d97237a346f1ec632ea5660ef" +
          "b57e8717a8628d7f82af50a4e84b11f21bdff6839196a880ae20b2a0918d58cd",
          signature_hex: "548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5a" +
          "e93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "0469b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd02" +
      "14d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa" +
      "2f",
      cases: [
        // Published result F (1 - Message changed)
        {
          id: 8,
          message_hex: "1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce1" +
          "3e3a649700820f0061efabf849a85d474326c8a541d99830eea8131eaea584f2" +
          "2d88c353965dabcdc4bf6b55949fd529507dfb803ab6b480cd73ca0ba00ca19c" +
          "438849e2cea262a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169",
          signature_hex: "288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790" +
          "247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04bf02cbcf6d8cc26e91766d8af0b164fc5968535e84c158eb3bc4e2d79c3cc6" +
      "82069ba6cb06b49d60812066afa16ecf7b51352f2c03bd93ec220822b1f3dfba" +
      "03",
      cases: [
        // Published result F (3 - S changed)
        {
          id: 9,
          message_hex: "3fe60dd9ad6caccf5a6f583b3ae65953563446c4510b70da115ffaa0ba04c076" +
          "115c7043ab8733403cd69c7d14c212c655c07b43a7c71b9a4cffe22c2684788e" +
          "c6870dc2013f269172c822256f9e7cc674791bf2d8486c0f5684283e1649576e" +
          "fc982ede17c7b74b214754d70402fb4bb45ad086cf2cf76b3d63f7fce39ac970",
          signature_hex: "f5acb06c59c2b4927fb852faa07faf4b1852bbb5d06840935e849c4d293d1bad" +
          "049dab79c89cc02f1484c437f523e080a75f134917fda752f2d5ca397addfe5d",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04224a4d65b958f6d6afb2904863efd2a734b31798884801fcab5a590f4d6da9" +
      "de178d51fddada62806f097aa615d33b8f2404e6b1479f5fd4859d595734d6d2" +
      "b9",
      cases: [
        // Published result F (2 - R changed)
        {
          id: 10,
          message_hex: "983a71b9994d95e876d84d28946a041f8f0a3f544cfcc055496580f1dfd4e312" +
          "a2ad418fe69dbc61db230cc0c0ed97e360abab7d6ff4b81ee970a7e97466acfd" +
          "9644f828ffec538abc383d0e92326d1c88c55e1f46a668a039beaa1be631a891" +
          "29938c00a81a3ae46d4aecbf9707f764dbaccea3ef7665e4c4307fa0b0a3075c",
          signature_hex: "87b93ee2fecfda54deb8dff8e426f3c72c8864991f8ec2b3205bb3b416de93d2" +
          "4044a24df85be0cc76f21a4430b75b8e77b932a87f51e4eccbc45c263ebf8f66",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "0443691c7795a57ead8c5c68536fe934538d46f12889680a9cb6d055a0662283" +
      "69f8790110b3c3b281aa1eae037d4f1234aff587d903d93ba3af225c27ddc9cc" +
      "ac",
      cases: [
        // Published result F (3 - S changed)
        {
          id: 11,
          message_hex: "4a8c071ac4fd0d52faa407b0fe5dab759f7394a5832127f2a3498f34aac28733" +
          "9e043b4ffa79528faf199dc917f7b066ad65505dab0e11e6948515052ce20cfd" +
          "b892ffb8aa9bf3f1aa5be30a5bbe85823bddf70b39fd7ebd4a93a2f75472c1d4" +
          "f606247a9821f1a8c45a6cb80545de2e0c6c0174e2392088c754e9c8443eb5af",
          signature_hex: "8acd62e8c262fa50dd9840480969f4ef70f218ebf8ef9584f199031132c6b1ce" +
          "cfca7ed3d4347fb2a29e526b43c348ae1ce6c60d44f3191b6d8ea3a2d9c92154",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "049157dbfcf8cf385f5bb1568ad5c6e2a8652ba6dfc63bc1753edf5268cb7eb5" +
      "96972570f4313d47fc96f7c02d5594d77d46f91e949808825b3d31f029e82964" +
      "05",
      cases: [
        // Published result F (1 - Message changed)
        {
          id: 12,
          message_hex: "0a3a12c3084c865daf1d302c78215d39bfe0b8bf28272b3c0b74beb4b7409db0" +
          "718239de700785581514321c6440a4bbaea4c76fa47401e151e68cb6c29017f0" +
          "bce4631290af5ea5e2bf3ed742ae110b04ade83a5dbd7358f29a85938e23d87a" +
          "c8233072b79c94670ff0959f9c7f4517862ff829452096c78f5f2e9a7e4e9216",
          signature_hex: "dfaea6f297fa320b707866125c2a7d5d515b51a503bee817de9faa343cc48eeb" +
          "8f780ad713f9c3e5a4f7fa4c519833dfefc6a7432389b1e4af463961f09764f2",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "04072b10c081a4c1713a294f248aef850e297991aca47fa96a7470abe3b8acfd" +
      "da9581145cca04a0fb94cedce752c8f0370861916d2a94e7c647c5373ce6a4c8" +
      "f5",
      cases: [
        // Published result F (4 - Q changed)
        {
          id: 13,
          message_hex: "785d07a3c54f63dca11f5d1a5f496ee2c2f9288e55007e666c78b007d95cc285" +
          "81dce51f490b30fa73dc9e2d45d075d7e3a95fb8a9e1465ad191904124160b7c" +
          "60fa720ef4ef1c5d2998f40570ae2a870ef3e894c2bc617d8a1dc85c3c557749" +
          "28c38789b4e661349d3f84d2441a3b856a76949b9f1f80bc161648a1cad5588e",
          signature_hex: "09f5483eccec80f9d104815a1be9cc1a8e5b12b6eb482a65c6907b7480cf4f19" +
          "a4f90e560c5e4eb8696cb276e5165b6a9d486345dedfb094a76e8442d026378d",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "0409308ea5bfad6e5adf408634b3d5ce9240d35442f7fe116452aaec0d25be8c" +
      "24f40c93e023ef494b1c3079b2d10ef67f3170740495ce2cc57f8ee4b0618b8e" +
      "e5",
      cases: [
        // Published result F (1 - Message changed)
        {
          id: 14,
          message_hex: "76f987ec5448dd72219bd30bf6b66b0775c80b394851a43ff1f537f140a6e722" +
          "9ef8cd72ad58b1d2d20298539d6347dd5598812bc65323aceaf05228f738b5ad" +
          "3e8d9fe4100fd767c2f098c77cb99c2992843ba3eed91d32444f3b6db6cd212d" +
          "d4e5609548f4bb62812a920f6e2bf1581be1ebeebdd06ec4e971862cc42055ca",
          signature_hex: "5cc8aa7c35743ec0c23dde88dabd5e4fcd0192d2116f6926fef788cddb754e73" +
          "9c9c045ebaa1b828c32f82ace0d18daebf5e156eb7cbfdc1eff4399a8a900ae7",
          expected: Ok(false),
        },
      ],
    },
    {
      public_point_hex: "042d98ea01f754d34bbc3003df5050200abf445ec728556d7ed7d5c54c55552b" +
      "6d9b52672742d637a32add056dfd6d8792f2a33c2e69dafabea09b960bc61e23" +
      "0a",
      cases: [
        // Published result P (0 )
        {
          id: 15,
          message_hex: "60cd64b2cd2be6c33859b94875120361a24085f3765cb8b2bf11e026fa9d8855" +
          "dbe435acf7882e84f3c7857f96e2baab4d9afe4588e4a82e17a78827bfdb5ddb" +
          "d1c211fbc2e6d884cddd7cb9d90d5bf4a7311b83f352508033812c776a0e00c0" +
          "03c7e0d628e50736c7512df0acfa9f2320bd102229f46495ae6d0857cc452a84",
          signature_hex: "06108e525f845d0155bf60193222b3219c98e3d49424c2fb2a0987f825c17959" +
          "62b5cdd591e5b507e560167ba8f6f7cda74673eb315680cb89ccbc4eec477dce",
          expected: Ok(true),
        },
      ],
    },
  ]
}

///|
test "NIST CAVS P256 SHA256 SigVer complete selected group 15 cases" {
  crypto_check_signature_groups(
    "NIST SigVer",
    crypto_nist_signature_groups(),
    15,
    3,
  )
}

///|
struct CryptoPublicKeyCase {
  id : Int32
  x_hex : String
  y_hex : String
  classification : String
}

///|
// NIST PKV fields are unsigned integers, including four 257-bit failures.
// An odd hex nibble count is encoded with one leading zero nibble. This
// preserves the published integer, and never truncates an invalid coordinate.
fn crypto_nist_public_keys() -> Array[CryptoPublicKeyCase] {
  [
    {
      id: 1,
      x_hex: "e0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b7",
      y_hex: "86d7e9255d0f4b6f44fa2cd6f8ba3c0aa828321d6d8cc430ca6284ce1d5b43a0",
      classification: "valid",
    },
    {
      id: 2,
      x_hex: "d17c446237d9df87266ba3a91ff27f45abfdcb77bfd83536e92903efb861a9a9",
      y_hex: "01eabb6a349ce2cd447d777b6739c5fc066add2002d2029052c408d070106623" +
      "1c",
      classification: "range",
    },
    {
      id: 3,
      x_hex: "017875397ae87369365656d490e8ce956911bd97607f2aff41b56f6f3a619898" +
      "26",
      y_hex: "980a3c4f61b9692633fbba5ef04c9cb546dd05cdec9fa8428b8849670e2fba92",
      classification: "range",
    },
    {
      id: 4,
      x_hex: "f2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc12273",
      y_hex: "32bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd",
      classification: "off_curve",
    },
    {
      id: 5,
      x_hex: "010b0ca230fff7c04768f4b3d5c75fa9f6c539bea644dffbec5dc796a213061b" +
      "58",
      y_hex: "f5edf37c11052b75f771b7f9fa050e353e464221fec916684ed45b6fead38205",
      classification: "range",
    },
    {
      id: 6,
      x_hex: "2c1052f25360a15062d204a056274e93cbe8fc4c4e9b9561134ad5c15ce525da",
      y_hex: "ced9783713a8a2a09eff366987639c625753295d9a85d0f5325e32dedbcada0b",
      classification: "valid",
    },
    {
      id: 7,
      x_hex: "a40d077a87dae157d93dcccf3fe3aca9c6479a75aa2669509d2ef05c7de6782f",
      y_hex: "503d86b87d743ba20804fd7e7884aa017414a7b5b5963e0d46e3a9611419ddf3",
      classification: "off_curve",
    },
    {
      id: 8,
      x_hex: "2633d398a3807b1895548adbb0ea2495ef4b930f91054891030817df87d4ac0a",
      y_hex: "d6b2f738e3873cc8364a2d364038ce7d0798bb092e3dd77cbdae7c263ba618d2",
      classification: "valid",
    },
    {
      id: 9,
      x_hex: "014bf57f76c260b51ec6bbc72dbd49f02a56eaed070b774dc4bad75a54653c3d" +
      "56",
      y_hex: "7a231a23bf8b3aa31d9600d888a0678677a30e573decd3dc56b33f365cc11236",
      classification: "range",
    },
    {
      id: 10,
      x_hex: "2fa74931ae816b426f484180e517f5050c92decfc8daf756cd91f54d51b302f1",
      y_hex: "5b994346137988c58c14ae2152ac2f6ad96d97decb33099bd8a0210114cd1141",
      classification: "valid",
    },
    {
      id: 11,
      x_hex: "f8c6dd3181a76aa0e36c2790bba47041acbe7b1e473ff71eee39a824dc595ff0",
      y_hex: "9c965f227f281b3072b95b8daf29e88b35284f3574462e268e529bbdc50e9e52",
      classification: "off_curve",
    },
    {
      id: 12,
      x_hex: "7a81a7e0b015252928d8b36e4ca37e92fdc328eb25c774b4f872693028c4be38",
      y_hex: "08862f7335147261e7b1c3d055f9a316e4cab7daf99cc09d1c647f5dd6e7d5bb",
      classification: "off_curve",
    },
  ]
}

///|
test "NIST CAVS P256 PKV complete selected group 12 cases" {
  let cases = crypto_nist_public_keys()
  assert_eq(cases.length(), 12)
  let mut valid = 0
  let mut range_failures = 0
  let mut off_curve_failures = 0
  for vector in cases {
    let x = w3c_hex(vector.x_hex, vector.x_hex.length() / 2)
    let y = w3c_hex(vector.y_hex, vector.y_hex.length() / 2)
    let cose = b"\xa5\x01\x02\x03\x26\x20\x01\x21" +
      cose_bstr(x) +
      b"\x22" +
      cose_bstr(y)
    match @webauthn.validate_es256_credential_public_key(cose) {
      Err(error) => {
        assert_eq(vector.classification, "range")
        assert_eq(
          error.kind,
          @webauthn.InvalidCoordinateLength(expected=32, actual=33),
        )
        range_failures = range_failures + 1
      }
      Ok(parameters) =>
        match @webauthn.import_es256_public_key(parameters) {
          Ok(key) => {
            assert_eq(vector.classification, "valid")
            assert_eq(key.parameters().x, x[:])
            assert_eq(key.parameters().y, y[:])
            valid = valid + 1
          }
          Err(error) => {
            if vector.classification != "off_curve" {
              fail("NIST PKV case \{vector.id}: unexpected \{error.to_repr()}")
            }
            assert_eq(error, @webauthn.InvalidPublicKey)
            off_curve_failures = off_curve_failures + 1
          }
        }
    }
  }
  assert_eq(valid, 4)
  assert_eq(range_failures, 4)
  assert_eq(off_curve_failures, 4)
}

///|
fn crypto_assert_sha256(message : Bytes, expected_hex : String) -> Unit raise {
  let original = message[:].to_owned()
  let expected = w3c_hex(expected_hex, 32)
  let digest = @webauthn.sha256(message)
  assert_eq(digest.length(), 32)
  assert_eq(digest, expected)
  assert_eq(message, original)
  let wrapped = b"prefix" + message + b"suffix"
  assert_eq(@webauthn.sha256(wrapped[6:6 + message.length()]), expected)
}

///|
test "SHA256 independent SHA256LongMsg.rsp bits=1304" {
  let message = w3c_hex(
    "451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae08" +
    "6b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b8" +
    "5c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56" +
    "c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac" +
    "4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480" +
    "858bec",
    163,
  )
  crypto_assert_sha256(
    message, "3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=0" {
  let message = w3c_hex("", 0)
  crypto_assert_sha256(
    message, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=8" {
  let message = w3c_hex("d3", 1)
  crypto_assert_sha256(
    message, "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=24" {
  let message = w3c_hex("b4190e", 3)
  crypto_assert_sha256(
    message, "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=440" {
  let message = w3c_hex(
    "3ebfb06db8c38d5ba037f1363e118550aad94606e26835a01af05078533cc25f" +
    "2f39573c04b632f62f68c294ab31f2a3e2a1a0d8c2be51",
    55,
  )
  crypto_assert_sha256(
    message, "6595a2ef537a69ba8583dfbf7f5bec0ab1f93ce4c8ee1916eff44a93af5749c4",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=448" {
  let message = w3c_hex(
    "2d52447d1244d2ebc28650e7b05654bad35b3a68eedc7f8515306b496d75f3e7" +
    "3385dd1b002625024b81a02f2fd6dffb6e6d561cb7d0bd7a",
    56,
  )
  crypto_assert_sha256(
    message, "cfb88d6faf2de3a69d36195acec2e255e2af2b7d933997f348e09f6ce5758360",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=456" {
  let message = w3c_hex(
    "4cace422e4a015a75492b3b3bbfbdf3758eaff4fe504b46a26c90dacc119fa90" +
    "50f603d2b58b398cad6d6d9fa922a154d9e0bc4389968274b0",
    57,
  )
  crypto_assert_sha256(
    message, "4d54b2d284a6794581224e08f675541c8feab6eefa3ac1cfe5da4e03e62f72e4",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=504" {
  let message = w3c_hex(
    "e2f76e97606a872e317439f1a03fcd92e632e5bd4e7cbc4e97f1afc19a16fde9" +
    "2d77cbe546416b51640cddb92af996534dfd81edb17c4424cf1ac4d75aceeb",
    63,
  )
  crypto_assert_sha256(
    message, "18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23",
  )
}

///|
test "SHA256 independent SHA256ShortMsg.rsp bits=512" {
  let message = w3c_hex(
    "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8" +
    "a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509",
    64,
  )
  crypto_assert_sha256(
    message, "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa",
  )
}

///|
test "SHA256 independent NIST SHA256 abc" {
  let message = w3c_hex("616263", 3)
  crypto_assert_sha256(
    message, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "SHA256 independent NIST SHA256 56-byte multi-block example" {
  let message = w3c_hex(
    "6162636462636465636465666465666765666768666768696768696a68696a6b" +
    "696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
    56,
  )
  crypto_assert_sha256(
    message, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "SHA256 independent RFC6234 SHA256 million a" {
  let message = Bytes::make(1000000, b'\x61')
  crypto_assert_sha256(
    message, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  )
}

///|
test "SHA256 independent Generated 65-byte boundary input" {
  let message = w3c_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
    "40",
    65,
  )
  crypto_assert_sha256(
    message, "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
  )
}

///|
// The unchanged P3 fixture supplies each registration public key and both
// original assertion byte fields. DER is retained exactly as W3C publishes it.
// raw64 is a test-only unsigned R || S conversion for the raw primitive.
// The WebAuthn assertion entry point consumes the original DER signature.
fn crypto_w3c_key(
  vector : W3cProtocolVector,
) -> @webauthn.ValidatedEs256PublicKey raise {
  let object = match
    @webauthn.parse_attestation_object(vector.registration_object) {
    Ok(value) => value
    Err(error) => fail("W3C registration structure: \{error.to_repr()}")
  }
  let attested = match object.auth_data.attested {
    Some(value) => value
    None => fail("W3C registration missing public key")
  }
  let parameters = match attested.validate_es256() {
    Ok(value) => value
    Err(error) => fail("W3C public key parameters: \{error.to_repr()}")
  }
  let key = match @webauthn.import_es256_public_key(parameters) {
    Ok(value) => value
    Err(error) => fail("W3C public point: \{error.to_repr()}")
  }
  assert_eq(key.parameters(), parameters)
  key
}

///|
fn crypto_assert_w3c(
  vector : W3cProtocolVector,
  wrong_vector : W3cProtocolVector,
  der_hex : String,
  raw_hex : String,
  client_hash_hex : String,
  signed_hash_hex : String,
) -> Unit raise {
  let key = crypto_w3c_key(vector)
  let client_hash = w3c_hex(client_hash_hex, 32)
  assert_eq(@webauthn.sha256(vector.assertion_client), client_hash)
  let signed = match
    @webauthn.build_webauthn_assertion_signed_data(
      vector.assertion_auth,
      vector.assertion_client,
    ) {
    Ok(value) => value
    Err(error) => fail("W3C signed data builder: \{error.to_repr()}")
  }
  assert_eq(signed, vector.assertion_auth + client_hash)
  assert_eq(signed.length(), 69)
  assert_eq(@webauthn.sha256(signed), w3c_hex(signed_hash_hex, 32))
  let raw = w3c_hex(raw_hex, 64)
  assert_eq(@webauthn.verify_es256_signature(key, signed, raw), Ok(true))
  assert_eq(
    @webauthn.verify_es256_signature(key, @webauthn.sha256(signed), raw),
    Ok(false),
  )
  let der = w3c_hex(der_hex, der_hex.length() / 2)
  assert_eq(
    @webauthn.verify_es256_signature(key, signed, der),
    Err(@webauthn.InvalidSignatureLength(expected=64, actual=der.length())),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      vector.assertion_client,
      der,
    ),
    Ok(true),
  )
  let modified_json = b" " + vector.assertion_client
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      modified_json,
      der,
    ),
    Ok(false),
  )
  assert_false(vector.assertion_auth[0] == b'\x00')
  let modified_auth = b"\x00" + vector.assertion_auth[1:].to_owned()
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      modified_auth,
      vector.assertion_client,
      der,
    ),
    Ok(false),
  )
  let modified_signature = der[0:der.length() - 1].to_owned() +
    Bytes::from_array([(der[der.length() - 1].to_int() ^ 1).to_byte()])
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      vector.assertion_client,
      modified_signature,
    ),
    Ok(false),
  )
  // Move the first property to the end while retaining every property value.
  let prefix = b"{\"type\":\"webauthn.get\","
  assert_eq(vector.assertion_client[0:prefix.length()], prefix[:])
  let reordered_json = b"{" +
    vector.assertion_client[prefix.length():vector.assertion_client.length() - 1].to_owned() +
    b",\"type\":\"webauthn.get\"}"
  assert_eq(
    @json.parse(@utf8.decode(reordered_json)),
    @json.parse(@utf8.decode(vector.assertion_client)),
  )
  assert_false(@webauthn.sha256(reordered_json) == client_hash)
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      reordered_json,
      der,
    ),
    Ok(false),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      b"",
      der,
    ),
    Ok(false),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      b"",
      vector.assertion_client,
      der,
    ),
    Ok(false),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      vector.assertion_client,
      der[0:der.length() - 1],
    ),
    Err(@webauthn.InvalidSignatureEncoding),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      vector.assertion_client,
      der + b"\x00",
    ),
    Err(@webauthn.InvalidSignatureEncoding),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      vector.assertion_auth,
      vector.assertion_client,
      raw,
    ),
    Err(@webauthn.InvalidSignatureEncoding),
  )
  assert_eq(
    @webauthn.verify_webauthn_es256_assertion_signature(
      crypto_w3c_key(wrong_vector),
      vector.assertion_auth,
      vector.assertion_client,
      der,
    ),
    Ok(false),
  )
}

///|
test "W3C 16.2 original signed bytes and DER wire verification" {
  crypto_assert_w3c(
    w3c_vector_none(),
    w3c_vector_cross_origin(),
    "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a877802" +
    "18deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f9372" +
    "95ea13653e331e87",
    "f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd38" +
    "8480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87",
    "676a6e380fd31ea5710705c7be1ac4889b037895d0a25291f51251b7d7b1df02",
    "85029a0978399f2afc714aade7957eac4fc46d21b5f5b6b5d019f18032d2e3a6",
  )
}

///|
test "W3C 16.4 original signed bytes and DER wire verification" {
  crypto_assert_w3c(
    w3c_vector_cross_origin(),
    w3c_vector_none(),
    "3046022100eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c" +
    "951b6e40e7022100c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c" +
    "0733b1184036d1cf",
    "eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c951b6e40e7" +
    "c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c0733b1184036d1cf",
    "5433303f133eeec1c6ef3d8bddad49f6f1fe29951d297201abfb928a6a9c2a67",
    "9911630b731fbc66a979672294e2cc826e518ce251a05737cca14d285a278959",
  )
}

///|
test "W3C 16.5 original signed bytes and DER wire verification" {
  crypto_assert_w3c(
    w3c_vector_top_origin(),
    w3c_vector_none(),
    "3045022100b5a70c81780d5fcc9a4f2ae9caae99058f8accaf58b91fb5932964" +
    "6c28ac6ffc022012e101c165db3c8e9957f0c54dd6ca9b56bc3bd2f280bd2faa" +
    "6c1d02c6e5c171",
    "b5a70c81780d5fcc9a4f2ae9caae99058f8accaf58b91fb59329646c28ac6ffc" +
    "12e101c165db3c8e9957f0c54dd6ca9b56bc3bd2f280bd2faa6c1d02c6e5c171",
    "429e6077534d353c23193006e88028cbbc926758a771ea16a6c825894ebc6bfa",
    "49add7e2e30d357a01026318673237fab66d9dff9928a2f16f3da716af078466",
  )
}
