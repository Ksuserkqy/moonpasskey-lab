///|
// Unmodified official byte sequences from W3C WebAuthn Level 3,
// Recommendation 25 August 2026, informative sections 16.2, 16.4 and 16.5.
// https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
// Copyright 2026 World Wide Web Consortium. W3C Software and Document
// License 2023: see W3C-NOTICE.md. Only clientDataJSON, attestationObject and
// assertion authenticatorData are retained. No private keys or signatures.
// Fixtures are exact published hex, not reconstructed JSON or synthetic data.
// These structural examples are not conformance certification or verification.
struct W3cProtocolVector {
  registration_client : Bytes
  registration_object : Bytes
  assertion_client : Bytes
  assertion_auth : Bytes
  registration_challenge : String
  assertion_challenge : String
  cross_origin : Bool
  top_origin : String?
  registration_flags : Byte
  assertion_flags : Byte
  aaguid : Bytes
  credential_id : Bytes
}

///|
// Test-only fixture decoder: refuse malformed or accidentally truncated hex.
fn w3c_hex(input : String, expected_size : Int32) -> Bytes raise {
  assert_eq(input.length() % 2, 0)
  let bytes : Array[Byte] = []
  let mut high = 0
  for index, code_unit in input.code_units() {
    let digit = match code_unit.to_int() {
      '0'..<='9' as c => c - '0'
      'a'..<='f' as c => c - 'a' + 10
      _ => fail("invalid hex in official fixture")
    }
    if index % 2 == 0 {
      high = digit * 16
    } else {
      bytes.push((high + digit).to_byte())
    }
  }
  assert_eq(bytes.length(), expected_size)
  Bytes::from_array(bytes)
}

///|
// W3C §16.2: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256
fn w3c_vector_none() -> W3cProtocolVector raise {
  {
    registration_client: w3c_hex(
      "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878" +
      "475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a226874" +
      "7470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c226578747261446174" +
      "61223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e" +
      "616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354" +
      "427258426941774a544c453551227d",
      255,
    ),
    registration_object: w3c_hex(
      "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735a" +
      "e7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70" +
      "189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20d" +
      "b90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b" +
      "9220",
      194,
    ),
    assertion_client: w3c_hex(
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455" +
      "506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a226874747073" +
      "3a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
      132,
    ),
    assertion_auth: w3c_hex(
      "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
      37,
    ),
    registration_challenge: "AMMPt4UxxGTStncdq417YDwBFi8vpIa-pw8oOuVW4TA",
    assertion_challenge: "OcDnUhQXulTUPo3JUXT0I97pvzzYBP9tZchXyav01Ag",
    cross_origin: false,
    top_origin: None,
    registration_flags: b'\x59',
    assertion_flags: b'\x19',
    aaguid: w3c_hex("8446ccb9ab1db374750b2367ff6f3a1f", 16),
    credential_id: w3c_hex(
      "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4", 32,
    ),
  }
}

///|
// W3C §16.4: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-crossOrigin
fn w3c_vector_cross_origin() -> W3cProtocolVector raise {
  {
    registration_client: w3c_hex(
      "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224f2d57717a514e5463" +
      "554a484930437257576e7951504859647862694332674872434d475666704c4f306b222c226f726967696e223a226874" +
      "7470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461" +
      "223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e61" +
      "6c206669656c647320696e20746865206675747572652c207375636820617320746869733a207a5a7175457444523944" +
      "577170573574425754467567227d",
      254,
    ),
    registration_object: w3c_hex(
      "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735a" +
      "e7f8edd46592a5e0f01452b2e4b54500000000883f4f6014f19c09d87aa38123be48d000206e1050c0d2ca2f07c755cb" +
      "2c66a74c64fa43065c18f938354d9915db2bd5ce57a501020326200121582022200a473f90b11078851550d03b4e44a2" +
      "279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a" +
      "9c6e",
      194,
    ),
    assertion_client: w3c_hex(
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226832716c463771445f65356c" +
      "5f505f62796b7945377135645650674547685f49584a6b655737736e4d5463222c226f726967696e223a226874747073" +
      "3a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22" +
      "636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c2066" +
      "69656c647320696e20746865206675747572652c207375636820617320746869733a2039327063545644304162792d71" +
      "3464746d6a36656667227d",
      251,
    ),
    assertion_auth: w3c_hex(
      "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000",
      37,
    ),
    registration_challenge: "O-WqzQNTcUJHI0CrWWnyQPHYdxbiC2gHrCMGVfpLO0k",
    assertion_challenge: "h2qlF7qD_e5l_P_bykyE7q5dVPgEGh_IXJkeW7snMTc",
    cross_origin: true,
    top_origin: None,
    registration_flags: b'\x45',
    assertion_flags: b'\x05',
    aaguid: w3c_hex("883f4f6014f19c09d87aa38123be48d0", 16),
    credential_id: w3c_hex(
      "6e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57", 32,
    ),
  }
}

///|
// W3C §16.5: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-topOrigin
fn w3c_vector_top_origin() -> W3cProtocolVector raise {
  {
    registration_client: w3c_hex(
      "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e" +
      "6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a226874" +
      "7470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e" +
      "223a2268747470733a2f2f6578616d706c652e636f6d227d",
      168,
    ),
    registration_object: w3c_hex(
      "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735a" +
      "e7f8edd46592a5e0f01452b2e4b5410000000097586fd09799a76401c200455099ef2a0020b8ad59b996047ab18e2ceb" +
      "57206c362da57458793481f4a8ebf101c7ca7cc0f1a5010203262001215820a1c47c1d82da4ebe82cd72207102b38067" +
      "0701993bc35398ae2e5726427fe01d22582086c1080d82987028c7f54ecb1b01185de243b359294a0ed210cd47480f0a" +
      "dc88",
      194,
    ),
    assertion_client: w3c_hex(
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22315570636a4b53324b6f3437" +
      "7379486a7372787a68572d466f51465132796b3572426c584f6573656f4759222c226f726967696e223a226874747073" +
      "3a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a22" +
      "68747470733a2f2f6578616d706c652e636f6d222c22657874726144617461223a22636c69656e74446174614a534f4e" +
      "206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e207468652066" +
      "75747572652c207375636820617320746869733a205569466f4a4d56525148444146574669347678557051227d",
      285,
    ),
    assertion_auth: w3c_hex(
      "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000",
      37,
    ),
    registration_challenge: "Th9MYZhpnjPBTxkhU_Sdfg6ONXfVrEFsXzrckqQfJ-U",
    assertion_challenge: "1UpcjKS2Ko47syHjsrxzhW-FoQFQ2yk5rBlXOeseoGY",
    cross_origin: true,
    top_origin: Some("https://example.com"),
    registration_flags: b'\x41',
    assertion_flags: b'\x05',
    aaguid: w3c_hex("97586fd09799a76401c200455099ef2a", 16),
    credential_id: w3c_hex(
      "b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1", 32,
    ),
  }
}

///|
fn w3c_client(
  raw : BytesView,
  expected_type : String,
  expected_challenge : String,
  vector : W3cProtocolVector,
) -> Unit raise {
  let client = match @webauthn.parse_client_data(raw) {
    Ok(value) => value
    Err(error) => fail("official clientDataJSON failed: \{error.to_repr()}")
  }
  assert_eq(client.raw, raw)
  assert_eq(client.type_, expected_type)
  assert_eq(client.challenge, expected_challenge)
  assert_eq(client.origin, "https://example.org")
  assert_eq(client.cross_origin, Some(vector.cross_origin))
  assert_eq(client.top_origin, vector.top_origin)
  // All field ranges slice the original input, including optional/unknown data.
  assert_true(client.members.length() >= 4)
  for field in client.members {
    assert_true(field.key_range.start >= 0)
    assert_true(field.key_range.end <= raw.length())
    assert_true(field.value_range.start < field.value_range.end)
    assert_true(field.value_range.end <= raw.length())
    assert_eq(raw[field.key_range.start], b'"')
    assert_eq(raw[field.key_range.end - 1], b'"')
  }
}

///|
fn w3c_auth_common(
  data : @webauthn.AuthenticatorData,
  flags : Byte,
) -> Unit raise {
  assert_eq(
    data.rp_id_hash,
    w3c_hex(
      "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5", 32,
    )[:],
  )
  assert_eq(data.rp_id_hash_range, { start: 0, end: 32, })
  assert_eq(data.flags.raw, flags)
  assert_true(data.flags.up)
  assert_eq(data.flags.reserved, b'\x00')
  assert_false(data.flags.ed)
  assert_eq(data.flags_range, { start: 32, end: 33, })
  assert_eq(data.sign_count, 0U)
  assert_eq(data.sign_count_range, { start: 33, end: 37, })
  assert_eq(data.extensions, None)
  assert_eq(data.extensions_raw, None)
}

///|
fn w3c_registration(vector : W3cProtocolVector) -> Unit raise {
  w3c_client(
    vector.registration_client,
    "webauthn.create",
    vector.registration_challenge,
    vector,
  )
  let object = match
    @webauthn.parse_attestation_object(vector.registration_object) {
    Ok(value) => value
    Err(error) => fail("official attestationObject failed: \{error.to_repr()}")
  }
  assert_eq(object.raw, vector.registration_object[:])
  assert_eq(object.cbor.range, { start: 0, end: 194, })
  assert_true(object.cbor.kind is @cbor.Map(entries) && entries.length() == 3)
  assert_eq(object.fmt, "none")
  assert_eq(object.statement_status, @webauthn.NoneStructureChecked)
  assert_true(
    object.att_stmt.kind is @cbor.Map(entries) && entries.length() == 0,
  )
  assert_eq(
    object.auth_data_payload_range.end - object.auth_data_payload_range.start,
    164,
  )
  assert_eq(
    object.auth_data.raw,
    object.raw[object.auth_data_payload_range.start:object.auth_data_payload_range.end],
  )
  assert_eq(
    @webauthn.parse_authenticator_data(object.auth_data.raw),
    Ok(object.auth_data),
  )
  w3c_auth_common(object.auth_data, vector.registration_flags)
  assert_true(object.auth_data.flags.at)
  let attested = match object.auth_data.attested {
    Some(value) => value
    None => fail("official registration must include AT data")
  }
  assert_eq(attested.range, { start: 37, end: 164, })
  assert_eq(attested.aaguid, vector.aaguid[:])
  assert_eq(attested.credential_id_length, 32U)
  assert_eq(attested.credential_id, vector.credential_id[:])
  assert_eq(attested.credential_id_range, { start: 55, end: 87, })
  assert_eq(attested.credential_public_key.range, { start: 87, end: 164, })
  assert_eq(attested.credential_public_key_raw.length(), 77)
  assert_eq(attested.credential_public_key_raw, object.auth_data.raw[87:164])
  let entries = match attested.credential_public_key.kind {
    @cbor.Map(entries) => entries
    _ => fail("official ES256 key must be a CBOR map")
  }
  assert_eq(entries.length(), 5)
  // Check decoded labels/values from this known fixture. This is not a claim
  // that the parser implements COSE key or signature verification.
  assert_eq(entries[0].0.kind, @cbor.Unsigned(1UL))
  assert_eq(entries[0].1.kind, @cbor.Unsigned(2UL))
  assert_eq(entries[1].0.kind, @cbor.Unsigned(3UL))
  assert_eq(entries[1].1.kind, @cbor.Negative(6UL))
  assert_eq(entries[2].0.kind, @cbor.Negative(0UL))
  assert_eq(entries[2].1.kind, @cbor.Unsigned(1UL))
  assert_eq(entries[3].0.kind, @cbor.Negative(1UL))
  assert_eq(entries[4].0.kind, @cbor.Negative(2UL))
  for index in 3..<5 {
    assert_true(
      entries[index].1.kind is @cbor.ByteString(coordinate) &&
      coordinate.length() == 32,
    )
  }
}

///|
fn w3c_assertion(vector : W3cProtocolVector) -> Unit raise {
  w3c_client(
    vector.assertion_client,
    "webauthn.get",
    vector.assertion_challenge,
    vector,
  )
  let data = match @webauthn.parse_authenticator_data(vector.assertion_auth) {
    Ok(value) => value
    Err(error) =>
      fail("official assertion authenticatorData failed: \{error.to_repr()}")
  }
  assert_eq(data.raw, vector.assertion_auth[:])
  assert_eq(data.raw.length(), 37)
  w3c_auth_common(data, vector.assertion_flags)
  assert_false(data.flags.at)
  assert_eq(data.attested, None)
}

///|
test "W3C 16.2 registration official protocol vector" {
  w3c_registration(w3c_vector_none())
}

///|
test "W3C 16.2 assertion official protocol vector" {
  w3c_assertion(w3c_vector_none())
}

///|
test "W3C 16.4 registration official protocol vector" {
  w3c_registration(w3c_vector_cross_origin())
}

///|
test "W3C 16.4 assertion official protocol vector" {
  w3c_assertion(w3c_vector_cross_origin())
}

///|
test "W3C 16.5 registration official protocol vector" {
  w3c_registration(w3c_vector_top_origin())
}

///|
test "W3C 16.5 assertion official protocol vector" {
  w3c_assertion(w3c_vector_top_origin())
}

///|
// P4 parameter checks reuse the three unchanged P3 official registrations.
// Point membership and cryptographic verification remain separate operations.
fn w3c_es256_parameters(vector : W3cProtocolVector) -> Unit raise {
  let object = match
    @webauthn.parse_attestation_object(vector.registration_object) {
    Ok(value) => value
    Err(error) =>
      fail("official registration structure failed: \{error.to_repr()}")
  }
  let attested = match object.auth_data.attested {
    Some(value) => value
    None => fail("official registration must include AT data")
  }
  let parameters = match attested.validate_es256() {
    Ok(value) => value
    Err(error) => fail("official ES256 parameters failed: \{error.to_repr()}")
  }
  assert_eq(parameters.kty, 2U)
  assert_eq(parameters.alg, -7)
  assert_eq(parameters.crv, 1U)
  assert_eq(parameters.raw, attested.credential_public_key_raw)
  assert_eq(parameters.raw, object.auth_data.raw[87:164])
  assert_eq(parameters.range, { start: 87, end: 164, })
  assert_eq(parameters.kty_range, { start: 89, end: 90, })
  assert_eq(parameters.alg_range, { start: 91, end: 92, })
  assert_eq(parameters.crv_range, { start: 93, end: 94, })
  assert_eq(parameters.x_range, { start: 95, end: 129, })
  assert_eq(parameters.y_range, { start: 130, end: 164, })
  assert_eq(parameters.x.length(), 32)
  assert_eq(parameters.y.length(), 32)
  assert_eq(parameters.x, object.auth_data.raw[97:129])
  assert_eq(parameters.y, object.auth_data.raw[132:164])
  assert_eq(parameters.point_validation, @webauthn.NotPerformed)
}

///|
test "W3C 16.2 existing registration validates ES256 parameters only" {
  w3c_es256_parameters(w3c_vector_none())
}

///|
test "W3C 16.4 existing registration validates ES256 parameters only" {
  w3c_es256_parameters(w3c_vector_cross_origin())
}

///|
test "W3C 16.5 existing registration validates ES256 parameters only" {
  w3c_es256_parameters(w3c_vector_top_origin())
}
