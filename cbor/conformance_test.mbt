///|
// Official source for this unchanged ES256 public-key encoding example:
// W3C WebAuthn Level 3, 2026-08-25 Recommendation, section 6.5.1.1.
// https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-credentialpublickey-examples
// Copyright 2026 World Wide Web Consortium. W3C Software and Document License
// 2023. See W3C-NOTICE.md. Reordered fixtures below are synthetic derivatives.
fn official_es256_fixture() -> Bytes {
  b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" +
  b"\x65\xed\xa5\xa1\x25\x77\xc2\xba\xe8\x29\x43\x7f\xe3\x38\x70\x1a\x10\xaa\xa3\x75\xe1\xbb\x5b\x5d\xe1\x08\xde\x43\x9c\x08\x55\x1d" +
  b"\x22\x58\x20" +
  b"\x1e\x52\xed\x75\x70\x11\x63\xf7\xf9\xe4\x0d\xdf\x9f\x34\x1b\x3d\xc9\xba\x86\x0a\xf7\xe0\xca\x7c\xa7\xe9\xee\xcd\x00\x84\xd1\x9c"
}

///|
test "conformance mixed container depth cannot bypass CTAP with caller limits" {
  // Synthetic map -> array -> map -> array, followed by a scalar or map.
  let four = b"\xa1\x00\x81\xa1\x00\x81\x00"
  let five = b"\xa1\x00\x81\xa1\x00\x81\xa0"
  for max_depth in [4, 5, 32, 64] {
    let limits = @cbor.Limits::new(max_depth~)
    assert_true(
      decoded(four, profile=@cbor.Ctap2Canonical, limits~).kind is @cbor.Map(_),
    )
    let name = if max_depth == 4 {
      "max_depth"
    } else {
      "ctap2_container_depth"
    }
    expect_error(
      @cbor.parse_all(five, profile=@cbor.Ctap2Canonical, limits~),
      offset=6,
      context="root.map[0].value.array[0].map[0].value.array[0]",
      kind=@cbor.ResourceLimit(name~, limit=4, actual=5UL),
    )
  }
  assert_true(
    decoded(five, limits=@cbor.Limits::new(max_depth=5)).kind is @cbor.Map(_),
  )
  expect_error(
    @cbor.parse_all(five, limits=@cbor.Limits::new(max_depth=4)),
    offset=6,
    context="root.map[0].value.array[0].map[0].value.array[0]",
    kind=@cbor.ResourceLimit(name="max_depth", limit=4, actual=5UL),
  )
}

///|
test "conformance CTAP depth includes compound keys with shifted source and offset" {
  // Synthetic containers in map keys count exactly as containers in values.
  let four = b"\xa1\x81\xa1\x81\x00\x00\x00"
  let five = b"\xa1\x81\xa1\x81\x80\x00\x00"
  for input in [four, five] {
    let wrapped = b"prefix\x00\x00" + input + b"suffix"
    let view = wrapped[6:8 + input.length()]
    match @cbor.parse_one(view, offset=2) {
      Ok(parsed) => {
        assert_eq(parsed.consumed, 7)
        expect_range(parsed.value, 2, 9)
      }
      Err(_) => fail("generic compound-key fixture must parse")
    }
  }
  assert_true(decoded(four, profile=@cbor.Ctap2Canonical).kind is @cbor.Map(_))
  let wrapped = b"prefix\x00\x00" + five + b"suffix"
  expect_error(
    @cbor.parse_one(
      wrapped[6:15],
      offset=2,
      profile=@cbor.Ctap2Canonical,
      limits=@cbor.Limits::new(max_depth=64),
    ),
    offset=6,
    context="root.map[0].key.array[0].map[0].key.array[0]",
    kind=@cbor.ResourceLimit(name="ctap2_container_depth", limit=4, actual=5UL),
  )
}

///|
test "conformance sibling containers do not accumulate nesting depth" {
  // Synthetic siblings have at most three nested array/map levels.
  let value = decoded(
    b"\x84\x80\xa0\x81\x80\xa1\x00\x80",
    profile=@cbor.Ctap2Canonical,
    limits=@cbor.Limits::new(max_depth=3),
  )
  match value.kind {
    @cbor.Array(items) => assert_eq(items.length(), 4)
    _ => fail("expected four sibling containers")
  }
}

///|
test "conformance CTAP preserves float widths as unsupported instead of nonminimal" {
  // Synthetic IEEE 754 encodings of 1.5. Python struct.pack with >e, >f and >d
  // independently gives these bit patterns. CTAP preserves each width.
  for
    (input, width) in [
      (b"\xf9\x3e\x00", 2),
      (b"\xfa\x3f\xc0\x00\x00", 4),
      (b"\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00", 8),
    ] {
    for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
      expect_error(
        @cbor.parse_all(input, profile~),
        offset=0,
        context="root",
        kind=@cbor.UnsupportedFloat(width~),
      )
      expect_error(
        @cbor.parse_all(b"\x81" + input, profile~),
        offset=1,
        context="root.array[0]",
        kind=@cbor.UnsupportedFloat(width~),
      )
    }
  }
}

///|
test "conformance float special values retain unsupported classification" {
  // Synthetic negative zero, positive infinity and quiet NaN at each width.
  for
    (input, width) in [
      (b"\xf9\x80\x00", 2),
      (b"\xf9\x7c\x00", 2),
      (b"\xf9\x7e\x00", 2),
      (b"\xfa\x80\x00\x00\x00", 4),
      (b"\xfa\x7f\x80\x00\x00", 4),
      (b"\xfa\x7f\xc0\x00\x00", 4),
      (b"\xfb\x80\x00\x00\x00\x00\x00\x00\x00", 8),
      (b"\xfb\x7f\xf0\x00\x00\x00\x00\x00\x00", 8),
      (b"\xfb\x7f\xf8\x00\x00\x00\x00\x00\x00", 8),
    ] {
    for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
      expect_error(
        @cbor.parse_all(input, profile~),
        offset=0,
        context="root",
        kind=@cbor.UnsupportedFloat(width~),
      )
    }
  }
}

///|
test "conformance scalar map order handles integer width boundaries" {
  // Synthetic keys 23, 24, -1, -25 in CTAP encoding order.
  let ordered = b"\xa4\x17\x00\x18\x18\x01\x20\x02\x38\x18\x03"
  match decoded(ordered, profile=@cbor.Ctap2Canonical).kind {
    @cbor.Map(entries) => {
      assert_eq(entries[0].0.kind, @cbor.Unsigned(23UL))
      assert_eq(entries[1].0.kind, @cbor.Unsigned(24UL))
      assert_eq(entries[2].0.kind, @cbor.Negative(0UL))
      assert_eq(entries[3].0.kind, @cbor.Negative(24UL))
    }
    _ => fail("expected map with integer boundary keys")
  }
  let reversed = b"\xa4\x18\x18\x01\x17\x00\x20\x02\x38\x18\x03"
  assert_true(decoded(reversed).kind is @cbor.Map(_))
  expect_error(
    @cbor.parse_all(reversed, profile=@cbor.Ctap2Canonical),
    offset=4,
    context="root.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=1),
  )
  let wide = b"\xa2\x1b\xff\xff\xff\xff\xff\xff\xff\xff\x00\x20\x01"
  assert_true(decoded(wide, profile=@cbor.Ctap2Canonical).kind is @cbor.Map(_))
  expect_error(
    @cbor.parse_all(
      b"\xa2\x20\x01\x1b\xff\xff\xff\xff\xff\xff\xff\xff\x00",
      profile=@cbor.Ctap2Canonical,
    ),
    offset=3,
    context="root.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=1),
  )
}

///|
test "conformance text key ordering distinguishes encoded length and byte ties" {
  // Synthetic keys z, aa, ab. Encoded length precedes lexical payload order.
  let ordered = b"\xa3\x61z\x00\x62aa\x01\x62ab\x02"
  assert_true(
    decoded(ordered, profile=@cbor.Ctap2Canonical).kind is @cbor.Map(_),
  )
  for
    (input, index, offset, previous_offset) in [
      (b"\xa3\x62aa\x01\x61z\x00\x62ab\x02", 1, 5, 1),
      (b"\xa3\x61z\x00\x62ab\x01\x62aa\x02", 2, 8, 4),
    ] {
    assert_true(decoded(input).kind is @cbor.Map(_))
    expect_error(
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical),
      offset~,
      context="root.map[\{index}].key",
      kind=@cbor.UnsortedMapKey(previous_offset~),
    )
  }
}

///|
test "conformance compound key comparison follows three step encoding contract" {
  // Synthetic map keys {} and {0:0}. CTAP section 8 notes that its current
  // protocol does not use compound keys. These exercise the existing parser
  // comparator, without assigning CTAP command semantics to those keys.
  let ordered = b"\xa2\xa0\x00\xa1\x00\x00\x01"
  let reversed = b"\xa2\xa1\x00\x00\x01\xa0\x00"
  assert_true(
    decoded(ordered, profile=@cbor.Ctap2Canonical).kind is @cbor.Map(_),
  )
  assert_true(decoded(reversed).kind is @cbor.Map(_))
  expect_error(
    @cbor.parse_all(reversed, profile=@cbor.Ctap2Canonical),
    offset=5,
    context="root.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=1),
  )
  for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
    expect_error(
      @cbor.parse_all(b"\xa1\xc0\x00\x00", profile~),
      offset=1,
      context="root.map[0].key",
      kind=if profile is @cbor.Generic {
        @cbor.UnsupportedTag(0UL)
      } else {
        @cbor.ForbiddenTag(0UL)
      },
    )
  }
}

///|
test "conformance UInt64 and negative argument boundaries remain lossless" {
  // Synthetic major-type heads. Negative(n) represents -1-n without an Int64
  // conversion. The last argument represents -18446744073709551616.
  let vectors : Array[(Bytes, @cbor.ValueKind)] = [
    (b"\x00", @cbor.Unsigned(0UL)),
    (b"\x17", @cbor.Unsigned(23UL)),
    (b"\x18\x18", @cbor.Unsigned(24UL)),
    (b"\x18\xff", @cbor.Unsigned(255UL)),
    (b"\x19\x01\x00", @cbor.Unsigned(256UL)),
    (b"\x1a\xff\xff\xff\xff", @cbor.Unsigned(4294967295UL)),
    (
      b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff",
      @cbor.Unsigned(18446744073709551615UL),
    ),
    (b"\x20", @cbor.Negative(0UL)),
    (b"\x37", @cbor.Negative(23UL)),
    (b"\x38\x18", @cbor.Negative(24UL)),
    (
      b"\x3b\x7f\xff\xff\xff\xff\xff\xff\xff",
      @cbor.Negative(9223372036854775807UL),
    ),
    (
      b"\x3b\x80\x00\x00\x00\x00\x00\x00\x00",
      @cbor.Negative(9223372036854775808UL),
    ),
    (
      b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff",
      @cbor.Negative(18446744073709551615UL),
    ),
  ]
  for (input, expected) in vectors {
    for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
      let value = decoded(input, profile~)
      assert_eq(value.kind, expected)
      expect_range(value, 0, input.length())
    }
  }
}

///|
test "conformance maximum unsigned and negative arguments remain distinct map keys" {
  // Synthetic full-width signed-boundary and maximum-argument map keys.
  for head in [b'\x1b', b'\x3b'] {
    let smaller = Bytes::make(1, head) + b"\x7f\xff\xff\xff\xff\xff\xff\xff"
    let larger = Bytes::make(1, head) + Bytes::make(8, b'\xff')
    let ordered = b"\xa2" + smaller + b"\x00" + larger + b"\x01"
    match decoded(ordered, profile=@cbor.Ctap2Canonical).kind {
      @cbor.Map(entries) => {
        assert_eq(entries.length(), 2)
        assert_true(entries[0].0.kind != entries[1].0.kind)
        expect_range(entries[0].0, 1, 10)
        expect_range(entries[1].0, 11, 20)
      }
      _ => fail("expected two distinct full-width keys")
    }
    for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
      expect_error(
        @cbor.parse_all(b"\xa2" + larger + b"\x00" + larger + b"\x01", profile~),
        offset=11,
        context="root.map[1].key",
        kind=@cbor.DuplicateMapKey(first_offset=1),
      )
    }
  }
}

///|
test "official W3C ES256 COSE example retains every key value and source range" {
  let input = official_es256_fixture()
  assert_eq(input.length(), 77)
  for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
    let value = decoded(input, profile~)
    expect_range(value, 0, 77)
    match value.kind {
      @cbor.Map(entries) => {
        assert_eq(entries.length(), 5)
        let keys : Array[@cbor.ValueKind] = [
          @cbor.Unsigned(1UL),
          @cbor.Unsigned(3UL),
          @cbor.Negative(0UL),
          @cbor.Negative(1UL),
          @cbor.Negative(2UL),
        ]
        let values : Array[@cbor.ValueKind] = [
          @cbor.Unsigned(2UL),
          @cbor.Negative(6UL),
          @cbor.Unsigned(1UL),
          @cbor.ByteString(input[10:42]),
          @cbor.ByteString(input[45:77]),
        ]
        let ranges = [
          (1, 2, 2, 3),
          (3, 4, 4, 5),
          (5, 6, 6, 7),
          (7, 8, 8, 42),
          (42, 43, 43, 77),
        ]
        for index in 0..<5 {
          assert_eq(entries[index].0.kind, keys[index])
          assert_eq(entries[index].1.kind, values[index])
          let (key_start, key_end, value_start, value_end) = ranges[index]
          expect_range(entries[index].0, key_start, key_end)
          expect_range(entries[index].1, value_start, value_end)
        }
      }
      _ => fail("official COSE example must be a CBOR map")
    }
  }
}

///|
test "synthetic reordered derivatives of W3C COSE example violate CTAP ordering" {
  let original = official_es256_fixture()
  // Only whole pairs are reordered. Public-key bytes and labels are retained.
  let first_pairs = original[:1].to_owned() +
    original[3:5].to_owned() +
    original[1:3].to_owned() +
    original[5:].to_owned()
  let coordinates = original[:7].to_owned() +
    original[42:77].to_owned() +
    original[7:42].to_owned()
  for
    (input, index, offset, previous_offset) in [
      (first_pairs, 1, 3, 1),
      (coordinates, 4, 42, 7),
    ] {
    match decoded(input).kind {
      @cbor.Map(entries) => assert_eq(entries.length(), 5)
      _ => fail("reordered derivative must remain a generic CBOR map")
    }
    expect_error(
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical),
      offset~,
      context="root.map[\{index}].key",
      kind=@cbor.UnsortedMapKey(previous_offset~),
    )
  }
}
