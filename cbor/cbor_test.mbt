///|
// These are synthetic fixtures written for MoonPasskey Lab. Byte encodings are
// hand-derived from CBOR major types and independently checked with a small
// Python encoder using int.to_bytes. They are not official WebAuthn vectors.
fn decoded(
  input : BytesView,
  profile~ : @cbor.Profile = @cbor.Generic,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @cbor.Value raise {
  match @cbor.parse_all(input, profile~, limits~) {
    Ok(value) => value
    Err(_) => fail("expected valid CBOR")
  }
}

///|
fn[T] expect_error(
  result : Result[T, @cbor.ParseError],
  offset~ : Int32,
  context~ : String,
  kind~ : @cbor.ErrorKind,
) -> Unit raise {
  match result {
    Err(error) => {
      assert_eq(error.offset, offset)
      assert_eq(error.context, context)
      assert_eq(error.kind, kind)
    }
    Ok(_) => fail("expected a CBOR parse error")
  }
}

///|
fn expect_range(value : @cbor.Value, start : Int32, end : Int32) -> Unit raise {
  assert_eq(value.range.start, start)
  assert_eq(value.range.end, end)
  assert_eq(value.encoded_length(), end - start)
}

///|
test "unsigned integers cover immediate and every argument width" {
  for number in 0..<24 {
    let input = Bytes::make(1, number.to_byte())
    assert_eq(decoded(input).kind, @cbor.Unsigned(number.to_uint64()))
  }
  let vectors : Array[(Bytes, UInt64)] = [
    (b"\x18\x18", 24UL),
    (b"\x18\xff", 255UL),
    (b"\x19\x01\x00", 256UL),
    (b"\x19\xff\xff", 65535UL),
    (b"\x1a\x00\x01\x00\x00", 65536UL),
    (b"\x1a\xff\xff\xff\xff", 4294967295UL),
    (b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00", 4294967296UL),
    (b"\x1b\x7f\xff\xff\xff\xff\xff\xff\xff", 9223372036854775807UL),
    (b"\x1b\x80\x00\x00\x00\x00\x00\x00\x00", 9223372036854775808UL),
    (b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff", 18446744073709551615UL),
  ]
  for (input, number) in vectors {
    let value = decoded(input)
    assert_eq(value.kind, @cbor.Unsigned(number))
    expect_range(value, 0, input.length())
    assert_eq(decoded(input, profile=@cbor.Ctap2Canonical).kind, value.kind)
  }
}

///|
test "negative integer arguments preserve the entire minus one minus n domain" {
  let vectors : Array[(Bytes, UInt64)] = [
    (b"\x20", 0UL),
    (b"\x37", 23UL),
    (b"\x38\x18", 24UL),
    (b"\x38\xff", 255UL),
    (b"\x39\x01\x00", 256UL),
    (b"\x39\xff\xff", 65535UL),
    (b"\x3a\x00\x01\x00\x00", 65536UL),
    (b"\x3a\xff\xff\xff\xff", 4294967295UL),
    (b"\x3b\x00\x00\x00\x01\x00\x00\x00\x00", 4294967296UL),
    (b"\x3b\x7f\xff\xff\xff\xff\xff\xff\xff", 9223372036854775807UL),
    (b"\x3b\x80\x00\x00\x00\x00\x00\x00\x00", 9223372036854775808UL),
    (b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff", 18446744073709551615UL),
  ]
  for (input, argument) in vectors {
    assert_eq(decoded(input).kind, @cbor.Negative(argument))
    assert_eq(
      decoded(input, profile=@cbor.Ctap2Canonical).kind,
      @cbor.Negative(argument),
    )
  }
}

///|
test "generic accepts every nonminimal integer argument width" {
  for
    input in [
      b"\x18\x00", b"\x19\x00\x00", b"\x1a\x00\x00\x00\x00", b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00",
    ] {
    assert_eq(decoded(input).kind, @cbor.Unsigned(0UL))
  }
  assert_eq(decoded(b"\x38\x00").kind, @cbor.Negative(0UL))
}

///|
test "generic strings arrays and maps accept all definite length widths" {
  for
    (major, expected) in [
      (2, @cbor.ByteString(b""[:])),
      (3, @cbor.TextString("")),
      (4, @cbor.Array([])),
      (5, @cbor.Map([])),
    ] {
    for (additional, width) in [(24, 1), (25, 2), (26, 4), (27, 8)] {
      let input = Bytes::make(1, (major * 32 + additional).to_byte()) +
        Bytes::make(width, b'\x00')
      let value = decoded(input)
      assert_eq(value.kind, expected)
      expect_range(value, 0, width + 1)
      expect_error(
        @cbor.parse_all(input, profile=@cbor.Ctap2Canonical),
        offset=0,
        context="root",
        kind=@cbor.NonMinimalEncoding,
      )
    }
  }
}

///|
test "byte strings preserve arbitrary payloads and complete source ranges" {
  let empty = decoded(b"\x40")
  assert_eq(empty.kind, @cbor.ByteString(b""[:]))
  expect_range(empty, 0, 1)
  let binary = decoded(b"\x44\x00\x80\xff\x61")
  assert_eq(binary.kind, @cbor.ByteString(b"\x00\x80\xff\x61"[:]))
  expect_range(binary, 0, 5)
  let extended = decoded(b"\x58\x02hi")
  assert_eq(extended.kind, @cbor.ByteString(b"hi"[:]))
  expect_range(extended, 0, 4)
}

///|
test "text strings support empty ASCII Unicode and retain a leading BOM" {
  let vectors : Array[(Bytes, String)] = [
    (b"\x60", ""),
    (b"\x62hi", "hi"),
    (b"\x62\xc2\xa2", "¢"),
    (b"\x63\xe2\x82\xac", "€"),
    (b"\x64\xf0\x9f\x98\x80", "😀"),
    (b"\x63\xe0\xa0\x80", "\u{0800}"),
    (b"\x63\xed\x9f\xbf", "\u{D7FF}"),
    (b"\x63\xee\x80\x80", "\u{E000}"),
    (b"\x64\xf0\x90\x80\x80", "\u{10000}"),
    (b"\x64\xf4\x8f\xbf\xbf", "\u{10FFFF}"),
    (b"\x64\xef\xbb\xbfA", "\uFEFFA"),
    (b"\x61\x00", "\u0000"),
  ]
  for (input, text) in vectors {
    let value = decoded(input)
    assert_eq(value.kind, @cbor.TextString(text))
    expect_range(value, 0, input.length())
  }
}

///|
test "arrays retain nested value ranges including container heads" {
  let value = decoded(b"\x82\x81\x01\xa1\x61a\x42xy")
  expect_range(value, 0, 9)
  match value.kind {
    @cbor.Array(items) => {
      assert_eq(items.length(), 2)
      expect_range(items[0], 1, 3)
      expect_range(items[1], 3, 9)
      match items[0].kind {
        @cbor.Array(inner) => {
          assert_eq(inner[0].kind, @cbor.Unsigned(1UL))
          expect_range(inner[0], 2, 3)
        }
        _ => fail("expected nested array")
      }
      match items[1].kind {
        @cbor.Map(entries) => {
          assert_eq(entries[0].0.kind, @cbor.TextString("a"))
          assert_eq(entries[0].1.kind, @cbor.ByteString(b"xy"[:]))
          expect_range(entries[0].0, 4, 6)
          expect_range(entries[0].1, 6, 9)
        }
        _ => fail("expected nested map")
      }
    }
    _ => fail("expected array")
  }
  assert_true(decoded(b"\x80").kind is @cbor.Array([]))
}

///|
test "generic maps preserve the original entry order and key types" {
  let value = decoded(b"\xa2\x61b\x02\x01\xf4")
  match value.kind {
    @cbor.Map(entries) => {
      assert_eq(entries.length(), 2)
      assert_eq(entries[0].0.kind, @cbor.TextString("b"))
      assert_eq(entries[0].1.kind, @cbor.Unsigned(2UL))
      assert_eq(entries[1].0.kind, @cbor.Unsigned(1UL))
      assert_eq(entries[1].1.kind, @cbor.Boolean(false))
      expect_range(entries[0].0, 1, 3)
      expect_range(entries[1].1, 5, 6)
    }
    _ => fail("expected map")
  }
  assert_true(decoded(b"\xa0").kind is @cbor.Map([]))
}

///|
test "every supported value type can be a distinct canonical map key" {
  let input = b"\xac\x00\x00\x20\x00\x40\x00\x60\x00\x80\x00\xa0\x00" +
    b"\xe0\x00\xf4\x00\xf5\x00\xf6\x00\xf7\x00\xf8\x20\x00"
  match decoded(input, profile=@cbor.Ctap2Canonical).kind {
    @cbor.Map(entries) => {
      assert_eq(entries.length(), 12)
      assert_eq(entries[0].0.kind, @cbor.Unsigned(0UL))
      assert_eq(entries[1].0.kind, @cbor.Negative(0UL))
      assert_eq(entries[2].0.kind, @cbor.ByteString(b""[:]))
      assert_eq(entries[3].0.kind, @cbor.TextString(""))
      assert_true(entries[4].0.kind is @cbor.Array([]))
      assert_true(entries[5].0.kind is @cbor.Map([]))
      assert_eq(entries[6].0.kind, @cbor.Simple(b'\x00'))
      assert_eq(entries[7].0.kind, @cbor.Boolean(false))
      assert_eq(entries[8].0.kind, @cbor.Boolean(true))
      assert_eq(entries[9].0.kind, @cbor.Null)
      assert_eq(entries[10].0.kind, @cbor.Undefined)
      assert_eq(entries[11].0.kind, @cbor.Simple(b'\x20'))
    }
    _ => fail("expected all supported key types")
  }
}

///|
test "booleans null undefined and all supported simple values decode" {
  for
    (input, kind) in [
      (b"\xf4", @cbor.Boolean(false)),
      (b"\xf5", @cbor.Boolean(true)),
      (b"\xf6", @cbor.Null),
      (b"\xf7", @cbor.Undefined),
    ] {
    assert_eq(decoded(input).kind, kind)
  }
  for number in 0..<20 {
    let input = Bytes::make(1, (0xe0 + number).to_byte())
    assert_eq(decoded(input).kind, @cbor.Simple(number.to_byte()))
  }
  for number in 32..<256 {
    let input = b"\xf8" + Bytes::make(1, number.to_byte())
    assert_eq(decoded(input).kind, @cbor.Simple(number.to_byte()))
    assert_eq(
      decoded(input, profile=@cbor.Ctap2Canonical).kind,
      @cbor.Simple(number.to_byte()),
    )
  }
}

///|
test "two byte simple values below 32 are malformed in both profiles" {
  for number in 0..<32 {
    let input = b"\xf8" + Bytes::make(1, number.to_byte())
    for profile in [@cbor.Generic, @cbor.Ctap2Canonical] {
      expect_error(
        @cbor.parse_all(input, profile~),
        offset=1,
        context="root.simple",
        kind=@cbor.InvalidSimpleValue(number.to_byte()),
      )
    }
  }
}

///|
test "parse one reports exact consumption with trailing bytes" {
  match @cbor.parse_one(b"\x42hi\xff\x00") {
    Ok(parsed) => {
      assert_eq(parsed.value.kind, @cbor.ByteString(b"hi"[:]))
      assert_eq(parsed.consumed, 3)
      expect_range(parsed.value, 0, 3)
    }
    Err(_) => fail("the trailing byte belongs to the next item")
  }
}

///|
test "parse one offsets support a consecutive CBOR sequence" {
  let input = b"\x01\x62hi\x82\xf4\xf6"
  let mut offset = 0
  for length in [1, 3, 3] {
    match @cbor.parse_one(input, offset~) {
      Ok(parsed) => {
        assert_eq(parsed.consumed, length)
        expect_range(parsed.value, offset, offset + length)
        offset += parsed.consumed
      }
      Err(_) => fail("each sequence item must decode")
    }
  }
  assert_eq(offset, input.length())
}

///|
test "source views with nonzero origins use view relative offsets" {
  let wrapped = b"prefix\x81\x42hi\xffsuffix"
  let view = wrapped[6:10]
  let value = decoded(view)
  expect_range(value, 0, 4)
  match value.kind {
    @cbor.Array(items) => {
      expect_range(items[0], 1, 4)
      assert_eq(items[0].kind, @cbor.ByteString(b"hi"[:]))
    }
    _ => fail("expected array")
  }
  expect_error(
    @cbor.parse_all(wrapped[10:11]),
    offset=0,
    context="root",
    kind=@cbor.UnexpectedBreak,
  )
}

///|
test "parse all rejects every trailing byte after the first complete item" {
  expect_error(
    @cbor.parse_all(b"\x00\x01\xff"),
    offset=1,
    context="trailing data",
    kind=@cbor.TrailingData(remaining=2),
  )
}

///|
test "invalid parse offsets report the supplied offset without overflow" {
  for offset in [-2147483648, -1, 2, 2147483647] {
    expect_error(
      @cbor.parse_one(b"\x00", offset~),
      offset=0,
      context="offset",
      kind=@cbor.InvalidOffset(offset),
    )
  }
  expect_error(
    @cbor.parse_one(b"\x00", offset=1),
    offset=1,
    context="root",
    kind=@cbor.UnexpectedEnd(expected=1, remaining=0),
  )
}

///|
test "empty input has a precise missing head error" {
  expect_error(
    @cbor.parse_all(b""),
    offset=0,
    context="root",
    kind=@cbor.UnexpectedEnd(expected=1, remaining=0),
  )
}

///|
test "all unsigned and negative argument widths reject every truncation" {
  for major in [0, 1] {
    for (additional, width) in [(24, 1), (25, 2), (26, 4), (27, 8)] {
      let complete = Bytes::make(1, (major * 32 + additional).to_byte()) +
        Bytes::make(width, b'\xff')
      for available in 0..<width {
        // ByteReader performs each u32 read atomically. A u64 consists of two
        // u32 reads, so a missing low word starts at byte five.
        let read_offset = if width == 8 && available >= 4 { 5 } else { 1 }
        let read_width = if width == 8 { 4 } else { width }
        let remaining = if read_offset == 5 { available - 4 } else { available }
        expect_error(
          @cbor.parse_all(complete[:1 + available]),
          offset=read_offset,
          context="root.argument",
          kind=@cbor.UnexpectedEnd(expected=read_width, remaining~),
        )
      }
    }
  }
}

///|
test "incomplete byte and text payloads identify the payload read" {
  for (input, context) in [(b"\x43ab", "root.bytes"), (b"\x63ab", "root.text")] {
    expect_error(
      @cbor.parse_all(input),
      offset=1,
      context~,
      kind=@cbor.UnexpectedEnd(expected=3, remaining=2),
    )
  }
}

///|
test "nested truncations report exact array and map locations" {
  for
    (input, offset, context) in [
      (b"\x82\x00", 2, "root.array[1]"),
      (b"\xa1", 1, "root.map[0].key"),
      (b"\xa1\x01", 2, "root.map[0].value"),
      (b"\x81\xa1\x01\x18", 4, "root.array[0].map[0].value.argument"),
    ] {
    expect_error(
      @cbor.parse_all(input),
      offset~,
      context~,
      kind=@cbor.UnexpectedEnd(expected=1, remaining=0),
    )
  }
}

///|
test "UTF8 rejects invalid leads overlong surrogates and out of range codepoints" {
  for
    payload in [
      b"\x80", b"\xbf", b"\xc0\xaf", b"\xc1\xbf", b"\xc2", b"\xc2A", b"\xe0\x80\xaf",
      b"\xe2\x82", b"\xe2\x28\xa1", b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\xf0\x80\x80\xaf",
      b"\xf0\x9f\x98", b"\xf0\x28\x8c\xbc", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80",
      b"\xfe", b"\xff",
    ] {
    let input = Bytes::make(1, (0x60 + payload.length()).to_byte()) + payload
    expect_error(
      @cbor.parse_all(input),
      offset=1,
      context="root.text",
      kind=@cbor.InvalidUtf8,
    )
  }
}

///|
test "UTF8 errors retain the first bad sequence start and nested context" {
  expect_error(
    @cbor.parse_all(b"\x64ab\xc0\xaf"),
    offset=3,
    context="root.text",
    kind=@cbor.InvalidUtf8,
  )
  expect_error(
    @cbor.parse_all(b"\x81\x62\xe2\x82"),
    offset=2,
    context="root.array[0].text",
    kind=@cbor.InvalidUtf8,
  )
  let wrapped = b"prefix\x64ab\xc0\xafsuffix"
  expect_error(
    @cbor.parse_all(wrapped[6:11]),
    offset=3,
    context="root.text",
    kind=@cbor.InvalidUtf8,
  )
}

///|
test "duplicate scalar map keys are rejected independently of their values" {
  for
    input in [
      b"\xa2\x01\x00\x01\x01", b"\xa2\x20\x00\x20\x01", b"\xa2\xf4\x00\xf4\x01",
      b"\xa2\xf5\x00\xf5\x01", b"\xa2\xf6\x00\xf6\x01", b"\xa2\xf7\x00\xf7\x01",
      b"\xa2\xe0\x00\xe0\x01",
    ] {
    expect_error(
      @cbor.parse_all(input),
      offset=3,
      context="root.map[1].key",
      kind=@cbor.DuplicateMapKey(first_offset=1),
    )
  }
}

///|
test "duplicate map keys ignore source range and integer encoding width" {
  expect_error(
    @cbor.parse_all(b"\xa2\x01\x00\x19\x00\x01\x01"),
    offset=3,
    context="root.map[1].key",
    kind=@cbor.DuplicateMapKey(first_offset=1),
  )
  expect_error(
    @cbor.parse_all(b"\xa2\x20\x00\x38\x00\x01"),
    offset=3,
    context="root.map[1].key",
    kind=@cbor.DuplicateMapKey(first_offset=1),
  )
}

///|
test "byte text and integer map keys retain their distinct types" {
  let value = decoded(b"\xa4\x41\x01\x00\x61\x01\x01\x01\x02\x20\x03")
  match value.kind {
    @cbor.Map(entries) => assert_eq(entries.length(), 4)
    _ => fail("expected four distinct typed keys")
  }
}

///|
test "duplicate byte and text keys ignore nonminimal string length heads" {
  for input in [b"\xa2\x41x\x00\x58\x01x\x01", b"\xa2\x61x\x00\x78\x01x\x01"] {
    expect_error(
      @cbor.parse_all(input),
      offset=4,
      context="root.map[1].key",
      kind=@cbor.DuplicateMapKey(first_offset=1),
    )
  }
}

///|
test "recursive array map keys use semantic equality" {
  expect_error(
    @cbor.parse_all(b"\xa2\x82\x01\x81\x02\x00\x82\x18\x01\x81\x19\x00\x02\x01"),
    offset=6,
    context="root.map[1].key",
    kind=@cbor.DuplicateMapKey(first_offset=1),
  )
  assert_true(
    decoded(b"\xa2\x82\x01\x02\x00\x82\x02\x01\x01").kind is @cbor.Map(_),
  )
}

///|
test "map valued keys ignore their own entry order for duplicate detection" {
  expect_error(
    @cbor.parse_all(b"\xa2\xa2\x01\x02\x03\x04\x00\xa2\x03\x04\x01\x02\x01"),
    offset=7,
    context="root.map[1].key",
    kind=@cbor.DuplicateMapKey(first_offset=1),
  )
  assert_true(
    decoded(b"\xa2\xa1\x01\x02\x00\xa1\x01\x03\x01").kind is @cbor.Map(_),
  )
}

///|
test "nested duplicate keys report the inner map path" {
  expect_error(
    @cbor.parse_all(b"\x81\xa2\x01\x00\x01\x01"),
    offset=4,
    context="root.array[0].map[1].key",
    kind=@cbor.DuplicateMapKey(first_offset=2),
  )
}

///|
test "declared lengths above Int range fail budgets before narrowing" {
  for
    (head, name) in [
      (b'\x5b', "max_string_bytes"),
      (b'\x7b', "max_string_bytes"),
      (b'\x9b', "max_array_items"),
      (b'\xbb', "max_map_pairs"),
    ] {
    let input = Bytes::make(1, head) + b"\xff\xff\xff\xff\xff\xff\xff\xff"
    let limit = match name {
      "max_array_items" => 4096
      "max_map_pairs" => 1024
      _ => 1048576
    }
    expect_error(
      @cbor.parse_all(input),
      offset=0,
      context="root",
      kind=@cbor.ResourceLimit(name~, limit~, actual=18446744073709551615UL),
    )
  }
  expect_error(
    @cbor.parse_all(
      b"\x5a\x80\x00\x00\x00",
      limits=@cbor.Limits::new(max_string_bytes=2147483647),
    ),
    offset=0,
    context="root",
    kind=@cbor.ResourceLimit(
      name="max_string_bytes",
      limit=2147483647,
      actual=2147483648UL,
    ),
  )
}

///|
test "input byte budget accepts its boundary and rejects the complete view" {
  let limits = @cbor.Limits::new(max_input_bytes=1)
  assert_eq(decoded(b"\x00", limits~).kind, @cbor.Unsigned(0UL))
  expect_error(
    @cbor.parse_one(b"\x00\x00", limits~),
    offset=0,
    context="input",
    kind=@cbor.ResourceLimit(name="max_input_bytes", limit=1, actual=2UL),
  )
}

///|
test "default input budget accepts one MiB and rejects one additional byte" {
  let limit = 1_048_576
  let exact = Bytes::make(limit, b'\x00')
  match @cbor.parse_one(exact) {
    Ok(parsed) => {
      assert_eq(parsed.consumed, 1)
      assert_eq(parsed.value.kind, @cbor.Unsigned(0UL))
      expect_range(parsed.value, 0, 1)
    }
    Err(_) => fail("a view at the default byte limit must parse")
  }
  let excessive = Bytes::make(limit + 1, b'\x00')
  let kind = @cbor.ResourceLimit(
    name="max_input_bytes",
    limit~,
    actual=1_048_577UL,
  )
  expect_error(@cbor.parse_one(excessive), offset=0, context="input", kind~)
  expect_error(@cbor.parse_all(excessive), offset=0, context="input", kind~)
}

///|
test "string budget counts UTF8 bytes and accepts exact empty boundaries" {
  let limits = @cbor.Limits::new(max_string_bytes=2)
  assert_eq(decoded(b"\x62\xc2\xa2", limits~).kind, @cbor.TextString("¢"))
  assert_eq(decoded(b"\x42ab", limits~).kind, @cbor.ByteString(b"ab"[:]))
  for input in [b"\x63\xe2\x82\xac", b"\x43abc"] {
    expect_error(
      @cbor.parse_all(input, limits~),
      offset=0,
      context="root",
      kind=@cbor.ResourceLimit(name="max_string_bytes", limit=2, actual=3UL),
    )
  }
  let zero = @cbor.Limits::new(max_string_bytes=0)
  assert_true(decoded(b"\x40", limits=zero).kind is @cbor.ByteString(_))
  assert_true(decoded(b"\x60", limits=zero).kind is @cbor.TextString(""))
}

///|
test "array and map item budgets apply before reading missing children" {
  assert_true(
    decoded(b"\x81\x00", limits=@cbor.Limits::new(max_array_items=1)).kind
    is @cbor.Array(_),
  )
  assert_true(
    decoded(b"\xa1\x00\x01", limits=@cbor.Limits::new(max_map_pairs=1)).kind
    is @cbor.Map(_),
  )
  expect_error(
    @cbor.parse_all(b"\x82", limits=@cbor.Limits::new(max_array_items=1)),
    offset=0,
    context="root",
    kind=@cbor.ResourceLimit(name="max_array_items", limit=1, actual=2UL),
  )
  expect_error(
    @cbor.parse_all(b"\xa2", limits=@cbor.Limits::new(max_map_pairs=1)),
    offset=0,
    context="root",
    kind=@cbor.ResourceLimit(name="max_map_pairs", limit=1, actual=2UL),
  )
}

///|
test "zero container size budgets permit empty containers" {
  let limits = @cbor.Limits::new(max_array_items=0, max_map_pairs=0)
  assert_true(decoded(b"\x80", limits~).kind is @cbor.Array([]))
  assert_true(decoded(b"\xa0", limits~).kind is @cbor.Map([]))
}

///|
test "depth budget counts containers with scalar root at zero" {
  let zero = @cbor.Limits::new(max_depth=0)
  assert_eq(decoded(b"\x00", limits=zero).kind, @cbor.Unsigned(0UL))
  expect_error(
    @cbor.parse_all(b"\x80", limits=zero),
    offset=0,
    context="root",
    kind=@cbor.ResourceLimit(name="max_depth", limit=0, actual=1UL),
  )
  let two = @cbor.Limits::new(max_depth=2)
  assert_true(decoded(b"\x81\xa1\x00\x00", limits=two).kind is @cbor.Array(_))
  expect_error(
    @cbor.parse_all(b"\x81\xa1\x00\x80", limits=two),
    offset=3,
    context="root.array[0].map[0].value",
    kind=@cbor.ResourceLimit(name="max_depth", limit=2, actual=3UL),
  )
}

///|
test "hard depth boundary permits 64 containers with an explicit limit" {
  let limits = @cbor.Limits::new(max_depth=64)
  let permitted = Bytes::make(64, b'\x81') + b"\x00"
  assert_true(decoded(permitted, limits~).kind is @cbor.Array(_))
  let excessive = Bytes::make(65, b'\x81') + b"\x00"
  let mut context = "root"
  for _ in 0..<64 {
    context += ".array[0]"
  }
  expect_error(
    @cbor.parse_all(excessive, limits~),
    offset=64,
    context~,
    kind=@cbor.ResourceLimit(name="max_depth", limit=64, actual=65UL),
  )
}

///|
test "value budget counts root map keys values and empty containers" {
  assert_true(
    decoded(b"\xa1\x00\x01", limits=@cbor.Limits::new(max_values=3)).kind
    is @cbor.Map(_),
  )
  expect_error(
    @cbor.parse_all(b"\xa1\x00\x01", limits=@cbor.Limits::new(max_values=2)),
    offset=2,
    context="root.map[0].value",
    kind=@cbor.ResourceLimit(name="max_values", limit=2, actual=3UL),
  )
  expect_error(
    @cbor.parse_all(b"\x80", limits=@cbor.Limits::new(max_values=0)),
    offset=0,
    context="root",
    kind=@cbor.ResourceLimit(name="max_values", limit=0, actual=1UL),
  )
}

///|
test "every invalid limit is rejected even for an otherwise valid scalar" {
  for
    (limits, name, value) in [
      (@cbor.Limits::new(max_input_bytes=-1), "max_input_bytes", -1),
      (@cbor.Limits::new(max_string_bytes=-1), "max_string_bytes", -1),
      (@cbor.Limits::new(max_array_items=-1), "max_array_items", -1),
      (@cbor.Limits::new(max_map_pairs=-1), "max_map_pairs", -1),
      (@cbor.Limits::new(max_depth=-1), "max_depth", -1),
      (@cbor.Limits::new(max_depth=65), "max_depth", 65),
      (@cbor.Limits::new(max_values=-1), "max_values", -1),
    ] {
    expect_error(
      @cbor.parse_all(b"\x00", limits~),
      offset=0,
      context="limits",
      kind=@cbor.InvalidLimit(name~, value~),
    )
  }
}

///|
test "tags are explicitly unsupported and forbidden in the CTAP profile" {
  for (input, tag) in [(b"\xc0\x00", 0UL), (b"\xd8\x18\x00", 24UL)] {
    expect_error(
      @cbor.parse_all(input),
      offset=0,
      context="root",
      kind=@cbor.UnsupportedTag(tag),
    )
    expect_error(
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical),
      offset=0,
      context="root",
      kind=@cbor.ForbiddenTag(tag),
    )
  }
}

///|
test "all floating point widths are explicitly unsupported" {
  for
    (input, width) in [
      (b"\xf9\x00\x00", 2),
      (b"\xfa\x00\x00\x00\x00", 4),
      (b"\xfb\x00\x00\x00\x00\x00\x00\x00\x00", 8),
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
test "truncated simple and float payloads identify the incomplete read" {
  expect_error(
    @cbor.parse_all(b"\xf8"),
    offset=1,
    context="root.simple",
    kind=@cbor.UnexpectedEnd(expected=1, remaining=0),
  )
  for (head, width) in [(b'\xf9', 2), (b'\xfa', 4), (b'\xfb', 8)] {
    for available in 0..<width {
      let input = Bytes::make(1, head) + Bytes::make(available, b'\x00')
      expect_error(
        @cbor.parse_all(input),
        offset=1,
        context="root.float",
        kind=@cbor.UnexpectedEnd(expected=width, remaining=available),
      )
    }
  }
}

///|
test "indefinite lengths have explicit profile specific errors" {
  for major in 2..<6 {
    let input = Bytes::make(1, (major * 32 + 31).to_byte()) + b"\xff"
    expect_error(
      @cbor.parse_all(input),
      offset=0,
      context="root",
      kind=@cbor.UnsupportedIndefiniteLength(major_type=major),
    )
    expect_error(
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical),
      offset=0,
      context="root",
      kind=@cbor.IndefiniteLengthNotAllowed,
    )
  }
}

///|
test "reserved additional information and break cannot become values" {
  for major in 0..<8 {
    for additional in 28..<31 {
      let input = Bytes::make(1, (major * 32 + additional).to_byte())
      expect_error(
        @cbor.parse_all(input),
        offset=0,
        context="root",
        kind=@cbor.InvalidAdditionalInfo(additional.to_byte()),
      )
    }
  }
  for major in [0, 1, 6] {
    let input = Bytes::make(1, (major * 32 + 31).to_byte())
    expect_error(
      @cbor.parse_all(input),
      offset=0,
      context="root",
      kind=@cbor.InvalidAdditionalInfo(b'\x1f'),
    )
  }
  expect_error(
    @cbor.parse_all(b"\x81\xff"),
    offset=1,
    context="root.array[0]",
    kind=@cbor.UnexpectedBreak,
  )
}

///|
test "canonical mode rejects nonminimal heads for every sized type" {
  for
    input in [
      b"\x18\x17", b"\x19\x00\xff", b"\x1a\x00\x00\xff\xff", b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff",
      b"\x38\x00", b"\x58\x00", b"\x78\x00", b"\x98\x00", b"\xb8\x00",
    ] {
    ignore(decoded(input))
    expect_error(
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical),
      offset=0,
      context="root",
      kind=@cbor.NonMinimalEncoding,
    )
  }
}

///|
test "canonical map ordering uses major type before encoded length" {
  // Unsigned 24 has a two-byte encoding and must precede one-byte negative -1.
  let ordered = b"\xa2\x18\x18\xf4\x20\xf5"
  assert_true(
    decoded(ordered, profile=@cbor.Ctap2Canonical).kind is @cbor.Map(_),
  )
  let reversed = b"\xa2\x20\xf4\x18\x18\xf5"
  assert_true(decoded(reversed).kind is @cbor.Map(_))
  expect_error(
    @cbor.parse_all(reversed, profile=@cbor.Ctap2Canonical),
    offset=3,
    context="root.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=1),
  )
}

///|
test "canonical compound map keys use encoded length before byte order" {
  // [0,0,0] encodes in four bytes, [24,24] in five. Their array heads
  // would give the opposite order under raw-byte-only sorting.
  let ordered = b"\xa2\x83\x00\x00\x00\x00\x82\x18\x18\x18\x18\x01"
  assert_true(
    decoded(ordered, profile=@cbor.Ctap2Canonical).kind is @cbor.Map(_),
  )
  let reversed = b"\xa2\x82\x18\x18\x18\x18\x00\x83\x00\x00\x00\x01"
  assert_true(decoded(reversed).kind is @cbor.Map(_))
  expect_error(
    @cbor.parse_all(reversed, profile=@cbor.Ctap2Canonical),
    offset=7,
    context="root.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=1),
  )
}

///|
test "canonical equal length map keys compare original encoding bytes" {
  assert_true(
    decoded(b"\xa2\x41a\x00\x41b\x01", profile=@cbor.Ctap2Canonical).kind
    is @cbor.Map(_),
  )
  expect_error(
    @cbor.parse_all(b"\xa2\x41b\x00\x41a\x01", profile=@cbor.Ctap2Canonical),
    offset=4,
    context="root.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=1),
  )
}

///|
test "canonical ordering is enforced inside map valued keys" {
  assert_true(
    decoded(b"\xa1\xa2\x01\x00\x02\x00\x00", profile=@cbor.Ctap2Canonical).kind
    is @cbor.Map(_),
  )
  expect_error(
    @cbor.parse_all(
      b"\xa1\xa2\x02\x00\x01\x00\x00",
      profile=@cbor.Ctap2Canonical,
    ),
    offset=4,
    context="root.map[0].key.map[1].key",
    kind=@cbor.UnsortedMapKey(previous_offset=2),
  )
}

///|
test "canonical mode accepts four container layers and rejects five" {
  assert_true(
    decoded(b"\x81\x81\x81\x81\x00", profile=@cbor.Ctap2Canonical).kind
    is @cbor.Array(_),
  )
  let five = b"\x81\x81\x81\x81\x80"
  assert_true(decoded(five).kind is @cbor.Array(_))
  expect_error(
    @cbor.parse_all(five, profile=@cbor.Ctap2Canonical),
    offset=4,
    context="root.array[0].array[0].array[0].array[0]",
    kind=@cbor.ResourceLimit(name="ctap2_container_depth", limit=4, actual=5UL),
  )
}

///|
test "synthetic Base64URL attestation shaped CBOR flows through the public API" {
  // Synthetic structural fixture, created locally for this test under the
  // project Apache-2.0 license. Independent Python int.to_bytes encoder input
  // {'fmt':'none', 'authData':bytes([0,1,255]), 'attStmt':{}} produced hex
  // a363666d74646e6f6e65686175746844617461430001ff6761747453746d74a0.
  // Python base64.urlsafe_b64encode produced the literal below.
  match @base64url.decode("o2NmbXRkbm9uZWhhdXRoRGF0YUMAAf9nYXR0U3RtdKA") {
    Ok(input) => {
      assert_eq(
        input, b"\xa3\x63fmt\x64none\x68authData\x43\x00\x01\xff\x67attStmt\xa0",
      )
      let value = decoded(input)
      expect_range(value, 0, 32)
      match value.kind {
        @cbor.Map(entries) => {
          assert_eq(entries.length(), 3)
          assert_eq(entries[0].0.kind, @cbor.TextString("fmt"))
          assert_eq(entries[0].1.kind, @cbor.TextString("none"))
          assert_eq(entries[1].0.kind, @cbor.TextString("authData"))
          assert_eq(entries[1].1.kind, @cbor.ByteString(b"\x00\x01\xff"[:]))
          assert_eq(entries[2].0.kind, @cbor.TextString("attStmt"))
          assert_true(entries[2].1.kind is @cbor.Map([]))
          expect_range(entries[0].0, 1, 5)
          expect_range(entries[0].1, 5, 10)
          expect_range(entries[1].0, 10, 19)
          expect_range(entries[1].1, 19, 23)
          expect_range(entries[2].0, 23, 31)
          expect_range(entries[2].1, 31, 32)
        }
        _ => fail("expected structural CBOR map")
      }
    }
    Err(_) => fail("synthetic fixture Base64URL must decode")
  }
}
