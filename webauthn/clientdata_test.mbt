///|
// Project-generated synthetic JSON and malformed-input fixtures, not official
// WebAuthn vectors. Byte offsets are counted in the original UTF-8 input.
fn client_ok(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @webauthn.ClientData raise {
  match @webauthn.parse_client_data(input, limits~) {
    Ok(value) => value
    Err(error) => fail("expected valid clientDataJSON: \{error.to_repr()}")
  }
}

///|
fn client_error(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> @webauthn.ParseError raise {
  match @webauthn.parse_client_data(input, limits~) {
    Err(error) => {
      assert_true(error.offset >= 0 && error.offset <= input.length())
      assert_true(error.context.has_prefix("clientDataJSON"))
      error
    }
    Ok(_) => fail("expected invalid clientDataJSON")
  }
}

///|
fn client_with_extra(extra : Bytes) -> Bytes {
  b"{\"type\":\"webauthn.create\",\"challenge\":\"AA\",\"origin\":\"https://example.test\",\"extra\":" +
  extra +
  b"}"
}

///|
test "clientdata create preserves exact raw bytes and parsed fields" {
  let raw = b" { \"type\" : \"webauthn.create\", \"challenge\": \"AA\", \"origin\":\"https://example.test\" }\n"
  let data = client_ok(raw)
  assert_eq(data.raw, raw[:])
  assert_eq(data.type_, "webauthn.create")
  assert_eq(data.challenge, "AA")
  assert_eq(data.origin, "https://example.test")
  assert_eq(data.cross_origin, None)
  assert_eq(data.top_origin, None)
  assert_eq(data.members.length(), 3)
}

///|
test "clientdata get accepts reordered fields and escaped names" {
  let raw = b"{\"origin\":\"https:\\/\\/example.test\",\"challenge\":\"AA\",\"ty\\u0070e\":\"webauthn.get\"}"
  let data = client_ok(raw)
  assert_eq(data.type_, "webauthn.get")
  assert_eq(data.origin, "https://example.test")
  assert_eq(data.raw, raw[:])
  assert_eq(data.members[2].name, "type")
}

///|
test "clientdata required strings may be empty without semantic approval" {
  let data = client_ok(b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}")
  assert_eq(data.type_, "")
  assert_eq(data.challenge, "")
  assert_eq(data.origin, "")
}

///|
test "clientdata accepts unknown type and challenge text structurally" {
  let data = client_ok(
    b"{\"type\":\"future-operation\",\"challenge\":\"not base64!\",\"origin\":\"untrusted\"}",
  )
  assert_eq(data.type_, "future-operation")
  assert_eq(data.challenge, "not base64!")
}

///|
test "clientdata reports every missing required field" {
  for
    (raw, name) in [
      (b"{\"challenge\":\"\",\"origin\":\"\"}", "type"),
      (b"{\"type\":\"\",\"origin\":\"\"}", "challenge"),
      (b"{\"type\":\"\",\"challenge\":\"\"}", "origin"),
      (b"{}", "type"),
    ] {
    let error = client_error(raw)
    assert_eq(error.kind, @webauthn.MissingField(name))
    assert_eq(error.offset, raw.length())
    assert_eq(error.context, "clientDataJSON." + name)
  }
}

///|
test "clientdata rejects wrong required field types at value byte" {
  for
    raw in [
      b"{\"type\":0,\"challenge\":\"\",\"origin\":\"\"}", b"{\"type\":true,\"challenge\":\"\",\"origin\":\"\"}",
      b"{\"type\":null,\"challenge\":\"\",\"origin\":\"\"}", b"{\"type\":[],\"challenge\":\"\",\"origin\":\"\"}",
      b"{\"type\":{},\"challenge\":\"\",\"origin\":\"\"}",
    ] {
    let error = client_error(raw)
    assert_eq(error.kind, @webauthn.WrongType(expected="string"))
    assert_eq(error.offset, 8)
  }
  assert_eq(
    client_error(b"{\"type\":\"\",\"challenge\":false,\"origin\":\"\"}").context,
    "clientDataJSON.challenge",
  )
  assert_eq(
    client_error(b"{\"type\":\"\",\"challenge\":\"\",\"origin\":null}").context,
    "clientDataJSON.origin",
  )
}

///|
test "clientdata optional booleans preserve absence and explicit false" {
  for
    (raw, expected) in [
      (
        b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"crossOrigin\":false}",
        false,
      ),
      (
        b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"crossOrigin\":true}",
        true,
      ),
    ] {
    let data = client_ok(raw)
    assert_eq(data.cross_origin, Some(expected))
    assert_eq(data.top_origin, None)
  }
}

///|
test "clientdata topOrigin stays optional and semantic relationship is deferred" {
  for extra in [b"\"crossOrigin\":true,", b"\"crossOrigin\":false,", b""] {
    let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"," +
      extra +
      b"\"topOrigin\":\"https://top.test\"}"
    assert_eq(client_ok(raw).top_origin, Some("https://top.test"))
  }
}

///|
test "clientdata optional fields reject null and wrong types" {
  for
    (raw, expected) in [
      (
        b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"crossOrigin\":null}",
        "boolean",
      ),
      (
        b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"crossOrigin\":\"false\"}",
        "boolean",
      ),
      (
        b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"topOrigin\":null}",
        "string",
      ),
      (
        b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"topOrigin\":false}",
        "string",
      ),
    ] {
    assert_eq(client_error(raw).kind, @webauthn.WrongType(expected~))
  }
}

///|
test "clientdata unknown fields accept all JSON kinds with raw range" {
  for
    value in [
      b"null", b"false", b"true", b"-1.25e+4", b"\"text\"", b"[]", b"{}", b"[{\"nested\":[1,2]}]",
    ] {
    let raw = client_with_extra(value)
    let data = client_ok(raw)
    let field = data.members[3]
    assert_eq(field.name, "extra")
    assert_eq(data.raw[field.value_range.start:field.value_range.end], value[:])
  }
}

///|
test "clientdata rejects duplicate decoded known unknown and nested members" {
  for
    (raw, name) in [
      (
        b"{\"type\":\"\",\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}", "type",
      ),
      (
        b"{\"type\":\"\",\"ty\\u0070e\":\"\",\"challenge\":\"\",\"origin\":\"\"}",
        "type",
      ),
      (client_with_extra(b"{\"x\":0,\"\\u0078\":1}"), "x"),
      (client_with_extra(b"[{\"x\":0,\"x\":1}]"), "x"),
      (
        b"{\"x\":0,\"x\":1,\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}", "x",
      ),
    ] {
    match client_error(raw).kind {
      @webauthn.DuplicateMember(name=actual, first_offset~) => {
        assert_eq(actual, name)
        assert_true(first_offset > 0)
      }
      _ => fail("expected duplicate JSON member")
    }
  }
}

///|
test "clientdata duplicate error identifies both opening quotes" {
  let error = client_error(b"{\"type\":\"\",\"ty\\u0070e\":\"\"}")
  assert_eq(error.offset, 11)
  assert_eq(error.kind, @webauthn.DuplicateMember(name="type", first_offset=1))
}

///|
test "clientdata parses Unicode literals and valid surrogate pairs" {
  let raw = b"{\"type\":\"webauthn.get\",\"challenge\":\"\\ud83d\\ude00\",\"origin\":\"\xe6\xb5\x8b\xe8\xaf\x95\"}"
  let data = client_ok(raw)
  assert_eq(data.challenge, "😀")
  assert_eq(data.origin, "测试")
  assert_eq(data.raw, raw[:])
}

///|
test "clientdata rejects malformed Unicode and ordinary escapes" {
  for
    value in [
      b"\"\\uD800\"", b"\"\\uDC00\"", b"\"\\uD800\\u0041\"", b"\"\\uXX00\"", b"\"\\q\"",
      b"\"line\nfeed\"", b"\"\x00\"",
    ] {
    assert_eq(
      client_error(client_with_extra(value)).kind,
      @webauthn.InvalidJson,
    )
  }
}

///|
test "clientdata strict UTF8 rejects malformed sequences even in unknown fields" {
  for
    bytes in [
      b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82", b"\x80",
      b"\xe2A\xac",
    ] {
    let prefix = b"{\"type\":\""
    let error = client_error(
      prefix + bytes + b"\",\"challenge\":\"\",\"origin\":\"\"}",
    )
    assert_eq(error.kind, @webauthn.InvalidUtf8)
    assert_eq(error.offset, prefix.length())
  }
}

///|
test "clientdata initial UTF8 BOM is skipped for parsing and retained raw" {
  let raw = b"\xef\xbb\xbf{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  let data = client_ok(raw)
  assert_eq(data.raw, raw[:])
  assert_eq(data.members[0].key_range.start, 4)
  assert_eq(client_error(b" \xef\xbb\xbf{}").kind, @webauthn.InvalidJson)
}

///|
test "clientdata byte ranges stay relative to a supplied subview" {
  let raw = b"prefix{\"type\":\"x\",\"challenge\":\"\",\"origin\":\"\"}suffix"
  let input = raw[6:raw.length() - 6]
  let data = client_ok(input)
  let first = data.members[0]
  assert_eq(first.key_range, { start: 1, end: 7, })
  assert_eq(first.value_range, { start: 8, end: 11, })
  assert_eq(data.raw, input)
  assert_eq(data.raw[first.key_range.start:first.key_range.end], b"\"type\""[:])
}

///|
test "clientdata rejects every proper truncation of a minimal document" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  for end in 0..<raw.length() {
    let error = client_error(raw[:end])
    assert_eq(error.kind, @webauthn.UnexpectedEnd(expected=1, remaining=0))
  }
}

///|
test "clientdata rejects truncated escapes numbers literals and containers" {
  for
    raw in [
      b"{\"x\":\"\\", b"{\"x\":\"\\u12", b"{\"x\":\"\\uD800\\u", b"{\"x\":tru", b"{\"x\":1e",
      b"{\"x\":-", b"{\"x\":[0", b"{\"x\":{",
    ] {
    assert_eq(
      client_error(raw).kind,
      @webauthn.UnexpectedEnd(expected=1, remaining=0),
    )
  }
}

///|
test "clientdata rejects malformed JSON punctuation and number grammar" {
  for
    value in [
      b"[1,]", b"{\"x\":0,}", b"{x:0}", b"{\"x\" 0}", b"[1 2]", b"01", b"-01", b"+1",
      b".1", b"1.", b"1e+", b"NaN", b"Infinity", b"undefined", b"TRUE", b"'text'",
    ] {
    client_error(client_with_extra(value)) |> ignore
  }
}

///|
test "clientdata rejects valid JSON nonobject roots" {
  for raw in [b"[]", b"\"text\"", b"null", b"true", b"0", b"-1.2e3"] {
    assert_eq(client_error(raw).kind, @webauthn.WrongType(expected="object"))
  }
}

///|
test "clientdata rejects trailing JSON or garbage while accepting whitespace" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  client_ok(raw + b" \r\n\t") |> ignore
  for tail in [b"{}", b"false", b"\x00", b"garbage"] {
    let error = client_error(raw + tail)
    assert_eq(error.offset, raw.length())
    assert_eq(error.kind, @webauthn.TrailingData(remaining=tail.length()))
  }
}

///|
test "clientdata input budget accepts exact maximum and rejects oversize" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  client_ok(raw, limits=@cbor.Limits::new(max_input_bytes=raw.length()))
  |> ignore
  let error = client_error(
    raw,
    limits=@cbor.Limits::new(max_input_bytes=raw.length() - 1),
  )
  assert_eq(
    error.kind,
    @webauthn.ResourceLimit(
      name="max_input_bytes",
      limit=raw.length() - 1,
      actual=raw.length().to_uint64(),
    ),
  )
  let huge = Bytes::make(1_048_577, b' ')
  assert_eq(
    client_error(huge).kind,
    @webauthn.ResourceLimit(
      name="max_input_bytes",
      limit=1_048_576,
      actual=1_048_577UL,
    ),
  )
}

///|
test "clientdata string budget counts encoded content and member names" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  client_ok(raw, limits=@cbor.Limits::new(max_string_bytes=9)) |> ignore
  assert_true(
    client_error(raw, limits=@cbor.Limits::new(max_string_bytes=8)).kind
    is @webauthn.ResourceLimit(name="max_string_bytes", ..),
  )
  let escaped = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\",\"extra\":\"\\u0041\\u0042\"}"
  client_ok(escaped, limits=@cbor.Limits::new(max_string_bytes=12)) |> ignore
  assert_true(
    client_error(escaped, limits=@cbor.Limits::new(max_string_bytes=11)).kind
    is @webauthn.ResourceLimit(name="max_string_bytes", ..),
  )
}

///|
test "clientdata map budget applies to known unknown and nested members" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  client_ok(raw, limits=@cbor.Limits::new(max_map_pairs=3)) |> ignore
  assert_true(
    client_error(raw, limits=@cbor.Limits::new(max_map_pairs=2)).kind
    is @webauthn.ResourceLimit(name="max_map_pairs", ..),
  )
  let nested = client_with_extra(b"{\"a\":0,\"b\":1,\"c\":2,\"d\":3,\"e\":4}")
  assert_true(
    client_error(nested, limits=@cbor.Limits::new(max_map_pairs=4)).kind
    is @webauthn.ResourceLimit(name="max_map_pairs", ..),
  )
}

///|
test "clientdata array budget applies before unknown elements are allocated" {
  let raw = client_with_extra(b"[0,1]")
  client_ok(raw, limits=@cbor.Limits::new(max_array_items=2)) |> ignore
  assert_true(
    client_error(raw, limits=@cbor.Limits::new(max_array_items=1)).kind
    is @webauthn.ResourceLimit(name="max_array_items", limit=1, actual=2UL),
  )
  client_ok(
    client_with_extra(b"[]"),
    limits=@cbor.Limits::new(max_array_items=0),
  )
  |> ignore
}

///|
test "clientdata depth budget counts root object and unknown containers" {
  let raw = client_with_extra(b"[{}]")
  client_ok(raw, limits=@cbor.Limits::new(max_depth=3)) |> ignore
  assert_true(
    client_error(raw, limits=@cbor.Limits::new(max_depth=2)).kind
    is @webauthn.ResourceLimit(name="max_depth", limit=2, actual=3UL),
  )
  assert_true(
    client_error(b"{}", limits=@cbor.Limits::new(max_depth=0)).kind
    is @webauthn.ResourceLimit(name="max_depth", limit=0, actual=1UL),
  )
}

///|
test "clientdata node budget counts object keys and values" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  client_ok(raw, limits=@cbor.Limits::new(max_values=7)) |> ignore
  assert_true(
    client_error(raw, limits=@cbor.Limits::new(max_values=6)).kind
    is @webauthn.ResourceLimit(name="max_values", limit=6, actual=7UL),
  )
  assert_true(
    client_error(raw, limits=@cbor.Limits::new(max_values=0)).kind
    is @webauthn.ResourceLimit(name="max_values", limit=0, actual=1UL),
  )
}

///|
test "clientdata invalid budgets fail before scanning" {
  for
    limits in [
      @cbor.Limits::new(max_input_bytes=-1),
      @cbor.Limits::new(max_string_bytes=-1),
      @cbor.Limits::new(max_array_items=-1),
      @cbor.Limits::new(max_map_pairs=-1),
      @cbor.Limits::new(max_values=-1),
      @cbor.Limits::new(max_depth=-1),
      @cbor.Limits::new(max_depth=65),
    ] {
    assert_true(client_error(b"", limits~).kind is @webauthn.InvalidLimit(..))
  }
}

///|
test "clientdata all one byte suffix mutations stay bounded without panic" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  for byte in 0..<256 {
    match @webauthn.parse_client_data(raw + Bytes::make(1, byte.to_byte())) {
      Ok(data) => assert_eq(data.raw.length(), raw.length() + 1)
      Err(error) =>
        assert_true(error.offset >= 0 && error.offset <= raw.length() + 1)
    }
  }
}

///|
test "clientdata accepts the exact default 1MiB input without rewriting raw" {
  let document = b"{\"type\":\"\",\"challenge\":\"\",\"origin\":\"\"}"
  let raw = document + Bytes::make(1_048_576 - document.length(), b' ')
  let data = client_ok(raw)
  assert_eq(data.raw, raw[:])
}

///|
test "clientdata hard recursion ceiling accepts 64 and rejects 65 containers" {
  let limits = @cbor.Limits::new(max_depth=64)
  let mut value = b"0"
  for _ in 0..<63 {
    value = b"[" + value + b"]"
  }
  client_ok(client_with_extra(value), limits~) |> ignore
  let error = client_error(client_with_extra(b"[" + value + b"]"), limits~)
  assert_eq(
    error.kind,
    @webauthn.ResourceLimit(name="max_depth", limit=64, actual=65UL),
  )
}

///|
test "clientdata invalid UTF8 offset counts bytes after multibyte text" {
  let prefix = b"{\"type\":\"\xe6\xb5\x8b\xe8\xaf\x95\" ,\"extra\":\""
  let error = client_error(prefix + b"\xff\"}")
  assert_eq(error.kind, @webauthn.InvalidUtf8)
  assert_eq(error.offset, prefix.length())
}

///|
test "clientdata decodes every standard JSON escape without changing raw" {
  let raw = b"{\"type\":\"\",\"challenge\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0000\",\"origin\":\"\"}"
  let data = client_ok(raw)
  assert_eq(data.challenge, "\"\\/\b\u{0c}\n\r\t\u{0}")
  assert_eq(data.raw, raw[:])
}
