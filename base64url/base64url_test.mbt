///|
test "empty input" {
  assert_eq(@base64url.encode(b""), Ok(""))
  assert_eq(@base64url.encode(b"", padding=true), Ok(""))
  assert_eq(@base64url.decode(""), Ok(b""))
}

///|
test "RFC 4648 section 10 vectors" {
  // These ASCII vectors use the alphabet shared by Base64 and Base64URL.
  let vectors : Array[(Bytes, String, String)] = [
    (b"f", "Zg", "Zg=="),
    (b"fo", "Zm8", "Zm8="),
    (b"foo", "Zm9v", "Zm9v"),
    (b"foob", "Zm9vYg", "Zm9vYg=="),
    (b"fooba", "Zm9vYmE", "Zm9vYmE="),
    (b"foobar", "Zm9vYmFy", "Zm9vYmFy"),
  ]
  for (bytes, plain, padded) in vectors {
    assert_eq(@base64url.encode(bytes), Ok(plain))
    assert_eq(@base64url.encode(bytes, padding=true), Ok(padded))
    assert_eq(@base64url.decode(plain), Ok(bytes))
    assert_eq(@base64url.decode(padded), Ok(bytes))
  }
}

///|
test "URL-safe alphabet" {
  assert_eq(@base64url.encode(b"\xfb\xff\xff"), Ok("-___"))
  assert_eq(@base64url.decode("-___"), Ok(b"\xfb\xff\xff"))
  assert_eq(@base64url.encode(b"\xff"), Ok("_w"))
  assert_eq(@base64url.decode("_w=="), Ok(b"\xff"))
  assert_eq(@base64url.encode(b"\xff\xff"), Ok("__8"))
  assert_eq(@base64url.decode("__8="), Ok(b"\xff\xff"))
}

///|
test "independent long binary known-answer vector" {
  // Synthetic bytes 0..47. Expected text independently checked with Node.js
  // Buffer.toString("base64url") and Python base64.urlsafe_b64encode.
  let bytes = Bytes::makei(48, index => index.to_byte())
  let expected = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"
  assert_eq(@base64url.encode(bytes), Ok(expected))
  assert_eq(@base64url.decode(expected), Ok(bytes))
}

///|
test "reject standard alphabet" {
  assert_eq(
    @base64url.decode("+w=="),
    Err(@base64url.InvalidCharacter(position=0)),
  )
  assert_eq(
    @base64url.decode("/w=="),
    Err(@base64url.InvalidCharacter(position=0)),
  )
  assert_eq(
    @base64url.decode("AA+A"),
    Err(@base64url.InvalidCharacter(position=2)),
  )
}

///|
test "reject whitespace and controls" {
  for input in [" Zg", "Z g", "Zg ", "Zg\n", "Zg\r", "Zg\t", "Zg\u0000"] {
    assert_true(@base64url.decode(input) is Err(@base64url.InvalidCharacter(_)))
  }
}

///|
test "reject Unicode and preserve error offsets" {
  assert_eq(
    @base64url.decode("Zgé"),
    Err(@base64url.InvalidCharacter(position=2)),
  )
  assert_eq(
    @base64url.decode("Zg中"),
    Err(@base64url.InvalidCharacter(position=2)),
  )
  assert_eq(
    @base64url.decode("Zg😀"),
    Err(@base64url.InvalidCharacter(position=2)),
  )
}

///|
test "reject all other ASCII characters" {
  for value in 0..<128 {
    match value {
      'A'..<='Z' | 'a'..<='z' | '0'..<='9' | '-' | '_' | '=' => ()
      _ => {
        let input = "AA" + String::make(1, value.to_byte().to_char()) + "A"
        assert_eq(
          @base64url.decode(input),
          Err(@base64url.InvalidCharacter(position=2)),
        )
      }
    }
  }
}

///|
test "reject impossible input lengths" {
  for input in ["A", "AAAAA", "AAAAAAAAA"] {
    assert_eq(@base64url.decode(input), Err(@base64url.InvalidEncoding))
  }
}

///|
test "reject malformed padding" {
  for
    input in [
      "=", "==", "===", "====", "A=", "A==", "A===", "AA=", "AA===", "AAA==", "AAAA=",
      "=AAA", "A=AA", "AA=A", "Zg==AA", "Zg==Zm8=", "Zg====",
    ] {
    assert_eq(@base64url.decode(input), Err(@base64url.InvalidEncoding))
  }
}

///|
test "reject nonzero unused bits" {
  for input in ["Zh", "Zh==", "Z_", "Z_==", "Zm9", "Zm9=", "Zm-", "Zm-="] {
    assert_eq(@base64url.decode(input), Err(@base64url.InvalidEncoding))
  }
}

///|
test "all final sextet values obey unused-bit constraints" {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  for value in 0..<64 {
    let character = alphabet[value:value + 1].to_owned()
    for padding in [false, true] {
      let two = "A" + character + (if padding { "==" } else { "" })
      if value % 16 == 0 {
        assert_eq(
          @base64url.decode(two),
          Ok(Bytes::make(1, (value >> 4).to_byte())),
        )
      } else {
        assert_eq(@base64url.decode(two), Err(@base64url.InvalidEncoding))
      }
      let three = "AA" + character + (if padding { "=" } else { "" })
      if value % 4 == 0 {
        assert_eq(
          @base64url.decode(three),
          Ok(Bytes::from_array([b'\x00', (value >> 2).to_byte()])),
        )
      } else {
        assert_eq(@base64url.decode(three), Err(@base64url.InvalidEncoding))
      }
    }
  }
}

///|
test "decoded binary can be consumed through ByteReader public API" {
  // Synthetic input 01 12 34 89 ab cd ef, independently encoded with Node.js.
  match @base64url.decode("ARI0iavN7w") {
    Ok(bytes) => {
      let reader = @bytereader.ByteReader::new(bytes)
      assert_eq(reader.read_u8(), Ok(b'\x01'))
      assert_eq(reader.read_u16_be(), Ok(0x1234U))
      assert_eq(reader.read_u32_be(), Ok(0x89abcdefU))
      assert_eq(reader.position(), 7)
      assert_true(reader.is_empty())
      assert_true(reader.read_u8() is Err(@bytereader.OutOfBounds(_)))
    }
    Err(_) => fail("known binary input must decode")
  }
}

///|
test "all single bytes round trip" {
  for value in 0..<256 {
    let bytes = Bytes::make(1, value.to_byte())
    for padding in [false, true] {
      match @base64url.encode(bytes, padding~) {
        Ok(encoded) => assert_eq(@base64url.decode(encoded), Ok(bytes))
        Err(_) => fail("single-byte input must encode")
      }
    }
  }
}

///|
test "deterministic binary round trips across group boundaries" {
  for length in 0..<258 {
    let bytes = Bytes::makei(length, index => (index * 73 + length).to_byte())
    for padding in [false, true] {
      match @base64url.encode(bytes, padding~) {
        Ok(encoded) => assert_eq(@base64url.decode(encoded), Ok(bytes))
        Err(_) => fail("bounded binary input must encode")
      }
    }
  }
}

///|
test "decode a substring view" {
  let wrapped = "prefix-_8=suffix"
  assert_eq(@base64url.decode(wrapped[6:10]), Ok(b"\xfb\xff"))
}

///|
test "accept exact maximum binary size" {
  let bytes = Bytes::make(@base64url.MAX_BYTES, b'\xff')
  for padding in [false, true] {
    match @base64url.encode(bytes, padding~) {
      Ok(encoded) => {
        assert_true(encoded.length() <= @base64url.MAX_ENCODED_LENGTH)
        assert_eq(@base64url.decode(encoded), Ok(bytes))
      }
      Err(_) => fail("maximum input size must encode")
    }
  }
}

///|
test "reject oversized binary input" {
  let length = @base64url.MAX_BYTES + 1
  let bytes = Bytes::make(length, b'\x00')
  assert_eq(
    @base64url.encode(bytes),
    Err(@base64url.InputTooLarge(actual=length, limit=@base64url.MAX_BYTES)),
  )
  assert_true(
    @base64url.encode(bytes, padding=true) is Err(@base64url.InputTooLarge(_)),
  )
}

///|
test "reject oversized encoded input before character processing" {
  let length = @base64url.MAX_ENCODED_LENGTH + 1
  let input = String::make(length, '!')
  assert_eq(
    @base64url.decode(input),
    Err(
      @base64url.InputTooLarge(
        actual=length,
        limit=@base64url.MAX_ENCODED_LENGTH,
      ),
    ),
  )
}

///|
test "reject decoded output beyond maximum even within encoded limit" {
  let prefix = String::make(@base64url.MAX_ENCODED_LENGTH - 4, 'A')
  assert_eq(
    @base64url.decode(prefix + "AAA="),
    Err(
      @base64url.InputTooLarge(
        actual=@base64url.MAX_BYTES + 1,
        limit=@base64url.MAX_BYTES,
      ),
    ),
  )
  assert_true(
    @base64url.decode(prefix + "AAA") is Err(@base64url.InputTooLarge(_)),
  )
  assert_eq(
    @base64url.decode(prefix + "AAAA"),
    Err(
      @base64url.InputTooLarge(
        actual=@base64url.MAX_BYTES + 2,
        limit=@base64url.MAX_BYTES,
      ),
    ),
  )
}

///|
test "reject malformed padded encodings after long prefixes" {
  // Synthetic zero-byte prefixes. These lengths enter the SIMD candidate
  // path on wasm/native, including its fallback for malformed encodings.
  for prefix_length in [28, 32, 60] {
    let prefix = String::make(prefix_length, 'A')
    let prefix_bytes = Bytes::make(prefix_length / 4 * 3, b'\x00')
    assert_eq(@base64url.decode(prefix + "Zg=="), Ok(prefix_bytes + b"f"))
    assert_eq(@base64url.decode(prefix + "Zm8="), Ok(prefix_bytes + b"fo"))
    for
      suffix in [
        "=AAA", "A=AA", "AA=A", "A===", "====", "Zg=A", "AA==AAAA", "AAA=AAAA", "Zg======",
        "Zh==", "Zm9=",
      ] {
      let input = prefix + suffix
      assert_true(input.length() >= 32)
      assert_eq(input.length() % 4, 0)
      assert_eq(@base64url.decode(input), Err(@base64url.InvalidEncoding))
    }
  }
}

///|
test "encode a nonzero-origin byte view" {
  let input = b"prefix\xfb\xffsuffix"
  let view = input[6:8]
  assert_eq(@base64url.encode(view), Ok("-_8"))
  assert_eq(@base64url.encode(view, padding=true), Ok("-_8="))
}

///|
test "decode substring errors use view-relative positions" {
  let input = "prefixAA+Asuffix"
  assert_eq(
    @base64url.decode(input),
    Err(@base64url.InvalidCharacter(position=8)),
  )
  assert_eq(
    @base64url.decode(input[6:10]),
    Err(@base64url.InvalidCharacter(position=2)),
  )
  let unicode = "prefixZg😀suffix"
  assert_eq(
    @base64url.decode(unicode[6:10]),
    Err(@base64url.InvalidCharacter(position=2)),
  )
}

///|
test "FB FF fixed vector encodes and decodes" {
  assert_eq(@base64url.encode(b"\xfb\xff"), Ok("-_8"))
  assert_eq(@base64url.encode(b"\xfb\xff", padding=true), Ok("-_8="))
  assert_eq(@base64url.decode("-_8"), Ok(b"\xfb\xff"))
  assert_eq(@base64url.decode("-_8="), Ok(b"\xfb\xff"))
}
