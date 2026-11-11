///|
test "empty input starts at the end" {
  let reader = @bytereader.ByteReader::new(b"")
  assert_eq(reader.position(), 0)
  assert_eq(reader.remaining(), 0)
  assert_true(reader.is_empty())
}

///|
test "read_u8 supports unsigned byte boundaries" {
  let reader = @bytereader.ByteReader::new(b"\x00\x7f\x80\xff")
  assert_eq(reader.read_u8(), Ok(b'\x00'))
  assert_eq(reader.read_u8(), Ok(b'\x7f'))
  assert_eq(reader.read_u8(), Ok(b'\x80'))
  assert_eq(reader.read_u8(), Ok(b'\xff'))
  assert_eq(reader.position(), 4)
  assert_eq(reader.remaining(), 0)
  assert_true(reader.is_empty())
}

///|
test "read_u16_be supports zero and unsigned boundaries" {
  let reader = @bytereader.ByteReader::new(
    b"\x00\x00\x00\x01\x7f\xff\x80\x00\xff\xff",
  )
  assert_eq(reader.read_u16_be(), Ok(0U))
  assert_eq(reader.read_u16_be(), Ok(1U))
  assert_eq(reader.read_u16_be(), Ok(32767U))
  assert_eq(reader.read_u16_be(), Ok(32768U))
  assert_eq(reader.read_u16_be(), Ok(65535U))
  assert_eq(reader.position(), 10)
  assert_true(reader.is_empty())
}

///|
test "read_u32_be supports zero and the full unsigned range" {
  let reader = @bytereader.ByteReader::new(
    b"\x00\x00\x00\x00\x00\x00\x00\x01\x7f\xff\xff\xff\x80\x00\x00\x00\xff\xff\xff\xff",
  )
  assert_eq(reader.read_u32_be(), Ok(0U))
  assert_eq(reader.read_u32_be(), Ok(1U))
  assert_eq(reader.read_u32_be(), Ok(2147483647U))
  assert_eq(reader.read_u32_be(), Ok(2147483648U))
  assert_eq(reader.read_u32_be(), Ok(4294967295U))
  assert_eq(reader.position(), 20)
  assert_true(reader.is_empty())
}

///|
test "consecutive mixed reads maintain the cursor" {
  let reader = @bytereader.ByteReader::new(b"\xab\x12\x34xy\x89\xab\xcd\xef")
  assert_eq(reader.read_u8(), Ok(b'\xab'))
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 8)
  assert_eq(reader.read_u16_be(), Ok(0x1234U))
  assert_eq(reader.position(), 3)
  assert_eq(reader.remaining(), 6)
  assert_eq(reader.read_bytes(2), Ok(b"xy"[:]))
  assert_eq(reader.position(), 5)
  assert_eq(reader.remaining(), 4)
  assert_eq(reader.read_u32_be(), Ok(0x89abcdefU))
  assert_eq(reader.position(), 9)
  assert_eq(reader.remaining(), 0)
  assert_true(reader.is_empty())
}

///|
test "read_bytes returns exactly the requested bytes" {
  let reader = @bytereader.ByteReader::new(b"abcdef")
  assert_eq(reader.read_bytes(2), Ok(b"ab"[:]))
  assert_eq(reader.read_bytes(3), Ok(b"cde"[:]))
  assert_eq(reader.position(), 5)
  assert_eq(reader.remaining(), 1)
  assert_false(reader.is_empty())
  assert_eq(reader.read_bytes(1), Ok(b"f"[:]))
  assert_true(reader.is_empty())
}

///|
test "zero length reads preserve the cursor at beginning middle and end" {
  let reader = @bytereader.ByteReader::new(b"ab")
  assert_eq(reader.read_bytes(0), Ok(b""[:]))
  assert_eq(reader.position(), 0)
  assert_eq(reader.remaining(), 2)
  assert_eq(reader.read_u8(), Ok(b'a'))
  assert_eq(reader.read_bytes(0), Ok(b""[:]))
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 1)
  assert_eq(reader.read_u8(), Ok(b'b'))
  assert_eq(reader.read_bytes(0), Ok(b""[:]))
  assert_eq(reader.position(), 2)
  assert_true(reader.is_empty())
}

///|
test "zero length reads succeed on empty input" {
  let reader = @bytereader.ByteReader::new(b"")
  assert_eq(reader.read_bytes(0), Ok(b""[:]))
  assert_eq(reader.position(), 0)
  assert_true(reader.is_empty())
}

///|
test "oversized reads report context and permit recovery" {
  let reader = @bytereader.ByteReader::new(b"abc")
  assert_eq(reader.read_u8(), Ok(b'a'))
  assert_eq(
    reader.read_bytes(3),
    Err(@bytereader.OutOfBounds(requested=3, position=1, remaining=2)),
  )
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 2)
  assert_eq(reader.read_bytes(2), Ok(b"bc"[:]))
  assert_true(reader.is_empty())
}

///|
test "negative read length returns InvalidLength without consuming bytes" {
  let reader = @bytereader.ByteReader::new(b"ab")
  assert_eq(reader.read_u8(), Ok(b'a'))
  assert_eq(
    reader.read_bytes(-1),
    Err(@bytereader.InvalidLength(requested=-1, position=1, remaining=1)),
  )
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 1)
  assert_eq(reader.read_u8(), Ok(b'b'))
}

///|
test "minimum Int length is rejected without arithmetic overflow" {
  let reader = @bytereader.ByteReader::new(b"a")
  assert_eq(
    reader.read_bytes(-2147483648),
    Err(
      @bytereader.InvalidLength(requested=-2147483648, position=0, remaining=1),
    ),
  )
  assert_eq(reader.position(), 0)
  assert_eq(reader.remaining(), 1)
}

///|
test "maximum Int length is rejected before adding to a nonzero cursor" {
  let reader = @bytereader.ByteReader::new(b"ab")
  assert_eq(reader.read_u8(), Ok(b'a'))
  assert_eq(
    reader.read_bytes(2147483647),
    Err(@bytereader.OutOfBounds(requested=2147483647, position=1, remaining=1)),
  )
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 1)
  assert_eq(reader.read_u8(), Ok(b'b'))
}

///|
test "read_u8 fails atomically on empty input" {
  let reader = @bytereader.ByteReader::new(b"")
  assert_eq(
    reader.read_u8(),
    Err(@bytereader.OutOfBounds(requested=1, position=0, remaining=0)),
  )
  assert_eq(reader.position(), 0)
  assert_true(reader.is_empty())
}

///|
test "read_u16_be fails atomically for every truncated width" {
  let input = b"\x12"
  for available in 0..<2 {
    let reader = @bytereader.ByteReader::new(input[:available])
    assert_eq(
      reader.read_u16_be(),
      Err(@bytereader.OutOfBounds(requested=2, position=0, remaining=available)),
    )
    assert_eq(reader.position(), 0)
    assert_eq(reader.remaining(), available)
    assert_eq(reader.read_bytes(available), Ok(input[:available]))
  }
}

///|
test "read_u32_be fails atomically for every truncated width" {
  let input = b"\x12\x34\x56"
  for available in 0..<4 {
    let reader = @bytereader.ByteReader::new(input[:available])
    assert_eq(
      reader.read_u32_be(),
      Err(@bytereader.OutOfBounds(requested=4, position=0, remaining=available)),
    )
    assert_eq(reader.position(), 0)
    assert_eq(reader.remaining(), available)
    assert_eq(reader.read_bytes(available), Ok(input[:available]))
  }
}

///|
test "failed integer reads preserve a nonzero cursor" {
  let reader = @bytereader.ByteReader::new(b"\xaa\xbb")
  assert_eq(reader.read_u8(), Ok(b'\xaa'))
  assert_eq(
    reader.read_u16_be(),
    Err(@bytereader.OutOfBounds(requested=2, position=1, remaining=1)),
  )
  assert_eq(reader.position(), 1)
  assert_eq(
    reader.read_u32_be(),
    Err(@bytereader.OutOfBounds(requested=4, position=1, remaining=1)),
  )
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 1)
  assert_eq(reader.read_u8(), Ok(b'\xbb'))
}

///|
test "every read reports an error after exact consumption" {
  let reader = @bytereader.ByteReader::new(b"\x01\x02\x03\x04")
  assert_eq(reader.read_u32_be(), Ok(0x01020304U))
  assert_eq(
    reader.read_u8(),
    Err(@bytereader.OutOfBounds(requested=1, position=4, remaining=0)),
  )
  assert_eq(
    reader.read_u16_be(),
    Err(@bytereader.OutOfBounds(requested=2, position=4, remaining=0)),
  )
  assert_eq(
    reader.read_u32_be(),
    Err(@bytereader.OutOfBounds(requested=4, position=4, remaining=0)),
  )
  assert_eq(
    reader.read_bytes(1),
    Err(@bytereader.OutOfBounds(requested=1, position=4, remaining=0)),
  )
  assert_eq(reader.position(), 4)
  assert_eq(reader.remaining(), 0)
  assert_true(reader.is_empty())
}

///|
test "a nonzero-origin source view defines the complete readable range" {
  let input = b"prefix\x12\x34\x56\x78suffix"
  let view = input[6:10]
  let reader = @bytereader.ByteReader::new(view)
  assert_eq(reader.position(), 0)
  assert_eq(reader.remaining(), 4)
  assert_eq(reader.read_u16_be(), Ok(0x1234U))
  assert_eq(reader.read_bytes(2), Ok(b"\x56\x78"[:]))
  assert_eq(reader.position(), 4)
  assert_true(reader.is_empty())
  assert_eq(
    reader.read_u8(),
    Err(@bytereader.OutOfBounds(requested=1, position=4, remaining=0)),
  )
  assert_eq(input, b"prefix\x12\x34\x56\x78suffix")
}

///|
test "returned byte views remain valid across later reads" {
  let reader = @bytereader.ByteReader::new(b"abcd")
  let first = reader.read_bytes(2)
  assert_eq(reader.read_bytes(2), Ok(b"cd"[:]))
  assert_eq(first, Ok(b"ab"[:]))
  assert_eq(reader.position(), 4)
}

///|
test "12 34 56 78 supports consecutive u8 u16_be u8 reads" {
  let reader = @bytereader.ByteReader::new(b"\x12\x34\x56\x78")
  assert_eq(reader.position(), 0)
  assert_eq(reader.remaining(), 4)
  assert_false(reader.is_empty())
  assert_eq(reader.read_u8(), Ok(b'\x12'))
  assert_eq(reader.position(), 1)
  assert_eq(reader.remaining(), 3)
  assert_false(reader.is_empty())
  assert_eq(reader.read_u16_be(), Ok(0x3456U))
  assert_eq(reader.position(), 3)
  assert_eq(reader.remaining(), 1)
  assert_false(reader.is_empty())
  assert_eq(reader.read_u8(), Ok(b'\x78'))
  assert_eq(reader.position(), 4)
  assert_eq(reader.remaining(), 0)
  assert_true(reader.is_empty())
  assert_eq(
    reader.read_u8(),
    Err(@bytereader.OutOfBounds(requested=1, position=4, remaining=0)),
  )
  assert_eq(reader.position(), 4)
}
