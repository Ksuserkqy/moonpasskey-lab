///|
/// A failed read reports the requested byte count and the unchanged cursor.
#derive(Eq, Debug)
pub(all) enum ReadError {
  InvalidLength(requested~ : Int32, position~ : Int32, remaining~ : Int32)
  OutOfBounds(requested~ : Int32, position~ : Int32, remaining~ : Int32)
}

///|
pub extend ReadError with Eq::{equal, not_equal}

///|
pub extend ReadError with Debug::{to_repr}

///|
/// A forward-only reader over immutable bytes. Positions are relative to the
/// supplied view, and failed reads leave the position unchanged.
pub struct ByteReader {
  priv data : BytesView
  priv mut offset : Int32
}

///|
/// Creates a reader positioned at the beginning of the supplied view.
pub fn ByteReader::new(data : BytesView) -> ByteReader {
  { data, offset: 0, }
}

///|
/// Returns the number of bytes consumed from the supplied view.
pub fn ByteReader::position(self : ByteReader) -> Int32 {
  self.offset
}

///|
/// Returns the number of bytes available for subsequent reads.
pub fn ByteReader::remaining(self : ByteReader) -> Int32 {
  self.data.length() - self.offset
}

///|
/// Returns whether the cursor has reached the end of the supplied view.
pub fn ByteReader::is_empty(self : ByteReader) -> Bool {
  self.remaining() == 0
}

///|
/// Reads exactly `length` bytes. Zero-length reads succeed even at the end.
/// Negative lengths and reads exceeding the remaining bytes return an error.
pub fn ByteReader::read_bytes(
  self : ByteReader,
  length : Int32,
) -> Result[BytesView, ReadError] {
  let position = self.offset
  let remaining = self.remaining()
  if length < 0 {
    return Err(InvalidLength(requested=length, position~, remaining~))
  }
  if length > remaining {
    return Err(OutOfBounds(requested=length, position~, remaining~))
  }
  // The comparison above ensures position + length <= data.length().
  let end = position + length
  match self.data.get_view(start=position, end~) {
    Some(bytes) => {
      self.offset = end
      Ok(bytes)
    }
    None => Err(OutOfBounds(requested=length, position~, remaining~))
  }
}

///|
/// Reads one unsigned byte.
pub fn ByteReader::read_u8(self : ByteReader) -> Result[Byte, ReadError] {
  self.read_bytes(1).map(bytes => bytes[0])
}

///|
/// Reads an unsigned 16-bit big-endian integer into a UInt.
pub fn ByteReader::read_u16_be(self : ByteReader) -> Result[UInt32, ReadError] {
  self
  .read_bytes(2)
  .map(bytes => (bytes[0].to_uint() << 8) | bytes[1].to_uint())
}

///|
/// Reads an unsigned 32-bit big-endian integer, including values above 2^31 - 1.
pub fn ByteReader::read_u32_be(self : ByteReader) -> Result[UInt32, ReadError] {
  self
  .read_bytes(4)
  .map(bytes => {
    (bytes[0].to_uint() << 24) |
    (bytes[1].to_uint() << 16) |
    (bytes[2].to_uint() << 8) |
    bytes[3].to_uint()
  })
}
