///|
/// Generic accepts definite-length encodings, including nonminimal heads and
/// arbitrary map order. Ctap2Canonical additionally checks CTAP section 8.
#derive(Eq, Debug)
pub(all) enum Profile {
  Generic
  Ctap2Canonical
}

///|
pub extend Profile with Eq::{equal, not_equal}

///|
pub extend Profile with Debug::{to_repr}

///|
/// Half-open offsets relative to the BytesView supplied to the parser.
#derive(Eq, Debug)
pub(all) struct SourceRange {
  start : Int32
  end : Int32
}

///|
pub extend SourceRange with Eq::{equal, not_equal}

///|
pub extend SourceRange with Debug::{to_repr}

///|
/// Negative stores the CBOR unsigned argument n, representing -1-n, including
/// -2^64. Bytes remain views of the original input. Map entries retain order.
#derive(Eq, Debug)
pub(all) enum ValueKind {
  Unsigned(UInt64)
  Negative(UInt64)
  ByteString(BytesView)
  TextString(String)
  Array(ReadOnlyArray[Value])
  Map(ReadOnlyArray[(Value, Value)])
  Boolean(Bool)
  Null
  Undefined
  Simple(Byte)
}

///|
pub extend ValueKind with Eq::{equal, not_equal}

///|
pub extend ValueKind with Debug::{to_repr}

///|
/// A parsed value and its complete original encoding range, including head.
/// Derived equality includes source ranges. Duplicate map-key detection uses
/// separate, type-preserving semantic equality independent of ranges.
#derive(Eq, Debug)
pub struct Value {
  kind : ValueKind
  range : SourceRange
}

///|
pub extend Value with Eq::{equal, not_equal}

///|
pub extend Value with Debug::{to_repr}

///|
pub fn Value::encoded_length(self : Value) -> Int32 {
  self.range.end - self.range.start
}

///|
/// consumed counts bytes from the requested offset. Value ranges remain
/// relative to the complete supplied input view.
#derive(Eq, Debug)
pub struct Parsed {
  value : Value
  consumed : Int32
}

///|
pub extend Parsed with Eq::{equal, not_equal}

///|
pub extend Parsed with Debug::{to_repr}

///|
/// Resource budgets apply to one parse call. max_depth counts arrays/maps,
/// with a hard recursion ceiling of 64. Other budgets accept nonnegative Int.
pub(all) struct Limits {
  max_input_bytes : Int32
  max_string_bytes : Int32
  max_array_items : Int32
  max_map_pairs : Int32
  max_depth : Int32
  max_values : Int32
}

///|
pub fn Limits::new(
  max_input_bytes~ : Int32 = 1_048_576,
  max_string_bytes~ : Int32 = 1_048_576,
  max_array_items~ : Int32 = 4096,
  max_map_pairs~ : Int32 = 1024,
  max_depth~ : Int32 = 32,
  max_values~ : Int32 = 16384,
) -> Limits {
  {
    max_input_bytes,
    max_string_bytes,
    max_array_items,
    max_map_pairs,
    max_depth,
    max_values,
  }
}

///|
#derive(Eq, Debug)
pub(all) enum ErrorKind {
  UnexpectedEnd(expected~ : Int32, remaining~ : Int32)
  InvalidAdditionalInfo(Byte)
  UnexpectedBreak
  InvalidSimpleValue(Byte)
  InvalidUtf8
  DuplicateMapKey(first_offset~ : Int32)
  NonMinimalEncoding
  UnsortedMapKey(previous_offset~ : Int32)
  UnsupportedTag(UInt64)
  ForbiddenTag(UInt64)
  UnsupportedFloat(width~ : Int32)
  UnsupportedIndefiniteLength(major_type~ : Int32)
  IndefiniteLengthNotAllowed
  ResourceLimit(name~ : String, limit~ : Int32, actual~ : UInt64)
  InvalidLimit(name~ : String, value~ : Int32)
  InvalidOffset(Int32)
  TrailingData(remaining~ : Int32)
  InvalidReadLength(Int32)
}

///|
pub extend ErrorKind with Eq::{equal, not_equal}

///|
pub extend ErrorKind with Debug::{to_repr}

///|
/// offset identifies the invalid head/key/UTF-8 sequence, or the beginning of
/// an incomplete read. context identifies its nested array/map location.
#derive(Eq, Debug)
pub(all) struct ParseError {
  offset : Int32
  context : String
  kind : ErrorKind
}

///|
pub extend ParseError with Eq::{equal, not_equal}

///|
pub extend ParseError with Debug::{to_repr}
