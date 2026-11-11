///|
/// Protocol failures retain a byte offset and a nested field path. CBOR
/// failures preserve the original kind, including length and budget details.
#derive(Eq, Debug)
pub(all) enum ErrorKind {
  UnexpectedEnd(expected~ : Int32, remaining~ : Int32)
  InvalidReadLength(Int32)
  ResourceLimit(name~ : String, limit~ : Int32, actual~ : UInt64)
  InvalidLimit(name~ : String, value~ : Int32)
  InvalidUtf8
  InvalidJson
  DuplicateMember(name~ : String, first_offset~ : Int32)
  MissingField(String)
  UnexpectedField(String)
  WrongType(expected~ : String)
  InvalidFlags(Byte)
  InvalidCredentialIdLength(UInt32)
  InvalidExtensionKey
  InvalidNoneStatement
  InvalidFormatIdentifier
  Cbor(@cbor.ErrorKind)
  TrailingData(remaining~ : Int32)
}

///|
pub extend ErrorKind with Eq::{equal, not_equal}

///|
pub extend ErrorKind with Debug::{to_repr}

///|
/// Offsets are relative to the input view of the public parse call. For an
/// attestation object, nested authData errors are rebased to the outer input.
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

///|
priv suberror ProtocolFailure {
  Failed(ParseError)
}

///|
fn fail_at(
  offset : Int32,
  context : String,
  kind : ErrorKind,
) -> ProtocolFailure {
  Failed({ offset, context, kind, })
}

///|
/// Use the existing CBOR budgets for all three protocol entry points.
fn validate_protocol_limits(
  limits : @cbor.Limits,
  context : String,
) -> Unit raise ProtocolFailure {
  for
    (name, value) in [
      ("max_input_bytes", limits.max_input_bytes),
      ("max_string_bytes", limits.max_string_bytes),
      ("max_array_items", limits.max_array_items),
      ("max_map_pairs", limits.max_map_pairs),
      ("max_depth", limits.max_depth),
      ("max_values", limits.max_values),
    ] {
    if value < 0 {
      raise fail_at(0, context, InvalidLimit(name~, value~))
    }
  }
  if limits.max_depth > 64 {
    raise fail_at(
      0,
      context,
      InvalidLimit(name="max_depth", value=limits.max_depth),
    )
  }
}

///|
/// Only called on already bounded decoder output (at most 64 containers).
fn count_cbor_values(value : @cbor.Value) -> Int32 {
  let mut count = 1
  match value.kind {
    @cbor.Array(items) =>
      for item in items {
        count += count_cbor_values(item)
      }
    @cbor.Map(entries) =>
      for (key, item) in entries {
        count += count_cbor_values(key) + count_cbor_values(item)
      }
    _ => ()
  }
  count
}

///|
/// Deduct values consumed by previous embedded CBOR objects. Input and string
/// budgets are unchanged: embedded views cannot exceed the outer input.
fn remaining_value_limits(limits : @cbor.Limits, used : Int32) -> @cbor.Limits {
  @cbor.Limits::new(
    max_input_bytes=limits.max_input_bytes,
    max_string_bytes=limits.max_string_bytes,
    max_array_items=limits.max_array_items,
    max_map_pairs=limits.max_map_pairs,
    max_depth=limits.max_depth,
    max_values=limits.max_values - used,
  )
}

///|
/// WebAuthn §§8.1 and 9.1 use the same identifier character and size rules.
fn protocol_identifier_valid(identifier : String) -> Bool {
  if identifier.length() > 32 {
    return false
  }
  for _, code_unit in identifier.code_units() {
    let value = code_unit.to_int()
    if value < 0x21 || value > 0x7e || value == 0x22 || value == 0x5c {
      return false
    }
  }
  true
}
