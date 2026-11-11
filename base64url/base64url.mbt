///|
/// Maximum binary input or decoded output size, in bytes (1 MiB).
pub const MAX_BYTES : Int32 = 1_048_576

///|
/// Maximum encoded input length, including optional padding.
pub const MAX_ENCODED_LENGTH : Int32 = 1_398_104

///|
/// Length errors report the input/output size and its limit in the same units.
/// InvalidEncoding covers invalid length, padding, and nonzero unused bits.
#derive(Eq, Debug)
pub(all) enum Base64UrlError {
  InputTooLarge(actual~ : Int32, limit~ : Int32)
  InvalidCharacter(position~ : Int32)
  InvalidEncoding
}

///|
pub extend Base64UrlError with Eq::{equal, not_equal}

///|
pub extend Base64UrlError with Debug::{to_repr}

///|
/// Encode RFC 4648 section 5 Base64URL, omitting padding by default.
/// Binary input is limited to MAX_BYTES before invoking the standard codec.
pub fn encode(
  bytes : BytesView,
  padding~ : Bool = false,
) -> Result[String, Base64UrlError] {
  if bytes.length() > MAX_BYTES {
    return Err(InputTooLarge(actual=bytes.length(), limit=MAX_BYTES))
  }
  Ok(
    @base64.encode(bytes, padding~)
    .replace_all(old="+", new="-")
    .replace_all(old="/", new="_"),
  )
}

///|
/// Decode strict URL-safe input with omitted or complete terminal padding.
/// Reject whitespace, the standard +/ alphabet, malformed padding and nonzero
/// unused bits. WebAuthn callers must additionally enforce omitted padding.
/// Error positions use zero-based UTF-16 code-unit offsets.
pub fn decode(input : StringView) -> Result[Bytes, Base64UrlError] {
  let length = input.length()
  if length > MAX_ENCODED_LENGTH {
    return Err(InputTooLarge(actual=length, limit=MAX_ENCODED_LENGTH))
  }
  for position, code_unit in input.code_units() {
    match code_unit.to_int() {
      'A'..<='Z' | 'a'..<='z' | '0'..<='9' | '-' | '_' | '=' => ()
      _ => return Err(InvalidCharacter(position~))
    }
  }
  // All size arithmetic is bounded by MAX_ENCODED_LENGTH. Count payload
  // characters so both padded and unpadded output limits are checked before
  // allocation. The standard codec validates the padding and unused bits.
  let mut payload_length = length
  while payload_length > 0 && input.get(payload_length - 1) is Some('=') {
    payload_length -= 1
  }
  let decoded_length = payload_length / 4 * 3 + payload_length % 4 * 3 / 4
  if decoded_length > MAX_BYTES {
    return Err(InputTooLarge(actual=decoded_length, limit=MAX_BYTES))
  }
  let normalized = input
    .to_owned()
    .replace_all(old="-", new="+")
    .replace_all(old="_", new="/")
  Ok(@base64.decode(normalized)) catch {
    @base64.Malformed(_) => Err(InvalidEncoding)
  }
}
