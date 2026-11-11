///|
/// Unverified authenticator assertions. Reserved bits are retained, not trusted.
#derive(Eq, Debug)
pub struct AuthenticatorFlags {
  raw : Byte
  up : Bool
  uv : Bool
  be : Bool
  bs : Bool
  at : Bool
  ed : Bool
  reserved : Byte
}

///|
pub extend AuthenticatorFlags with Eq::{equal, not_equal}

///|
pub extend AuthenticatorFlags with Debug::{to_repr}

///|
/// All ranges refer to the complete raw AuthenticatorData view, including CBOR.
/// Public-key map structure and encoding are checked; COSE semantics are not.
#derive(Eq, Debug)
pub struct AttestedCredentialData {
  raw : BytesView
  range : @cbor.SourceRange
  aaguid : BytesView
  aaguid_range : @cbor.SourceRange
  credential_id_length : UInt32
  credential_id_length_range : @cbor.SourceRange
  credential_id : BytesView
  credential_id_range : @cbor.SourceRange
  credential_public_key : @cbor.Value
  credential_public_key_raw : BytesView
}

///|
pub extend AttestedCredentialData with Eq::{equal, not_equal}

///|
pub extend AttestedCredentialData with Debug::{to_repr}

///|
/// Structural parsing only: no hash, signature, ceremony, or trust validation.
/// CBOR ranges and errors are relative to raw, even for conditional fields.
#derive(Eq, Debug)
pub struct AuthenticatorData {
  raw : BytesView
  rp_id_hash : BytesView
  rp_id_hash_range : @cbor.SourceRange
  flags : AuthenticatorFlags
  flags_range : @cbor.SourceRange
  sign_count : UInt32
  sign_count_range : @cbor.SourceRange
  attested : AttestedCredentialData?
  extensions : @cbor.Value?
  extensions_raw : BytesView?
}

///|
pub extend AuthenticatorData with Eq::{equal, not_equal}

///|
pub extend AuthenticatorData with Debug::{to_repr}

///|
fn[T] read_auth_field(
  result : Result[T, @bytereader.ReadError],
  context : String,
) -> T raise ProtocolFailure {
  match result {
    Ok(value) => value
    Err(@bytereader.OutOfBounds(requested~, position~, remaining~)) =>
      raise fail_at(
        position,
        context,
        UnexpectedEnd(expected=requested, remaining~),
      )
    Err(@bytereader.InvalidLength(requested~, position~, ..)) =>
      raise fail_at(position, context, InvalidReadLength(requested))
  }
}

///|
fn read_auth_cbor_map(
  input : BytesView,
  reader : @bytereader.ByteReader,
  context : String,
  limits : @cbor.Limits,
) -> @cbor.Value raise ProtocolFailure {
  let offset = reader.position()
  let parsed = match
    @cbor.parse_one(input, offset~, profile=@cbor.Ctap2Canonical, limits~) {
    Ok(parsed) => parsed
    Err(error) =>
      raise fail_at(
        error.offset,
        context + "." + error.context,
        Cbor(error.kind),
      )
  }
  if !(parsed.value.kind is @cbor.Map(_)) {
    raise fail_at(offset, context, WrongType(expected="CBOR map"))
  }
  let _ = read_auth_field(reader.read_bytes(parsed.consumed), context)
  parsed.value
}

///|
fn check_auth_extension_keys(value : @cbor.Value) -> Unit raise ProtocolFailure {
  if value.kind is @cbor.Map(entries) {
    for (key, _) in entries {
      let valid = match key.kind {
        @cbor.TextString(name) => protocol_identifier_valid(name)
        _ => false
      }
      if !valid {
        raise fail_at(
          key.range.start,
          "authData.extensions.key",
          InvalidExtensionKey,
        )
      }
    }
  }
}

///|
/// Parse a complete WebAuthn authenticatorData buffer. Canonical CBOR is
/// enforced for the credential public key and extensions (WebAuthn §2.4/3).
/// Reserved flag bits are exposed for forward compatibility; BS requires BE.
/// credentialIdLength is at most 1023; zero is accepted at this structural layer.
pub fn parse_authenticator_data(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> Result[AuthenticatorData, ParseError] {
  try {
    validate_protocol_limits(limits, "authData.limits")
    if input.length() > limits.max_input_bytes {
      raise fail_at(
        0,
        "authData",
        ResourceLimit(
          name="max_input_bytes",
          limit=limits.max_input_bytes,
          actual=input.length().to_uint64(),
        ),
      )
    }
    let reader = @bytereader.ByteReader::new(input)
    let rp_id_hash = read_auth_field(reader.read_bytes(32), "authData.rpIdHash")
    let raw_flags = read_auth_field(reader.read_u8(), "authData.flags")
    let bits = raw_flags.to_int()
    let flags : AuthenticatorFlags = {
      raw: raw_flags,
      up: (bits & 0x01) != 0,
      uv: (bits & 0x04) != 0,
      be: (bits & 0x08) != 0,
      bs: (bits & 0x10) != 0,
      at: (bits & 0x40) != 0,
      ed: (bits & 0x80) != 0,
      reserved: (bits & 0x22).to_byte(),
    }
    if flags.bs && !flags.be {
      raise fail_at(32, "authData.flags", InvalidFlags(raw_flags))
    }
    let sign_count = read_auth_field(reader.read_u32_be(), "authData.signCount")
    let mut used_values = 0
    let attested = if flags.at {
      let start = reader.position()
      let aaguid = read_auth_field(
        reader.read_bytes(16),
        "authData.attested.aaguid",
      )
      let credential_id_length = read_auth_field(
        reader.read_u16_be(),
        "authData.attested.credentialIdLength",
      )
      if credential_id_length > 1023U {
        raise fail_at(
          53,
          "authData.attested.credentialIdLength",
          InvalidCredentialIdLength(credential_id_length),
        )
      }
      let credential_id = read_auth_field(
        reader.read_bytes(credential_id_length.reinterpret_as_int()),
        "authData.attested.credentialId",
      )
      let key = read_auth_cbor_map(
        input, reader, "authData.attested.credentialPublicKey", limits,
      )
      used_values = count_cbor_values(key)
      let end = reader.position()
      Some(AttestedCredentialData::{
        raw: input[start:end],
        range: { start, end, },
        aaguid,
        aaguid_range: { start: 37, end: 53, },
        credential_id_length,
        credential_id_length_range: { start: 53, end: 55, },
        credential_id,
        credential_id_range: { start: 55, end: key.range.start, },
        credential_public_key: key,
        credential_public_key_raw: input[key.range.start:key.range.end],
      })
    } else {
      None
    }
    let extensions = if flags.ed {
      let value = read_auth_cbor_map(
        input,
        reader,
        "authData.extensions",
        remaining_value_limits(limits, used_values),
      )
      check_auth_extension_keys(value)
      Some(value)
    } else {
      None
    }
    if !reader.is_empty() {
      raise fail_at(
        reader.position(),
        "authData.trailing",
        TrailingData(remaining=reader.remaining()),
      )
    }
    Ok({
      raw: input,
      rp_id_hash,
      rp_id_hash_range: { start: 0, end: 32, },
      flags,
      flags_range: { start: 32, end: 33, },
      sign_count,
      sign_count_range: { start: 33, end: 37, },
      attested,
      extensions,
      extensions_raw: extensions.map(value => {
        input[value.range.start:value.range.end]
      }),
    })
  } catch {
    Failed(error) => Err(error)
  }
}
