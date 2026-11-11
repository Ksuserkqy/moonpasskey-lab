///|
/// This status describes syntax only; neither case establishes trust.
#derive(Eq, Debug)
pub(all) enum StatementStatus {
  NoneStructureChecked
  FormatNotValidated
}

///|
pub extend StatementStatus with Eq::{equal, not_equal}

///|
pub extend StatementStatus with Debug::{to_repr}

///|
/// CBOR field ranges refer to raw. Nested AuthenticatorData ranges refer to
/// auth_data.raw; add auth_data_payload_range.start to locate them in raw.
#derive(Eq, Debug)
pub struct AttestationObject {
  raw : BytesView
  cbor : @cbor.Value
  fmt : String
  fmt_range : @cbor.SourceRange
  auth_data : AuthenticatorData
  auth_data_range : @cbor.SourceRange
  auth_data_payload_range : @cbor.SourceRange
  att_stmt : @cbor.Value
  statement_status : StatementStatus
}

///|
pub extend AttestationObject with Eq::{equal, not_equal}

///|
pub extend AttestationObject with Debug::{to_repr}

///|
fn attestation_field(
  entries : ReadOnlyArray[(@cbor.Value, @cbor.Value)],
  name : String,
) -> @cbor.Value raise ProtocolFailure {
  for (key, value) in entries {
    if key.kind is @cbor.TextString(label) && label == name {
      return value
    }
  }
  raise fail_at(0, "attestationObject.\{name}", MissingField(name))
}

///|
/// Rebase the secondary offsets embedded in CBOR error kinds as well.
fn rebase_auth_error(error : ParseError, base : Int32) -> ParseError {
  let kind = match error.kind {
    Cbor(@cbor.DuplicateMapKey(first_offset~)) =>
      Cbor(@cbor.DuplicateMapKey(first_offset=base + first_offset))
    Cbor(@cbor.UnsortedMapKey(previous_offset~)) =>
      Cbor(@cbor.UnsortedMapKey(previous_offset=base + previous_offset))
    other => other
  }
  {
    offset: base + error.offset,
    context: "attestationObject." + error.context,
    kind,
  }
}

///|
/// Parse exactly fmt/authData/attStmt as specified by WebAuthn §6.5.4. Map and
/// array statements are retained structurally; only none's empty-map syntax is
/// checked. All WebAuthn CBOR uses the canonical decoder (§2.4, §3).
pub fn parse_attestation_object(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> Result[AttestationObject, ParseError] {
  try {
    validate_protocol_limits(limits, "attestationObject.limits")
    let value = match
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical, limits~) {
      Ok(value) => value
      Err(error) =>
        raise fail_at(
          error.offset,
          "attestationObject." + error.context,
          Cbor(error.kind),
        )
    }
    let entries = match value.kind {
      @cbor.Map(entries) => entries
      _ => raise fail_at(0, "attestationObject", WrongType(expected="CBOR map"))
    }
    for (key, _) in entries {
      match key.kind {
        @cbor.TextString("fmt" | "authData" | "attStmt") => ()
        @cbor.TextString(name) =>
          raise fail_at(
            key.range.start,
            "attestationObject.key",
            UnexpectedField(name),
          )
        _ =>
          raise fail_at(
            key.range.start,
            "attestationObject.key",
            WrongType(expected="text string"),
          )
      }
    }
    let format_value = attestation_field(entries, "fmt")
    let fmt = match format_value.kind {
      @cbor.TextString(text) => text
      _ =>
        raise fail_at(
          format_value.range.start,
          "attestationObject.fmt",
          WrongType(expected="text string"),
        )
    }
    if !protocol_identifier_valid(fmt) {
      raise fail_at(
        format_value.range.start,
        "attestationObject.fmt",
        InvalidFormatIdentifier,
      )
    }
    let auth_value = attestation_field(entries, "authData")
    let auth_bytes = match auth_value.kind {
      @cbor.ByteString(bytes) => bytes
      _ =>
        raise fail_at(
          auth_value.range.start,
          "attestationObject.authData",
          WrongType(expected="byte string"),
        )
    }
    let statement = attestation_field(entries, "attStmt")
    match statement.kind {
      @cbor.Map(entries) =>
        for (key, _) in entries {
          if !(key.kind is @cbor.TextString(_)) {
            raise fail_at(
              key.range.start,
              "attestationObject.attStmt.key",
              WrongType(expected="text string"),
            )
          }
        }
      @cbor.Array(_) => ()
      _ =>
        raise fail_at(
          statement.range.start,
          "attestationObject.attStmt",
          WrongType(expected="CBOR map or array"),
        )
    }
    let status = if fmt == "none" {
      if !(statement.kind is @cbor.Map(entries) && entries.length() == 0) {
        raise fail_at(
          statement.range.start,
          "attestationObject.attStmt",
          InvalidNoneStatement,
        )
      }
      NoneStructureChecked
    } else {
      FormatNotValidated
    }
    // Definite byte strings occupy the final payload bytes of their encoding.
    let payload_start = auth_value.range.end - auth_bytes.length()
    let nested_limits = remaining_value_limits(limits, count_cbor_values(value))
    let auth_data = match
      parse_authenticator_data(auth_bytes, limits=nested_limits) {
      Ok(auth_data) => auth_data
      Err(error) => raise Failed(rebase_auth_error(error, payload_start))
    }
    if auth_data.attested is None {
      raise fail_at(
        payload_start + 32,
        "attestationObject.authData.attestedCredentialData",
        MissingField("attestedCredentialData"),
      )
    }
    Ok({
      raw: input,
      cbor: value,
      fmt,
      fmt_range: format_value.range,
      auth_data,
      auth_data_range: auth_value.range,
      auth_data_payload_range: {
        start: payload_start,
        end: auth_value.range.end,
      },
      att_stmt: statement,
      statement_status: status,
    })
  } catch {
    Failed(error) => Err(error)
  }
}
