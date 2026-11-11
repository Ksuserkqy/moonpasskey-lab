///|
/// Parameter validation does not establish membership in the P-256 curve.
/// A future cryptographic validator must perform that separate check.
#derive(Eq, Debug)
pub(all) enum CurvePointValidation {
  NotPerformed
}

///|
pub extend CurvePointValidation with Eq::{equal, not_equal}

///|
pub extend CurvePointValidation with Debug::{to_repr}

///|
/// Checked ES256/EC2/P-256 parameters, NOT a cryptographically validated key.
/// x/y retain all 32 bytes, including leading zeroes. Field ranges include
/// their CBOR value headers. All ranges refer to the validator's source view;
/// for AttestedCredentialData::validate_es256 they refer to authData.raw.
/// raw is exactly the original encoded key, whose source span is range.
#derive(Eq, Debug)
pub struct Es256PublicKeyParameters {
  raw : BytesView
  range : @cbor.SourceRange
  kty : UInt32
  alg : Int32
  crv : UInt32
  x : BytesView
  y : BytesView
  kty_range : @cbor.SourceRange
  alg_range : @cbor.SourceRange
  crv_range : @cbor.SourceRange
  x_range : @cbor.SourceRange
  y_range : @cbor.SourceRange
  point_validation : CurvePointValidation
}

///|
pub extend Es256PublicKeyParameters with Eq::{equal, not_equal}

///|
pub extend Es256PublicKeyParameters with Debug::{to_repr}

///|
fn cose_required(
  value : @cbor.Value?,
  name : String,
  start : Int32,
  context : String,
) -> @cbor.Value raise ProtocolFailure {
  match value {
    Some(value) => value
    None => raise fail_at(start, context + "." + name, MissingField(name))
  }
}

///|
fn cose_coordinate(
  value : @cbor.Value,
  name : String,
  context : String,
) -> BytesView raise ProtocolFailure {
  let field = context + "." + name
  let bytes = match value.kind {
    @cbor.ByteString(bytes) => bytes
    @cbor.Boolean(_) if name == "y" =>
      raise fail_at(value.range.start, field, CompressedPointNotAllowed)
    _ =>
      raise fail_at(value.range.start, field, WrongType(expected="byte string"))
  }
  if bytes.length() != 32 {
    raise fail_at(
      value.range.start,
      field,
      InvalidCoordinateLength(expected=32, actual=bytes.length()),
    )
  }
  // SEC 2 v2 §2.4.2: P-256 p, encoded as an unsigned big-endian 32-byte value.
  // Fixed-width lexicographic comparison needs no bigint or ECC arithmetic.
  let prime : BytesView = b"\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
  if bytes.compare(prime) >= 0 {
    raise fail_at(value.range.start, field, InvalidCoordinate)
  }
  bytes
}

///|
/// Private entry: value must originate from the canonical decoder, either
/// below or from the immutable AT result constructed by the P3 parser.
fn check_es256_parameters(
  value : @cbor.Value,
  raw : BytesView,
  context : String,
) -> Es256PublicKeyParameters raise ProtocolFailure {
  let entries = match value.kind {
    @cbor.Map(entries) => entries
    _ =>
      raise fail_at(value.range.start, context, WrongType(expected="CBOR map"))
  }
  let mut kty = None
  let mut alg = None
  let mut crv = None
  let mut x = None
  let mut y = None
  // Reject disallowed labels before processing parameter values. Error kinds
  // never retain their contents, especially not the private d value.
  for index, (key, item) in entries {
    let parameter = "\{context}.parameter[\{index}]"
    match key.kind {
      @cbor.Unsigned(1UL) => kty = Some(item)
      @cbor.Unsigned(3UL) => alg = Some(item)
      @cbor.Negative(0UL) => crv = Some(item)
      @cbor.Negative(1UL) => x = Some(item)
      @cbor.Negative(2UL) => y = Some(item)
      @cbor.Negative(3UL) =>
        raise fail_at(key.range.start, parameter, PrivateKeyMaterialNotAllowed)
      @cbor.Unsigned(2UL) =>
        raise fail_at(
          key.range.start,
          parameter,
          ForbiddenCoseParameter(label=2),
        )
      @cbor.Unsigned(4UL) =>
        raise fail_at(
          key.range.start,
          parameter,
          ForbiddenCoseParameter(label=4),
        )
      @cbor.Unsigned(5UL) =>
        raise fail_at(
          key.range.start,
          parameter,
          ForbiddenCoseParameter(label=5),
        )
      @cbor.Unsigned(_) | @cbor.Negative(_) | @cbor.TextString(_) =>
        raise fail_at(key.range.start, parameter, UnsupportedCoseParameter)
      _ =>
        raise fail_at(
          key.range.start,
          parameter,
          WrongType(expected="integer or text COSE label"),
        )
    }
  }
  // Identify unsupported algorithms before key-type-specific requirements:
  // e.g. an OKP key need not contain y, but is still explicitly unsupported.
  let algorithm = cose_required(alg, "alg", value.range.start, context)
  match algorithm.kind {
    @cbor.Negative(6UL) => ()
    @cbor.Unsigned(_) | @cbor.Negative(_) =>
      raise fail_at(
        algorithm.range.start,
        context + ".alg",
        UnsupportedAlgorithm,
      )
    _ =>
      raise fail_at(
        algorithm.range.start,
        context + ".alg",
        WrongType(expected="integer"),
      )
  }
  let key_type = cose_required(kty, "kty", value.range.start, context)
  match key_type.kind {
    @cbor.Unsigned(2UL) => ()
    @cbor.Unsigned(_) | @cbor.Negative(_) =>
      raise fail_at(key_type.range.start, context + ".kty", UnsupportedKeyType)
    _ =>
      raise fail_at(
        key_type.range.start,
        context + ".kty",
        WrongType(expected="integer"),
      )
  }
  let curve = cose_required(crv, "crv", value.range.start, context)
  match curve.kind {
    @cbor.Unsigned(1UL) => ()
    @cbor.Unsigned(_) | @cbor.Negative(_) =>
      raise fail_at(curve.range.start, context + ".crv", InvalidCurve)
    _ =>
      raise fail_at(
        curve.range.start,
        context + ".crv",
        WrongType(expected="integer"),
      )
  }
  let x_value = cose_required(x, "x", value.range.start, context)
  let x_bytes = cose_coordinate(x_value, "x", context)
  let y_value = cose_required(y, "y", value.range.start, context)
  let y_bytes = cose_coordinate(y_value, "y", context)
  {
    raw,
    range: value.range,
    kty: 2U,
    alg: -7,
    crv: 1U,
    x: x_bytes,
    y: y_bytes,
    kty_range: key_type.range,
    alg_range: algorithm.range,
    crv_range: curve.range,
    x_range: x_value.range,
    y_range: y_value.range,
    point_validation: NotPerformed,
  }
}

///|
/// Validate one complete encoded WebAuthn ES256 Credential Public Key. Uses
/// the existing canonical CBOR decoder with its limits, duplicate checks and
/// trailing-data rejection. Errors/ranges are relative to input, even for a
/// sliced BytesView. No signature or curve-point membership check is made.
pub fn validate_es256_credential_public_key(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> Result[Es256PublicKeyParameters, ParseError] {
  try {
    validate_protocol_limits(limits, "credentialPublicKey.limits")
    let value = match
      @cbor.parse_all(input, profile=@cbor.Ctap2Canonical, limits~) {
      Ok(value) => value
      Err(error) =>
        raise fail_at(
          error.offset,
          "credentialPublicKey." + error.context,
          Cbor(error.kind),
        )
    }
    Ok(check_es256_parameters(value, input, "credentialPublicKey"))
  } catch {
    Failed(error) => Err(error)
  }
}

///|
/// Explicit opt-in validation of the canonical key already parsed in AT.
/// The P3 structural parsers remain algorithm-independent. Offsets/ranges
/// stay relative to authData.raw; add the parent's auth_data_payload_range
/// base if locating this result in an AttestationObject. No CBOR budget is
/// reset: this method only examines the immutable, already bounded key map.
pub fn AttestedCredentialData::validate_es256(
  self : AttestedCredentialData,
) -> Result[Es256PublicKeyParameters, ParseError] {
  Ok(
    check_es256_parameters(
      self.credential_public_key,
      self.credential_public_key_raw,
      "authData.attested.credentialPublicKey",
    ),
  ) catch {
    Failed(error) => Err(error)
  }
}
