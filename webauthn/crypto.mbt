///|
/// Recoverable cryptographic input and backend failures. A well-formed
/// signature that does not verify is Ok(false).
#derive(Eq, Debug)
pub(all) enum CryptoError {
  InvalidPublicKey
  InvalidSignatureLength(expected~ : Int32, actual~ : Int32)
  InvalidSignatureEncoding
  InvalidSignatureScalar(component~ : String)
  CryptoBackendError
  InputTooLarge
}

///|
pub extend CryptoError with Eq::{equal, not_equal}

///|
pub extend CryptoError with Debug::{to_repr}

///|
/// Constructed only after P4 parameter checks and actual P-256 point import.
/// The private backend field prevents callers from constructing this proof.
pub struct ValidatedEs256PublicKey {
  priv original : Es256PublicKeyParameters
  priv backend : @ecdsa.PublicKey
}

///|
/// Retain the original encoding, coordinates and source ranges. The returned
/// P4 record describes its parameter-only check with NotPerformed. The
/// ValidatedEs256PublicKey value additionally establishes point membership.
pub fn ValidatedEs256PublicKey::parameters(
  self : ValidatedEs256PublicKey,
) -> Es256PublicKeyParameters {
  self.original
}

///|
/// Import the immutable result of either P4 validation entry point. Those
/// entry points enforce 32-byte coordinates strictly below the field prime.
/// This guard is mandatory because MoonCrypt 0.4.16's of_xy alone accepts
/// coordinates congruent modulo p (upstream issue #1).
/// MoonCrypt checks the P-256 equation. Affine import has no infinity encoding,
/// and P-256 has cofactor one. No coordinate normalization is performed here.
pub fn import_es256_public_key(
  parameters : Es256PublicKeyParameters,
) -> Result[ValidatedEs256PublicKey, CryptoError] {
  try {
    let backend = @ecdsa.PublicKey::of_xy(
      parameters.x,
      parameters.y,
      curve=@ecdsa.Curve::P256,
    )
    Ok({ original: parameters, backend, })
  } catch {
    @spec.Tag => Err(InvalidPublicKey)
    @spec.Size(_) | @spec.Weak => Err(CryptoBackendError)
  }
}

///|
/// SHA-256 over the exact input view, including empty inputs. The pure
/// MoonCrypt SHA-256 backend has no recoverable failure and returns 32 bytes.
pub fn sha256(data : BytesView) -> Bytes {
  @sha2.hash(data, kind=@sha2.Sha256)
}

///|
/// RFC 9053 section 2.1 raw R || S encoding, each scalar unsigned big-endian.
/// SEC 2 v2 section 2.4.2 gives this P-256 group order. The comparisons use
/// fixed-width bytes and introduce no bigint or elliptic-curve arithmetic.
fn valid_es256_scalar(scalar : BytesView) -> Bool {
  let zero : BytesView = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  let order : BytesView = b"\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51"
  scalar.compare(zero) > 0 && scalar.compare(order) < 0
}

///|
/// Verify a COSE ES256 raw64 signature over a message. MoonCrypt's verifier
/// hashes this message once with SHA-256. Pass the original message, never a
/// precomputed digest. Both low-S and high-S signatures are accepted.
/// Length/range errors are Err. A legal encoding with an invalid signature
/// is Ok(false). This raw64 primitive has no ASN.1 DER auto-detection.
pub fn verify_es256_signature(
  public_key : ValidatedEs256PublicKey,
  message : BytesView,
  signature : BytesView,
) -> Result[Bool, CryptoError] {
  if signature.length() != 64 {
    return Err(InvalidSignatureLength(expected=64, actual=signature.length()))
  }
  if !valid_es256_scalar(signature[0:32]) {
    return Err(InvalidSignatureScalar(component="R"))
  }
  if !valid_es256_scalar(signature[32:64]) {
    return Err(InvalidSignatureScalar(component="S"))
  }
  Ok(public_key.backend.verify(message, signature))
}

///|
/// WebAuthn section 7.2 steps 20-21. Hash the original clientDataJSON bytes
/// and append that digest to the original authenticatorData bytes. This
/// byte-level helper also accepts empty views and makes no RP policy checks.
pub fn build_webauthn_assertion_signed_data(
  authenticator_data : BytesView,
  client_data_json : BytesView,
) -> Result[Bytes, CryptoError] {
  if authenticator_data.length() > 0x7fff_ffff - 32 {
    return Err(InputTooLarge)
  }
  let client_data_hash = sha256(client_data_json)
  Ok(
    Bytes::makei(authenticator_data.length() + 32, fn(index) {
      if index < authenticator_data.length() {
        authenticator_data[index]
      } else {
        client_data_hash[index - authenticator_data.length()]
      }
    }),
  )
}

///|
/// Encode a canonical nonnegative ASN.1 integer as a P-256 scalar. The caller
/// has already used Tlv.int() to check INTEGER tag, length and minimality.
fn es256_der_scalar(
  value : BytesView,
  component : String,
) -> Result[Bytes, CryptoError] {
  let magnitude = if value.length() > 1 && value[0] == b'\x00' {
    value[1:]
  } else {
    value
  }
  if magnitude.length() > 32 {
    return Err(InvalidSignatureScalar(component~))
  }
  let scalar = Bytes::make(32 - magnitude.length(), b'\x00') +
    magnitude.to_owned()
  if !valid_es256_scalar(scalar) {
    return Err(InvalidSignatureScalar(component~))
  }
  Ok(scalar)
}

///|
/// WebAuthn section 6.5.5 / RFC 3279 section 2.2.3 Ecdsa-Sig-Value.
/// Reuse the backend DER parser for canonical lengths, INTEGER encodings and
/// complete consumption. A valid P-256 signature occupies at most 72 bytes.
fn decode_es256_der_signature(
  signature : BytesView,
) -> Result[Bytes, CryptoError] {
  if signature.length() < 8 || signature.length() > 72 {
    return Err(InvalidSignatureEncoding)
  }
  try {
    let sequence = @asn1.only(signature)
    if sequence.tag != 0x30 {
      return Err(InvalidSignatureEncoding)
    }
    let items = sequence.items()
    if items.length() != 2 {
      return Err(InvalidSignatureEncoding)
    }
    // int() checks tag, nonempty content and minimal signed INTEGER encoding.
    let _ = items[0].int()
    let _ = items[1].int()
    if items[0].value[0] >= b'\x80' || items[1].value[0] >= b'\x80' {
      return Err(InvalidSignatureEncoding)
    }
    let r = match es256_der_scalar(items[0].value, "R") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let s = match es256_der_scalar(items[1].value, "S") {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    Ok(r + s)
  } catch {
    @asn1.Malformed(_) | @asn1.Unsupported(_) => Err(InvalidSignatureEncoding)
  }
}

///|
/// Verify an ES256 Assertion's original ASN.1 DER signature per WebAuthn
/// section 6.5.5. Strict DER decoding precedes hashing. The raw64 primitive
/// verifies authenticatorData || SHA256(original clientDataJSON), hashing
/// that concatenation once internally. RP policy checks remain separate.
pub fn verify_webauthn_es256_assertion_signature(
  public_key : ValidatedEs256PublicKey,
  authenticator_data : BytesView,
  client_data_json : BytesView,
  signature : BytesView,
) -> Result[Bool, CryptoError] {
  let raw_signature = match decode_es256_der_signature(signature) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match
    build_webauthn_assertion_signed_data(authenticator_data, client_data_json) {
    Ok(signed_data) =>
      verify_es256_signature(public_key, signed_data, raw_signature)
    Err(error) => Err(error)
  }
}
