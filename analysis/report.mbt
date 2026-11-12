///|
priv struct Report {
  fields : Map[String, Json]
  checks : Map[String, Json]
}

///|
fn Report::new(command : String) -> Report {
  let checks : Map[String, Json] = Map([])
  for
    name in [
      "json", "authenticator_data", "public_key", "identity", "challenge", "origin",
      "cross_origin", "rp_id_hash", "user_presence", "user_verification", "backup",
      "signature", "counter",
    ] {
    checks.set(name, jstring("NOT_PERFORMED"))
  }
  {
    fields: {
      "command": jstring(command),
      "status": jstring("PASS"),
      "algorithm": jstring("ES256"),
      "redacted": jbool(true),
    },
    checks,
  }
}

///|
fn Report::finish(self : Report) -> Json {
  self.fields.set("checks", Json::object(self.checks))
  Json::object(self.fields)
}

///|
fn Report::pass(self : Report, check : String) -> Unit {
  self.checks.set(check, jstring("PASS"))
}

///|
fn Report::reject(
  self : Report,
  check : String,
  kind : String,
  context : String,
  offset~ : Int32? = None,
) -> BridgeFailure {
  self.fields.set("status", jstring("FAIL"))
  self.checks.set(check, jstring("FAIL"))
  let error = { "kind": jstring(kind), "context": jstring(context) }
  if offset is Some(value) {
    error.set("offset", Json::number(value.to_double()))
  }
  self.fields.set("error", Json::object(error))
  ReportFailed(self.finish())
}

///|
fn parse_error_name(kind : @webauthn.ErrorKind) -> String {
  match kind {
    @webauthn.UnexpectedEnd(..) => "UnexpectedEnd"
    @webauthn.InvalidReadLength(_) => "InvalidReadLength"
    @webauthn.ResourceLimit(..) => "ResourceLimit"
    @webauthn.InvalidLimit(..) => "InvalidLimit"
    @webauthn.InvalidUtf8 => "InvalidUtf8"
    @webauthn.InvalidJson => "InvalidJson"
    @webauthn.DuplicateMember(..) => "DuplicateMember"
    @webauthn.MissingField(_) => "MissingField"
    @webauthn.UnexpectedField(_) => "UnexpectedField"
    @webauthn.WrongType(..) => "WrongType"
    @webauthn.InvalidFlags(_) => "InvalidFlags"
    @webauthn.InvalidCredentialIdLength(_) => "InvalidCredentialIdLength"
    @webauthn.InvalidExtensionKey => "InvalidExtensionKey"
    @webauthn.InvalidNoneStatement => "InvalidNoneStatement"
    @webauthn.InvalidFormatIdentifier => "InvalidFormatIdentifier"
    @webauthn.UnsupportedAlgorithm => "UnsupportedAlgorithm"
    @webauthn.UnsupportedKeyType => "UnsupportedKeyType"
    @webauthn.InvalidCurve => "InvalidCurve"
    @webauthn.InvalidCoordinateLength(..) => "InvalidCoordinateLength"
    @webauthn.InvalidCoordinate => "InvalidCoordinate"
    @webauthn.CompressedPointNotAllowed => "CompressedPointNotAllowed"
    @webauthn.PrivateKeyMaterialNotAllowed => "PrivateKeyMaterialNotAllowed"
    @webauthn.ForbiddenCoseParameter(..) => "ForbiddenCoseParameter"
    @webauthn.UnsupportedCoseParameter => "UnsupportedCoseParameter"
    @webauthn.TrailingData(..) => "TrailingData"
    @webauthn.Cbor(kind) => "Cbor." + cbor_error_name(kind)
  }
}

///|
fn cbor_error_name(kind : @cbor.ErrorKind) -> String {
  match kind {
    @cbor.UnexpectedEnd(..) => "UnexpectedEnd"
    @cbor.InvalidAdditionalInfo(_) => "InvalidAdditionalInfo"
    @cbor.UnexpectedBreak => "UnexpectedBreak"
    @cbor.InvalidSimpleValue(_) => "InvalidSimpleValue"
    @cbor.InvalidUtf8 => "InvalidUtf8"
    @cbor.DuplicateMapKey(..) => "DuplicateMapKey"
    @cbor.NonMinimalEncoding => "NonMinimalEncoding"
    @cbor.UnsortedMapKey(..) => "UnsortedMapKey"
    @cbor.UnsupportedTag(_) => "UnsupportedTag"
    @cbor.ForbiddenTag(_) => "ForbiddenTag"
    @cbor.UnsupportedFloat(..) => "UnsupportedFloat"
    @cbor.UnsupportedIndefiniteLength(..) => "UnsupportedIndefiniteLength"
    @cbor.IndefiniteLengthNotAllowed => "IndefiniteLengthNotAllowed"
    @cbor.ResourceLimit(..) => "ResourceLimit"
    @cbor.InvalidLimit(..) => "InvalidLimit"
    @cbor.InvalidOffset(_) => "InvalidOffset"
    @cbor.TrailingData(..) => "TrailingData"
    @cbor.InvalidReadLength(_) => "InvalidReadLength"
  }
}

///|
fn crypto_error_name(kind : @webauthn.CryptoError) -> String {
  match kind {
    @webauthn.InvalidPublicKey => "InvalidPublicKey"
    @webauthn.InvalidSignatureLength(..) => "InvalidSignatureLength"
    @webauthn.InvalidSignatureEncoding => "InvalidSignatureEncoding"
    @webauthn.InvalidSignatureScalar(..) => "InvalidSignatureScalar"
    @webauthn.CryptoBackendError => "CryptoBackendError"
    @webauthn.InputTooLarge => "InputTooLarge"
  }
}

///|
fn assertion_error_name(
  kind : @webauthn.AssertionVerificationErrorKind,
) -> String {
  match kind {
    @webauthn.Parse(error) => "Parse." + parse_error_name(error.kind)
    @webauthn.Crypto(error) => "Crypto." + crypto_error_name(error)
    @webauthn.InvalidConfiguration => "InvalidConfiguration"
    @webauthn.ResourceLimit(..) => "ResourceLimit"
    @webauthn.InvalidCredentialId => "InvalidCredentialId"
    @webauthn.CredentialIdMismatch => "CredentialIdMismatch"
    @webauthn.CredentialNotAllowed => "CredentialNotAllowed"
    @webauthn.InvalidUserHandle => "InvalidUserHandle"
    @webauthn.UserHandleRequired => "UserHandleRequired"
    @webauthn.UserHandleMismatch => "UserHandleMismatch"
    @webauthn.EmptyChallenge => "EmptyChallenge"
    @webauthn.InvalidChallengeEncoding => "InvalidChallengeEncoding"
    @webauthn.ChallengeMismatch => "ChallengeMismatch"
    @webauthn.InvalidClientDataType => "InvalidClientDataType"
    @webauthn.OriginNotAllowed => "OriginNotAllowed"
    @webauthn.CrossOriginNotAllowed => "CrossOriginNotAllowed"
    @webauthn.InconsistentTopOrigin => "InconsistentTopOrigin"
    @webauthn.TopOriginNotAllowed => "TopOriginNotAllowed"
    @webauthn.RpIdHashMismatch => "RpIdHashMismatch"
    @webauthn.UserPresenceRequired => "UserPresenceRequired"
    @webauthn.UserVerificationRequired => "UserVerificationRequired"
    @webauthn.BackupEligibilityMismatch => "BackupEligibilityMismatch"
    @webauthn.UnexpectedAttestedCredentialData =>
      "UnexpectedAttestedCredentialData"
    @webauthn.InvalidAssertionFlags => "InvalidAssertionFlags"
    @webauthn.InvalidSignature => "InvalidSignature"
    @webauthn.CounterNonIncreasing(..) => "CounterNonIncreasing"
  }
}

///|
fn assertion_check(context : String) -> String {
  if context.contains("challenge") {
    "challenge"
  } else if context.contains("topOrigin") || context.contains("crossOrigin") {
    "cross_origin"
  } else if context.contains("origin") {
    "origin"
  } else if context.contains("rpId") {
    "rp_id_hash"
  } else if context.contains("flags.up") {
    "user_presence"
  } else if context.contains("flags.uv") {
    "user_verification"
  } else if context.contains("flags.be") {
    "backup"
  } else if context.contains("signCount") {
    "counter"
  } else if context == "signature" {
    "signature"
  } else if context.contains("credential") || context.contains("user_handle") {
    "identity"
  } else if context.contains("authData") {
    "authenticator_data"
  } else {
    "json"
  }
}

///|
fn client_summary(client : @webauthn.ClientData) -> Json {
  Json::object({
    "type": jstring(client.type_),
    "challenge": Json::object({
      "redacted": jbool(true),
      "encodedLength": Json::number(client.challenge.length().to_double()),
    }),
    "origin": jstring(client.origin),
    "crossOrigin": optional_bool(client.cross_origin),
    "topOrigin": optional_string(client.top_origin),
  })
}

///|
fn auth_summary(auth : @webauthn.AuthenticatorData) -> Json {
  let flags = auth.flags
  Json::object({
    "rpIdHash": jstring(encoded(auth.rp_id_hash)),
    "length": Json::number(auth.raw.length().to_double()),
    "signCount": juint(auth.sign_count),
    "flags": Json::object({
      "up": jbool(flags.up),
      "uv": jbool(flags.uv),
      "be": jbool(flags.be),
      "bs": jbool(flags.bs),
      "at": jbool(flags.at),
      "ed": jbool(flags.ed),
      "rfu": Json::number(flags.reserved.to_int().to_double()),
    }),
  })
}

///|
fn read_client(
  raw : BytesView,
  report : Report,
) -> @webauthn.ClientData raise BridgeFailure {
  match @webauthn.parse_client_data(raw) {
    Ok(client) => {
      report.pass("json")
      report.fields.set("clientData", client_summary(client))
      client
    }
    Err(error) =>
      raise report.reject(
        "json",
        parse_error_name(error.kind),
        error.context,
        offset=Some(error.offset),
      )
  }
}

///|
fn read_auth(
  raw : BytesView,
  report : Report,
) -> @webauthn.AuthenticatorData raise BridgeFailure {
  match @webauthn.parse_authenticator_data(raw) {
    Ok(auth) => {
      report.pass("authenticator_data")
      report.fields.set("authenticatorData", auth_summary(auth))
      auth
    }
    Err(error) =>
      raise report.reject(
        "authenticator_data",
        parse_error_name(error.kind),
        error.context,
        offset=Some(error.offset),
      )
  }
}

///|
fn read_key(
  raw : BytesView,
  report : Report,
) -> @webauthn.ValidatedEs256PublicKey raise BridgeFailure {
  let parameters = match @webauthn.validate_es256_credential_public_key(raw) {
    Ok(value) => value
    Err(error) =>
      raise report.reject(
        "public_key",
        parse_error_name(error.kind),
        error.context,
        offset=Some(error.offset),
      )
  }
  match @webauthn.import_es256_public_key(parameters) {
    Ok(key) => {
      report.pass("public_key")
      report.fields.set(
        "publicKey",
        Json::object({
          "algorithm": jstring("ES256"),
          "curve": jstring("P-256"),
          "validated": jbool(true),
        }),
      )
      key
    }
    Err(error) =>
      raise report.reject(
        "public_key",
        crypto_error_name(error),
        "credential.publicKey",
      )
  }
}
