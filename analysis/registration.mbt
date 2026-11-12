///|
// This test adapter deliberately validates only none-attestation registration
// inputs. It performs no authenticator attestation-chain trust evaluation.
fn registration_policy_valid(
  policy : @webauthn.AssertionVerificationPolicy,
) -> Bool {
  if policy.expected_rp_id.is_empty() ||
    policy.expected_rp_id.length() > 253 ||
    policy.allowed_origins.is_empty() {
    return false
  }
  let mut length = 0
  let mut hyphen = false
  for _, unit in policy.expected_rp_id.code_units() {
    match unit.to_int() {
      '.' => {
        if length == 0 || hyphen {
          return false
        }
        length = 0
        hyphen = false
      }
      'a'..<='z' | 'A'..<='Z' | '0'..<='9' | '-' as value => {
        if length == 0 && value == '-' {
          return false
        }
        length += 1
        if length > 63 {
          return false
        }
        hyphen = value == '-'
      }
      _ => return false
    }
  }
  length > 0 &&
  !hyphen &&
  !policy.allowed_origins.contains("") &&
  !policy.allowed_top_origins.contains("")
}

///|
fn register_test(
  fields : Map[String, Json],
  report : Report,
  host : Bool,
) -> Json raise BridgeFailure {
  report.fields.set("testOnly", jbool(true))
  report.checks.set("attestation_trust", jstring("NOT_PERFORMED"))
  let client = read_client(binary(fields, "clientDataJSON", "input"), report)
  let policy = read_policy(fields)
  if !registration_policy_valid(policy) {
    raise report.reject("json", "InvalidConfiguration", "policy")
  }
  if client.type_ != "webauthn.create" {
    raise report.reject("json", "InvalidClientDataType", "clientDataJSON.type")
  }
  let challenge = binary(fields, "expectedChallenge", "input")
  if challenge.is_empty() || client.challenge.is_empty() {
    raise report.reject(
      "challenge", "EmptyChallenge", "clientDataJSON.challenge",
    )
  }
  if client.challenge.contains("=") {
    raise report.reject(
      "challenge", "InvalidChallengeEncoding", "clientDataJSON.challenge",
    )
  }
  let received = match @base64url.decode(client.challenge) {
    Ok(value) => value
    Err(_) =>
      raise report.reject(
        "challenge", "InvalidChallengeEncoding", "clientDataJSON.challenge",
      )
  }
  if !@spec.eq(received, challenge) ||
    !@spec.eq(@utf8.encode(client.challenge), @utf8.encode(encoded(challenge))) {
    raise report.reject(
      "challenge", "ChallengeMismatch", "clientDataJSON.challenge",
    )
  }
  report.pass("challenge")
  if !policy.allowed_origins.contains(client.origin) {
    raise report.reject("origin", "OriginNotAllowed", "clientDataJSON.origin")
  }
  report.pass("origin")
  let cross = client.cross_origin == Some(true)
  if cross && !policy.allow_cross_origin {
    raise report.reject(
      "cross_origin", "CrossOriginNotAllowed", "clientDataJSON.crossOrigin",
    )
  }
  if client.top_origin is Some(top) {
    if !cross {
      raise report.reject(
        "cross_origin", "InconsistentTopOrigin", "clientDataJSON.topOrigin",
      )
    }
    if !policy.allowed_top_origins.contains(top) {
      raise report.reject(
        "cross_origin", "TopOriginNotAllowed", "clientDataJSON.topOrigin",
      )
    }
  }
  report.pass("cross_origin")
  let attestation_raw = binary(fields, "attestationObject", "input")
  let attestation = match @webauthn.parse_attestation_object(attestation_raw) {
    Ok(value) => value
    Err(error) =>
      raise report.reject(
        "authenticator_data",
        parse_error_name(error.kind),
        error.context,
        offset=Some(error.offset),
      )
  }
  if attestation.fmt != "none" {
    raise report.reject(
      "authenticator_data", "UnsupportedTestAttestation", "attestationObject.fmt",
    )
  }
  let auth = attestation.auth_data
  report.pass("authenticator_data")
  report.fields.set("authenticatorData", auth_summary(auth))
  if !@spec.eq(
      auth.rp_id_hash,
      @webauthn.sha256(@utf8.encode(policy.expected_rp_id)),
    ) {
    raise report.reject(
      "rp_id_hash",
      "RpIdHashMismatch",
      "authData.rpIdHash",
      offset=Some(0),
    )
  }
  report.pass("rp_id_hash")
  if auth.flags.reserved != b'\x00' {
    raise report.reject(
      "authenticator_data",
      "InvalidAssertionFlags",
      "authData.flags.reserved",
      offset=Some(32),
    )
  }
  if !auth.flags.up {
    raise report.reject(
      "user_presence",
      "UserPresenceRequired",
      "authData.flags.up",
      offset=Some(32),
    )
  }
  report.pass("user_presence")
  if policy.user_verification == @webauthn.Required && !auth.flags.uv {
    raise report.reject(
      "user_verification",
      "UserVerificationRequired",
      "authData.flags.uv",
      offset=Some(32),
    )
  }
  report.pass("user_verification")
  report.pass("backup")
  let attested = match auth.attested {
    Some(value) => value
    None =>
      raise report.reject(
        "authenticator_data", "MissingAttestedCredentialData", "authData.attested",
      )
  }
  let id = binary(fields, "credentialId", "input")
  if id.is_empty() || id.length() > 1023 {
    raise report.reject("identity", "InvalidCredentialId", "credentialId")
  }
  if !@spec.eq(id, attested.credential_id) {
    raise report.reject("identity", "CredentialIdMismatch", "credentialId")
  }
  let handle = binary(fields, "userHandle", "input")
  if handle.is_empty() || handle.length() > 64 {
    raise report.reject("identity", "InvalidUserHandle", "userHandle")
  }
  report.pass("identity")
  read_key(attested.credential_public_key_raw, report) |> ignore
  if host {
    report.fields.set("redacted", jbool(false))
    report.fields.set("internal", jbool(true))
    report.fields.set(
      "record",
      Json::object({
        "credentialId": jstring(encoded(id)),
        "userHandle": jstring(encoded(handle)),
        "publicKey": jstring(encoded(attested.credential_public_key_raw)),
        "signCount": juint(auth.sign_count),
        "backupEligible": jbool(auth.flags.be),
      }),
    )
  }
  report.finish()
}
