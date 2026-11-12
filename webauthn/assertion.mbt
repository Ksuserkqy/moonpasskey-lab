///|
fn check_assertion_authenticator_data(
  auth : AuthenticatorData,
  credential : AssertionCredentialRecord,
  policy : AssertionVerificationPolicy,
) -> Unit raise AssertionFailure {
  let expected_hash = sha256(@utf8.encode(policy.expected_rp_id))
  if !@spec.eq(auth.rp_id_hash, expected_hash) {
    raise assertion_fail(
      "authData.rpIdHash",
      RpIdHashMismatch,
      offset=Some(auth.rp_id_hash_range.start),
    )
  }
  if auth.flags.at {
    raise assertion_fail(
      "authData.flags.at",
      UnexpectedAttestedCredentialData,
      offset=Some(auth.flags_range.start),
    )
  }
  if auth.flags.reserved != b'\x00' {
    raise assertion_fail(
      "authData.flags.reserved",
      InvalidAssertionFlags,
      offset=Some(auth.flags_range.start),
    )
  }
  if !auth.flags.up {
    raise assertion_fail(
      "authData.flags.up",
      UserPresenceRequired,
      offset=Some(auth.flags_range.start),
    )
  }
  if policy.user_verification == Required && !auth.flags.uv {
    raise assertion_fail(
      "authData.flags.uv",
      UserVerificationRequired,
      offset=Some(auth.flags_range.start),
    )
  }
  if credential.backup_eligible is Some(registered) &&
    registered != auth.flags.be {
    raise assertion_fail(
      "authData.flags.be",
      BackupEligibilityMismatch,
      offset=Some(auth.flags_range.start),
    )
  }
  // The bounded P3 parser checks BS implies BE and parses ED. This RP ignores
  // extension outputs under WebAuthn 7.2 step 23, retaining them in the result.
}

///|
fn assertion_counter_status(
  stored : UInt32,
  received : UInt32,
) -> CounterStatus {
  if stored == 0U && received == 0U {
    NotSupported
  } else if received > stored {
    Advanced
  } else {
    NonIncreasing
  }
}

///|
/// Verify one ES256 authentication response against trusted ceremony policy
/// and a caller-selected credential/account record. The response rawId must
/// be decoded from its transport encoding, and its outer type must already be
/// public-key. Discoverable account lookup belongs to the caller.
///
/// No state is persisted. Only Ok supplies a credential update proposal.
/// The caller must atomically consume the outstanding challenge and commit
/// state using a transaction or record revision/CAS, rechecking concurrent
/// updates. This function cannot establish freshness from bytes alone.
pub fn verify_webauthn_es256_assertion(
  request : AssertionVerificationRequest,
  credential : AssertionCredentialRecord,
  policy : AssertionVerificationPolicy,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> Result[AssertionVerificationResult, AssertionVerificationError] {
  try {
    check_assertion_configuration(request, credential, policy, limits)
    check_assertion_identity(request, credential, policy)
    let client = match parse_client_data(request.client_data_json, limits~) {
      Ok(value) => value
      Err(error) =>
        raise assertion_fail(
          "clientDataJSON",
          Parse(error),
          offset=Some(error.offset),
        )
    }
    check_assertion_client_data(client, request, policy)
    let auth = match
      parse_authenticator_data(request.authenticator_data, limits~) {
      Ok(value) => value
      Err(error) =>
        raise assertion_fail(
          "authData",
          Parse(error),
          offset=Some(error.offset),
        )
    }
    check_assertion_authenticator_data(auth, credential, policy)
    match
      verify_webauthn_es256_assertion_signature(
        credential.public_key,
        auth.raw,
        client.raw,
        request.signature,
      ) {
      Ok(true) => ()
      Ok(false) => raise assertion_fail("signature", InvalidSignature)
      Err(error) => raise assertion_fail("signature", Crypto(error))
    }
    let counter_status = assertion_counter_status(
      credential.sign_count,
      auth.sign_count,
    )
    if counter_status == NonIncreasing && policy.counter_risk == Reject {
      raise assertion_fail(
        "authData.signCount",
        CounterNonIncreasing(
          stored=credential.sign_count,
          received=auth.sign_count,
        ),
        offset=Some(auth.sign_count_range.start),
      )
    }
    // Retain the counter high-water mark under ReportOnly. A lower received
    // value remains visible in authenticator_data and counter_status.
    let sign_count = if auth.sign_count > credential.sign_count {
      auth.sign_count
    } else {
      credential.sign_count
    }
    Ok({
      client_data: client,
      authenticator_data: auth,
      counter_status,
      credential_update: {
        credential_id: credential.credential_id,
        previous_sign_count: credential.sign_count,
        previous_backup_eligible: credential.backup_eligible,
        sign_count,
        backup_eligible: credential.backup_eligible,
        backup_state: auth.flags.bs,
      },
    })
  } catch {
    AssertionFailed(error) => Err(error)
  }
}
