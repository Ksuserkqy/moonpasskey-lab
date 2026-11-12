///|
// W3C WebAuthn REC 2026-08-25 sections 16.2, 16.4 and 16.5.
// Reuse the original P3 byte fixtures and P5 key import. The DER signatures
// are exact published bytes covered by CRYPTO-VECTORS-NOTICE.md.
// The account record and RP policy here are project test context. Account
// lookup and challenge storage are outside these official byte vectors.
fn assertion_w3c_verify(
  vector : W3cProtocolVector,
  signature_hex : String,
) -> Unit raise {
  let parsed = match @webauthn.parse_client_data(vector.assertion_client) {
    Ok(value) => value
    Err(_) => fail("official client data parse failed")
  }
  let challenge = match @base64url.decode(vector.assertion_challenge) {
    Ok(value) => value
    Err(_) => fail("official expected challenge decode failed")
  }
  let request : @webauthn.AssertionVerificationRequest = {
    client_data_json: vector.assertion_client,
    authenticator_data: vector.assertion_auth,
    signature: w3c_hex(signature_hex, signature_hex.length() / 2),
    credential_id: vector.credential_id,
    user_handle: None,
    expected_challenge: challenge,
    user_identification: @webauthn.Identified,
  }
  let record : @webauthn.AssertionCredentialRecord = {
    credential_id: vector.credential_id,
    user_handle: b"test-account",
    public_key: crypto_w3c_key(vector),
    sign_count: 0U,
    backup_eligible: Some((vector.assertion_flags.to_int() & 8) != 0),
  }
  let top_origins = match vector.top_origin {
    Some(origin) => [origin]
    None => []
  }
  let policy = @webauthn.AssertionVerificationPolicy::new(
    "example.org",
    [parsed.origin],
    allow_cross_origin=vector.cross_origin,
    allowed_top_origins=top_origins,
    allowed_credential_ids=[vector.credential_id],
  )
  let result = assertion_ok(request, record, policy)
  assert_eq(result.client_data.raw, vector.assertion_client[:])
  assert_eq(result.authenticator_data.raw, vector.assertion_auth[:])
  assert_eq(result.counter_status, @webauthn.NotSupported)
  assert_eq(result.credential_update.credential_id, vector.credential_id[:])
  assert_eq(result.credential_update.sign_count, 0U)
  assert_true(result.authenticator_data.flags.up)
  assert_eq(result.authenticator_data.flags.raw, vector.assertion_flags)
  assert_eq(
    result.credential_update.backup_state,
    result.authenticator_data.flags.bs,
  )
  let mut challenge_offset = None
  for field in parsed.members {
    if field.name == "challenge" {
      challenge_offset = Some(field.value_range.start)
    }
  }
  assertion_error(
    { ..request, expected_challenge: b"different outstanding challenge", },
    record,
    policy,
    @webauthn.ChallengeMismatch,
    "clientDataJSON.challenge",
    offset=challenge_offset,
  )
}

///|
test "assertion W3C 16.2 full ES256 policy and original DER verification" {
  assertion_w3c_verify(
    w3c_vector_none(),
    "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a877802" +
    "18deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f9372" +
    "95ea13653e331e87",
  )
}

///|
test "assertion W3C 16.4 crossOrigin true with optional topOrigin absent" {
  assertion_w3c_verify(
    w3c_vector_cross_origin(),
    "3046022100eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c" +
    "951b6e40e7022100c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c" +
    "0733b1184036d1cf",
  )
}

///|
test "assertion W3C 16.5 crossOrigin true and allowed topOrigin" {
  assertion_w3c_verify(
    w3c_vector_top_origin(),
    "3045022100b5a70c81780d5fcc9a4f2ae9caae99058f8accaf58b91fb5932964" +
    "6c28ac6ffc022012e101c165db3c8e9957f0c54dd6ca9b56bc3bd2f280bd2faa" +
    "6c1d02c6e5c171",
  )
}
