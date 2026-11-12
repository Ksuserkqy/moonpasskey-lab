///|
// Synthetic full-verifier regressions. Inputs are fixed public-only fixtures
// generated outside the core; no test signs with the implementation it tests.
fn assertion_check_counter(
  stored : UInt32,
  received : UInt32,
  status : @webauthn.CounterStatus,
  proposed : UInt32,
  risk~ : @webauthn.CounterRiskPolicy = @webauthn.ReportOnly,
) -> Unit raise {
  let fixture = assertion_fixture(count=received)
  let record = assertion_record(count=stored)
  let policy = { ..assertion_policy(), counter_risk: risk, }
  let result = assertion_ok(assertion_request(fixture), record, policy)
  assert_eq(result.counter_status, status)
  assert_eq(result.authenticator_data.sign_count, received)
  let update = result.credential_update
  assert_eq(update.previous_sign_count, stored)
  assert_eq(update.sign_count, proposed)
  assert_eq(update.previous_backup_eligible, None)
  assert_eq(update.backup_eligible, None)
  assert_eq(update.credential_id, b"credential"[:])
  assert_false(update.backup_state)
  // Verification returns a proposal and leaves the caller's snapshot intact.
  assert_eq(record.sign_count, stored)
  assert_eq(record.backup_eligible, None)
}

///|
fn assertion_reject_counter(stored : UInt32, received : UInt32) -> Unit raise {
  assertion_error(
    assertion_request(assertion_fixture(count=received)),
    assertion_record(count=stored),
    { ..assertion_policy(), counter_risk: @webauthn.Reject, },
    @webauthn.CounterNonIncreasing(stored~, received~),
    "authData.signCount",
    offset=Some(33),
  )
}

///|
fn assertion_flags_error(
  flags : Byte,
  kind : @webauthn.AssertionVerificationErrorKind,
  context : String,
  be~ : Bool? = None,
  uv~ : @webauthn.UserVerificationRequirement = @webauthn.Preferred,
) -> Unit raise {
  assertion_error(
    assertion_request(assertion_fixture(flags~)),
    assertion_record(be~),
    { ..assertion_policy(), user_verification: uv, },
    kind,
    context,
    offset=Some(32),
  )
}

///|
fn assertion_signature_error(
  signature : BytesView,
  kind : @webauthn.AssertionVerificationErrorKind,
) -> Unit raise {
  assertion_error(
    { ..assertion_request(assertion_fixture()), signature, },
    assertion_record(),
    assertion_policy(),
    kind,
    "signature",
  )
}

///|
test "assertion signed fixture baseline returns original bytes and state snapshot" {
  let fixture = assertion_fixture()
  let result = assertion_ok(
    assertion_request(fixture),
    assertion_record(),
    assertion_policy(),
  )
  assert_eq(result.client_data.raw, fixture.client[:])
  assert_eq(result.authenticator_data.raw, fixture.auth[:])
  assert_eq(result.authenticator_data.rp_id_hash_range, { start: 0, end: 32, })
  assert_eq(result.authenticator_data.flags_range, { start: 32, end: 33, })
  assert_true(result.authenticator_data.flags.up)
  assert_false(result.authenticator_data.flags.uv)
  assert_eq(result.credential_update.previous_sign_count, 0U)
  assert_eq(result.credential_update.sign_count, 0U)
  assert_eq(result.credential_update.backup_eligible, None)
}

///|
test "assertion signed reordered JSON succeeds and retains exact original" {
  let fixture = assertion_fixture(client="reordered")
  let result = assertion_ok(
    assertion_request(fixture),
    assertion_record(),
    assertion_policy(),
  )
  assert_eq(result.client_data.raw, fixture.client[:])
  assert_eq(result.client_data.type_, "webauthn.get")
  assert_eq(result.client_data.challenge, "Y2hhbGxlbmdl")
}

///|
test "assertion signed initial UTF8 BOM succeeds and remains in hash input" {
  let fixture = assertion_fixture(client="bom")
  assert_eq(fixture.client[0:3], b"\xef\xbb\xbf"[:])
  let result = assertion_ok(
    assertion_request(fixture),
    assertion_record(),
    assertion_policy(),
  )
  assert_eq(result.client_data.raw, fixture.client[:])
}

///|
test "assertion input subviews use local ranges and exclude surrounding bytes" {
  let fixture = assertion_fixture()
  let client = b"prefix" + fixture.client + b"suffix"
  let auth = b"prefix" + fixture.auth + b"suffix"
  let signature = b"prefix" + fixture.signature + b"suffix"
  let request = {
    ..assertion_request(fixture),
    client_data_json: client[6:client.length() - 6],
    authenticator_data: auth[6:auth.length() - 6],
    signature: signature[6:signature.length() - 6],
  }
  let result = assertion_ok(request, assertion_record(), assertion_policy())
  assert_eq(result.client_data.raw, fixture.client[:])
  assert_eq(result.authenticator_data.raw, fixture.auth[:])
  assert_eq(result.authenticator_data.sign_count_range, { start: 33, end: 37, })
}

///|
test "assertion counter zero to zero is unproven counter" {
  assertion_check_counter(0U, 0U, @webauthn.NotSupported, 0U)
}

///|
test "assertion counter zero to positive advances" {
  assertion_check_counter(0U, 3U, @webauthn.Advanced, 3U)
}

///|
test "assertion counter five to eight advances" {
  assertion_check_counter(5U, 8U, @webauthn.Advanced, 8U)
}

///|
test "assertion counter five to five reports risk" {
  assertion_check_counter(5U, 5U, @webauthn.NonIncreasing, 5U)
}

///|
test "assertion counter five to three retains high water" {
  assertion_check_counter(5U, 3U, @webauthn.NonIncreasing, 5U)
}

///|
test "assertion counter five to zero retains high water" {
  assertion_check_counter(5U, 0U, @webauthn.NonIncreasing, 5U)
}

///|
test "assertion counter unsigned maximum advances" {
  assertion_check_counter(0U, 4294967295U, @webauthn.Advanced, 4294967295U)
}

///|
test "assertion counter crossing signed boundary advances" {
  assertion_check_counter(8U, 4294967295U, @webauthn.Advanced, 4294967295U)
}

///|
test "assertion counter maximum equal reports risk" {
  assertion_check_counter(
    4294967295U,
    4294967295U,
    @webauthn.NonIncreasing,
    4294967295U,
  )
}

///|
test "assertion counter maximum to lower retains high water" {
  assertion_check_counter(4294967295U, 8U, @webauthn.NonIncreasing, 4294967295U)
}

///|
test "assertion counter maximum to zero is risk not wraparound" {
  assertion_check_counter(4294967295U, 0U, @webauthn.NonIncreasing, 4294967295U)
}

///|
test "assertion Reject counter zero pair remains allowed" {
  assertion_check_counter(
    0U,
    0U,
    @webauthn.NotSupported,
    0U,
    risk=@webauthn.Reject,
  )
}

///|
test "assertion Reject counter first positive remains allowed" {
  assertion_check_counter(0U, 3U, @webauthn.Advanced, 3U, risk=@webauthn.Reject)
}

///|
test "assertion Reject counter advance remains allowed" {
  assertion_check_counter(5U, 8U, @webauthn.Advanced, 8U, risk=@webauthn.Reject)
}

///|
test "assertion Reject counter unsigned maximum remains allowed" {
  assertion_check_counter(
    8U,
    4294967295U,
    @webauthn.Advanced,
    4294967295U,
    risk=@webauthn.Reject,
  )
}

///|
test "assertion Reject counter equal returns no proposal" {
  assertion_reject_counter(5U, 5U)
}

///|
test "assertion Reject counter rollback returns no proposal" {
  assertion_reject_counter(5U, 3U)
}

///|
test "assertion Reject counter reset returns no proposal" {
  assertion_reject_counter(5U, 0U)
}

///|
test "assertion Reject counter maximum equal returns no proposal" {
  assertion_reject_counter(4294967295U, 4294967295U)
}

///|
test "assertion Reject counter maximum reset returns no proposal" {
  assertion_reject_counter(4294967295U, 0U)
}

///|
test "assertion policy constructor defaults counter risk to ReportOnly" {
  let policy = assertion_policy()
  assert_eq(policy.counter_risk, @webauthn.ReportOnly)
  assert_false(policy.allow_cross_origin)
  assert_eq(policy.user_verification, @webauthn.Preferred)
}

///|
test "assertion Required accepts UV" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x05')),
    assertion_record(),
    { ..assertion_policy(), user_verification: @webauthn.Required, },
  )
  assert_true(result.authenticator_data.flags.up)
  assert_eq(result.authenticator_data.flags.uv, true)
}

///|
test "assertion Preferred accepts UV" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x05')),
    assertion_record(),
    { ..assertion_policy(), user_verification: @webauthn.Preferred, },
  )
  assert_true(result.authenticator_data.flags.up)
  assert_eq(result.authenticator_data.flags.uv, true)
}

///|
test "assertion Preferred accepts absent UV" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x01')),
    assertion_record(),
    { ..assertion_policy(), user_verification: @webauthn.Preferred, },
  )
  assert_true(result.authenticator_data.flags.up)
  assert_eq(result.authenticator_data.flags.uv, false)
}

///|
test "assertion Discouraged accepts UV" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x05')),
    assertion_record(),
    { ..assertion_policy(), user_verification: @webauthn.Discouraged, },
  )
  assert_true(result.authenticator_data.flags.up)
  assert_eq(result.authenticator_data.flags.uv, true)
}

///|
test "assertion Discouraged accepts absent UV" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x01')),
    assertion_record(),
    { ..assertion_policy(), user_verification: @webauthn.Discouraged, },
  )
  assert_true(result.authenticator_data.flags.up)
  assert_eq(result.authenticator_data.flags.uv, false)
}

///|
test "assertion Required rejects absent UV before signature acceptance" {
  assertion_flags_error(
    b'\x01',
    @webauthn.UserVerificationRequired,
    "authData.flags.uv",
    uv=@webauthn.Required,
  )
}

///|
test "assertion UP false rejects even with valid signature" {
  assertion_flags_error(
    b'\x00',
    @webauthn.UserPresenceRequired,
    "authData.flags.up",
  )
}

///|
test "assertion UV does not substitute for required UP" {
  assertion_flags_error(
    b'\x04',
    @webauthn.UserPresenceRequired,
    "authData.flags.up",
    uv=@webauthn.Required,
  )
}

///|
test "assertion backup single device unknown baseline" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x01')),
    assertion_record(be=None),
    assertion_policy(),
  )
  assert_eq(result.authenticator_data.flags.be, false)
  assert_eq(result.authenticator_data.flags.bs, false)
  assert_eq(result.credential_update.previous_backup_eligible, None)
  assert_eq(result.credential_update.backup_eligible, None)
  assert_eq(result.credential_update.backup_state, false)
}

///|
test "assertion backup multidevice unbacked unknown baseline" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x09')),
    assertion_record(be=None),
    assertion_policy(),
  )
  assert_eq(result.authenticator_data.flags.be, true)
  assert_eq(result.authenticator_data.flags.bs, false)
  assert_eq(result.credential_update.previous_backup_eligible, None)
  assert_eq(result.credential_update.backup_eligible, None)
  assert_eq(result.credential_update.backup_state, false)
}

///|
test "assertion backup multidevice backed unknown baseline" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x19')),
    assertion_record(be=None),
    assertion_policy(),
  )
  assert_eq(result.authenticator_data.flags.be, true)
  assert_eq(result.authenticator_data.flags.bs, true)
  assert_eq(result.credential_update.previous_backup_eligible, None)
  assert_eq(result.credential_update.backup_eligible, None)
  assert_eq(result.credential_update.backup_state, true)
}

///|
test "assertion backup single device known baseline" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x01')),
    assertion_record(be=Some(false)),
    assertion_policy(),
  )
  assert_eq(result.authenticator_data.flags.be, false)
  assert_eq(result.authenticator_data.flags.bs, false)
  assert_eq(result.credential_update.previous_backup_eligible, Some(false))
  assert_eq(result.credential_update.backup_eligible, Some(false))
  assert_eq(result.credential_update.backup_state, false)
}

///|
test "assertion backup multidevice unbacked known baseline" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x09')),
    assertion_record(be=Some(true)),
    assertion_policy(),
  )
  assert_eq(result.authenticator_data.flags.be, true)
  assert_eq(result.authenticator_data.flags.bs, false)
  assert_eq(result.credential_update.previous_backup_eligible, Some(true))
  assert_eq(result.credential_update.backup_eligible, Some(true))
  assert_eq(result.credential_update.backup_state, false)
}

///|
test "assertion backup multidevice backed known baseline" {
  let result = assertion_ok(
    assertion_request(assertion_fixture(flags=b'\x19')),
    assertion_record(be=Some(true)),
    assertion_policy(),
  )
  assert_eq(result.authenticator_data.flags.be, true)
  assert_eq(result.authenticator_data.flags.bs, true)
  assert_eq(result.credential_update.previous_backup_eligible, Some(true))
  assert_eq(result.credential_update.backup_eligible, Some(true))
  assert_eq(result.credential_update.backup_state, true)
}

///|
test "assertion backup false registration rejects observed true" {
  assertion_flags_error(
    b'\x09',
    @webauthn.BackupEligibilityMismatch,
    "authData.flags.be",
    be=Some(false),
  )
}

///|
test "assertion backup true registration rejects observed false" {
  assertion_flags_error(
    b'\x01',
    @webauthn.BackupEligibilityMismatch,
    "authData.flags.be",
    be=Some(true),
  )
}

///|
test "assertion BS changes in both directions without clone classification" {
  let record = assertion_record(be=Some(true))
  for (flags, backed_up) in [(b'\x19', true), (b'\x09', false)] {
    let result = assertion_ok(
      assertion_request(assertion_fixture(flags~)),
      record,
      assertion_policy(),
    )
    assert_eq(result.counter_status, @webauthn.NotSupported)
    assert_eq(result.credential_update.backup_state, backed_up)
    assert_eq(result.credential_update.backup_eligible, Some(true))
  }
}

///|
test "assertion BS without BE preserves structural parser error" {
  let fixture = assertion_fixture(flags=b'\x11')
  let nested = match @webauthn.parse_authenticator_data(fixture.auth) {
    Err(error) => error
    Ok(_) => fail("invalid BS/BE unexpectedly parsed")
  }
  assert_eq(nested.kind, @webauthn.InvalidFlags(b'\x11'))
  assertion_error(
    assertion_request(fixture),
    assertion_record(),
    assertion_policy(),
    @webauthn.Parse(nested),
    "authData",
    offset=Some(nested.offset),
  )
}

///|
test "assertion reserved flag 03 is rejected by assertion policy" {
  assertion_flags_error(
    b'\x03',
    @webauthn.InvalidAssertionFlags,
    "authData.flags.reserved",
  )
}

///|
test "assertion reserved flag 21 is rejected by assertion policy" {
  assertion_flags_error(
    b'\x21',
    @webauthn.InvalidAssertionFlags,
    "authData.flags.reserved",
  )
}

///|
test "assertion valid AT structure is rejected for assertion ceremony" {
  let fixture = assertion_fixture(flags=b'\x41')
  let parsed = match @webauthn.parse_authenticator_data(fixture.auth) {
    Ok(value) => value
    Err(error) => fail("synthetic AT fixture malformed \{error.to_repr()}")
  }
  assert_true(parsed.attested is Some(_))
  assertion_flags_error(
    b'\x41',
    @webauthn.UnexpectedAttestedCredentialData,
    "authData.flags.at",
  )
}

///|
test "assertion signed ED map is retained while outputs are ignored" {
  let fixture = assertion_fixture(flags=b'\x81')
  let result = assertion_ok(
    assertion_request(fixture),
    assertion_record(),
    assertion_policy(),
  )
  assert_true(result.authenticator_data.flags.ed)
  assert_true(result.authenticator_data.extensions is Some(_))
  assert_eq(result.authenticator_data.extensions_raw, Some(fixture.auth[37:]))
  assert_eq(result.authenticator_data.raw, fixture.auth[:])
}

///|
test "assertion signed ED plus UV satisfies Required" {
  let fixture = assertion_fixture(flags=b'\x85')
  let result = assertion_ok(assertion_request(fixture), assertion_record(), {
    ..assertion_policy(),
    user_verification: @webauthn.Required,
  })
  assert_true(result.authenticator_data.flags.uv)
  assert_true(result.authenticator_data.extensions is Some(_))
}

///|
test "assertion ignored extension output remains signature bound" {
  let fixture = assertion_fixture(flags=b'\x81')
  let auth = fixture.auth[:fixture.auth.length() - 1].to_owned() + b"\xf4"
  assertion_error(
    { ..assertion_request(fixture), authenticator_data: auth, },
    assertion_record(),
    assertion_policy(),
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion signature empty signature has encoding error" {
  assertion_signature_error(
    b"",
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature single byte signature has encoding error" {
  assertion_signature_error(
    b"\x30",
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion oversized DER is a cryptographic format error" {
  assertion_signature_error(
    Bytes::make(73, b'\x00'),
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature truncated DER has encoding error" {
  let fixture = assertion_fixture()
  assertion_signature_error(
    fixture.signature[:fixture.signature.length() - 1],
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature trailing bytes has encoding error" {
  let fixture = assertion_fixture()
  assertion_signature_error(
    fixture.signature + b"\x00",
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature raw64 instead of DER has encoding error" {
  assertion_signature_error(
    Bytes::make(64, b'\x01'),
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature negative integer has encoding error" {
  assertion_signature_error(
    b"\x30\x06\x02\x01\x80\x02\x01\x01",
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature redundant integer padding has encoding error" {
  assertion_signature_error(
    b"\x30\x07\x02\x02\x00\x01\x02\x01\x01",
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
  )
}

///|
test "assertion signature zero R has scalar error" {
  assertion_signature_error(
    b"\x30\x06\x02\x01\x00\x02\x01\x01",
    @webauthn.Crypto(@webauthn.InvalidSignatureScalar(component="R")),
  )
}

///|
test "assertion signature zero S has scalar error" {
  assertion_signature_error(
    b"\x30\x06\x02\x01\x01\x02\x01\x00",
    @webauthn.Crypto(@webauthn.InvalidSignatureScalar(component="S")),
  )
}

///|
test "assertion signature order R has scalar error" {
  assertion_signature_error(
    crypto_der_body(
      crypto_der_integer(b"\x00" + crypto_order()) + crypto_der_integer(b"\x01"),
    ),
    @webauthn.Crypto(@webauthn.InvalidSignatureScalar(component="R")),
  )
}

///|
test "assertion signature order S has scalar error" {
  assertion_signature_error(
    crypto_der_body(
      crypto_der_integer(b"\x01") + crypto_der_integer(b"\x00" + crypto_order()),
    ),
    @webauthn.Crypto(@webauthn.InvalidSignatureScalar(component="S")),
  )
}

///|
test "assertion legal DER wrong signature is distinct from format error" {
  assertion_signature_error(
    b"\x30\x06\x02\x01\x01\x02\x01\x01",
    @webauthn.InvalidSignature,
  )
}

///|
test "assertion different valid public key causes signature mismatch" {
  let fixture = assertion_fixture()
  let record = {
    ..assertion_record(),
    public_key: crypto_imported(crypto_parameters_fixture()),
  }
  assertion_error(
    assertion_request(fixture),
    record,
    assertion_policy(),
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion validated public key cannot be obtained from invalid point" {
  let zero = Bytes::make(32, b'\x00')
  let parameters = crypto_parameters(crypto_parameters_fixture(x=zero, y=zero))
  match @webauthn.import_es256_public_key(parameters) {
    Err(error) => assert_eq(error, @webauthn.InvalidPublicKey)
    Ok(_) => fail("invalid point must not enter credential record")
  }
}

///|
test "assertion signature mutation with valid DER fails verification" {
  let fixture = assertion_fixture()
  let last = fixture.signature.length() - 1
  let changed = fixture.signature[:last].to_owned() +
    Bytes::from_array([(fixture.signature[last].to_int() ^ 1).to_byte()])
  assertion_signature_error(changed, @webauthn.InvalidSignature)
}

///|
test "assertion semantically identical JSON whitespace mutation fails signature" {
  let fixture = assertion_fixture()
  assertion_error(
    { ..assertion_request(fixture), client_data_json: b" " + fixture.client, },
    assertion_record(),
    assertion_policy(),
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion semantically identical property reordering fails signature" {
  let fixture = assertion_fixture()
  assertion_error(
    {
      ..assertion_request(fixture),
      client_data_json: assertion_client("reordered"),
    },
    assertion_record(),
    assertion_policy(),
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion counter byte mutation fails signature before proposal" {
  let fixture = assertion_fixture()
  let auth = fixture.auth[:36].to_owned() + b"\x08"
  assertion_error(
    { ..assertion_request(fixture), authenticator_data: auth, },
    assertion_record(),
    assertion_policy(),
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion UV flag mutation still accepted by policy fails signature" {
  let fixture = assertion_fixture()
  let auth = fixture.auth[:32].to_owned() +
    b"\x05" +
    fixture.auth[33:].to_owned()
  assertion_error(
    { ..assertion_request(fixture), authenticator_data: auth, },
    assertion_record(),
    assertion_policy(),
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion invalid signature precedes rejecting counter risk" {
  let fixture = assertion_fixture(count=3U)
  assertion_error(
    {
      ..assertion_request(fixture),
      signature: b"\x30\x06\x02\x01\x01\x02\x01\x01",
    },
    assertion_record(count=5U),
    { ..assertion_policy(), counter_risk: @webauthn.Reject, },
    @webauthn.InvalidSignature,
    "signature",
  )
}

///|
test "assertion malformed signature precedes counter update" {
  let fixture = assertion_fixture(count=8U)
  assertion_error(
    { ..assertion_request(fixture), signature: b"", },
    assertion_record(count=5U),
    assertion_policy(),
    @webauthn.Crypto(@webauthn.InvalidSignatureEncoding),
    "signature",
  )
}

///|
test "assertion truncated authData preserves nested parser offset" {
  let fixture = assertion_fixture()
  let raw = fixture.auth[:36]
  let nested = match @webauthn.parse_authenticator_data(raw) {
    Err(error) => error
    Ok(_) => fail("truncated counter unexpectedly parsed")
  }
  assertion_error(
    { ..assertion_request(fixture), authenticator_data: raw, },
    assertion_record(),
    assertion_policy(),
    @webauthn.Parse(nested),
    "authData",
    offset=Some(nested.offset),
  )
}
