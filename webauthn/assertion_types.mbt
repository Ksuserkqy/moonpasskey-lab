///|
#derive(Eq, Debug)
pub(all) enum UserVerificationRequirement {
  Required
  Preferred
  Discouraged
}

///|
pub extend UserVerificationRequirement with Eq::{equal, not_equal}

///|
pub extend UserVerificationRequirement with Debug::{to_repr}

///|
#derive(Eq, Debug)
pub(all) enum CounterRiskPolicy {
  ReportOnly
  Reject
}

///|
pub extend CounterRiskPolicy with Eq::{equal, not_equal}

///|
pub extend CounterRiskPolicy with Debug::{to_repr}

///|
#derive(Eq, Debug)
pub(all) enum CounterStatus {
  NotSupported
  Advanced
  NonIncreasing
}

///|
pub extend CounterStatus with Eq::{equal, not_equal}

///|
pub extend CounterStatus with Debug::{to_repr}

///|
/// Discoverable requires userHandle and a caller-resolved account record.
#derive(Eq, Debug)
pub(all) enum AssertionUserIdentification {
  Identified
  Discoverable
}

///|
pub extend AssertionUserIdentification with Eq::{equal, not_equal}

///|
pub extend AssertionUserIdentification with Debug::{to_repr}

///|
/// Response bytes plus the trusted, outstanding challenge for this ceremony.
/// The caller supplies the response type public-key and decoded rawId bytes.
pub(all) struct AssertionVerificationRequest {
  client_data_json : BytesView
  authenticator_data : BytesView
  signature : BytesView
  credential_id : BytesView
  user_handle : BytesView?
  expected_challenge : BytesView
  user_identification : AssertionUserIdentification
}

///|
/// Trusted storage record already associated with the selected account.
/// Discoverable account lookup happens before calling the verifier.
pub(all) struct AssertionCredentialRecord {
  credential_id : BytesView
  user_handle : BytesView
  public_key : ValidatedEs256PublicKey
  sign_count : UInt32
  backup_eligible : Bool?
}

///|
/// Exact serialized Origin allowlists and a trusted ASCII domain RP ID.
/// An empty credential allowlist corresponds to omitted/empty allowCredentials.
pub(all) struct AssertionVerificationPolicy {
  expected_rp_id : String
  allowed_origins : Array[String]
  user_verification : UserVerificationRequirement
  allow_cross_origin : Bool
  allowed_top_origins : Array[String]
  allowed_credential_ids : Array[Bytes]
  counter_risk : CounterRiskPolicy
}

///|
pub fn AssertionVerificationPolicy::new(
  expected_rp_id : String,
  allowed_origins : Array[String],
  user_verification~ : UserVerificationRequirement = Preferred,
  allow_cross_origin~ : Bool = false,
  allowed_top_origins~ : Array[String] = [],
  allowed_credential_ids~ : Array[Bytes] = [],
  counter_risk~ : CounterRiskPolicy = ReportOnly,
) -> AssertionVerificationPolicy {
  {
    expected_rp_id,
    allowed_origins,
    user_verification,
    allow_cross_origin,
    allowed_top_origins,
    allowed_credential_ids,
    counter_risk,
  }
}

///|
#derive(Eq, Debug)
pub(all) enum AssertionVerificationErrorKind {
  Parse(ParseError)
  Crypto(CryptoError)
  InvalidConfiguration
  ResourceLimit(limit~ : Int32, actual~ : Int32)
  InvalidCredentialId
  CredentialIdMismatch
  CredentialNotAllowed
  InvalidUserHandle
  UserHandleRequired
  UserHandleMismatch
  EmptyChallenge
  InvalidChallengeEncoding
  ChallengeMismatch
  InvalidClientDataType
  OriginNotAllowed
  CrossOriginNotAllowed
  InconsistentTopOrigin
  TopOriginNotAllowed
  RpIdHashMismatch
  UserPresenceRequired
  UserVerificationRequired
  BackupEligibilityMismatch
  UnexpectedAttestedCredentialData
  InvalidAssertionFlags
  InvalidSignature
  CounterNonIncreasing(stored~ : UInt32, received~ : UInt32)
}

///|
pub extend AssertionVerificationErrorKind with Eq::{equal, not_equal}

///|
pub extend AssertionVerificationErrorKind with Debug::{to_repr}

///|
/// offset is relative to the named response byte field. Configuration errors
/// have no input offset. Nested parser errors preserve their original details.
#derive(Eq, Debug)
pub(all) struct AssertionVerificationError {
  context : String
  offset : Int32?
  kind : AssertionVerificationErrorKind
}

///|
pub extend AssertionVerificationError with Eq::{equal, not_equal}

///|
pub extend AssertionVerificationError with Debug::{to_repr}

///|
priv suberror AssertionFailure {
  AssertionFailed(AssertionVerificationError)
}

///|
fn assertion_fail(
  context : String,
  kind : AssertionVerificationErrorKind,
  offset~ : Int32? = None,
) -> AssertionFailure {
  AssertionFailed({ context, offset, kind, })
}

///|
/// A proposal produced only after successful policy and signature checks.
/// Compare the snapshot with storage atomically before applying this update.
#derive(Eq, Debug)
pub struct AssertionCredentialUpdate {
  credential_id : BytesView
  previous_sign_count : UInt32
  previous_backup_eligible : Bool?
  sign_count : UInt32
  backup_eligible : Bool?
  backup_state : Bool
}

///|
pub extend AssertionCredentialUpdate with Eq::{equal, not_equal}

///|
pub extend AssertionCredentialUpdate with Debug::{to_repr}

///|
/// Only the verifier constructs successful results. Raw parser results retain
/// source ranges. credential_update is a proposal for caller persistence.
#derive(Eq, Debug)
pub struct AssertionVerificationResult {
  client_data : ClientData
  authenticator_data : AuthenticatorData
  counter_status : CounterStatus
  credential_update : AssertionCredentialUpdate
}

///|
pub extend AssertionVerificationResult with Eq::{equal, not_equal}

///|
pub extend AssertionVerificationResult with Debug::{to_repr}
