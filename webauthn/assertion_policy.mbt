///|
fn assertion_check_byte_budget(
  bytes : BytesView,
  context : String,
  limit : Int32,
) -> Unit raise AssertionFailure {
  if bytes.length() > limit {
    raise assertion_fail(context, ResourceLimit(limit~, actual=bytes.length()))
  }
}

///|
/// Count UTF-8 bytes before allocation. Reject malformed trusted UTF-16
/// configuration because the pinned UTF-8 encoder panics on those values on
/// some targets. Matching retains each configured string exactly.
fn assertion_check_string_budget(
  value : String,
  context : String,
  limit : Int32,
) -> Unit raise AssertionFailure {
  if value.is_empty() {
    raise assertion_fail(context, InvalidConfiguration)
  }
  let mut bytes = 0UL
  let mut leading_surrogate = false
  for _, code_unit in value.code_units() {
    let unit = code_unit.to_int()
    if leading_surrogate {
      if unit < 0xDC00 || unit > 0xDFFF {
        raise assertion_fail(context, InvalidConfiguration)
      }
      leading_surrogate = false
    } else if unit >= 0xD800 && unit <= 0xDBFF {
      leading_surrogate = true
      bytes += 4UL
    } else if unit >= 0xDC00 && unit <= 0xDFFF {
      raise assertion_fail(context, InvalidConfiguration)
    } else if unit < 0x80 {
      bytes += 1UL
    } else if unit < 0x800 {
      bytes += 2UL
    } else {
      bytes += 3UL
    }
    if bytes > limit.to_uint64() {
      let actual = if bytes > 0x7fff_ffffUL {
        0x7fff_ffff
      } else {
        bytes.to_int()
      }
      raise assertion_fail(context, ResourceLimit(limit~, actual~))
    }
  }
  if leading_surrogate {
    raise assertion_fail(context, InvalidConfiguration)
  }
}

///|
/// Supported configuration subset: ASCII domain labels, including localhost.
/// Preserve case and require the caller to establish RP-ID registrability and
/// browser-origin eligibility. This performs no PSL or IDNA normalization.
fn assertion_check_rp_id(rp_id : String) -> Unit raise AssertionFailure {
  let context = "policy.expected_rp_id"
  if rp_id.is_empty() || rp_id.length() > 253 {
    raise assertion_fail(context, InvalidConfiguration)
  }
  let mut label_length = 0
  let mut last_hyphen = false
  for _, code_unit in rp_id.code_units() {
    let unit = code_unit.to_int()
    match unit {
      '.' => {
        if label_length == 0 || last_hyphen {
          raise assertion_fail(context, InvalidConfiguration)
        }
        label_length = 0
        last_hyphen = false
      }
      'A'..<='Z' | 'a'..<='z' | '0'..<='9' | '-' => {
        if label_length == 0 && unit == '-' {
          raise assertion_fail(context, InvalidConfiguration)
        }
        label_length += 1
        if label_length > 63 {
          raise assertion_fail(context, InvalidConfiguration)
        }
        last_hyphen = unit == '-'
      }
      _ => raise assertion_fail(context, InvalidConfiguration)
    }
  }
  if label_length == 0 || last_hyphen {
    raise assertion_fail(context, InvalidConfiguration)
  }
}

///|
fn assertion_check_origins(
  origins : Array[String],
  context : String,
  limits : @cbor.Limits,
) -> Unit raise AssertionFailure {
  if origins.length() > limits.max_array_items {
    raise assertion_fail(
      context,
      ResourceLimit(limit=limits.max_array_items, actual=origins.length()),
    )
  }
  for index, origin in origins {
    assertion_check_string_budget(
      origin,
      "\{context}[\{index}]",
      limits.max_string_bytes,
    )
  }
}

///|
fn assertion_check_credential_id(
  id : BytesView,
  context : String,
  limit : Int32,
) -> Unit raise AssertionFailure {
  assertion_check_byte_budget(id, context, limit)
  if id.length() == 0 || id.length() > 1023 {
    raise assertion_fail(context, InvalidCredentialId)
  }
}

///|
fn assertion_check_user_handle(
  handle : BytesView,
  context : String,
  limit : Int32,
) -> Unit raise AssertionFailure {
  assertion_check_byte_budget(handle, context, limit)
  if handle.length() == 0 || handle.length() > 64 {
    raise assertion_fail(context, InvalidUserHandle)
  }
}

///|
fn check_assertion_configuration(
  request : AssertionVerificationRequest,
  record : AssertionCredentialRecord,
  policy : AssertionVerificationPolicy,
  limits : @cbor.Limits,
) -> Unit raise AssertionFailure {
  validate_protocol_limits(limits, "assertion.limits") catch {
    Failed(error) => raise assertion_fail("assertion.limits", Parse(error))
  }
  assertion_check_byte_budget(
    request.client_data_json,
    "request.client_data_json",
    limits.max_input_bytes,
  )
  assertion_check_byte_budget(
    request.authenticator_data,
    "request.authenticator_data",
    limits.max_input_bytes,
  )
  let challenge_limit = if limits.max_input_bytes < @base64url.MAX_BYTES {
    limits.max_input_bytes
  } else {
    @base64url.MAX_BYTES
  }
  assertion_check_byte_budget(
    request.expected_challenge,
    "request.expected_challenge",
    challenge_limit,
  )
  if request.expected_challenge.length() == 0 {
    raise assertion_fail("request.expected_challenge", EmptyChallenge)
  }
  assertion_check_credential_id(
    request.credential_id,
    "request.credential_id",
    limits.max_input_bytes,
  )
  assertion_check_credential_id(
    record.credential_id,
    "record.credential_id",
    limits.max_input_bytes,
  )
  assertion_check_user_handle(
    record.user_handle,
    "record.user_handle",
    limits.max_input_bytes,
  )
  if request.user_handle is Some(handle) {
    assertion_check_user_handle(
      handle,
      "request.user_handle",
      limits.max_input_bytes,
    )
  }
  assertion_check_byte_budget(
    record.public_key.parameters().raw,
    "record.public_key",
    limits.max_input_bytes,
  )
  assertion_check_rp_id(policy.expected_rp_id)
  assertion_check_string_budget(
    policy.expected_rp_id,
    "policy.expected_rp_id",
    limits.max_string_bytes,
  )
  if policy.allowed_origins.is_empty() {
    raise assertion_fail("policy.allowed_origins", InvalidConfiguration)
  }
  assertion_check_origins(
    policy.allowed_origins,
    "policy.allowed_origins",
    limits,
  )
  assertion_check_origins(
    policy.allowed_top_origins,
    "policy.allowed_top_origins",
    limits,
  )
  if policy.allowed_credential_ids.length() > limits.max_array_items {
    raise assertion_fail(
      "policy.allowed_credential_ids",
      ResourceLimit(
        limit=limits.max_array_items,
        actual=policy.allowed_credential_ids.length(),
      ),
    )
  }
  for index, id in policy.allowed_credential_ids {
    let context = "policy.allowed_credential_ids[\{index}]"
    assertion_check_byte_budget(id, context, limits.max_input_bytes)
    if id.length() == 0 || id.length() > 1023 {
      raise assertion_fail(context, InvalidConfiguration)
    }
  }
}

///|
fn assertion_client_offset(client : ClientData, name : String) -> Int32? {
  for field in client.members {
    if field.name == name {
      return Some(field.value_range.start)
    }
  }
  None
}

///|
fn check_assertion_client_data(
  client : ClientData,
  request : AssertionVerificationRequest,
  policy : AssertionVerificationPolicy,
) -> Unit raise AssertionFailure {
  if client.type_ != "webauthn.get" {
    raise assertion_fail(
      "clientDataJSON.type",
      InvalidClientDataType,
      offset=assertion_client_offset(client, "type"),
    )
  }
  let challenge_offset = assertion_client_offset(client, "challenge")
  if client.challenge.is_empty() {
    raise assertion_fail(
      "clientDataJSON.challenge",
      EmptyChallenge,
      offset=challenge_offset,
    )
  }
  for _, code_unit in client.challenge.code_units() {
    if code_unit.to_int() == '=' {
      raise assertion_fail(
        "clientDataJSON.challenge",
        InvalidChallengeEncoding,
        offset=challenge_offset,
      )
    }
  }
  let decoded = match @base64url.decode(client.challenge) {
    Ok(bytes) => bytes
    Err(_) =>
      raise assertion_fail(
        "clientDataJSON.challenge",
        InvalidChallengeEncoding,
        offset=challenge_offset,
      )
  }
  let expected_encoding = match @base64url.encode(request.expected_challenge) {
    Ok(text) => text
    Err(_) =>
      raise assertion_fail("request.expected_challenge", InvalidConfiguration)
  }
  if !@spec.eq(decoded, request.expected_challenge) ||
    !@spec.eq(@utf8.encode(client.challenge), @utf8.encode(expected_encoding)) {
    raise assertion_fail(
      "clientDataJSON.challenge",
      ChallengeMismatch,
      offset=challenge_offset,
    )
  }
  if !policy.allowed_origins.contains(client.origin) {
    raise assertion_fail(
      "clientDataJSON.origin",
      OriginNotAllowed,
      offset=assertion_client_offset(client, "origin"),
    )
  }
  let cross_origin = client.cross_origin == Some(true)
  if cross_origin && !policy.allow_cross_origin {
    raise assertion_fail(
      "clientDataJSON.crossOrigin",
      CrossOriginNotAllowed,
      offset=assertion_client_offset(client, "crossOrigin"),
    )
  }
  if client.top_origin is Some(top_origin) {
    let offset = assertion_client_offset(client, "topOrigin")
    if !cross_origin {
      raise assertion_fail(
        "clientDataJSON.topOrigin",
        InconsistentTopOrigin,
        offset~,
      )
    }
    if !policy.allowed_top_origins.contains(top_origin) {
      raise assertion_fail(
        "clientDataJSON.topOrigin",
        TopOriginNotAllowed,
        offset~,
      )
    }
  }
}

///|
fn check_assertion_identity(
  request : AssertionVerificationRequest,
  record : AssertionCredentialRecord,
  policy : AssertionVerificationPolicy,
) -> Unit raise AssertionFailure {
  if !@spec.eq(request.credential_id, record.credential_id) {
    raise assertion_fail("request.credential_id", CredentialIdMismatch)
  }
  if !policy.allowed_credential_ids.is_empty() {
    let mut allowed = false
    for id in policy.allowed_credential_ids {
      if @spec.eq(request.credential_id, id) {
        allowed = true
      }
    }
    if !allowed {
      raise assertion_fail("request.credential_id", CredentialNotAllowed)
    }
  }
  match request.user_handle {
    Some(handle) =>
      if !@spec.eq(handle, record.user_handle) {
        raise assertion_fail("request.user_handle", UserHandleMismatch)
      }
    None =>
      if request.user_identification is Discoverable {
        raise assertion_fail("request.user_handle", UserHandleRequired)
      }
  }
}
