///|
fn read_policy(
  fields : Map[String, Json],
) -> @webauthn.AssertionVerificationPolicy raise BridgeFailure {
  let path = "input.policy"
  let values = object(required(fields, "policy", "input"), path)
  let uv = match optional_text(values, "uv", path) {
    None | Some("preferred") => @webauthn.Preferred
    Some("required") => @webauthn.Required
    Some("discouraged") => @webauthn.Discouraged
    _ => raise BridgeError(code="InvalidConfiguration", path=path + ".uv")
  }
  let counter = match optional_text(values, "counterPolicy", path) {
    None | Some("report-only") => @webauthn.ReportOnly
    Some("reject") => @webauthn.Reject
    _ =>
      raise BridgeError(
        code="InvalidConfiguration",
        path=path + ".counterPolicy",
      )
  }
  let ids = strings(values, "allowedCredentialIds", path, optional=true).map(value => {
    decode(value, path + ".allowedCredentialIds")
  })
  @webauthn.AssertionVerificationPolicy::new(
    text(values, "rpId", path),
    strings(values, "allowedOrigins", path),
    user_verification=uv,
    counter_risk=counter,
    allow_cross_origin=boolean(values, "allowCrossOrigin", path, false),
    allowed_top_origins=strings(
      values,
      "allowedTopOrigins",
      path,
      optional=true,
    ),
    allowed_credential_ids=ids,
  )
}

///|
fn verify(
  fields : Map[String, Json],
  report : Report,
) -> Json raise BridgeFailure {
  let credential_fields = object(
    required(fields, "credential", "input"),
    "input.credential",
  )
  let key = read_key(
    binary(credential_fields, "publicKey", "input.credential"),
    report,
  )
  let credential : @webauthn.AssertionCredentialRecord = {
    credential_id: binary(credential_fields, "credentialId", "input.credential"),
    user_handle: binary(credential_fields, "userHandle", "input.credential"),
    public_key: key,
    sign_count: uint32(credential_fields, "signCount", "input.credential"),
    backup_eligible: optional_boolean(
      credential_fields, "backupEligible", "input.credential",
    ),
  }
  let identification = match
    optional_text(fields, "userIdentification", "input") {
    None | Some("identified") => @webauthn.Identified
    Some("discoverable") => @webauthn.Discoverable
    _ =>
      raise BridgeError(
        code="InvalidConfiguration",
        path="input.userIdentification",
      )
  }
  let request : @webauthn.AssertionVerificationRequest = {
    client_data_json: binary(fields, "clientDataJSON", "input"),
    authenticator_data: binary(fields, "authenticatorData", "input"),
    signature: binary(fields, "signature", "input"),
    credential_id: binary(fields, "credentialId", "input"),
    user_handle: optional_binary(fields, "userHandle", "input").map(bytes => {
      bytes[:]
    }),
    expected_challenge: binary(fields, "expectedChallenge", "input"),
    user_identification: identification,
  }
  let policy = read_policy(fields)
  report.fields.set("crypto", Json::object({ "format": jstring("DER") }))
  match @webauthn.verify_webauthn_es256_assertion(request, credential, policy) {
    Err(error) => {
      if error.context == "signature" {
        report.fields.set(
          "crypto",
          Json::object({
            "format": jstring("DER"),
            "signatureValid": jbool(false),
          }),
        )
      }
      raise report.reject(
        assertion_check(error.context),
        assertion_error_name(error.kind),
        error.context,
        offset=error.offset,
      )
    }
    Ok(result) => {
      for
        check in [
          "json", "authenticator_data", "public_key", "identity", "challenge", "origin",
          "cross_origin", "rp_id_hash", "user_presence", "user_verification", "backup",
          "signature",
        ] {
        report.pass(check)
      }
      let counter = match result.counter_status {
        @webauthn.NotSupported => "NOT_SUPPORTED"
        @webauthn.Advanced => "ADVANCED"
        @webauthn.NonIncreasing => "WARNING"
      }
      report.checks.set("counter", jstring(counter))
      report.fields.set("clientData", client_summary(result.client_data))
      report.fields.set(
        "authenticatorData",
        auth_summary(result.authenticator_data),
      )
      report.fields.set(
        "crypto",
        Json::object({ "format": jstring("DER"), "signatureValid": jbool(true) }),
      )
      report.fields.set(
        "counter",
        Json::object({
          "status": jstring(counter),
          "stored": juint(credential.sign_count),
          "received": juint(result.authenticator_data.sign_count),
        }),
      )
      let update = result.credential_update
      report.fields.set(
        "credentialUpdate",
        Json::object({
          "signCount": juint(update.sign_count),
          "backupEligible": optional_bool(update.backup_eligible),
          "backupState": jbool(update.backup_state),
          "previousSignCount": juint(update.previous_sign_count),
        }),
      )
      report.finish()
    }
  }
}

///|
fn analyze_assertion(
  fields : Map[String, Json],
  report : Report,
) -> Json raise BridgeFailure {
  let client = read_client(binary(fields, "clientDataJSON", "input"), report)
  let auth = read_auth(binary(fields, "authenticatorData", "input"), report)
  let key = read_key(binary(fields, "publicKey", "input"), report)
  let signature = binary(fields, "signature", "input")
  report.fields.set("crypto", Json::object({ "format": jstring("DER") }))
  match
    @webauthn.verify_webauthn_es256_assertion_signature(
      key,
      auth.raw,
      client.raw,
      signature,
    ) {
    Ok(true) => {
      report.pass("signature")
      report.fields.set(
        "crypto",
        Json::object({ "format": jstring("DER"), "signatureValid": jbool(true) }),
      )
    }
    Ok(false) => {
      report.fields.set(
        "crypto",
        Json::object({
          "format": jstring("DER"),
          "signatureValid": jbool(false),
        }),
      )
      raise report.reject("signature", "InvalidSignature", "signature")
    }
    Err(error) =>
      raise report.reject("signature", crypto_error_name(error), "signature")
  }
  report.finish()
}

///|
fn run(input : String, host : Bool) -> String {
  let output = try {
    if input.length() > MAX_JSON_UNITS {
      raise BridgeError(code="ResourceLimit", path="input")
    }
    let json = @json.parse(
      input,
      max_nesting_depth=32,
      reject_duplicate_keys=true,
    ) catch {
      @json.DuplicateKey(_, _) =>
        raise BridgeError(code="DuplicateField", path="input")
      @json.DepthLimitExceeded =>
        raise BridgeError(code="ResourceLimit", path="input")
      _ => raise BridgeError(code="InvalidJson", path="input")
    }
    let fields = object(json, "input")
    let command = text(fields, "command", "input")
    let report = Report::new(command)
    match command {
      "client-data" => {
        read_client(binary(fields, "clientDataJSON", "input"), report) |> ignore
        report.finish()
      }
      "authenticator-data" => {
        read_auth(binary(fields, "authenticatorData", "input"), report)
        |> ignore
        report.finish()
      }
      "analyze-assertion" => analyze_assertion(fields, report)
      "verify-assertion" => verify(fields, report)
      "register-test" => register_test(fields, report, host)
      _ => raise BridgeError(code="UnknownCommand", path="input.command")
    }
  } catch {
    ReportFailed(report) => report
    BridgeError(code~, path~) => {
      let report = Report::new("invalid-input")
      match report.reject("json", code, path) {
        ReportFailed(value) => value
        _ => report.finish()
      }
    }
  }
  output.stringify()
}

///|
/// Analyze transport JSON and return a redacted report. Binary transport uses
/// strict unpadded Base64URL. This pure entry point performs no IO or storage.
pub fn run_json(input : String) -> String {
  run(input, false)
}

///|
/// Trusted RP-host entry point. TEST ONLY registration additionally returns
/// a credential record for the host's private transactional store. The host
/// must filter that record before producing logs or browser-facing reports.
pub fn run_host_json(input : String) -> String {
  run(input, true)
}
