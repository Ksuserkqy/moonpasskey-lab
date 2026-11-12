///|
// The transport envelope is bounded separately from the unchanged binary
// parsers. Binary fields retain each parser's default one-MiB limit.
const MAX_JSON_UNITS : Int32 = 4_194_304

///|
priv suberror BridgeFailure {
  BridgeError(code~ : String, path~ : String)
  ReportFailed(Json)
}

///|
fn object(value : Json, path : String) -> Map[String, Json] raise BridgeFailure {
  match value {
    Json::Object(fields) => fields
    _ => raise BridgeError(code="WrongType", path~)
  }
}

///|
fn required(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> Json raise BridgeFailure {
  match fields.get(name) {
    Some(value) => value
    None => raise BridgeError(code="MissingField", path=path + "." + name)
  }
}

///|
fn text(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> String raise BridgeFailure {
  match required(fields, name, path) {
    Json::String(value) => value
    _ => raise BridgeError(code="WrongType", path=path + "." + name)
  }
}

///|
fn optional_text(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> String? raise BridgeFailure {
  match fields.get(name) {
    None | Some(Json::Null) => None
    Some(Json::String(value)) => Some(value)
    _ => raise BridgeError(code="WrongType", path=path + "." + name)
  }
}

///|
fn boolean(
  fields : Map[String, Json],
  name : String,
  path : String,
  default : Bool,
) -> Bool raise BridgeFailure {
  match fields.get(name) {
    None => default
    Some(Json::True) => true
    Some(Json::False) => false
    _ => raise BridgeError(code="WrongType", path=path + "." + name)
  }
}

///|
fn optional_boolean(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> Bool? raise BridgeFailure {
  match fields.get(name) {
    None | Some(Json::Null) => None
    Some(Json::True) => Some(true)
    Some(Json::False) => Some(false)
    _ => raise BridgeError(code="WrongType", path=path + "." + name)
  }
}

///|
fn strings(
  fields : Map[String, Json],
  name : String,
  path : String,
  optional~ : Bool = false,
) -> Array[String] raise BridgeFailure {
  let values = match fields.get(name) {
    None if optional => return []
    Some(Json::Array(values)) => values
    None => raise BridgeError(code="MissingField", path=path + "." + name)
    _ => raise BridgeError(code="WrongType", path=path + "." + name)
  }
  if values.length() > 4096 {
    raise BridgeError(code="ResourceLimit", path=path + "." + name)
  }
  let result = []
  for value in values {
    match value {
      Json::String(string) => result.push(string)
      _ => raise BridgeError(code="WrongType", path=path + "." + name)
    }
  }
  result
}

///|
fn uint32(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> UInt32 raise BridgeFailure {
  match required(fields, name, path) {
    Json::Number(value, ..) if value >= 0.0 && value <= 4294967295.0 => {
      let count = value.to_uint()
      if count.to_double() != value {
        raise BridgeError(code="InvalidInteger", path=path + "." + name)
      }
      count
    }
    _ => raise BridgeError(code="InvalidInteger", path=path + "." + name)
  }
}

///|
fn decode(encoded : String, path : String) -> Bytes raise BridgeFailure {
  if encoded.contains("=") {
    raise BridgeError(code="InvalidBase64URL", path~)
  }
  match @base64url.decode(encoded) {
    Ok(bytes) => bytes
    Err(_) => raise BridgeError(code="InvalidBase64URL", path~)
  }
}

///|
fn binary(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> Bytes raise BridgeFailure {
  decode(text(fields, name, path), path + "." + name)
}

///|
fn optional_binary(
  fields : Map[String, Json],
  name : String,
  path : String,
) -> Bytes? raise BridgeFailure {
  optional_text(fields, name, path).map(value => {
    decode(value, path + "." + name)
  })
}

///|
fn encoded(bytes : BytesView) -> String {
  match @base64url.encode(bytes) {
    Ok(value) => value
    Err(_) => ""
  }
}

///|
fn jstring(value : String) -> Json {
  Json::string(value)
}

///|
fn jbool(value : Bool) -> Json {
  Json::boolean(value)
}

///|
fn juint(value : UInt32) -> Json {
  Json::number(value.to_double())
}

///|
fn optional_bool(value : Bool?) -> Json {
  match value {
    Some(value) => jbool(value)
    None => Json::null()
  }
}

///|
fn optional_string(value : String?) -> Json {
  match value {
    Some(value) => jstring(value)
    None => Json::null()
  }
}
