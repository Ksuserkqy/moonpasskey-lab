///|
/// A top-level JSON member's complete key and value token ranges, in bytes
/// relative to ClientData.raw. Unknown members remain accessible in raw.
#derive(Eq, Debug)
pub struct ClientDataMember {
  name : String
  key_range : @cbor.SourceRange
  value_range : @cbor.SourceRange
}

///|
pub extend ClientDataMember with Eq::{equal, not_equal}

///|
pub extend ClientDataMember with Debug::{to_repr}

///|
/// Structural client data only. raw is the exact immutable UTF-8 input,
/// including whitespace, order and escapes; later hashes MUST use raw.
/// Absent optional members remain None, without inventing source values.
#derive(Eq, Debug)
pub struct ClientData {
  raw : BytesView
  type_ : String
  challenge : String
  origin : String
  cross_origin : Bool?
  top_origin : String?
  members : ReadOnlyArray[ClientDataMember]
}

///|
pub extend ClientData with Eq::{equal, not_equal}

///|
pub extend ClientData with Debug::{to_repr}

///|
priv enum ClientJsonScalar {
  Text(String)
  Boolean(Bool)
  Other
}

///|
priv struct ClientJsonScanner {
  input : BytesView
  limits : @cbor.Limits
  mut offset : Int32
  mut values : Int32
  members : Array[ClientDataMember]
  fields : @sorted_map.SortedMap[String, (ClientJsonScalar, Int32)]
}

///|
fn ClientJsonScanner::invalid(
  self : ClientJsonScanner,
  context : String,
) -> ProtocolFailure {
  if self.offset == self.input.length() {
    fail_at(self.offset, context, UnexpectedEnd(expected=1, remaining=0))
  } else {
    fail_at(self.offset, context, InvalidJson)
  }
}

///|
fn ClientJsonScanner::space(self : ClientJsonScanner) -> Unit {
  while self.offset < self.input.length() &&
        self.input[self.offset] is (b' ' | b'\t' | b'\r' | b'\n') {
    self.offset += 1
  }
}

///|
fn ClientJsonScanner::expect(
  self : ClientJsonScanner,
  byte : Byte,
  context : String,
) -> Unit raise ProtocolFailure {
  if self.offset >= self.input.length() || self.input[self.offset] != byte {
    raise self.invalid(context)
  }
  self.offset += 1
}

///|
fn ClientJsonScanner::budget(
  _self : ClientJsonScanner,
  name : String,
  count : Int32,
  limit : Int32,
  start : Int32,
  context : String,
) -> Unit raise ProtocolFailure {
  if count > limit {
    raise fail_at(
      start,
      context,
      ResourceLimit(name~, limit~, actual=count.to_uint64()),
    )
  }
}

///|
fn ClientJsonScanner::node(
  self : ClientJsonScanner,
  start : Int32,
  context : String,
) -> Unit raise ProtocolFailure {
  // Test before addition: even Int32::max_value is a safe configured limit.
  if self.values >= self.limits.max_values {
    raise fail_at(
      start,
      context,
      ResourceLimit(
        name="max_values",
        limit=self.limits.max_values,
        actual=self.values.to_uint64() + 1UL,
      ),
    )
  }
  self.values += 1
}

///|
fn ClientJsonScanner::hex(
  self : ClientJsonScanner,
  context : String,
) -> Int32 raise ProtocolFailure {
  let mut value = 0
  for _ in 0..<4 {
    if self.offset >= self.input.length() {
      raise self.invalid(context)
    }
    let digit = match self.input[self.offset] {
      b'0'..<=b'9' as c => c.to_int() - 48
      b'a'..<=b'f' as c => c.to_int() - 87
      b'A'..<=b'F' as c => c.to_int() - 55
      _ => raise self.invalid(context)
    }
    value = value * 16 + digit
    self.offset += 1
  }
  value
}

///|
/// Scan boundaries and budgets before passing a single string token to the
/// standard JSON decoder. No unbounded object tree is built by core/json.
fn ClientJsonScanner::string(
  self : ClientJsonScanner,
  context : String,
) -> String raise ProtocolFailure {
  let start = self.offset
  self.node(start, context)
  self.expect(b'"', context)
  let content_start = self.offset
  while self.offset < self.input.length() {
    let byte = self.input[self.offset]
    if byte == b'"' {
      self.budget(
        "max_string_bytes",
        self.offset - content_start,
        self.limits.max_string_bytes,
        start,
        context,
      )
      self.offset += 1
      let token = @utf8.decode(self.input[start:self.offset]) catch {
        @utf8.Malformed(suffix) =>
          raise fail_at(self.offset - suffix.length(), context, InvalidUtf8)
      }
      return try {
        match @json.parse(token) {
          Json::String(value) => value
          _ => raise fail_at(start, context, InvalidJson)
        }
      } catch {
        _ => raise fail_at(start, context, InvalidJson)
      }
    }
    if byte < b' ' {
      raise self.invalid(context)
    }
    if byte == b'\\' {
      let escape_start = self.offset
      self.offset += 1
      if self.offset >= self.input.length() {
        raise self.invalid(context)
      }
      match self.input[self.offset] {
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' =>
          self.offset += 1
        b'u' => {
          self.offset += 1
          let code = self.hex(context)
          if code >= 0xD800 && code <= 0xDBFF {
            self.expect(b'\\', context)
            self.expect(b'u', context)
            let low = self.hex(context)
            if low < 0xDC00 || low > 0xDFFF {
              raise fail_at(escape_start, context, InvalidJson)
            }
          } else if code >= 0xDC00 && code <= 0xDFFF {
            raise fail_at(escape_start, context, InvalidJson)
          }
        }
        _ => raise self.invalid(context)
      }
    } else {
      self.offset += 1
    }
    self.budget(
      "max_string_bytes",
      self.offset - content_start,
      self.limits.max_string_bytes,
      start,
      context,
    )
  }
  raise self.invalid(context)
}

///|
fn ClientJsonScanner::literal(
  self : ClientJsonScanner,
  text : BytesView,
  context : String,
) -> Unit raise ProtocolFailure {
  for byte in text {
    self.expect(byte, context)
  }
}

///|
fn ClientJsonScanner::digits(
  self : ClientJsonScanner,
  context : String,
) -> Unit raise ProtocolFailure {
  let start = self.offset
  while self.offset < self.input.length() &&
        self.input[self.offset] is (b'0'..<=b'9') {
    self.offset += 1
  }
  if self.offset == start {
    raise self.invalid(context)
  }
}

///|
fn ClientJsonScanner::number(
  self : ClientJsonScanner,
  context : String,
) -> Unit raise ProtocolFailure {
  if self.input[self.offset] == b'-' {
    self.offset += 1
  }
  if self.offset < self.input.length() && self.input[self.offset] == b'0' {
    self.offset += 1
  } else {
    self.digits(context)
  }
  if self.offset < self.input.length() && self.input[self.offset] == b'.' {
    self.offset += 1
    self.digits(context)
  }
  if self.offset < self.input.length() &&
    self.input[self.offset] is (b'e' | b'E') {
    self.offset += 1
    if self.offset < self.input.length() &&
      self.input[self.offset] is (b'+' | b'-') {
      self.offset += 1
    }
    self.digits(context)
  }
}

///|
fn ClientJsonScanner::container_depth(
  self : ClientJsonScanner,
  depth : Int32,
  start : Int32,
  context : String,
) -> Unit raise ProtocolFailure {
  self.budget("max_depth", depth + 1, self.limits.max_depth, start, context)
}

///|
fn ClientJsonScanner::object(
  self : ClientJsonScanner,
  depth : Int32,
  context : String,
) -> Unit raise ProtocolFailure {
  self.container_depth(depth, self.offset, context)
  self.offset += 1
  self.space()
  if self.offset < self.input.length() && self.input[self.offset] == b'}' {
    self.offset += 1
    return
  }
  let seen : @sorted_map.SortedMap[String, Int32] = @sorted_map.SortedMap([])
  let mut count = 0
  while true {
    let key_start = self.offset
    self.budget(
      "max_map_pairs",
      count + 1,
      self.limits.max_map_pairs,
      key_start,
      context,
    )
    let key_context = "\{context}.member[\{count}].key"
    let name = self.string(key_context)
    let key_end = self.offset
    match seen.get(name) {
      Some(first_offset) =>
        raise fail_at(
          key_start,
          key_context,
          DuplicateMember(name~, first_offset~),
        )
      None => seen.set(name, key_start)
    }
    self.space()
    self.expect(b':', context)
    self.space()
    let value_start = self.offset
    let scalar = self.value(depth + 1, "\{context}.member[\{count}].value")
    if depth == 0 {
      self.members.push({
        name,
        key_range: { start: key_start, end: key_end, },
        value_range: { start: value_start, end: self.offset, },
      })
      self.fields.set(name, (scalar, value_start))
    }
    count += 1
    self.space()
    if self.offset < self.input.length() && self.input[self.offset] == b'}' {
      self.offset += 1
      return
    }
    self.expect(b',', context)
    self.space()
  }
}

///|
fn ClientJsonScanner::array(
  self : ClientJsonScanner,
  depth : Int32,
  context : String,
) -> Unit raise ProtocolFailure {
  self.container_depth(depth, self.offset, context)
  self.offset += 1
  self.space()
  if self.offset < self.input.length() && self.input[self.offset] == b']' {
    self.offset += 1
    return
  }
  let mut count = 0
  while true {
    self.budget(
      "max_array_items",
      count + 1,
      self.limits.max_array_items,
      self.offset,
      context,
    )
    self.value(depth + 1, "\{context}.array[\{count}]") |> ignore
    count += 1
    self.space()
    if self.offset < self.input.length() && self.input[self.offset] == b']' {
      self.offset += 1
      return
    }
    self.expect(b',', context)
    self.space()
  }
}

///|
fn ClientJsonScanner::value(
  self : ClientJsonScanner,
  depth : Int32,
  context : String,
) -> ClientJsonScalar raise ProtocolFailure {
  if self.offset >= self.input.length() {
    raise self.invalid(context)
  }
  if self.input[self.offset] == b'"' {
    return Text(self.string(context))
  }
  self.node(self.offset, context)
  match self.input[self.offset] {
    b'{' => {
      self.object(depth, context)
      Other
    }
    b'[' => {
      self.array(depth, context)
      Other
    }
    b't' => {
      self.literal(b"true", context)
      Boolean(true)
    }
    b'f' => {
      self.literal(b"false", context)
      Boolean(false)
    }
    b'n' => {
      self.literal(b"null", context)
      Other
    }
    b'-' | b'0'..<=b'9' => {
      self.number(context)
      Other
    }
    _ => raise self.invalid(context)
  }
}

///|
fn ClientJsonScanner::text_field(
  self : ClientJsonScanner,
  name : String,
  required : Bool,
) -> String? raise ProtocolFailure {
  match self.fields.get(name) {
    Some((Text(text), _)) => Some(text)
    Some((_, offset)) =>
      raise fail_at(
        offset,
        "clientDataJSON." + name,
        WrongType(expected="string"),
      )
    None =>
      if required {
        raise fail_at(self.offset, "clientDataJSON." + name, MissingField(name))
      } else {
        None
      }
  }
}

///|
/// Parse UTF-8 JSON with byte offsets, rejecting duplicate decoded names in
/// every object. Limits reuse CBOR policy: keys and values count as nodes;
/// strings count encoded content bytes excluding quotes. Unknown members are
/// checked and retained by range. Scalar-only core/json calls decode strings.
/// Empty strings, unknown type values and origin/challenge semantics are left
/// to validation. Optional crossOrigin/topOrigin preserve presence; their
/// relationship and origin trust are outside this structural parser.
pub fn parse_client_data(
  input : BytesView,
  limits~ : @cbor.Limits = @cbor.Limits::new(),
) -> Result[ClientData, ParseError] {
  try {
    validate_protocol_limits(limits, "clientDataJSON.limits")
    if input.length() > limits.max_input_bytes {
      raise fail_at(
        0,
        "clientDataJSON",
        ResourceLimit(
          name="max_input_bytes",
          limit=limits.max_input_bytes,
          actual=input.length().to_uint64(),
        ),
      )
    }
    try @utf8.decode(input) |> ignore catch {
      @utf8.Malformed(suffix) =>
        raise fail_at(
          input.length() - suffix.length(),
          "clientDataJSON",
          InvalidUtf8,
        )
    }
    let initial_offset = if input is [.. b"\xef\xbb\xbf", ..] { 3 } else { 0 }
    let scanner : ClientJsonScanner = {
      input,
      limits,
      offset: initial_offset,
      values: 0,
      members: [],
      fields: @sorted_map.SortedMap([]),
    }
    scanner.space()
    let start = scanner.offset
    let is_object = start < input.length() && input[start] == b'{'
    scanner.value(0, "clientDataJSON") |> ignore
    scanner.space()
    if scanner.offset < input.length() {
      raise fail_at(
        scanner.offset,
        "clientDataJSON",
        TrailingData(remaining=input.length() - scanner.offset),
      )
    }
    if !is_object {
      raise fail_at(start, "clientDataJSON", WrongType(expected="object"))
    }
    let type_ = match scanner.text_field("type", true) {
      Some(text) => text
      None => ""
    }
    let challenge = match scanner.text_field("challenge", true) {
      Some(text) => text
      None => ""
    }
    let origin = match scanner.text_field("origin", true) {
      Some(text) => text
      None => ""
    }
    let cross_origin = match scanner.fields.get("crossOrigin") {
      None => None
      Some((Boolean(value), _)) => Some(value)
      Some((_, offset)) =>
        raise fail_at(
          offset,
          "clientDataJSON.crossOrigin",
          WrongType(expected="boolean"),
        )
    }
    let top_origin = scanner.text_field("topOrigin", false)
    Ok({
      raw: input,
      type_,
      challenge,
      origin,
      cross_origin,
      top_origin,
      members: ReadOnlyArray::from_array(scanner.members),
    })
  } catch {
    Failed(error) => Err(error)
  }
}
