///|
priv suberror DecodeFailure {
  Failed(ParseError)
}

///|
fn failure(offset : Int32, context : String, kind : ErrorKind) -> DecodeFailure {
  Failed({ offset, context, kind, })
}

///|
/// Translate errors from the existing ByteReader without duplicating reads.
fn[T] require_read(
  result : Result[T, @bytereader.ReadError],
  context : String,
) -> T raise DecodeFailure {
  match result {
    Ok(value) => value
    Err(@bytereader.OutOfBounds(requested~, position~, remaining~)) =>
      raise failure(
        position,
        context,
        UnexpectedEnd(expected=requested, remaining~),
      )
    Err(@bytereader.InvalidLength(requested~, position~, ..)) =>
      raise failure(position, context, InvalidReadLength(requested))
  }
}

///|
priv struct Decoder {
  input : BytesView
  reader : @bytereader.ByteReader
  profile : Profile
  limits : Limits
  mut values : Int32
}

///|
fn validate_limits(limits : Limits) -> Unit raise DecodeFailure {
  for
    (name, value) in [
      ("max_input_bytes", limits.max_input_bytes),
      ("max_string_bytes", limits.max_string_bytes),
      ("max_array_items", limits.max_array_items),
      ("max_map_pairs", limits.max_map_pairs),
      ("max_depth", limits.max_depth),
      ("max_values", limits.max_values),
    ] {
    if value < 0 {
      raise failure(0, "limits", InvalidLimit(name~, value~))
    }
  }
  if limits.max_depth > 64 {
    raise failure(
      0,
      "limits",
      InvalidLimit(name="max_depth", value=limits.max_depth),
    )
  }
}

///|
/// Check UInt64 lengths before narrowing to the toolchain's signed Int.
fn bounded_length(
  value : UInt64,
  limit : Int32,
  name : String,
  offset : Int32,
  context : String,
) -> Int32 raise DecodeFailure {
  if value > limit.to_uint64() {
    raise failure(offset, context, ResourceLimit(name~, limit~, actual=value))
  }
  value.to_int()
}

///|
fn Decoder::argument(
  self : Decoder,
  additional : Int32,
  start : Int32,
  context : String,
) -> UInt64 raise DecodeFailure {
  let field = context + ".argument"
  let value = match additional {
    0..<24 => additional.to_uint64()
    24 => require_read(self.reader.read_u8(), field).to_uint64()
    25 => require_read(self.reader.read_u16_be(), field).to_uint64()
    26 => require_read(self.reader.read_u32_be(), field).to_uint64()
    27 => {
      let high = require_read(self.reader.read_u32_be(), field).to_uint64()
      let low = require_read(self.reader.read_u32_be(), field).to_uint64()
      (high << 32) | low
    }
    _ =>
      raise failure(start, context, InvalidAdditionalInfo(additional.to_byte()))
  }
  if self.profile is Ctap2Canonical {
    let minimal = if value < 24UL {
      value.to_int()
    } else if value <= 0xFFUL {
      24
    } else if value <= 0xFFFFUL {
      25
    } else if value <= 0xFFFF_FFFFUL {
      26
    } else {
      27
    }
    if additional != minimal {
      raise failure(start, context, NonMinimalEncoding)
    }
  }
  value
}

///|
fn Decoder::check_depth(
  self : Decoder,
  depth : Int32,
  start : Int32,
  context : String,
) -> Unit raise DecodeFailure {
  if depth >= self.limits.max_depth {
    raise failure(
      start,
      context,
      ResourceLimit(
        name="max_depth",
        limit=self.limits.max_depth,
        actual=depth.to_uint64() + 1UL,
      ),
    )
  }
  if self.profile is Ctap2Canonical && depth >= 4 {
    raise failure(
      start,
      context,
      ResourceLimit(
        name="ctap2_container_depth",
        limit=4,
        actual=depth.to_uint64() + 1UL,
      ),
    )
  }
}

///|
fn Decoder::finish(
  self : Decoder,
  kind : ValueKind,
  key : SemanticKey,
  start : Int32,
) -> DecodedValue {
  { value: { kind, range: { start, end: self.reader.position(), }, }, key, }
}

///|
/// CTAP section 8 orders keys by major type, encoded length, then bytes.
/// SemanticKey's internal total order is used solely for duplicate detection.
fn Decoder::check_key_order(
  self : Decoder,
  previous : Value,
  current : Value,
  context : String,
) -> Unit raise DecodeFailure {
  let before = self.input[previous.range.start:previous.range.end]
  let after = self.input[current.range.start:current.range.end]
  // Both ranges come from successfully parsed, nonempty encodings.
  let before_major = before[0].to_int() >> 5
  let after_major = after[0].to_int() >> 5
  let out_of_order = if before_major != after_major {
    before_major > after_major
  } else if before.length() != after.length() {
    before.length() > after.length()
  } else {
    before.compare(after) >= 0
  }
  if out_of_order {
    raise failure(
      current.range.start,
      context,
      UnsortedMapKey(previous_offset=previous.range.start),
    )
  }
}

///|
fn Decoder::parse_array(
  self : Decoder,
  length : UInt64,
  depth : Int32,
  start : Int32,
  context : String,
) -> DecodedValue raise DecodeFailure {
  self.check_depth(depth, start, context)
  let count = bounded_length(
    length,
    self.limits.max_array_items,
    "max_array_items",
    start,
    context,
  )
  // Grow from parsed children instead of reserving an untrusted declared size.
  let values : Array[Value] = []
  let keys : Array[SemanticKey] = []
  for index in 0..<count {
    let child = self.parse_value(depth + 1, "\{context}.array[\{index}]")
    values.push(child.value)
    keys.push(child.key)
  }
  self.finish(
    Array(ReadOnlyArray::from_array(values)),
    ArrayKey(ReadOnlyArray::from_array(keys)),
    start,
  )
}

///|
fn Decoder::parse_map(
  self : Decoder,
  length : UInt64,
  depth : Int32,
  start : Int32,
  context : String,
) -> DecodedValue raise DecodeFailure {
  self.check_depth(depth, start, context)
  let count = bounded_length(
    length,
    self.limits.max_map_pairs,
    "max_map_pairs",
    start,
    context,
  )
  let entries : Array[(Value, Value)] = []
  let seen : @sorted_map.SortedMap[SemanticKey, (SemanticKey, Int32)] = @sorted_map.SortedMap([],
  )
  let mut previous : Value? = None
  for index in 0..<count {
    let key_context = "\{context}.map[\{index}].key"
    let key = self.parse_value(depth + 1, key_context)
    if seen.get(key.key) is Some((_, first_offset)) {
      raise failure(
        key.value.range.start,
        key_context,
        DuplicateMapKey(first_offset~),
      )
    }
    if self.profile is Ctap2Canonical && previous is Some(before) {
      self.check_key_order(before, key.value, key_context)
    }
    let value = self.parse_value(depth + 1, "\{context}.map[\{index}].value")
    seen.set(key.key, (value.key, key.value.range.start))
    entries.push((key.value, value.value))
    previous = Some(key.value)
  }
  // Normalize once, bottom-up. A map used as a key compares independently of
  // entry order, including when its keys or values are themselves containers.
  let normalized : Array[(SemanticKey, SemanticKey)] = []
  for (key, (value, _)) in seen.iter() {
    normalized.push((key, value))
  }
  self.finish(
    Map(ReadOnlyArray::from_array(entries)),
    MapKey(ReadOnlyArray::from_array(normalized)),
    start,
  )
}

///|
fn Decoder::parse_simple(
  self : Decoder,
  additional : Int32,
  start : Int32,
  context : String,
) -> DecodedValue raise DecodeFailure {
  match additional {
    0..<20 =>
      self.finish(
        Simple(additional.to_byte()),
        SimpleKey(additional.to_byte()),
        start,
      )
    20 => self.finish(Boolean(false), BooleanKey(false), start)
    21 => self.finish(Boolean(true), BooleanKey(true), start)
    22 => self.finish(Null, NullKey, start)
    23 => self.finish(Undefined, UndefinedKey, start)
    24 => {
      let offset = self.reader.position()
      let value = require_read(self.reader.read_u8(), context + ".simple")
      if value.to_int() < 32 {
        raise failure(offset, context + ".simple", InvalidSimpleValue(value))
      }
      self.finish(Simple(value), SimpleKey(value), start)
    }
    25 | 26 | 27 => {
      let width = 1 << (additional - 24)
      let _ = require_read(self.reader.read_bytes(width), context + ".float")
      raise failure(start, context, UnsupportedFloat(width~))
    }
    _ => raise failure(start, context, UnexpectedBreak)
  }
}

///|
fn Decoder::parse_value(
  self : Decoder,
  depth : Int32,
  context : String,
) -> DecodedValue raise DecodeFailure {
  let start = self.reader.position()
  if self.values >= self.limits.max_values {
    raise failure(
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
  let head = require_read(self.reader.read_u8(), context).to_int()
  let major = head >> 5
  let additional = head & 31
  if additional >= 28 && additional <= 30 {
    raise failure(start, context, InvalidAdditionalInfo(additional.to_byte()))
  }
  if additional == 31 {
    match major {
      2 | 3 | 4 | 5 =>
        if self.profile is Ctap2Canonical {
          raise failure(start, context, IndefiniteLengthNotAllowed)
        } else {
          raise failure(
            start,
            context,
            UnsupportedIndefiniteLength(major_type=major),
          )
        }
      7 => raise failure(start, context, UnexpectedBreak)
      _ =>
        raise failure(
          start,
          context,
          InvalidAdditionalInfo(additional.to_byte()),
        )
    }
  }
  if major == 7 {
    return self.parse_simple(additional, start, context)
  }
  let argument = self.argument(additional, start, context)
  match major {
    0 => self.finish(Unsigned(argument), UnsignedKey(argument), start)
    1 => self.finish(Negative(argument), NegativeKey(argument), start)
    2 | 3 => {
      let length = bounded_length(
        argument,
        self.limits.max_string_bytes,
        "max_string_bytes",
        start,
        context,
      )
      let payload_start = self.reader.position()
      let payload_context = context +
        (if major == 2 { ".bytes" } else { ".text" })
      let bytes = require_read(self.reader.read_bytes(length), payload_context)
      if major == 2 {
        self.finish(ByteString(bytes), BytesKey(bytes), start)
      } else {
        let text = @utf8.decode(bytes, ignore_bom=false) catch {
          @utf8.Malformed(suffix) =>
            raise failure(
              payload_start + (suffix.start_offset() - bytes.start_offset()),
              payload_context,
              InvalidUtf8,
            )
        }
        self.finish(TextString(text), TextKey(text), start)
      }
    }
    4 => self.parse_array(argument, depth, start, context)
    5 => self.parse_map(argument, depth, start, context)
    _ =>
      if self.profile is Ctap2Canonical {
        raise failure(start, context, ForbiddenTag(argument))
      } else {
        raise failure(start, context, UnsupportedTag(argument))
      }
  }
}

///|
/// Parse one item at offset. Trailing bytes remain available to the caller.
/// All ranges are relative to input, including when offset is nonzero.
pub fn parse_one(
  input : BytesView,
  offset~ : Int32 = 0,
  profile~ : Profile = Generic,
  limits~ : Limits = Limits::new(),
) -> Result[Parsed, ParseError] {
  try {
    validate_limits(limits)
    if offset < 0 || offset > input.length() {
      raise failure(0, "offset", InvalidOffset(offset))
    }
    let _ = bounded_length(
      input.length().to_uint64(),
      limits.max_input_bytes,
      "max_input_bytes",
      0,
      "input",
    )
    let decoder : Decoder = {
      input,
      reader: @bytereader.ByteReader::new(input),
      profile,
      limits,
      values: 0,
    }
    let _ = require_read(decoder.reader.read_bytes(offset), "offset")
    let decoded = decoder.parse_value(0, "root")
    Ok({ value: decoded.value, consumed: decoder.reader.position() - offset, })
  } catch {
    Failed(error) => Err(error)
  }
}

///|
/// Parse exactly one complete item, rejecting any trailing bytes.
pub fn parse_all(
  input : BytesView,
  profile~ : Profile = Generic,
  limits~ : Limits = Limits::new(),
) -> Result[Value, ParseError] {
  match parse_one(input, profile~, limits~) {
    Err(error) => Err(error)
    Ok(parsed) =>
      if parsed.consumed != input.length() {
        Err({
          offset: parsed.consumed,
          context: "trailing data",
          kind: TrailingData(remaining=input.length() - parsed.consumed),
        })
      } else {
        Ok(parsed.value)
      }
  }
}
