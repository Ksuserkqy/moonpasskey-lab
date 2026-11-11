///|
/// A type-preserving semantic key, excluding encoding widths and ranges.
/// Arrays preserve order. Maps sort normalized key/value pairs using an
/// internal total order, so their semantic equality ignores entry order.
#derive(Eq, Compare)
priv enum SemanticKey {
  UnsignedKey(UInt64)
  NegativeKey(UInt64)
  BytesKey(BytesView)
  TextKey(String)
  ArrayKey(ReadOnlyArray[SemanticKey])
  MapKey(ReadOnlyArray[(SemanticKey, SemanticKey)])
  BooleanKey(Bool)
  NullKey
  UndefinedKey
  SimpleKey(Byte)
}

///|
priv struct DecodedValue {
  value : Value
  key : SemanticKey
}
