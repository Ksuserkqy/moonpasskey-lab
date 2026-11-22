///|
#borrow(path, buffer)
extern "C" fn read_input_native(
  path : Bytes,
  buffer : FixedArray[Byte],
  limit : Int32,
) -> Int32 = "moonpasskey_cli_read_input"

///|
fn read_input_bounded(path : String) -> Result[Bytes, InputReadFailure] {
  let path_bytes = @utf8.encode(path) + Bytes::make(1, 0)
  let buffer = FixedArray::make(MAX_INPUT_BYTES + 1, b'\x00')
  let count = read_input_native(path_bytes, buffer, buffer.length())
  if count < 0 {
    Err(InputReadError)
  } else if count > MAX_INPUT_BYTES {
    Err(InputTooLarge)
  } else {
    Ok(Bytes::from_array(buffer[:count]))
  }
}
