///|
#module("node:fs")
extern "js" fn open_input(path : String, flags : String) -> Int32 = "openSync"

///|
#module("node:fs")
extern "js" fn read_input(
  fd : Int32,
  buffer : FixedArray[Byte],
  offset : Int32,
  length : Int32,
) -> Int32 = "readSync"

///|
#module("node:fs")
extern "js" fn close_input(fd : Int32) -> Unit = "closeSync"

///|
extern "js" fn read_input_js(
  open : (String, String) -> Int32,
  read : (Int32, FixedArray[Byte], Int32, Int32) -> Int32,
  close : (Int32) -> Unit,
  path : String,
  buffer : FixedArray[Byte],
) -> Int32 =
  #| (open, read, close, path, buffer) => {
  #|   let fd;
  #|   let count = 0;
  #|   let failed = false;
  #|   try {
  #|     fd = open(path, "r");
  #|     while (count < buffer.length) {
  #|       const n = read(fd, buffer, count, buffer.length - count);
  #|       if (n === 0) break;
  #|       count += n;
  #|     }
  #|   } catch (_) {
  #|     failed = true;
  #|   } finally {
  #|     if (fd !== undefined) {
  #|       try { close(fd); } catch (_) { failed = true; }
  #|     }
  #|   }
  #|   return failed ? -1 : count;
  #| }

///|
fn read_input_bounded(path : String) -> Result[Bytes, InputReadFailure] {
  let buffer = FixedArray::make(MAX_INPUT_BYTES + 1, b'\x00')
  let count = read_input_js(open_input, read_input, close_input, path, buffer)
  if count < 0 {
    Err(InputReadError)
  } else if count > MAX_INPUT_BYTES {
    Err(InputTooLarge)
  } else {
    Ok(Bytes::from_array(buffer[:count]))
  }
}
