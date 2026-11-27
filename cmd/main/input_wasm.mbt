// These imports match the Moonrun ABI bundled with the pinned 1.0.0-rc1
// toolchain. The async ABI is private: changes to Moonrun require revalidation.

///|
const INPUT_READ_CHUNK : Int32 = 16_384

///|
#unsafe_skip_stub_check
fn input_run_job(job : UInt64) = "moonbitlang/async" "thread_pool/run_job"

///|
#unsafe_skip_stub_check
fn input_job_error(job : UInt64) -> Int32 = "moonbitlang/async" "thread_pool/job_get_err"

///|
#unsafe_skip_stub_check
fn input_job_result(job : UInt64) -> Int32 = "moonbitlang/async" "thread_pool/job_get_ret"

///|
#unsafe_skip_stub_check
fn input_open_fd(job : UInt64) -> UInt64 = "moonbitlang/async" "thread_pool/open_job_get_fd"

///|
#unsafe_skip_stub_check
fn input_free_job(job : UInt64) = "moonbitlang/async" "thread_pool/free_job"

///|
#unsafe_skip_stub_check
fn input_close_fd(fd : UInt64) -> Int32 = "moonbitlang/async" "fd_util/close_fd"

///|
#unsafe_skip_stub_check
fn input_read_job(fd : UInt64, len : Int32, position : Int64) -> UInt64 = "moonbitlang/async" "thread_pool/make_read_job"

///|
#cfg(target="wasm")
#unsafe_skip_stub_check
#borrow(path)
fn input_open_job(
  path : String,
  len : Int32,
  access : Int32,
  create : Int32,
  append : Int32,
  sync : Int32,
  mode : Int32,
  stat : Int32,
  stat_len : Int32,
) -> UInt64 = "moonbitlang/async" "thread_pool/make_open_stat_job"

///|
#cfg(target="wasm")
#unsafe_skip_stub_check
#borrow(buf)
fn input_read_result(
  job : UInt64,
  buf : FixedArray[Byte],
  offset : Int32,
  len : Int32,
) = "moonbitlang/async" "thread_pool/get_read_result"

///|
#cfg(target="wasm-gc")
#unsafe_skip_stub_check
fn input_open_gc_job(
  path : Int32,
  len : Int32,
  access : Int32,
  create : Int32,
  append : Int32,
  sync : Int32,
  mode : Int32,
  stat : Int32,
  stat_len : Int32,
) -> UInt64 = "moonbitlang/async" "thread_pool/make_open_stat_job"

///|
#cfg(target="wasm-gc")
#unsafe_skip_stub_check
fn input_read_gc_result(job : UInt64, ptr : Int32, offset : Int32, len : Int32) = "moonbitlang/async" "thread_pool/get_read_result"

///|
#cfg(target="wasm-gc")
extern "wasm" fn input_grow_memory(pages : Int32) -> Int32 =
  #| (func (param i32) (result i32) local.get 0 memory.grow)

///|
#cfg(target="wasm-gc")
extern "wasm" fn input_write_code_unit(ptr : Int32, value : Int32) =
  #| (func (param i32) (param i32) local.get 0 local.get 1 i32.store16)

///|
#cfg(target="wasm-gc")
extern "wasm" fn input_read_byte(ptr : Int32) -> Int32 =
  #| (func (param i32) (result i32) local.get 0 i32.load8_u)

///|
fn read_input_bounded(path : String) -> Result[Bytes, InputReadFailure] {
  // The host path APIs may otherwise truncate at NUL.
  for i = 0; i < path.length(); i = i + 1 {
    if path.code_unit_at(i).to_int() == 0 {
      return Err(InputReadError)
    }
  }
  input_read_bounded_valid_path(path)
}

///|
#cfg(target="wasm")
fn input_read_bounded_valid_path(
  path : String,
) -> Result[Bytes, InputReadFailure] {
  let job = input_open_job(path, path.length(), 0, 0, 0, 0, 0, 1, 16)
  input_run_job(job)
  if input_job_error(job) != 0 {
    input_free_job(job)
    return Err(InputReadError)
  }
  let fd = input_open_fd(job)
  input_free_job(job)
  let chunk = FixedArray::make(INPUT_READ_CHUNK, b'\x00')
  let output : Array[Byte] = []
  let mut failed = false
  while output.length() <= MAX_INPUT_BYTES {
    let remaining = MAX_INPUT_BYTES + 1 - output.length()
    let want = if remaining < INPUT_READ_CHUNK {
      remaining
    } else {
      INPUT_READ_CHUNK
    }
    let read = input_read_job(fd, want, -1L)
    input_run_job(read)
    let err = input_job_error(read)
    let count = input_job_result(read)
    if err != 0 || count < 0 || count > want {
      input_free_job(read)
      failed = true
      break
    }
    if count > 0 {
      input_read_result(read, chunk, 0, count)
    }
    input_free_job(read)
    if count == 0 {
      break
    }
    for i = 0; i < count; i = i + 1 {
      output.push(chunk[i])
    }
  }
  let close_result = input_close_fd(fd)
  if failed || close_result != 0 {
    return Err(InputReadError)
  }
  if output.length() > MAX_INPUT_BYTES {
    return Err(InputTooLarge)
  }
  Ok(Bytes::from_array(output))
}

///|
#cfg(target="wasm-gc")
fn input_read_bounded_valid_path(
  path : String,
) -> Result[Bytes, InputReadFailure] {
  // Windows paths are limited to 32767 UTF-16 units; Unix pathname limits
  // are smaller. A second 64 KiB page is reserved for one read chunk.
  if path.length() > 32768 {
    return Err(InputReadError)
  }
  let pages = input_grow_memory(2)
  // The host ABI uses 32-bit linear-memory pointers. Reject addresses that
  // cannot be represented by a positive Int, including growth failures.
  if pages < 0 || pages > 32765 {
    return Err(InputReadError)
  }
  let base = pages * 65536
  for i = 0; i < path.length(); i = i + 1 {
    input_write_code_unit(base + i * 2, path.code_unit_at(i).to_int())
  }
  let job = input_open_gc_job(base, path.length(), 0, 0, 0, 0, 0, 1, 16)
  input_run_job(job)
  if input_job_error(job) != 0 {
    input_free_job(job)
    return Err(InputReadError)
  }
  let fd = input_open_fd(job)
  input_free_job(job)
  let output : Array[Byte] = []
  let mut failed = false
  while output.length() <= MAX_INPUT_BYTES {
    let remaining = MAX_INPUT_BYTES + 1 - output.length()
    let want = if remaining < INPUT_READ_CHUNK {
      remaining
    } else {
      INPUT_READ_CHUNK
    }
    let read = input_read_job(fd, want, -1L)
    input_run_job(read)
    let err = input_job_error(read)
    let count = input_job_result(read)
    if err != 0 || count < 0 || count > want {
      input_free_job(read)
      failed = true
      break
    }
    if count > 0 {
      input_read_gc_result(read, base + 65536, 0, count)
    }
    input_free_job(read)
    if count == 0 {
      break
    }
    for i = 0; i < count; i = i + 1 {
      output.push(input_read_byte(base + 65536 + i).to_byte())
    }
  }
  let close_result = input_close_fd(fd)
  if failed || close_result != 0 {
    return Err(InputReadError)
  }
  if output.length() > MAX_INPUT_BYTES {
    return Err(InputTooLarge)
  }
  Ok(Bytes::from_array(output))
}
