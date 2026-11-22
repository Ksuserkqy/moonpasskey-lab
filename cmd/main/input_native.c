#include "moonbit.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wchar.h>
#endif

MOONBIT_FFI_EXPORT int32_t moonpasskey_cli_read_input(
    moonbit_bytes_t path, moonbit_bytes_t buffer, int32_t limit) {
  size_t path_len = (size_t)Moonbit_array_length(path);
  if (path_len == 0 || memchr(path, 0, path_len - 1) != NULL ||
      path[path_len - 1] != 0 || limit < 0 ||
      limit > Moonbit_array_length(buffer)) {
    return -1;
  }

#ifdef _WIN32
  int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     (const char *)path, -1, NULL, 0);
  if (wide_len == 0) return -1;
  wchar_t *wide_path = (wchar_t *)malloc((size_t)wide_len * sizeof(wchar_t));
  if (wide_path == NULL) return -1;
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)path,
                           -1, wide_path, wide_len)) {
    free(wide_path);
    return -1;
  }
  FILE *file = _wfopen(wide_path, L"rb");
  free(wide_path);
#else
  FILE *file = fopen((const char *)path, "rb");
#endif
  if (file == NULL) return -1;

  // Prevent stdio read-ahead from reading bytes beyond the requested budget.
  if (setvbuf(file, NULL, _IONBF, 0) != 0) {
    fclose(file);
    return -1;
  }
  size_t count = 0;
  while (count < (size_t)limit) {
    size_t n = fread(buffer + count, 1, (size_t)limit - count, file);
    count += n;
    if (ferror(file)) {
      fclose(file);
      return -1;
    }
    if (n == 0) break;
  }
  if (fclose(file) != 0) return -1;
  return (int32_t)count;
}
