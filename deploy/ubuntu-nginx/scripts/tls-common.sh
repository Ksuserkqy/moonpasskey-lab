#!/usr/bin/env bash
# Shared by the two local certificate generators; not a standalone command.

tls_fail() { printf 'TLS generation refused: %s\n' "$*" >&2; exit 1; }

tls_stat() {
  if stat -c '%u' "$1" >/dev/null 2>&1; then
    stat -c "$2" "$1"
  else
    case "$2" in
      '%u') stat -f '%u' "$1" ;;
      '%a') stat -f '%Lp' "$1" ;;
      '%h') stat -f '%l' "$1" ;;
    esac
  fi
}

tls_no_symlinks() {
  local cursor="$1"
  while [ "$cursor" != / ]; do
    [ ! -L "$cursor" ] || tls_fail 'symlinks are not accepted in TLS paths'
    cursor="${cursor%/*}"
    [ -n "$cursor" ] || cursor=/
  done
}

tls_setup() {
  TLS_BASE=/etc/moonpasskey/tls
  TLS_TEST=0
  case "$#" in
    0) [ "$(id -u)" = 0 ] || tls_fail 'production generation must run as root' ;;
    2)
      [ "$1" = --test-directory ] || tls_fail 'usage: generator [--test-directory ABSOLUTE_EXISTING_DIRECTORY]'
      TLS_BASE="$2"
      TLS_TEST=1
      ;;
    *) tls_fail 'usage: generator [--test-directory ABSOLUTE_EXISTING_DIRECTORY]' ;;
  esac
  case "$TLS_BASE" in
    /*) ;;
    *) tls_fail 'the TLS directory must be absolute' ;;
  esac
  case "$TLS_BASE/" in
    *'//'*|*'/../'*|*'/./'*|*$'\n'*|*$'\r'*) tls_fail 'the TLS directory must be a canonical path without traversal' ;;
  esac
  [ "$TLS_BASE" != / ] || tls_fail 'the filesystem root is not a TLS directory'
  tls_no_symlinks "$TLS_BASE"
  [ -d "$TLS_BASE" ] || tls_fail 'create the protected TLS base directory first'
  [ "$(tls_stat "$TLS_BASE" '%u')" = "$(id -u)" ] || tls_fail 'the TLS directory must belong to the invoking user'
  if [ "$TLS_TEST" = 1 ]; then
    [ "$(tls_stat "$TLS_BASE" '%a')" = 700 ] || tls_fail 'the test directory must have mode 0700'
    TLS_GROUP="$(id -g)"
  else
    [ "$(tls_stat "$TLS_BASE" '%a')" = 755 ] || tls_fail 'the production TLS directory must have mode 0755'
    # These root-owned parents must not let an unprivileged user swap paths.
    local cursor="$TLS_BASE" mode
    while [ "$cursor" != / ]; do
      [ "$(tls_stat "$cursor" '%u')" = 0 ] || tls_fail 'production TLS ancestors must belong to root'
      mode="$(tls_stat "$cursor" '%a')"
      [ "$((8#$mode & 022))" = 0 ] || tls_fail 'production TLS ancestors must not be writable by group or others'
      cursor="${cursor%/*}"
      [ -n "$cursor" ] || cursor=/
    done
    # Read by generate-backend-cert.sh after this shared setup returns.
    # shellcheck disable=SC2034
    TLS_GROUP=moonpasskey
  fi
  command -v openssl >/dev/null 2>&1 || tls_fail 'OpenSSL 3 or later is required'
  umask 077
  TLS_STAGE=
  TLS_LOCK=
  trap tls_cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

tls_cleanup() {
  if [ -n "$TLS_STAGE" ]; then rm -rf -- "$TLS_STAGE"; fi
  if [ -n "$TLS_LOCK" ]; then rmdir -- "$TLS_LOCK" 2>/dev/null || true; fi
}

tls_begin() {
  local name="$1" lock="$TLS_BASE/.$1.lock"
  mkdir "$lock" 2>/dev/null || tls_fail 'another generation is active, or a generation lock exists'
  TLS_LOCK="$lock"
  if [ -e "$TLS_BASE/$name" ] || [ -L "$TLS_BASE/$name" ]; then
    tls_fail 'existing certificate output will not be overwritten'
  fi
  TLS_STAGE="$(mktemp -d "$TLS_BASE/.$name.XXXXXXXXXX")"
}

tls_publish() {
  local name="$1"
  # The lock serializes both generators for this output. The protected parent
  # prevents other users replacing either the stage or destination.
  if [ -e "$TLS_BASE/$name" ] || [ -L "$TLS_BASE/$name" ]; then
    tls_fail 'existing certificate output will not be overwritten'
  fi
  mv "$TLS_STAGE" "$TLS_BASE/$name"
  TLS_STAGE=
}

tls_ca_input() {
  local path="$1" mode="$2"
  tls_no_symlinks "$path"
  [ -f "$path" ] || tls_fail 'CA input must be a regular file'
  [ "$(tls_stat "$path" '%u')" = "$(id -u)" ] || tls_fail 'CA input must belong to the invoking user'
  [ "$(tls_stat "$path" '%a')" = "$mode" ] || tls_fail 'CA input permissions are unsafe'
  [ "$(tls_stat "$path" '%h')" = 1 ] || tls_fail 'hard-linked CA inputs are not accepted'
}
