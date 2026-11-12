#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=tls-common.sh
source "$SCRIPT_DIRECTORY/tls-common.sh"
tls_setup "$@"
tls_begin ca

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$TLS_STAGE/ca.key"
serial="$(openssl rand -hex 16)"
openssl req -new -x509 -sha256 -days 3650 -set_serial "0x$serial" \
  -key "$TLS_STAGE/ca.key" -out "$TLS_STAGE/ca.crt" \
  -subj '/CN=MoonPasskey Backend Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'
openssl verify -no-CApath -no-CAstore -check_ss_sig -x509_strict \
  -CAfile "$TLS_STAGE/ca.crt" "$TLS_STAGE/ca.crt"
chmod 0700 "$TLS_STAGE"
chmod 0600 "$TLS_STAGE/ca.key"
chmod 0644 "$TLS_STAGE/ca.crt"
tls_publish ca
printf 'Generated a protected backend CA directory. Export only ca.crt for Nginx trust.\n'
