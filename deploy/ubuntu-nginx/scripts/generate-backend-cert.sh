#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIRECTORY="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=tls-common.sh
source "$SCRIPT_DIRECTORY/tls-common.sh"
tls_setup "$@"

if [ ! -d "$TLS_BASE/ca" ] || [ -L "$TLS_BASE/ca" ]; then
  tls_fail 'generate the protected backend CA first'
fi
[ "$(tls_stat "$TLS_BASE/ca" '%u')" = "$(id -u)" ] || tls_fail 'the CA directory must belong to the invoking user'
[ "$(tls_stat "$TLS_BASE/ca" '%a')" = 700 ] || tls_fail 'the CA directory must have mode 0700'
tls_ca_input "$TLS_BASE/ca/ca.key" 600
tls_ca_input "$TLS_BASE/ca/ca.crt" 644
openssl pkey -in "$TLS_BASE/ca/ca.key" -check -noout
openssl verify -no-CApath -no-CAstore -check_ss_sig -x509_strict \
  -CAfile "$TLS_BASE/ca/ca.crt" "$TLS_BASE/ca/ca.crt"
openssl x509 -in "$TLS_BASE/ca/ca.crt" -checkend 31536000 -noout

tls_begin backend
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$TLS_STAGE/backend.key"
openssl req -new -sha256 -key "$TLS_STAGE/backend.key" -out "$TLS_STAGE/backend.csr" \
  -subj '/CN=passkey-test.ksuser.cn'
cat > "$TLS_STAGE/extensions.cnf" <<'EXTENSIONS'
[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:passkey-test.ksuser.cn
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXTENSIONS
serial="$(openssl rand -hex 16)"
openssl x509 -req -sha256 -days 365 -set_serial "0x$serial" \
  -in "$TLS_STAGE/backend.csr" -CA "$TLS_BASE/ca/ca.crt" -CAkey "$TLS_BASE/ca/ca.key" \
  -extfile "$TLS_STAGE/extensions.cnf" -extensions server -out "$TLS_STAGE/backend.crt"
openssl verify -no-CApath -no-CAstore -x509_strict -purpose sslserver \
  -CAfile "$TLS_BASE/ca/ca.crt" -verify_hostname passkey-test.ksuser.cn "$TLS_STAGE/backend.crt"
rm "$TLS_STAGE/backend.csr" "$TLS_STAGE/extensions.cnf"
chgrp "$TLS_GROUP" "$TLS_STAGE" "$TLS_STAGE/backend.key" "$TLS_STAGE/backend.crt"
chmod 0750 "$TLS_STAGE"
chmod 0640 "$TLS_STAGE/backend.key" "$TLS_STAGE/backend.crt"
tls_publish backend
printf 'Generated backend leaf credentials for DNS:passkey-test.ksuser.cn.\n'
