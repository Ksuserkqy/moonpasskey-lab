#!/usr/bin/env bash
set -euo pipefail

# Run inside an isolated Ubuntu 22.04 test machine with the pinned Node installed.
# Nginx starts only as a temporary test process. No unit enable/start/reload occurs.
directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd "$directory"
grep -Eq '^VERSION_ID="?22\.04"?$' /etc/os-release
grep -Eq '^ID="?ubuntu"?$' /etc/os-release
[[ "$(/opt/node-v24.18.0/bin/node --version)" == v24.18.0 ]]
export PATH="/opt/node-v24.18.0/bin:/usr/sbin:/usr/bin:/sbin:/bin"
nginx -v
openssl version
systemd-analyze --version
shellcheck --version
for script in deploy/ubuntu-nginx/scripts/*.sh; do bash -n "$script"; done
shellcheck -x deploy/ubuntu-nginx/scripts/*.sh
systemd-analyze verify deploy/ubuntu-nginx/systemd/moonpasskey-rp.service
MOONPASSKEY_REQUIRE_NGINX=1 node --test deploy/ubuntu-nginx/tests/*.test.mjs
