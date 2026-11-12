#!/bin/bash
# Live HTTPS requests require the explicit --network flag and credentials file.
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec /bin/bash "$script_dir/preflight.sh" --mode verify "$@"
