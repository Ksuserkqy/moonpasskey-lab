#!/bin/bash
# Read-only Ubuntu readiness inspection. Never source the service environment.
set -euo pipefail
node_path=/opt/node-v24.18.0/bin/node
arguments=()
while (($#)); do
  case "$1" in
    --node)
      [[ $# -ge 2 ]] || { echo 'Missing --node value' >&2; exit 2; }
      node_path=$2
      shift 2
      ;;
    *) arguments+=("$1"); shift ;;
  esac
done
[[ "$node_path" = /* && -x "$node_path" ]] || {
  echo 'The pinned Node executable is unavailable; use --node with an absolute executable path.' >&2
  exit 2
}
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$node_path" "$script_dir/deployment-check.mjs" "${arguments[@]}"
