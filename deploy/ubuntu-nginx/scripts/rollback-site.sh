#!/usr/bin/env bash
set -euo pipefail

# Disable only the two links installed by this deployment guide. Dry-run is the
# default. Service control, reload, certificates and database retention are manual.
root=''
apply=false
while (($#)); do
  case "$1" in
    --apply) apply=true; shift ;;
    --test-root)
      (($# >= 2)) || { printf 'Missing --test-root value\n' >&2; exit 2; }
      [[ -n "$2" ]] || { printf 'Test root must not be empty\n' >&2; exit 2; }
      root=$2; shift 2 ;;
    *) printf 'Usage: rollback-site.sh [--apply] [--test-root ABSOLUTE_DIRECTORY]\n' >&2; exit 2 ;;
  esac
done

if [[ -n "$root" ]]; then
  [[ "$root" == /* && "$root" != / && -d "$root" && ! -L "$root" ]] || {
    printf 'Unsafe test root\n' >&2; exit 2;
  }
  canonical=$(cd -- "$root" && pwd -P)
  [[ "$canonical" == "$root" ]] || { printf 'Test root must be canonical\n' >&2; exit 2; }
elif "$apply" && [[ "$(id -u)" != 0 ]]; then
  printf 'Production apply requires root\n' >&2; exit 2
fi

for directory in /etc /etc/nginx /etc/nginx/sites-enabled /etc/nginx/sites-available; do
  [[ -d "$root$directory" && ! -L "$root$directory" ]] || {
    printf 'Missing or symbolic deployment directory\n' >&2; exit 2;
  }
done

# Validate every candidate before removing any link, including dangling links.
for site in moonpasskey-http.conf moonpasskey-https.conf; do
  link="$root/etc/nginx/sites-enabled/$site"
  target="$root/etc/nginx/sites-available/$site"
  if [[ -e "$link" || -L "$link" ]]; then
    [[ -L "$link" && "$(readlink "$link")" == "$target" ]] || {
      printf 'Refusing unexpected MoonPasskey site entry\n' >&2; exit 2;
    }
  fi
done

for site in moonpasskey-http.conf moonpasskey-https.conf; do
  link="$root/etc/nginx/sites-enabled/$site"
  if [[ -L "$link" ]]; then
    if "$apply"; then
      rm -- "$link"
      printf 'Disabled %s\n' "$site"
    else
      printf 'DRY_RUN would disable %s\n' "$site"
    fi
  fi
done
