#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
url=${1:?HTTPS URL required}; digest=${2:?SHA-256 required}; archive=${3:?owned archive path required}
[[ $url == https://* && $digest =~ ^[0-9a-f]{64}$ ]] || { printf 'Expected HTTPS and a SHA-256 pin\n' >&2; exit 1; }
c89_owned_path "$archive"
default_cache=$(realpath -m -- "${XDG_CACHE_HOME:-$HOME/.cache}/cpkt/deps")
cache=$(realpath -m -- "${CPKT_DEPENDENCY_CACHE:-$default_cache}")
if [[ $cache != "$default_cache" ]]; then
  case "$cache/" in "$root/build/"*|"$root/.cache/"*) ;; *) printf 'Dependency cache must be checkout-owned or the declared global cpkt cache\n' >&2; exit 1;; esac
fi
lifecycle=${CPKT_LIFECYCLE_SCRIPTS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills/pkt-systems-cmake-lifecycle/scripts}
source "$lifecycle/cpkt-archive-cache.sh"
if [[ -f $archive ]]; then printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -; fi
bucket=$cache/archives/sha256/$digest
shared=$bucket/${archive##*/}
mkdir -p "$bucket" "$(dirname -- "$archive")"
(
  flock -x 9
  # Corruption is a failed input, not permission to repair an immutable cache.
  if [[ -f $shared ]]; then
    printf '%s  %s\n' "$digest" "$shared" | sha256sum -c -
  else
    cpkt_restore_cached_archive "$shared" "$digest"
  fi
  if [[ ! -f $shared ]]; then
    temporary=$(mktemp "$bucket/.download.XXXXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    if [[ -f $archive ]]; then cp -- "$archive" "$temporary"
    else curl --fail --location --retry 3 "$url" -o "$temporary"; fi
    printf '%s  %s\n' "$digest" "$temporary" | sha256sum -c -
    mv -- "$temporary" "$shared"
  fi
  if [[ ! -f $archive ]]; then
    temporary=$(mktemp "${archive}.tmp.XXXXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    cp -- "$shared" "$temporary"
    printf '%s  %s\n' "$digest" "$temporary" | sha256sum -c -
    mv -- "$temporary" "$archive"
  fi
) 9>"$bucket/.lock"
