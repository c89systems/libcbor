#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
target=${1:?usage: deps.sh TARGET}
case "$target" in
x86_64-linux-gnu) digest=e898960071bc5f30a00f5308d559b60c7495fce442f9d9e1fce54d112a959d84 ;;
x86_64-linux-musl) digest=8c5de2f414c1c99147e22d9651de600b047299c7d547c53830c3c8fe15d34dbc ;;
aarch64-linux-gnu) digest=0ba48a8ca621ec9a1045bb2081ec440970695bfcc34aa75683dec8bdaff64e1c ;;
aarch64-linux-musl) digest=7146f274e3fbff74b7e1e4c3b3b8276c1c62843f2517f1940a65a17683a17230 ;;
armhf-linux-gnu) digest=8eb105e3d19328619c8274a64dcfe39df8d00861d0d31ca3dd3b692f21b25734 ;;
armhf-linux-musl) digest=7dbdeaa6b4c8180e14fbd3cc9388c81b88015a306ae268cc12468eb775969f15 ;;
arm64-apple-darwin) digest=b1c0d9eee975a1e30f7395db0bcc42fddcca45cbae6919a2d49b4e42ebbb88d3 ;;
*) printf 'Unsupported target: %s\n' "$target" >&2; exit 1 ;;
esac
name=cpkt-0.7.0-$target
archive=.cache/archives/$name.tar.gz
prefix=.cache/deps/$name
c89_owned_path "$archive"; c89_owned_path "$prefix"; c89_owned_path "$prefix.tmp"
mkdir -p .cache/archives .cache/deps
if [[ ! -f "$archive" ]]; then
  shared=${CPKT_DEPENDENCY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/cpkt/deps}/archives/sha256/$digest/$name.tar.gz
  if [[ -f "$shared" ]]; then
    cp -- "$shared" "$archive.part"
  else
    curl --fail --location --retry 3 "https://github.com/c89systems/cpkt/releases/download/v0.7.0/$name.tar.gz" -o "$archive.part"
  fi
  printf '%s  %s\n' "$digest" "$archive.part" | sha256sum -c -
  mv -- "$archive.part" "$archive"
fi
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
if [[ ! -d "$prefix" ]]; then
  mkdir -- "$prefix.tmp"
  trap 'rm -rf -- "$prefix.tmp"' EXIT
  tar -xzf "$archive" -C "$prefix.tmp" --strip-components=1
  mv -- "$prefix.tmp" "$prefix"
fi
