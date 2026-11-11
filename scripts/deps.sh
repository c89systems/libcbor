#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
target=${1:?usage: deps.sh TARGET}
component=${2:-lonejson}
if [[ $component == lonejson ]]; then
  case "$target" in
  x86_64-linux-gnu) digest=3fe1629888f264b9605fa5ba96ea57e4b5da11276c245cba11409608fb292480 ;;
  x86_64-linux-musl) digest=47049e9f26701f1a5b16c3fd9dfa4ad04357402539ec1f861745f7f8843c4be8 ;;
  aarch64-linux-gnu) digest=ce472cab6e7340dec9a4d713e04c31fbb207f2de72bfa9e7aaa8e9f9c2f02c3a ;;
  aarch64-linux-musl) digest=76652c0a1656a38a5fb6b05c55a88607f80b2797c80d5859ce0bff81d49494db ;;
  armhf-linux-gnu) digest=f466f7d639b09015b7b202d455d9d759d9a2249c0f43e4dc4c0b904f625ac716 ;;
  armhf-linux-musl) digest=03bb63d7f5f88217129bda677b35f85ee8109f785780723961aae8180de564c8 ;;
  arm64-apple-darwin) digest=51344ba031e2e09ea88266eb02b6e0ba3411a430c7081c9e204b237bc9bd4af8 ;;
  *) printf 'Unsupported target: %s\n' "$target" >&2; exit 1 ;;
  esac
  name=liblonejson-0.49.0-$target
  url=https://github.com/c89systems/lonejson/releases/download/v0.49.0/$name.tar.gz
elif [[ $component == cpkt ]]; then
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
  url=https://github.com/c89systems/cpkt/releases/download/v0.7.0/$name.tar.gz
elif [[ $component == lua ]]; then
  digest=1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce
  name=lua-5.5.1
  url=https://www.lua.org/ftp/$name.tar.gz
else
  printf 'Unsupported dependency: %s\n' "$component" >&2; exit 1
fi
archive=.cache/archives/$name.tar.gz
prefix=.cache/deps/$name
c89_owned_path "$archive"; c89_owned_path "$prefix"; c89_owned_path "$prefix.tmp"
mkdir -p .cache/archives .cache/deps
if [[ ! -f "$archive" ]]; then
  shared=${CPKT_DEPENDENCY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/cpkt/deps}/archives/sha256/$digest/$name.tar.gz
  if [[ -f "$shared" ]]; then
    cp -- "$shared" "$archive.part"
  else
    curl --fail --location --retry 3 "$url" -o "$archive.part"
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
