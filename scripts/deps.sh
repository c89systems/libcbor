#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
target=${1:?usage: deps.sh TARGET}
component=${2:-lonejson}
if [[ $component == lonejson ]]; then
  case "$target" in
  x86_64-linux-gnu) digest=c0b855e40cc21a39a3d4bb5366f0e7f3629e53c956a0e675dea69791a7d7b936 ;;
  x86_64-linux-musl) digest=e736ab07a9694558fab51d1b7403a2d0ce8884900be9d0bcee7ca1903489ef12 ;;
  aarch64-linux-gnu) digest=0bcc6d753b65bf122d7941fca0e4671f0dfdb508c4cfff968fe628357db7b04e ;;
  aarch64-linux-musl) digest=d18d291a2c6a731aa54205673633221e388e4fbea3e5e2ee15caf8a0c653b04b ;;
  armhf-linux-gnu) digest=5ea12a2dc327811101bad13dff23182c54a2bfa7133e87352442147706e6b094 ;;
  armhf-linux-musl) digest=d11abea1a1e0e387426b230fb19c7ef35086b351b40245a10efb12784ee64797 ;;
  arm64-apple-darwin) digest=efc25f93d2768fb57f89d54025711ae3f82f7feeba1c776b25108b43356d8031 ;;
  *) printf 'Unsupported target: %s\n' "$target" >&2; exit 1 ;;
  esac
  name=liblonejson-0.50.0-$target
  url=https://github.com/c89systems/lonejson/releases/download/v0.50.0/$name.tar.gz
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
