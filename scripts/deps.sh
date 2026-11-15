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
  x86_64-linux-gnu) digest=7a9f2c1de42beec5fb324ac9c8b5a8005c17fb98003d9625eb5ad5ad228ba941 ;;
  x86_64-linux-musl) digest=9f768f99fa1933adfa0ae5fa8d8f13d1b0c9136047adc72e36a1970d7932772e ;;
  aarch64-linux-gnu) digest=fd34aaefe2642f548990c7c53d2463e8104004d8e55e38bc2ba63399b28fee43 ;;
  aarch64-linux-musl) digest=533e75c266416a721bad6dd50126d25575c776e663b8d32686f491fdff80451b ;;
  armhf-linux-gnu) digest=4066a6fba75cc48baead943431be0b6fb55a290a48ed8b1405f9e068de5e10d0 ;;
  armhf-linux-musl) digest=f0412151082a3e99f141dd19f0a8040ba1c507695f6df270e72aa4b62e2c58c5 ;;
  arm64-apple-darwin) digest=25e912cf05614810de3c4d8afbde0bad9dd9033a87443256aef6073f1a432b62 ;;
  *) printf 'Unsupported target: %s\n' "$target" >&2; exit 1 ;;
  esac
  name=cpkt-0.8.0-$target
  url=https://github.com/c89systems/cpkt/releases/download/v0.8.0/$name.tar.gz
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
bash scripts/archive.sh "$url" "$digest" "$archive"
mkdir -p .cache/deps
if [[ ! -d "$prefix" ]]; then
  mkdir -- "$prefix.tmp"
  trap 'rm -rf -- "$prefix.tmp"' EXIT
  tar -xzf "$archive" --same-permissions -C "$prefix.tmp" --strip-components=1
  mv -- "$prefix.tmp" "$prefix"
fi
