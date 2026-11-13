#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
for tool in podman curl sha256sum; do command -v "$tool" >/dev/null; done
[[ $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || { printf 'E2E requires rootless Podman\n' >&2; exit 1; }
[[ $(uname -m) == x86_64 && $(uname -s) == Linux ]] || { printf 'Reference wheels require native x86_64 Linux\n' >&2; exit 1; }
state=build/e2e
c89_owned_path "$state"
mkdir -p "$state/state" .cache/e2e/wheels
while IFS=$'\t' read -r filename checksum url; do
  [[ $filename != */* && $checksum =~ ^[0-9a-f]{64}$ && $url == https://files.pythonhosted.org/* ]] || exit 1
  destination=.cache/e2e/wheels/$filename
  if [[ ! -f $destination ]]; then curl --fail --location --retry 2 "$url" -o "$destination"; fi
  printf '%s  %s\n' "$checksum" "$destination" | sha256sum -c -
done <tests/e2e/wheels.lock
cp tests/e2e/peer.py .cache/e2e/peer.py
cp tests/e2e/requirements.txt .cache/e2e/requirements.txt
podman build --pull=missing --iidfile "$state/image.id" -f tests/e2e/Containerfile .cache/e2e >"$state/build.log" 2>&1
image=$(cat "$state/image.id")
identity=$(printf '%s' "$root" | sha256sum)
name=libcbor-e2e-${identity:0:12}
port=$((20000 + 16#${identity:0:6} % 30000))
manifest=$state/pod.yaml
sed -e "s|@NAME@|$name|g" -e "s|@IMAGE@|$image|g" -e "s|@PORT@|$port|g" \
  -e "s|@STATE@|$root/$state/state|g" tests/e2e/pod.yaml.in >"$manifest"
started=0
cleanup() {
  local result=$?
  trap - EXIT
  if ((started)); then
    podman logs "$name-reference" >"$state/peer.log" 2>&1 || true
    podman kube down "$manifest" >"$state/down.log" 2>&1 || result=1
  fi
  if ((result != 0)); then cat "$state/peer.log" >&2 2>/dev/null || true; fi
  exit "$result"
}
trap cleanup EXIT
started=1
podman kube play --userns=keep-id "$manifest" >"$state/up.log" 2>&1
ready=0
for ((attempt=0;attempt<40;attempt++)); do
  if curl -fsS --connect-timeout 1 --max-time 1 "http://127.0.0.1:$port/health" >"$state/health"; then ready=1; break; fi
  sleep 0.25
done
((ready)) || { printf 'Reference peer readiness failed; inspect build/e2e\n' >&2; exit 1; }
[[ $(cat "$state/health") == python-cwt/4.0.0 ]]
[[ $(cat "$state/state/container-write") == python-cwt/4.0.0 ]]
printf 'host write\n' >"$state/state/host-write"
scripts/build.sh core x86_64-linux-gnu Debug
C89CBOR_E2E_PORT=$port ctest --test-dir build/x86_64-linux-gnu-debug --output-on-failure --stop-on-failure --no-tests=error -R '^reference-peer$'
podman logs "$name-reference" >"$state/peer.log" 2>&1
podman kube down "$manifest" >"$state/down.log" 2>&1
started=0
rm -- "$state/state/container-write" "$state/state/host-write"
printf 'Rootless reference peer stopped; host reset verified\n'
