#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "$0")/workspace.sh"
rm -rf -- "$root/build" "$root/dist" "$root/.cache"
rm -f -- "$root/compile_commands.json"
