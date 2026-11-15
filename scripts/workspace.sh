# Source from a repository-owned lifecycle entrypoint.
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"
for generated in build dist .cache; do
  [[ ! -L $generated ]] || { printf 'Generated root must be checkout-owned: %s\n' "$generated" >&2; exit 1; }
done
c89_owned_path() {
  case "$1" in build|build/*|dist|dist/*|.cache|.cache/*) ;; *) return 1;; esac
  [[ $(realpath -m -- "$1") == "$root/$1" ]] || { printf 'Unsafe generated path: %s\n' "$1" >&2; return 1; }
}
c89_target() {
  case "$1" in
    x86_64-linux-gnu|x86_64-linux-musl|aarch64-linux-gnu|aarch64-linux-musl|armhf-linux-gnu|armhf-linux-musl|arm64-apple-darwin) ;;
    *) printf 'Unsupported target: %s\n' "$1" >&2; return 1;;
  esac
}
c89_config() {
  case "$1" in Debug|Release) ;; *) printf 'Expected Debug or Release\n' >&2; return 1;; esac
}
