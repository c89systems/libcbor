SHELL := /bin/bash
.DEFAULT_GOAL := help
.NOTPARALLEL:
TARGET ?= x86_64-linux-gnu
CONFIG ?= Debug
VERSION ?=
BUILD_JOBS ?= 2
export BUILD_JOBS
.PHONY: help build test lua lua-test check-native matrix format format-check shell-check benchmark benchmark-compare package package-verify package-source source-smoke valgrind fuzz-smoke fuzz-long sanitize e2e prerelease-hardening prerelease clean release
help:
	@printf '%s\n' 'e2e / sanitize / fuzz-long: explicit prerelease hardening; see docs/hardening.md' 'prerelease-hardening: normal checks, native memory/sanitizers, reference peer and long fuzz'
	@printf '%s\n' 'build / test / lua / lua-test: TARGET=<triple> CONFIG=Debug|Release VERSION=<candidate>' 'check-native: native Debug C and installed-SDK Lua checks' 'matrix: build all seven targets, execute six Linux targets with QEMU where needed' 'format / format-check / shell-check: source and shell checks' 'benchmark / benchmark-compare: native Release C/Lua/transport measurements' 'package / package-verify / package-source / source-smoke: SDK and source evidence' 'valgrind / fuzz-smoke: native memory and instrumented fuzz checks' 'prerelease: complete local preparation (no signing, tags or publication)' 'release: signed default-branch/tag gate; see docs/delivery.md' 'clean: remove this checkout build/, dist/, .cache/ and editor database'
build:
	@scripts/build.sh core "$(TARGET)" "$(CONFIG)" "$(VERSION)"
	@scripts/build.sh lua "$(TARGET)" "$(CONFIG)"
test: build
	@scripts/build.sh test "$(TARGET)" "$(CONFIG)"
lua: build
lua-test: lua
	@scripts/build.sh lua-test "$(TARGET)" "$(CONFIG)"
check-native: test lua-test format-check shell-check
matrix:
	@scripts/matrix.sh "$(VERSION)"
format:
	@rg --files include src tests bench lua examples -g '*.c' -g '*.h' | xargs clang-format -i
format-check:
	@rg --files include src tests bench lua examples -g '*.c' -g '*.h' | xargs clang-format --dry-run --Werror
shell-check:
	@for script in scripts/*.sh; do bash -n "$$script" || exit; done
benchmark:
	@scripts/benchmark.sh "$(VERSION)"
benchmark-compare:
	@scripts/compare.sh "$(VERSION)"
package: build
	@scripts/package.sh "$(TARGET)" "$(CONFIG)" "$(VERSION)"
package-verify:
	@scripts/verify-package.sh "$(TARGET)" "$(CONFIG)" "$(VERSION)"
package-source:
	@scripts/source.sh "$(VERSION)"
source-smoke: package-source
	@scripts/source-smoke.sh "$(VERSION)"
valgrind:
	@scripts/hardening.sh valgrind "$(VERSION)"
fuzz-smoke:
	@scripts/hardening.sh fuzz "$(VERSION)"
fuzz-long:
	@scripts/hardening.sh fuzz-long "$(VERSION)"
sanitize:
	@scripts/hardening.sh sanitize "$(VERSION)"
e2e:
	@scripts/e2e.sh
prerelease-hardening:
	@$(MAKE) check-native VERSION="$(VERSION)"
	@$(MAKE) sanitize VERSION="$(VERSION)"
	@$(MAKE) valgrind VERSION="$(VERSION)"
	@$(MAKE) e2e VERSION="$(VERSION)"
	@$(MAKE) fuzz-long VERSION="$(VERSION)"
prerelease:
	@$(MAKE) check-native VERSION="$(VERSION)"
	@$(MAKE) matrix VERSION="$(VERSION)"
	@$(MAKE) valgrind VERSION="$(VERSION)"
	@$(MAKE) fuzz-smoke VERSION="$(VERSION)"
	@$(MAKE) source-smoke VERSION="$(VERSION)"
	@$(MAKE) package-lua-verify VERSION="$(VERSION)"
	@$(MAKE) package-checksums VERSION="$(VERSION)"
release:
	@scripts/release.sh "$(VERSION)"
clean:
	@rm -rf -- build dist .cache
	@rm -f -- compile_commands.json
.PHONY: package-lua package-checksums
package-lua:
	@scripts/lua-package.sh "$(VERSION)"
package-checksums:
	@scripts/manifest.sh "$(VERSION)"
.PHONY: package-lua-verify
package-lua-verify: package-lua
	@scripts/verify-lua.sh "$(VERSION)"
