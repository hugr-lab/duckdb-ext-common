#!/usr/bin/env bash
# Build and run the keychain module's test against the real OS store (spec 010). The module is duckdb-free:
# no duckdb tree is needed. On Linux the Secret Service must be up (CI: gnome-keyring in dbus-run-session).
#
#   scripts/test_keychain.sh [build dir]
set -euo pipefail
out="${1:-build/keychain-test}"
cxx="${CXX:-c++}"
mkdir -p "$out"
libs=()
case "$(uname -s)" in
Darwin) libs=(-framework Security -framework CoreFoundation) ;;
Linux) libs=(-ldl) ;;
MINGW* | MSYS* | CYGWIN*) libs=(-ladvapi32) ;;
esac
"$cxx" -std=c++17 -O1 -g -DDUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=ext_common -I keychain/include \
	keychain/test/test_keychain.cpp keychain/src/keychain.cpp ${libs[@]+"${libs[@]}"} -o "$out/test_keychain"
"$out/test_keychain"
