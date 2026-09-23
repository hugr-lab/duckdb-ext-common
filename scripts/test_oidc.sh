#!/usr/bin/env bash
# Build and run the OIDC core's test against a duckdb source tree (charter R10: the module is
# duckdb-free, so this compiles the module, the bundled yyjson and the test - the fake IdP is the
# bundled httplib's own server - and nothing of duckdb's; duckdb's include path is on the line
# only because the bundled headers reach into it). The namespace is the consumer's; here it is
# `ext_common`, the module's own.
#
#   scripts/test_oidc.sh <duckdb source dir> [build dir]
#
# OIDC_TLS=1 builds the TLS variant (DUCKDB_EXT_COMMON_OIDC_TLS, against the system OpenSSL -
# OPENSSL_ROOT points elsewhere, e.g. Homebrew's), the one every consumer ships (spec 003).
set -euo pipefail
duckdb="${1:?usage: test_oidc.sh <duckdb source dir> [build dir]}"
out="${2:-build/oidc-test}"
cxx="${CXX:-c++}"
flags="${CXXFLAGS:-}" # extra flags, e.g. the sanitizers
[ -f "$duckdb/third_party/httplib/httplib.hpp" ] || { echo "test_oidc: no bundled httplib at $duckdb" >&2; exit 1; }
mkdir -p "$out"
# the bundled httplib parses status lines and query strings through duckdb's RegexMatch wrapper over
# its bundled re2: re2 is compiled in from the same tree and the wrapper is the test's own shim
# (duckdb's reaches into its exception machinery), so the binary links nothing of a built duckdb
tls=()
if [ "${OIDC_TLS:-0}" = "1" ]; then
	ssl_root="${OPENSSL_ROOT:-}"
	tls=(-DDUCKDB_EXT_COMMON_OIDC_TLS=1)
	[ -n "$ssl_root" ] && tls+=(-I "$ssl_root/include" -L "$ssl_root/lib")
	tls+=(-lssl -lcrypto)
	# the bundled httplib reads the macOS trust store through these
	[ "$(uname)" = "Darwin" ] && tls+=(-framework CoreFoundation -framework Security)
fi
re2="$(find "$duckdb/third_party/re2" -name '*.cc' | sort | tr '\n' ' ') oidc/test/duckdb_re2_shim.cpp"
"$cxx" $flags -std=c++17 -O1 -g -pthread -DDUCKDB_EXT_COMMON_OIDC_NAMESPACE=ext_common \
	-I oidc/include -I "$duckdb/third_party/httplib" -I "$duckdb/third_party/yyjson/include" \
	-I "$duckdb/src/include" -I "$duckdb/third_party/fmt/include" -I "$duckdb/third_party/re2" \
	oidc/test/test_oidc_core.cpp oidc/src/oidc_core.cpp "$duckdb/third_party/yyjson/yyjson.cpp" $re2 \
	${tls[@]+"${tls[@]}"} -o "$out/test_oidc_core"
"$out/test_oidc_core"
