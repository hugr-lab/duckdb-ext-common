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
# OIDC_NO_BUILTIN=1 builds the core without its built-in client (spec 018, as a wasm build has it) with its own
# test, and checks the core's object references no socket, thread or TLS symbol.
set -euo pipefail
duckdb="${1:?usage: test_oidc.sh <duckdb source dir> [build dir]}"
out="${2:-build/oidc-test}"
cxx="${CXX:-c++}"
flags="${CXXFLAGS:-}" # extra flags, e.g. the sanitizers
[ -f "$duckdb/third_party/httplib/httplib.hpp" ] || { echo "test_oidc: no bundled httplib at $duckdb" >&2; exit 1; }
mkdir -p "$out"
if [ "${OIDC_NO_BUILTIN:-0}" = "1" ]; then
	common=(-std=c++17 -O1 -g -DDUCKDB_EXT_COMMON_OIDC_NAMESPACE=ext_common -DDUCKDB_EXT_COMMON_OIDC_NO_BUILTIN=1
		-I oidc/include -I "$duckdb/third_party/yyjson/include" -I "$duckdb/src/include")
	"$cxx" $flags "${common[@]}" -c oidc/src/oidc_core.cpp -o "$out/oidc_core_no_builtin.o"
	# what a page's wasm cannot resolve: sockets, a thread of its own (pthread_create, or libstdc++'s
	# std::thread::_M_start_thread), OpenSSL. macOS prefixes an underscore. nm's own failure fails the script.
	undefined="$(nm -u "$out/oidc_core_no_builtin.o")"
	if grep -E '(^|[ _])(socket|connect|getaddrinfo|getnameinfo|bind|listen|accept|send|recv|poll|select|pthread_create|SSL_[A-Za-z0-9_]*|EVP_[A-Za-z0-9_]*)$|_M_start_thread' <<<"$undefined"; then
		echo "test_oidc: the core without its built-in client still references the symbols above" >&2
		exit 1
	fi
	"$cxx" $flags "${common[@]}" oidc/test/test_no_builtin.cpp "$out/oidc_core_no_builtin.o" \
		"$duckdb/third_party/yyjson/yyjson.cpp" -o "$out/test_no_builtin"
	"$out/test_no_builtin"
	exit 0
fi
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
# a newer 2.0 tree defines hugeint_t(int64_t) constexpr in its header: the shim must not define it again
shim=()
if grep -q 'constexpr hugeint_t::hugeint_t(int64_t' "$duckdb/src/include/duckdb/common/hugeint.hpp"; then
	shim=(-DDUCKDB_SHIM_HUGEINT_INLINE=1)
fi
"$cxx" $flags -std=c++17 -O1 -g -pthread -DDUCKDB_EXT_COMMON_OIDC_NAMESPACE=ext_common ${shim[@]+"${shim[@]}"} \
	-I oidc/include -I "$duckdb/third_party/httplib" -I "$duckdb/third_party/yyjson/include" \
	-I "$duckdb/src/include" -I "$duckdb/third_party/fmt/include" -I "$duckdb/third_party/re2" \
	oidc/test/test_oidc_core.cpp oidc/src/oidc_core.cpp "$duckdb/third_party/yyjson/yyjson.cpp" $re2 \
	${tls[@]+"${tls[@]}"} -o "$out/test_oidc_core"
"$out/test_oidc_core"
