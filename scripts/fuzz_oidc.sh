#!/usr/bin/env bash
# libFuzzer over the OIDC core's parsers (clang only), against a duckdb source tree for the bundled
# yyjson and httplib. FUZZ_SECONDS bounds the run; the corpus is oidc/fuzz/corpus.
#
#   scripts/fuzz_oidc.sh <duckdb source dir> [build dir]
set -euo pipefail
duckdb="${1:?usage: fuzz_oidc.sh <duckdb source dir> [build dir]}"
out="${2:-build/oidc-fuzz}"
cxx="${CXX:-clang++}"
flags="${CXXFLAGS:-}" # extra flags
seconds="${FUZZ_SECONDS:-30}"
mkdir -p "$out"
# the bundled httplib parses status lines and query strings through duckdb's RegexMatch wrapper over
# its bundled re2: re2 is compiled in from the same tree and the wrapper is the test's own shim
# (duckdb's reaches into its exception machinery), so the binary links nothing of a built duckdb
re2="$(find "$duckdb/third_party/re2" -name '*.cc' | sort | tr '\n' ' ') oidc/test/duckdb_re2_shim.cpp"
"$cxx" $flags -std=c++17 -g -O1 -pthread -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
	-DDUCKDB_EXT_COMMON_OIDC_NAMESPACE=ext_common \
	-I oidc/include -I "$duckdb/third_party/httplib" -I "$duckdb/third_party/yyjson/include" \
	-I "$duckdb/src/include" -I "$duckdb/third_party/fmt/include" -I "$duckdb/third_party/re2" \
	oidc/fuzz/fuzz_oidc_parse.cpp oidc/src/oidc_core.cpp "$duckdb/third_party/yyjson/yyjson.cpp" $re2 \
	-o "$out/fuzz_oidc_parse"
"$out/fuzz_oidc_parse" -max_total_time="$seconds" -max_len=4096 -print_final_stats=1 oidc/fuzz/corpus
