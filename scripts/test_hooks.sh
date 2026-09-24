#!/usr/bin/env bash
# The hooks/ base's own test (spec 008): header-only, against a duckdb source tree's headers.
#
#   scripts/test_hooks.sh <duckdb source dir> [build dir]
set -euo pipefail
duckdb="${1:?usage: test_hooks.sh <duckdb source dir> [build dir]}"
out="${2:-build/hooks-test}"
mkdir -p "$out"
"${CXX:-c++}" -std=c++17 -O1 -pthread -I hooks -I "$duckdb/src/include" -I "$duckdb/third_party/fmt/include" \
	hooks/test/test_hooks.cpp -o "$out/test_hooks"
"$out/test_hooks"
