#!/usr/bin/env bash
# Every header under hooks/ and contracts/ must compile on its own against a duckdb source tree
# (charter R9): a contract that only compiles after some other include, or only against one duckdb
# line, breaks a consumer that includes it differently or builds on the other line.
#
#   scripts/check_headers.sh <duckdb source dir>
set -euo pipefail
duckdb="${1:?usage: check_headers.sh <duckdb source dir>}"
cxx="${CXX:-c++}"
[ -d "$duckdb/src/include/duckdb" ] || { echo "check_headers: no duckdb tree at $duckdb" >&2; exit 1; }

headers="$(find hooks contracts -name '*.hpp' 2>/dev/null | sort)"
if [ -z "$headers" ]; then
	echo "check_headers: no headers yet"
	exit 0
fi

fail=0
while IFS= read -r h; do
	# included from a one-line translation unit, the way a consumer includes it
	if printf '#include "%s"\n' "$PWD/$h" | "$cxx" -std=c++17 -fsyntax-only -x c++ -I hooks -I contracts \
		-I "$duckdb/src/include" -I "$duckdb/third_party/fmt/include" -; then
		echo "  ok   $h"
	else
		echo "  FAIL $h"
		fail=1
	fi
done <<<"$headers"
exit $fail
