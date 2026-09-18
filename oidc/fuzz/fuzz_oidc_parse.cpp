// libFuzzer target for the OIDC core's parsers (duckdb-ext-common spec 002): the bytes an IdP
// answers are the pre-authentication network input of a consumer, so they are the right thing to fuzz.
// The module is duckdb-free by design (charter R10), which is what makes this a small standalone
// binary: oidc_core.cpp + the bundled yyjson + this file, under -fsanitize=fuzzer,address,undefined.
//
// The first byte picks the parser and the HTTP status shape; the rest is the body. The parsers
// promise to refuse or bound every value and never to crash on a malformed document - that promise,
// not any particular output, is what a run asserts.
//
// Build + run: `scripts/fuzz_oidc.sh <duckdb tree>` (clang only; FUZZ_SECONDS bounds the run).

#include "oidc_core.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0) {
		return 0;
	}
	using namespace duckdb::DUCKDB_EXT_COMMON_OIDC_NAMESPACE::oidc;
	HttpResult response;
	auto selector = data[0];
	response.status = (selector & 0x80) ? 400 : 200; // an error status exercises the error branches
	response.body.assign(reinterpret_cast<const char *>(data + 1), size - 1);
	switch (selector % 3) {
	case 0:
		(void)ParseTokenResponse(response);
		break;
	case 1:
		(void)ParseDiscoveryDocument("https://issuer.test", response);
		break;
	default:
		(void)ParseDeviceAuthorization(response);
		break;
	}
	return 0;
}
