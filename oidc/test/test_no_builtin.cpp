// The OIDC core built without its built-in client (spec 018), as a wasm build has it: no httplib, no sockets, no
// thread of its own. A request without a transport is refused, the loopback receiver does not start, and the
// flows run through a consumer's transport. Build + run via `OIDC_NO_BUILTIN=1 scripts/test_oidc.sh <duckdb tree>`,
// which also checks that the core's object references no socket, thread or TLS symbol.

#include "oidc_core.hpp"

#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace duckdb::DUCKDB_EXT_COMMON_OIDC_NAMESPACE::oidc;

namespace {

int failures = 0;

void Check(bool ok, const std::string &what) {
	std::cout << (ok ? "  ok   " : "  FAIL ") << what << "\n";
	if (!ok) {
		failures++;
	}
}

const std::string ISSUER = "https://idp.example/realms/r";

//! A fake IdP behind a transport: discovery and a refresh grant, and what it was asked
struct FakeIdp {
	std::vector<std::string> asked;

	HttpResult Answer(const std::string &method, const std::string &url, const std::string &body) {
		asked.push_back(method + " " + url);
		HttpResult out;
		if (method == "GET" && url == ISSUER + "/.well-known/openid-configuration") {
			out.status = 200;
			out.body = "{\"issuer\":\"" + ISSUER + "\",\"token_endpoint\":\"" + ISSUER +
			           "/token\",\"authorization_endpoint\":\"" + ISSUER + "/auth\"}";
		} else if (method == "POST" && url == ISSUER + "/token" &&
		           body.find("grant_type=refresh_token") != std::string::npos) {
			out.status = 200;
			out.body = "{\"access_token\":\"at-1\",\"refresh_token\":\"rt-2\",\"expires_in\":300}";
		} else {
			out.status = 404;
		}
		return out;
	}
};

} // namespace

int main() {
	std::cout << "the OIDC core without its built-in client (spec 018)\n";

	auto refused = HttpGet(ISSUER + "/.well-known/openid-configuration");
	Check(!refused.Ok() && refused.status == 0 && refused.error.find("no built-in HTTP client") != std::string::npos,
	      "no transport: a request is refused, not attempted: " + refused.error);
	auto discovered = Discover(ISSUER);
	Check(!discovered.error.empty(), "no transport: discovery fails with the refusal: " + discovered.error);

	LoopbackRedirect receiver;
	std::string error;
	Check(!receiver.Start(error) && error.find("no loopback receiver") != std::string::npos,
	      "the loopback receiver does not start: " + error);

	FakeIdp idp;
	{
		TransportScope scope([&idp](const std::string &method, const std::string &url,
		                            const std::map<std::string, std::string> &, const std::string &body,
		                            const std::string &, int) { return idp.Answer(method, url, body); });
		auto ep = Discover(ISSUER);
		Check(ep.error.empty() && ep.token_endpoint == ISSUER + "/token", "a transport carries discovery: " + ep.error);
		auto renewed = RefreshGrant(ep, "spa", "", "rt-1");
		Check(renewed.Ok() && renewed.access_token == "at-1" && renewed.refresh_token == "rt-2",
		      "a transport carries a grant: " + renewed.error);
	}
	Check(idp.asked.size() == 2, "the transport saw both requests");
	Check(!HttpGet(ISSUER + "/.well-known/openid-configuration").Ok(), "out of the scope, refused again");

	std::cout << (failures ? "FAILED: " + std::to_string(failures) + "\n" : std::string("all passed\n"));
	return failures ? 1 : 0;
}
