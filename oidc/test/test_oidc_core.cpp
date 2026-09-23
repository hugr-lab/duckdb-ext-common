// The OIDC client core (duckdb-ext-common spec 002, from duckdb-acl spec 060) against a fake IdP
// served in-process by the bundled httplib:
// discovery (with the RFC 8414 issuer check), client_credentials, password, refresh, the device
// flow's pending->granted poll, the browser flow (authorization code + PKCE, loopback redirect -
// spec 003) and the cache's refresh margin. Built with OIDC_TLS=1 it also proves the TLS branch is
// compiled in. No network, no sleeps beyond the
// poll's own zero-interval path. Build + run via `scripts/test_oidc.sh <duckdb tree>`.

#include "oidc_core.hpp"

#include "httplib.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

using namespace duckdb::DUCKDB_EXT_COMMON_OIDC_NAMESPACE::oidc;

namespace {

int failures = 0;

bool Check(bool ok, const std::string &what) {
	std::cout << (ok ? "  ok:   " : "  FAIL: ") << what << std::endl;
	if (!ok) {
		failures++;
	}
	return ok;
}

void Scenario(const std::string &name, const std::function<void()> &body) {
	std::cout << name << std::endl;
	try {
		body();
	} catch (std::exception &ex) {
		Check(false, name + " aborted: " + std::string(ex.what()));
	}
}

//! The fake IdP: enough of an issuer for every flow the core speaks. Runs on a loopback port the
//! OS picks; `pending_polls` device polls answer authorization_pending before the grant.
struct FakeIdp {
	duckdb_httplib::Server server;
	std::thread thread;
	int port = 0;
	std::atomic<int> pending_polls {0};
	std::atomic<int> device_polls_seen {0};
	std::mutex auth_mutex;
	std::string auth_challenge;    // the code_challenge of the last /authorize
	std::string auth_redirect_uri; // and its redirect_uri
	std::atomic<int> codes_exchanged {0};

	std::string Issuer() const {
		return "http://127.0.0.1:" + std::to_string(port);
	}

	void Start() {
		server.Get("/.well-known/openid-configuration",
		           [this](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			           res.set_content("{\"issuer\":\"" + Issuer() + "\",\"token_endpoint\":\"" + Issuer() +
			                               "/token\",\"device_authorization_endpoint\":\"" + Issuer() +
			                               "/device\",\"authorization_endpoint\":\"" + Issuer() + "/authorize\"}",
			                           "application/json");
		           });
		// a LYING document: served at /realms/other, speaking for the root issuer - discovery asked
		// about /realms/other must refuse it on the issuer check, not on a 404
		server.Get("/realms/other/.well-known/openid-configuration", [this](const duckdb_httplib::Request &,
		                                                                    duckdb_httplib::Response &res) {
			res.set_content("{\"issuer\":\"" + Issuer() + "\",\"token_endpoint\":\"" + Issuer() + "/token\"}",
			                "application/json");
		});
		// a canonical trailing slash: the advertised issuer ends in '/', the asked-for one does not
		server.Get("/slashy/.well-known/openid-configuration", [this](const duckdb_httplib::Request &,
		                                                              duckdb_httplib::Response &res) {
			res.set_content("{\"issuer\":\"" + Issuer() + "/slashy/\",\"token_endpoint\":\"" + Issuer() + "/token\"}",
			                "application/json");
		});
		// an https issuer whose document names a cleartext authorization endpoint - a downgrade
		server.Get("/downgrade/.well-known/openid-configuration", [this](const duckdb_httplib::Request &,
		                                                                 duckdb_httplib::Response &res) {
			res.set_content("{\"issuer\":\"https://idp.test/downgrade\",\"token_endpoint\":\"https://idp.test/"
			                "token\",\"authorization_endpoint\":\"" +
			                    Issuer() + "/authorize\"}",
			                "application/json");
		});
		// the browser's side of the flow: client `cli` is sent back with a code, client `denied` with
		// the IdP's refusal - both to the redirect_uri, carrying the state
		server.Get("/authorize", [this](const duckdb_httplib::Request &req, duckdb_httplib::Response &res) {
			auto redirect_uri = req.get_param_value("redirect_uri");
			if (req.get_param_value("response_type") != "code" ||
			    req.get_param_value("code_challenge_method") != "S256" || redirect_uri.empty()) {
				res.status = 400;
				return;
			}
			{
				std::lock_guard<std::mutex> guard(auth_mutex);
				auth_challenge = req.get_param_value("code_challenge");
				auth_redirect_uri = redirect_uri;
			}
			auto state = req.get_param_value("state");
			if (req.get_param_value("client_id") == "denied") {
				res.set_redirect(redirect_uri + "?error=access_denied&state=" + state);
			} else {
				res.set_redirect(redirect_uri + "?code=ac-1&state=" + state);
			}
		});
		server.Post("/device", [this](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			res.set_content("{\"device_code\":\"dc-1\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"" + Issuer() +
			                    "/activate\",\"interval\":0,\"expires_in\":60}",
			                "application/json");
		});
		server.Post("/token", [this](const duckdb_httplib::Request &req, duckdb_httplib::Response &res) {
			auto grant = req.get_param_value("grant_type");
			auto deny = [&](const std::string &code, const std::string &description) {
				res.status = 400;
				res.set_content("{\"error\":\"" + code + "\",\"error_description\":\"" + description + "\"}",
				                "application/json");
			};
			if (grant == "client_credentials") {
				if (req.get_param_value("client_id") == "svc" && req.get_param_value("client_secret") == "s3cr3t") {
					res.set_content("{\"access_token\":\"cc-token\",\"expires_in\":120}", "application/json");
				} else {
					deny("invalid_client", "bad client secret");
				}
				return;
			}
			if (grant == "password") {
				if (req.get_param_value("username") == "analyst" && req.get_param_value("password") == "pw") {
					res.set_content("{\"access_token\":\"pw-token\",\"refresh_token\":\"rt-1\",\"expires_in\":60}",
					                "application/json");
				} else {
					deny("invalid_grant", "wrong credentials");
				}
				return;
			}
			if (grant == "refresh_token") {
				if (req.get_param_value("refresh_token") == "rt-1") {
					res.set_content("{\"access_token\":\"pw-token-2\",\"expires_in\":60}", "application/json");
				} else {
					deny("invalid_grant", "unknown refresh token");
				}
				return;
			}
			if (grant == "authorization_code") {
				std::lock_guard<std::mutex> guard(auth_mutex);
				if (req.get_param_value("code") != "ac-1" || req.get_param_value("redirect_uri") != auth_redirect_uri) {
					deny("invalid_grant", "unknown code or redirect_uri");
				} else if (PkceChallenge(req.get_param_value("code_verifier")) != auth_challenge) {
					deny("invalid_grant", "PKCE verification failed");
				} else {
					codes_exchanged++;
					res.set_content("{\"access_token\":\"browser-token\",\"refresh_token\":\"rt-b\",\"expires_in\":60}",
					                "application/json");
				}
				return;
			}
			if (grant == "urn:ietf:params:oauth:grant-type:device_code") {
				device_polls_seen++;
				if (req.get_param_value("device_code") != "dc-1") {
					deny("access_denied", "unknown device code");
				} else if (pending_polls.fetch_sub(1) > 0) {
					deny("authorization_pending", "the user has not approved yet");
				} else {
					res.set_content("{\"access_token\":\"device-token\",\"expires_in\":90}", "application/json");
				}
				return;
			}
			deny("unsupported_grant_type", grant);
		});
		port = server.bind_to_any_port("127.0.0.1");
		thread = std::thread([this] { server.listen_after_bind(); });
		server.wait_until_ready();
	}

	void Stop() {
		server.stop();
		if (thread.joinable()) {
			thread.join();
		}
	}
};

//! The test's "browser": GET the authorization URL, follow the one redirect to the loopback
//! receiver. Returns the receiver's status.
int Browse(const std::string &url) {
	auto rest = url.substr(std::string("http://").size());
	auto slash = rest.find('/');
	duckdb_httplib::Client idp("http://" + rest.substr(0, slash));
	auto first = idp.Get(rest.substr(slash));
	if (!first || first->status != 302) {
		return first ? first->status : -1;
	}
	auto location = first->get_header_value("Location");
	auto back = location.substr(std::string("http://").size());
	auto back_slash = back.find('/');
	duckdb_httplib::Client receiver("http://" + back.substr(0, back_slash));
	auto second = receiver.Get(back.substr(back_slash));
	return second ? second->status : -1;
}

int64_t Now() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

} // namespace

int main() {
	std::cout << "=== the OIDC client core against a fake IdP (spec 060) ===" << std::endl;
	FakeIdp idp;
	idp.Start();

	Endpoints ep;
	Scenario("discovery finds the endpoints and checks the issuer", [&] {
		ep = Discover(idp.Issuer());
		Check(ep.Ok(), "discovery succeeds: " + ep.error);
		Check(ep.token_endpoint == idp.Issuer() + "/token", "token endpoint discovered");
		Check(!ep.device_authorization_endpoint.empty(), "device endpoint discovered");
		auto mismatch = Discover(idp.Issuer() + "/realms/other");
		Check(!mismatch.Ok() && mismatch.error.find("issuer mismatch") != std::string::npos,
		      "a document speaking for another issuer is refused ON THE ISSUER CHECK: " + mismatch.error);
		auto slashy = Discover(idp.Issuer() + "/slashy");
		Check(slashy.Ok(),
		      "a canonical trailing slash in the advertised issuer is normalised, not refused: " + slashy.error);
	});

	Scenario("client_credentials - the machine identity flow", [&] {
		auto granted = ClientCredentials(ep, "svc", "s3cr3t");
		Check(granted.Ok() && granted.access_token == "cc-token", "the right secret earns a token");
		Check(granted.expires_at > 0, "the expiry travelled");
		auto denied = ClientCredentials(ep, "svc", "wrong");
		Check(!denied.Ok() && denied.error_code == "invalid_client",
		      "a wrong secret is the protocol's own refusal: " + denied.error);
	});

	Scenario("password grant and its refresh", [&] {
		auto granted = PasswordGrant(ep, "cli", "", "analyst", "pw");
		Check(granted.Ok() && granted.access_token == "pw-token", "user/password earns a token");
		Check(granted.refresh_token == "rt-1", "with a refresh token");
		auto renewed = RefreshGrant(ep, "cli", "", granted.refresh_token);
		Check(renewed.Ok() && renewed.access_token == "pw-token-2", "the refresh renews silently");
		auto denied = PasswordGrant(ep, "cli", "", "analyst", "nope");
		Check(!denied.Ok() && denied.error_code == "invalid_grant", "wrong credentials refused");
	});

	Scenario("device flow - begin, pending, granted", [&] {
		auto begun = DeviceBegin(ep, "cli");
		Check(begun.Ok() && begun.user_code == "WDJB-MJHT", "the user gets a code to type");
		idp.pending_polls = 2;
		auto deadline =
		    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
		        .count() +
		    30;
		auto granted = DevicePoll(ep, "cli", begun.device_code, /*interval*/ 0, deadline);
		Check(granted.Ok() && granted.access_token == "device-token",
		      "the poll rides out authorization_pending: " + granted.error);
		Check(idp.device_polls_seen >= 3, "at least two pendings were actually answered before the grant");
		auto denied = DevicePoll(ep, "cli", "dc-bogus", 0, deadline);
		Check(!denied.Ok() && denied.error_code == "access_denied", "an unknown device code is refused");
		idp.pending_polls = 1000; // never granted - only the cancellation can end this poll
		auto cancelled = DevicePoll(ep, "cli", begun.device_code, 0, deadline, [] { return true; });
		Check(!cancelled.Ok() && cancelled.error_code == "cancelled",
		      "a cancellation ends the poll before the deadline");
	});

	Scenario("PKCE: the RFC 7636 appendix B vector, and fresh randomness", [&] {
		Check(PkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") ==
		          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		      "S256 of the RFC's verifier is the RFC's challenge");
		auto a = RandomUrlSafe(32), b = RandomUrlSafe(32);
		Check(a.size() == 43 && a != b, "32 random bytes are 43 url-safe chars, and never twice the same");
		Check(a.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") ==
		          std::string::npos,
		      "only the base64url alphabet, no padding");
	});

	Scenario("the browser flow: authorization code + PKCE over a loopback redirect", [&] {
		Check(ep.authorization_endpoint == idp.Issuer() + "/authorize", "authorization endpoint discovered");
		std::thread browser;
		std::string seen_url;
		auto granted = AuthorizationCodeLogin(
		    ep, "cli", "openid offline_access",
		    [&](const std::string &url) {
			    seen_url = url;
			    browser = std::thread([url] { Browse(url); });
		    },
		    Now() + 30);
		if (browser.joinable()) {
			browser.join();
		}
		Check(granted.Ok() && granted.access_token == "browser-token", "the code is exchanged: " + granted.error);
		Check(granted.refresh_token == "rt-b", "with a refresh token");
		Check(seen_url.find("code_challenge_method=S256") != std::string::npos &&
		          seen_url.find("redirect_uri=http%3A%2F%2F127.0.0.1%3A") != std::string::npos,
		      "the request carries S256 and a 127.0.0.1 redirect");
		Check(idp.codes_exchanged == 1, "exactly one exchange");
	});

	Scenario("the browser flow: the IdP's refusal, a forged callback, a wrong verifier", [&] {
		std::thread browser;
		auto denied = AuthorizationCodeLogin(
		    ep, "denied", "", [&](const std::string &url) { browser = std::thread([url] { Browse(url); }); },
		    Now() + 30);
		browser.join();
		Check(!denied.Ok() && denied.error_code == "access_denied", "access_denied comes back: " + denied.error);

		// a forged callback (another state) is refused and ignored; the real one still completes
		LoopbackRedirect receiver;
		std::string error;
		Check(receiver.Start(error), "the receiver binds: " + error);
		auto request = BuildAuthorizationRequest(ep, "cli", receiver.RedirectUri(), "openid");
		Check(request.Ok() && request.verifier.size() == 43, "a request with a 43-char verifier");
		std::atomic<int> forged_status {0};
		browser = std::thread([&] {
			auto base = receiver.RedirectUri().substr(std::string("http://").size());
			auto slash = base.find('/');
			duckdb_httplib::Client local("http://" + base.substr(0, slash));
			auto forged = local.Get(base.substr(slash) + "?code=evil&state=not-the-state");
			forged_status = forged ? forged->status : -1;
			Browse(request.url);
		});
		auto redirect = receiver.Wait(request.state, Now() + 30);
		browser.join();
		Check(forged_status == 400, "the forged callback is answered 400");
		Check(redirect.Ok() && redirect.code == "ac-1", "the real callback's code, not the forged one");
		auto wrong = ExchangeAuthorizationCode(ep, "cli", redirect.code, RandomUrlSafe(32), request.redirect_uri);
		Check(!wrong.Ok() && wrong.error_code == "invalid_grant", "a verifier that is not the challenge's is refused");
		auto right = ExchangeAuthorizationCode(ep, "cli", redirect.code, request.verifier, request.redirect_uri);
		Check(right.Ok(), "the right verifier is accepted: " + right.error);
	});

	Scenario("the browser flow: cancellation, the deadline, and the endpoints' checks", [&] {
		auto cancelled = AuthorizationCodeLogin(
		    ep, "cli", "", [](const std::string &) {}, Now() + 30, [] { return true; });
		Check(!cancelled.Ok() && cancelled.error_code == "cancelled", "a cancellation ends the wait");
		auto expired = AuthorizationCodeLogin(
		    ep, "cli", "", [](const std::string &) {}, Now() - 1);
		Check(!expired.Ok() && expired.error_code == "expired_token", "the deadline ends the wait");
		Endpoints machine_only = ep;
		machine_only.authorization_endpoint.clear();
		auto none = AuthorizationCodeLogin(
		    machine_only, "cli", "", [](const std::string &) {}, Now() + 30);
		Check(!none.Ok() && none.error.find("no authorization_endpoint") != std::string::npos,
		      "an issuer without the endpoint is told apart: " + none.error);
		auto downgrade = ParseDiscoveryDocument("https://idp.test/downgrade",
		                                        HttpGet(idp.Issuer() + "/downgrade/.well-known/openid-configuration"));
		Check(!downgrade.Ok() && downgrade.error.find("cleartext endpoint") != std::string::npos,
		      "a cleartext authorization endpoint of an https issuer is refused: " + downgrade.error);
	});

	Scenario("the TLS branch is compiled in exactly when DUCKDB_EXT_COMMON_OIDC_TLS is", [&] {
		// port 1 on loopback: nothing listens, so a TLS build fails to CONNECT; a plain build refuses
		// before trying (spec 003: the gate once tested a macro nobody defined)
		auto result = HttpGet("https://127.0.0.1:1/");
		auto refused_for_tls = result.error.find("TLS-enabled build") != std::string::npos;
#ifdef DUCKDB_EXT_COMMON_OIDC_TLS
		Check(!result.Ok() && !refused_for_tls, "a TLS build attempts the connection: " + result.error);
#else
		Check(!result.Ok() && refused_for_tls, "a plain build refuses https outright: " + result.error);
#endif
	});

	Scenario("the cache serves only tokens with margin left", [&] {
		auto &cache = TokenCache::Instance();
		TokenSet fresh;
		fresh.access_token = "cached";
		fresh.expires_at =
		    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
		        .count() +
		    600;
		cache.Set(&idp, "kc", fresh);
		Check(cache.Get(&idp, "kc").access_token == "cached", "a fresh token is served");
		Check(cache.Get(&idp, "kc", /*margin*/ 700).access_token.empty(),
		      "inside the margin it is not served (and the stale row is dropped)");
		Check(cache.Get(&idp, "kc").access_token.empty(), "the stale read erased it");
		cache.Set(&idp, "kc", fresh);
		cache.Invalidate(&idp, "kc");
		Check(cache.Get(&idp, "kc").access_token.empty(), "invalidate removes it");
	});

	idp.Stop();
	std::cout << (failures == 0 ? "PASS" : "FAIL") << " test_oidc_core" << std::endl;
	return failures == 0 ? 0 : 1;
}
