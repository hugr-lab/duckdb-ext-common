//===----------------------------------------------------------------------===//
// oidc_core.hpp - the OIDC client core (duckdb-ext-common spec 002; from duckdb-acl spec 060)
//
// The acquisition primitives every client-side layer shares: endpoint discovery (RFC 8414), the
// POST flows (client_credentials / password / device, RFC 8628), refresh, the authorization code
// flow with PKCE and a loopback redirect (RFC 7636, RFC 8252 - spec 003), and a token cache with a
// refresh margin. Deliberately duckdb-free (std + yyjson + the bundled httplib in the one TU,
// both from the consumer's duckdb tree - charter R10), so a standalone test can link it. It obtains
// tokens; it never verifies them. Generalised from hugr-lab/mssql-extension's Azure implementation.
//===----------------------------------------------------------------------===//

#pragma once

// The namespace is the consumer's (spec 002 §4, charter R13): the module is compiled into every
// consumer, and two consumers linked into one image must not produce the same symbols. duckdb-acl
// sets `acl` (so the names stay `duckdb::acl::oidc::...`), tresor sets `tresor`.
#ifndef DUCKDB_EXT_COMMON_OIDC_NAMESPACE
#error "define DUCKDB_EXT_COMMON_OIDC_NAMESPACE=<your extension's namespace> on every TU that includes oidc_core.hpp"
#endif

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace duckdb {
namespace DUCKDB_EXT_COMMON_OIDC_NAMESPACE {
namespace oidc {

//! One HTTP exchange. `error` is non-empty only on transport failure; an HTTP
//! error status arrives as `status` + `body` for the caller to interpret.
struct HttpResult {
	int status = 0;
	std::string body;
	std::string error;

	bool Ok() const {
		return error.empty() && status >= 200 && status < 300;
	}
};

//! GET / form-POST against an http(s) URL. https needs a TLS-enabled build
//! (DUCKDB_EXT_COMMON_OIDC_TLS, where the consumer links OpenSSL); without one it
//! returns a transport error that says so rather than silently downgrading.
HttpResult HttpGet(const std::string &url, int timeout_seconds = 10);
HttpResult HttpPostForm(const std::string &url, const std::map<std::string, std::string> &params,
                        int timeout_seconds = 30);
//! Any method, with headers and an optional body: the transport a consumer's own REST calls ride
//! (tresor's service API), so an image carries one TLS-compiled httplib, this module's (spec 003).
HttpResult HttpSend(const std::string &method, const std::string &url,
                    const std::map<std::string, std::string> &headers, const std::string &body = "",
                    const std::string &content_type = "", int timeout_seconds = 30);

//! The issuer's endpoints, discovered or assembled by the caller.
struct Endpoints {
	std::string issuer;
	std::string token_endpoint;
	std::string device_authorization_endpoint; // may be empty: not every issuer offers RFC 8628
	std::string authorization_endpoint;        // may be empty: a machine-only issuer has no browser flow
	std::string error;                         // non-empty when discovery failed

	bool Ok() const {
		return error.empty() && !token_endpoint.empty();
	}
};

//! GET `<issuer>/.well-known/openid-configuration` (RFC 8414). The advertised
//! issuer must equal the asked-for one — a mismatch is refused, not adopted.
Endpoints Discover(const std::string &issuer_url, int timeout_seconds = 10);

//! What a token endpoint answered. `error` carries the human-readable failure;
//! `error_code` the protocol's machine code (authorization_pending, slow_down,
//! invalid_grant, ...), empty on success.
struct TokenSet {
	std::string access_token;
	std::string refresh_token;     // empty when the grant returns none
	int64_t expires_at = 0;        // epoch seconds; 0 = the response carried no expiry
	std::string issued_token_type; // RFC 8693's answer field; empty when the response carried none
	std::string error;
	std::string error_code;

	bool Ok() const {
		return error.empty() && !access_token.empty();
	}
};

//! grant_type=client_credentials — the machine identity flow.
TokenSet ClientCredentials(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                           const std::string &scope = "");

//! grant_type=password — the resource-owner flow; only where the IdP and the
//! admin allow it (design/016: an admin-enabled row of the menu, never forced).
TokenSet PasswordGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &username, const std::string &password, const std::string &scope = "");

//! RFC 8693 token exchange (spec 004): the client (client_secret_post; empty secret for a public one)
//! presents `subject_token` - an access token it received - and asks the IdP for an access token for
//! `audience` (and/or `resource`, `scope`). An answer that is not an access token is refused.
TokenSet TokenExchange(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &subject_token, const std::string &audience, const std::string &scope = "",
                       const std::string &resource = "");

//! Entra's On-Behalf-Of (RFC 7523 jwt-bearer, requested_token_use=on_behalf_of): `assertion` is the
//! access token the client received, `scope` names the downstream API (api://.../.default).
TokenSet OnBehalfOf(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                    const std::string &assertion, const std::string &scope);

//! grant_type=refresh_token — silent renewal off a previous TokenSet.
TokenSet RefreshGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                      const std::string &refresh_token);

//! The device flow's first half (RFC 8628 §3.1-3.2): what to show the user.
struct DeviceAuthorization {
	std::string device_code;
	std::string user_code;
	std::string verification_uri;
	std::string verification_uri_complete; // may be empty
	int64_t interval = 5;                  // seconds between polls
	int64_t expires_in = 600;
	std::string error;

	bool Ok() const {
		return error.empty() && !device_code.empty();
	}
};

DeviceAuthorization DeviceBegin(const Endpoints &ep, const std::string &client_id, const std::string &scope = "");

//! The parsers behind the exchanges above, over a response already received:
//! pure functions of the bytes an IdP answered, which is what the fuzz target
//! (oidc/fuzz/fuzz_oidc_parse.cpp) feeds them. Every value out is
//! bounded or refused; nothing is inferred from a malformed document.
//! `issuer` is the asked-for issuer, already stripped of trailing slashes.
TokenSet ParseTokenResponse(const HttpResult &response);
Endpoints ParseDiscoveryDocument(const std::string &issuer, const HttpResult &response);
DeviceAuthorization ParseDeviceAuthorization(const HttpResult &response);

//! The device flow's second half: poll until granted, denied, the deadline, or
//! the caller's own cancellation. Honours authorization_pending (wait
//! `interval`) and slow_down (+5s, §3.5); sleeps in one-second slices so a
//! cancellation (a query interrupt) is honoured promptly. `interval` of 0
//! polls without sleeping (tests); the poll never outlives
//! `deadline_epoch_seconds`.
TokenSet DevicePoll(const Endpoints &ep, const std::string &client_id, const std::string &device_code,
                    int64_t interval_seconds, int64_t deadline_epoch_seconds,
                    const std::function<bool()> &cancelled = nullptr);

//! PKCE (RFC 7636 §4.2): BASE64URL(SHA256(verifier)), no padding - `S256`, never `plain`.
std::string PkceChallenge(const std::string &verifier);

//! `bytes` bytes of OS randomness (std::random_device), base64url without padding: a PKCE verifier
//! (32 bytes -> 43 chars) or a `state`.
std::string RandomUrlSafe(size_t bytes = 32);

//! The browser flow's first half: the URL to send the person to, and what must be remembered to
//! finish it. `redirect_uri` is the loopback receiver's.
struct AuthorizationRequest {
	std::string url;
	std::string state;
	std::string verifier;
	std::string redirect_uri;
	std::string error;

	bool Ok() const {
		return error.empty() && !url.empty();
	}
};

AuthorizationRequest BuildAuthorizationRequest(const Endpoints &ep, const std::string &client_id,
                                               const std::string &redirect_uri, const std::string &scope = "");

//! grant_type=authorization_code with the PKCE verifier - a public client, no secret.
TokenSet ExchangeAuthorizationCode(const Endpoints &ep, const std::string &client_id, const std::string &code,
                                   const std::string &verifier, const std::string &redirect_uri);

//! The redirect receiver of a native client (RFC 8252 §7.3): an http server on 127.0.0.1, on a
//! port the OS picks and no other socket may share, that waits for the one `GET /callback` carrying
//! the expected `state`. Until `Expect` names that state every callback is refused; afterwards a
//! callback with another state is answered 400 and ignored - the wait goes on. Nothing from a
//! request is reflected into the page the browser gets. One login per receiver.
class LoopbackRedirect {
public:
	LoopbackRedirect();
	~LoopbackRedirect();
	LoopbackRedirect(const LoopbackRedirect &) = delete;
	LoopbackRedirect &operator=(const LoopbackRedirect &) = delete;

	//! Binds and starts serving; false (with `error`) when no port could be bound or it was started
	//! before.
	bool Start(std::string &error);
	//! http://127.0.0.1:<port>/callback - valid after Start.
	std::string RedirectUri() const;
	//! The state this login sent. Call it BEFORE the browser is sent anywhere: a callback that lands
	//! before it is refused, and a browser does not retry (the review's finding).
	void Expect(const std::string &state);

	struct Result {
		std::string code;
		std::string error;      // human-readable
		std::string error_code; // the IdP's `error`, or expired_token / cancelled / invalid_request

		bool Ok() const {
			return error.empty() && !code.empty();
		}
	};
	//! Until the expected callback, the deadline or the cancellation (checked every 200 ms, outside the
	//! lock the callback takes). The server is stopped on return; a second Wait reports the first's end.
	Result Wait(int64_t deadline_epoch_seconds, const std::function<bool()> &cancelled = nullptr);

private:
	struct Impl;
	std::unique_ptr<Impl> impl;
};

//! The whole browser flow: receiver, request, `present(url)` (the consumer prints it and opens a
//! browser - the module spawns nothing), wait, exchange. Failures come back like every flow's:
//! the IdP's error code (access_denied, ...), expired_token at the deadline, cancelled.
TokenSet AuthorizationCodeLogin(const Endpoints &ep, const std::string &client_id, const std::string &scope,
                                const std::function<void(const std::string &url)> &present,
                                int64_t deadline_epoch_seconds, const std::function<bool()> &cancelled = nullptr);

//! The cache: keyed by an owner pointer (a DatabaseInstance, a provider, ...)
//! plus a caller-chosen key; a token is served only while it has more than
//! `margin_seconds` of life left, so a consumer never receives one about to
//! die mid-use. mssql-extension's TokenCache, generalised.
class TokenCache {
public:
	static TokenCache &Instance();

	//! The cached set, or an empty one when absent / inside the margin (a stale
	//! entry is erased on read).
	TokenSet Get(const void *owner, const std::string &key, int64_t margin_seconds = 300);
	void Set(const void *owner, const std::string &key, TokenSet set);
	void Invalidate(const void *owner, const std::string &key);
	void Clear();

private:
	std::mutex mutex;
	std::map<std::pair<const void *, std::string>, TokenSet> cache;
};

} // namespace oidc
} // namespace DUCKDB_EXT_COMMON_OIDC_NAMESPACE
} // namespace duckdb
