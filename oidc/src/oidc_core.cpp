//===----------------------------------------------------------------------===//
// oidc_core.cpp - the OIDC client core (duckdb-ext-common spec 002). See oidc_core.hpp.
//
// The one TU that compiles duckdb's bundled httplib for this module. With
// DUCKDB_EXT_COMMON_OIDC_TLS (a consumer's build that carries OpenSSL) it is compiled with
// CPPHTTPLIB_OPENSSL_SUPPORT - the header then lives in the duckdb_httplib_openssl namespace, so
// there is no ODR overlap with a plain compilation elsewhere in the image (the single-TU
// discipline mssql-extension uses). The namespace is the consumer's (oidc_core.hpp).
//===----------------------------------------------------------------------===//

#ifdef DUCKDB_EXT_COMMON_OIDC_TLS
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include "httplib.hpp"

#include "oidc_core.hpp"
#include "yyjson.hpp"

#include <condition_variable>
#include <random>
#include <thread>

#ifdef DUCKDB_EXT_COMMON_OIDC_TLS
namespace hl = duckdb_httplib_openssl;
#else
namespace hl = duckdb_httplib;
#endif

namespace duckdb {
namespace DUCKDB_EXT_COMMON_OIDC_NAMESPACE {
namespace oidc {

namespace {

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

struct UrlParts {
	bool https = false;
	std::string host;
	int port = 0;
	std::string path;
	std::string error;
};

//! scheme://host[:port]/path — anything else is an error, never a guess.
UrlParts ParseUrl(const std::string &url) {
	UrlParts out;
	std::string rest;
	if (url.rfind("https://", 0) == 0) {
		out.https = true;
		rest = url.substr(8);
	} else if (url.rfind("http://", 0) == 0) {
		rest = url.substr(7);
	} else {
		out.error = "unsupported URL (http:// or https:// expected): " + url;
		return out;
	}
	auto slash = rest.find('/');
	auto authority = slash == std::string::npos ? rest : rest.substr(0, slash);
	out.path = slash == std::string::npos ? "/" : rest.substr(slash);
	auto default_port = out.https ? 443 : 80;
	std::string port_text;
	if (!authority.empty() && authority.front() == '[') { // [v6]:port - the colon comes after ']'
		auto bracket = authority.find(']');
		if (bracket == std::string::npos) {
			out.error = "malformed URL authority: " + url;
			return out;
		}
		out.host = authority.substr(1, bracket - 1);
		if (bracket + 1 < authority.size()) {
			if (authority[bracket + 1] != ':') {
				out.error = "malformed URL authority: " + url;
				return out;
			}
			port_text = authority.substr(bracket + 2);
		}
	} else {
		auto colon = authority.rfind(':');
		if (colon != std::string::npos) {
			out.host = authority.substr(0, colon);
			port_text = authority.substr(colon + 1);
		} else {
			out.host = authority;
		}
	}
	if (port_text.empty()) {
		out.port = default_port;
	} else {
		// digits only, and a port-sized value - "80xyz" must refuse, not silently become 80
		for (char c : port_text) {
			if (!isdigit(static_cast<unsigned char>(c))) {
				out.error = "malformed port in URL: " + url;
				return out;
			}
		}
		auto value = port_text.size() <= 5 ? std::atoi(port_text.c_str()) : 0;
		if (value <= 0 || value > 65535) {
			out.error = "malformed port in URL: " + url;
			return out;
		}
		out.port = value;
	}
	if (out.host.empty()) {
		out.error = "malformed URL authority: " + url;
	}
	return out;
}

std::string UrlEncode(const std::string &value) {
	static const char *hex = "0123456789ABCDEF";
	std::string out;
	out.reserve(value.size());
	for (unsigned char c : value) {
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			out.push_back(char(c));
		} else {
			out.push_back('%');
			out.push_back(hex[c >> 4]);
			out.push_back(hex[c & 15]);
		}
	}
	return out;
}

std::string FormEncode(const std::map<std::string, std::string> &params) {
	std::string body;
	for (auto &entry : params) {
		if (!body.empty()) {
			body.push_back('&');
		}
		body += UrlEncode(entry.first) + "=" + UrlEncode(entry.second);
	}
	return body;
}

template <class REQUEST>
HttpResult Run(const UrlParts &url, int timeout_seconds, REQUEST &&request) {
	HttpResult out;
	if (!url.error.empty()) {
		out.error = url.error;
		return out;
	}
	if (url.https) {
#ifdef DUCKDB_EXT_COMMON_OIDC_TLS
		hl::SSLClient client(url.host, url.port);
		client.set_connection_timeout(timeout_seconds);
		client.set_read_timeout(timeout_seconds);
		client.enable_server_certificate_verification(true);
		auto res = request(client);
		if (!res) {
			out.error = "https request failed: " + hl::to_string(res.error());
			return out;
		}
		out.status = res->status;
		out.body = res->body;
		return out;
#else
		out.error = "https needs a TLS-enabled build (DUCKDB_EXT_COMMON_OIDC_TLS) - this build can reach "
		            "http:// issuers only";
		return out;
#endif
	}
	hl::Client client(url.host, url.port);
	client.set_connection_timeout(timeout_seconds);
	client.set_read_timeout(timeout_seconds);
	auto res = request(client);
	if (!res) {
		out.error = "http request failed: " + hl::to_string(res.error());
		return out;
	}
	out.status = res->status;
	out.body = res->body;
	return out;
}

//! yyjson helpers over one response body
struct Json {
	duckdb_yyjson::yyjson_doc *doc = nullptr;

	explicit Json(const std::string &body) {
		doc = duckdb_yyjson::yyjson_read(body.data(), body.size(), 0);
	}
	~Json() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}
	std::string Str(const char *key) const {
		if (!doc) {
			return "";
		}
		auto value = duckdb_yyjson::yyjson_obj_get(duckdb_yyjson::yyjson_doc_get_root(doc), key);
		if (!value || !duckdb_yyjson::yyjson_is_str(value)) {
			return "";
		}
		return duckdb_yyjson::yyjson_get_str(value);
	}
	int64_t Int(const char *key) const {
		if (!doc) {
			return 0;
		}
		auto value = duckdb_yyjson::yyjson_obj_get(duckdb_yyjson::yyjson_doc_get_root(doc), key);
		if (!value || !duckdb_yyjson::yyjson_is_num(value)) {
			return 0;
		}
		return duckdb_yyjson::yyjson_get_sint(value);
	}
};

//! SHA-256 (FIPS 180-4), for the PKCE challenge only: the module builds without a crypto library.
std::string Sha256(const std::string &message) {
	static const uint32_t k[64] = {
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	auto rotr = [](uint32_t x, int n) {
		return (x >> n) | (x << (32 - n));
	};
	std::string data = message;
	uint64_t bit_length = uint64_t(message.size()) * 8;
	data.push_back(char(0x80));
	while (data.size() % 64 != 56) {
		data.push_back(char(0));
	}
	for (int i = 7; i >= 0; i--) {
		data.push_back(char((bit_length >> (i * 8)) & 0xff));
	}
	for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
		uint32_t w[64];
		for (int i = 0; i < 16; i++) {
			auto p = reinterpret_cast<const unsigned char *>(data.data() + chunk + i * 4);
			w[i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
		}
		for (int i = 16; i < 64; i++) {
			auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
			auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
		for (int i = 0; i < 64; i++) {
			auto t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
			auto t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
			hh = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
		h[5] += f;
		h[6] += g;
		h[7] += hh;
	}
	std::string digest;
	for (auto word : h) {
		for (int i = 3; i >= 0; i--) {
			digest.push_back(char((word >> (i * 8)) & 0xff));
		}
	}
	return digest;
}

//! RFC 4648 §5, without padding (RFC 7636 appendix A).
std::string Base64Url(const std::string &bytes) {
	static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::string out;
	size_t i = 0;
	for (; i + 2 < bytes.size(); i += 3) {
		uint32_t v =
		    (uint32_t(uint8_t(bytes[i])) << 16) | (uint32_t(uint8_t(bytes[i + 1])) << 8) | uint8_t(bytes[i + 2]);
		out.push_back(alphabet[(v >> 18) & 63]);
		out.push_back(alphabet[(v >> 12) & 63]);
		out.push_back(alphabet[(v >> 6) & 63]);
		out.push_back(alphabet[v & 63]);
	}
	if (i + 1 == bytes.size()) {
		uint32_t v = uint32_t(uint8_t(bytes[i])) << 16;
		out.push_back(alphabet[(v >> 18) & 63]);
		out.push_back(alphabet[(v >> 12) & 63]);
	} else if (i + 2 == bytes.size()) {
		uint32_t v = (uint32_t(uint8_t(bytes[i])) << 16) | (uint32_t(uint8_t(bytes[i + 1])) << 8);
		out.push_back(alphabet[(v >> 18) & 63]);
		out.push_back(alphabet[(v >> 12) & 63]);
		out.push_back(alphabet[(v >> 6) & 63]);
	}
	return out;
}

//! What the IdP's redirect says goes into an error message a consumer may print to a terminal:
//! control characters out, and bounded.
std::string Printable(const std::string &text) {
	std::string out;
	for (unsigned char c : text.substr(0, 512)) {
		out.push_back(c < 0x20 || c == 0x7f ? '?' : char(c));
	}
	return out;
}

//! The page the browser lands on: fixed text, nothing from the request reflected into it.
std::string CallbackPage(bool ok) {
	return std::string("<!doctype html><html><head><meta charset=\"utf-8\"><title>Login</title></head><body>"
	                   "<p>") +
	       (ok ? "Login complete." : "Login failed.") + " You can close this window.</p></body></html>";
}

TokenSet PostGrant(const Endpoints &ep, const std::map<std::string, std::string> &params) {
	if (!ep.Ok()) {
		TokenSet out;
		out.error = ep.error.empty() ? "no token endpoint" : ep.error;
		return out;
	}
	return ParseTokenResponse(HttpPostForm(ep.token_endpoint, params));
}

} // namespace

//! Every token endpoint answer goes through here: 2xx with an access_token is a
//! grant; anything else is the protocol's error/error_description, or the raw
//! transport failure. Nothing is inferred.
TokenSet ParseTokenResponse(const HttpResult &response) {
	TokenSet out;
	if (!response.error.empty()) {
		out.error = response.error;
		return out;
	}
	Json json(response.body);
	if (response.Ok()) {
		out.access_token = json.Str("access_token");
		out.refresh_token = json.Str("refresh_token");
		out.issued_token_type = json.Str("issued_token_type");
		auto expires_in = json.Int("expires_in");
		static constexpr int64_t A_YEAR = int64_t(366) * 86400;
		if (expires_in > A_YEAR) { // a year: past that the value is nonsense, and unclamped it
			expires_in = A_YEAR;   // could overflow the epoch arithmetic (the review's finding)
		}
		out.expires_at = expires_in > 0 ? NowSeconds() + expires_in : 0;
		if (out.access_token.empty()) {
			out.error = "the token endpoint answered 2xx without an access_token";
		}
		return out;
	}
	out.error_code = Printable(json.Str("error").substr(0, 64));
	auto description = Printable(json.Str("error_description"));
	out.error = out.error_code.empty() ? ("HTTP " + std::to_string(response.status) + " from the token endpoint")
	                                   : (out.error_code + (description.empty() ? "" : (": " + description)));
	return out;
}

HttpResult HttpGet(const std::string &url, int timeout_seconds) {
	auto parts = ParseUrl(url);
	return Run(parts, timeout_seconds, [&](auto &client) { return client.Get(parts.path.c_str()); });
}

HttpResult HttpPostForm(const std::string &url, const std::map<std::string, std::string> &params, int timeout_seconds) {
	auto parts = ParseUrl(url);
	auto body = FormEncode(params);
	return Run(parts, timeout_seconds, [&](auto &client) {
		return client.Post(parts.path.c_str(), body, "application/x-www-form-urlencoded");
	});
}

HttpResult HttpSend(const std::string &method, const std::string &url,
                    const std::map<std::string, std::string> &headers, const std::string &body,
                    const std::string &content_type, int timeout_seconds) {
	auto parts = ParseUrl(url);
	hl::Headers request_headers;
	for (auto &header : headers) {
		request_headers.emplace(header.first, header.second);
	}
	return Run(parts, timeout_seconds, [&](auto &client) {
		hl::Request request;
		request.method = method;
		request.path = parts.path;
		request.headers = request_headers;
		if (!body.empty() || !content_type.empty()) {
			request.body = body;
			request.set_header("Content-Type", content_type.empty() ? "application/octet-stream" : content_type);
		}
		return client.send(request);
	});
}

Endpoints Discover(const std::string &issuer_url, int timeout_seconds) {
	Endpoints out;
	auto issuer = issuer_url;
	while (!issuer.empty() && issuer.back() == '/') {
		issuer.pop_back();
	}
	out.issuer = issuer;
	return ParseDiscoveryDocument(issuer, HttpGet(issuer + "/.well-known/openid-configuration", timeout_seconds));
}

Endpoints ParseDiscoveryDocument(const std::string &issuer, const HttpResult &response) {
	Endpoints out;
	out.issuer = issuer;
	if (!response.Ok()) {
		out.error =
		    response.error.empty() ? ("discovery answered HTTP " + std::to_string(response.status)) : response.error;
		return out;
	}
	Json json(response.body);
	auto advertised = json.Str("issuer");
	// normalised exactly like the asked-for issuer: some IdPs canonically end in '/' (Azure AD v1)
	while (!advertised.empty() && advertised.back() == '/') {
		advertised.pop_back();
	}
	// RFC 8414: the document must speak for the issuer it was asked about — adopting a different one
	// would let a compromised document redirect every flow
	if (advertised != issuer) {
		out.error = "discovery issuer mismatch: asked \"" + issuer + "\", document says \"" + advertised + "\"";
		return out;
	}
	out.token_endpoint = json.Str("token_endpoint");
	out.device_authorization_endpoint = json.Str("device_authorization_endpoint");
	out.authorization_endpoint = json.Str("authorization_endpoint");
	if (out.token_endpoint.empty()) {
		out.error = "discovery document carries no token_endpoint";
		return out;
	}
	// an https issuer whose document names a cleartext endpoint is a downgrade: the credentials the
	// flows POST must not travel weaker than the discovery did (the review's finding)
	if (issuer.rfind("https://", 0) == 0) {
		for (const auto *endpoint :
		     {&out.token_endpoint, &out.device_authorization_endpoint, &out.authorization_endpoint}) {
			if (!endpoint->empty() && endpoint->rfind("https://", 0) != 0) {
				out.error = "discovery names a cleartext endpoint for an https issuer - refused: " + *endpoint;
				return out;
			}
		}
	}
	return out;
}

TokenSet ClientCredentials(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                           const std::string &scope) {
	std::map<std::string, std::string> params {
	    {"grant_type", "client_credentials"}, {"client_id", client_id}, {"client_secret", client_secret}};
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	return PostGrant(ep, params);
}

TokenSet PasswordGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &username, const std::string &password, const std::string &scope) {
	std::map<std::string, std::string> params {
	    {"grant_type", "password"}, {"client_id", client_id}, {"username", username}, {"password", password}};
	if (!client_secret.empty()) {
		params["client_secret"] = client_secret;
	}
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	return PostGrant(ep, params);
}

namespace {
constexpr const char *ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

TokenSet Refused(const std::string &code, const std::string &message) {
	TokenSet refused;
	refused.error_code = code;
	refused.error = message;
	return refused;
}

//! The end of every exchange (spec 004):
//! - an answer that is not an access token (a refresh or ID token in its place) is refused, not used as one;
//! - a refresh token is dropped: an exchanged token belongs to one session, and must not outlive it;
//! - the presented token never reaches an error, even when the IdP quotes it back.
TokenSet FinishExchange(TokenSet out, const std::string &presented) {
	if (out.Ok() && !out.issued_token_type.empty() && out.issued_token_type != ACCESS_TOKEN_TYPE) {
		return Refused("invalid_token_type", "the exchange answered with something other than an access token");
	}
	out.refresh_token.clear();
	if (!out.Ok()) {
		out.access_token.clear();
		out.issued_token_type.clear();
		for (auto at = out.error.find(presented); !presented.empty() && at != std::string::npos;
		     at = out.error.find(presented, at)) {
			out.error.replace(at, presented.size(), "<redacted>");
		}
	}
	return out;
}
} // namespace

TokenSet TokenExchange(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &subject_token, const std::string &audience, const std::string &scope,
                       const std::string &resource) {
	if (subject_token.empty()) {
		return Refused("invalid_request", "token exchange: no subject token");
	}
	if (audience.empty() && scope.empty() && resource.empty()) {
		// the IdP would answer with a token for every audience the client may reach
		return Refused("invalid_request", "token exchange: no audience, resource or scope to exchange for");
	}
	std::map<std::string, std::string> params {{"grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"},
	                                           {"client_id", client_id},
	                                           {"subject_token", subject_token},
	                                           {"subject_token_type", ACCESS_TOKEN_TYPE},
	                                           {"requested_token_type", ACCESS_TOKEN_TYPE}};
	if (!client_secret.empty()) {
		params["client_secret"] = client_secret;
	}
	if (!audience.empty()) {
		params["audience"] = audience;
	}
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	if (!resource.empty()) {
		params["resource"] = resource;
	}
	return FinishExchange(PostGrant(ep, params), subject_token);
}

TokenSet OnBehalfOf(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                    const std::string &assertion, const std::string &scope) {
	if (assertion.empty() || scope.empty()) {
		return Refused("invalid_request", "on-behalf-of: an assertion and a scope are required");
	}
	std::map<std::string, std::string> params {{"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
	                                           {"client_id", client_id},
	                                           {"assertion", assertion},
	                                           {"requested_token_use", "on_behalf_of"},
	                                           {"scope", scope}};
	if (!client_secret.empty()) {
		params["client_secret"] = client_secret;
	}
	return FinishExchange(PostGrant(ep, params), assertion);
}

TokenSet RefreshGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                      const std::string &refresh_token) {
	std::map<std::string, std::string> params {
	    {"grant_type", "refresh_token"}, {"client_id", client_id}, {"refresh_token", refresh_token}};
	if (!client_secret.empty()) {
		params["client_secret"] = client_secret;
	}
	return PostGrant(ep, params);
}

DeviceAuthorization DeviceBegin(const Endpoints &ep, const std::string &client_id, const std::string &scope) {
	DeviceAuthorization out;
	if (!ep.Ok()) {
		out.error = ep.error.empty() ? "no endpoints" : ep.error;
		return out;
	}
	if (ep.device_authorization_endpoint.empty()) {
		out.error = "the issuer advertises no device_authorization_endpoint (RFC 8628 not offered)";
		return out;
	}
	std::map<std::string, std::string> params {{"client_id", client_id}};
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	return ParseDeviceAuthorization(HttpPostForm(ep.device_authorization_endpoint, params));
}

DeviceAuthorization ParseDeviceAuthorization(const HttpResult &response) {
	DeviceAuthorization out;
	if (!response.Ok()) {
		Json json(response.body);
		auto code = json.Str("error");
		out.error = !response.error.empty() ? response.error
		            : code.empty()          ? ("HTTP " + std::to_string(response.status))
		                           : (Printable(code.substr(0, 64)) + ": " + Printable(json.Str("error_description")));
		return out;
	}
	Json json(response.body);
	out.device_code = json.Str("device_code");
	out.user_code = json.Str("user_code");
	out.verification_uri = json.Str("verification_uri");
	out.verification_uri_complete = json.Str("verification_uri_complete");
	auto interval = json.Int("interval");
	if (interval > 0) {
		out.interval = interval > 900 ? 900 : interval; // a malicious interval must not become a sleep
	}
	auto expires_in = json.Int("expires_in");
	if (expires_in > 0) {
		out.expires_in = expires_in > 86400 ? 86400 : expires_in;
	}
	if (out.device_code.empty()) {
		out.error = "device authorization answered without a device_code";
	}
	return out;
}

TokenSet DevicePoll(const Endpoints &ep, const std::string &client_id, const std::string &device_code,
                    int64_t interval_seconds, int64_t deadline_epoch_seconds, const std::function<bool()> &cancelled) {
	auto interval = interval_seconds < 0 ? 0 : interval_seconds;
	auto is_cancelled = [&] {
		return cancelled && cancelled();
	};
	while (true) {
		if (is_cancelled()) {
			TokenSet out;
			out.error = "device flow cancelled";
			out.error_code = "cancelled";
			return out;
		}
		auto result = PostGrant(ep, {{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
		                             {"client_id", client_id},
		                             {"device_code", device_code}});
		if (result.Ok()) {
			return result;
		}
		if (result.error_code == "slow_down") {
			interval = interval + 5 > 3600 ? 3600 : interval + 5; // RFC 8628 §3.5, bounded
		} else if (result.error_code != "authorization_pending") {
			return result; // denied, expired, transport - the caller's to report
		}
		// subtraction, not addition: a hostile interval must not overflow the guard into an
		// unbounded sleep (the review's finding) - the promise is that the poll never outlives
		// the deadline, whatever the server answers
		if (interval >= deadline_epoch_seconds - NowSeconds()) {
			result.error = "device flow timed out before the user approved";
			result.error_code = "expired_token";
			return result;
		}
		for (int64_t slept = 0; slept < interval; slept++) {
			if (is_cancelled()) {
				TokenSet out;
				out.error = "device flow cancelled";
				out.error_code = "cancelled";
				return out;
			}
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
}

std::string PkceChallenge(const std::string &verifier) {
	return Base64Url(Sha256(verifier));
}

std::string RandomUrlSafe(size_t bytes) {
	// the OS CSPRNG on every platform the consumers ship (spec 003); it throws when the OS has no
	// entropy source to give, and a login without randomness must fail rather than go on predictable
	std::random_device device;
	std::string raw;
	raw.reserve(bytes);
	while (raw.size() < bytes) {
		auto value = device();
		for (size_t i = 0; i < sizeof(value) && raw.size() < bytes; i++) {
			raw.push_back(char((value >> (i * 8)) & 0xff));
		}
	}
	return Base64Url(raw);
}

AuthorizationRequest BuildAuthorizationRequest(const Endpoints &ep, const std::string &client_id,
                                               const std::string &redirect_uri, const std::string &scope) {
	AuthorizationRequest out;
	if (!ep.Ok()) {
		out.error = ep.error.empty() ? "no endpoints" : ep.error;
		return out;
	}
	if (ep.authorization_endpoint.empty()) {
		out.error = "the issuer advertises no authorization_endpoint (no browser login offered)";
		return out;
	}
	out.state = RandomUrlSafe(32);
	out.verifier = RandomUrlSafe(32);
	out.redirect_uri = redirect_uri;
	std::map<std::string, std::string> params {{"response_type", "code"},
	                                           {"client_id", client_id},
	                                           {"redirect_uri", redirect_uri},
	                                           {"state", out.state},
	                                           {"code_challenge", PkceChallenge(out.verifier)},
	                                           {"code_challenge_method", "S256"}};
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	auto separator = ep.authorization_endpoint.find('?') == std::string::npos ? "?" : "&";
	out.url = ep.authorization_endpoint + separator + FormEncode(params);
	return out;
}

TokenSet ExchangeAuthorizationCode(const Endpoints &ep, const std::string &client_id, const std::string &code,
                                   const std::string &verifier, const std::string &redirect_uri) {
	return PostGrant(ep, {{"grant_type", "authorization_code"},
	                      {"client_id", client_id},
	                      {"code", code},
	                      {"code_verifier", verifier},
	                      {"redirect_uri", redirect_uri}});
}

struct LoopbackRedirect::Impl {
	hl::Server server;
	std::thread thread;
	int port = 0;
	bool started = false;
	std::mutex mutex;
	std::condition_variable arrived;
	std::string expected_state;
	bool done = false;
	Result result;

	void Stop() {
		server.stop();
		if (thread.joinable()) {
			thread.join();
		}
	}
};

LoopbackRedirect::LoopbackRedirect() : impl(new Impl()) {
}

LoopbackRedirect::~LoopbackRedirect() {
	impl->Stop();
}

bool LoopbackRedirect::Start(std::string &error) {
	auto &state = *impl;
	if (state.started) {
		error = "the login redirect receiver was already started";
		return false;
	}
	state.started = true;
	state.server.Get("/callback", [&state](const hl::Request &req, hl::Response &res) {
		res.set_header("Cache-Control", "no-store");
		res.set_header("Connection", "close");
		std::lock_guard<std::mutex> guard(state.mutex);
		// only the request carrying the state this login sent completes it; anything else - a stray
		// tab, a forged request from another local process - is refused and the wait goes on
		if (state.done || state.expected_state.empty() || req.get_param_value("state") != state.expected_state) {
			res.status = 400;
			res.set_content(CallbackPage(false), "text/html; charset=utf-8");
			return;
		}
		auto code = req.get_param_value("code");
		auto idp_error = req.get_param_value("error");
		if (!idp_error.empty() || code.empty()) {
			state.result.error_code = idp_error.empty() ? "invalid_request" : Printable(idp_error);
			auto description = Printable(req.get_param_value("error_description"));
			state.result.error = idp_error.empty()
			                         ? "the redirect carried neither a code nor an error"
			                         : (state.result.error_code + (description.empty() ? "" : ": " + description));
		} else {
			state.result.code = code;
		}
		state.done = true;
		res.set_content(CallbackPage(state.result.Ok()), "text/html; charset=utf-8");
		state.arrived.notify_all();
	});
	// the port is this receiver's alone: httplib's default options set SO_REUSEPORT (SO_REUSEADDR on
	// Windows), which would let another local socket bind the same port and take the callback (the
	// review's finding). No sharing option at all; on Windows an exclusive bind besides.
	state.server.set_socket_options([](socket_t sock) {
#ifdef _WIN32
		BOOL exclusive = TRUE;
		setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&exclusive),
		           sizeof(exclusive));
#else
		(void)sock;
#endif
	});
	// a local process holding connections open must not hold the login (or its shutdown) for long
	state.server.set_read_timeout(2, 0);
	state.server.set_write_timeout(2, 0);
	state.server.set_keep_alive_max_count(1);
	// 127.0.0.1 exactly (RFC 8252 §7.3): never every interface, never a name that may resolve off-box
	state.port = state.server.bind_to_any_port("127.0.0.1");
	if (state.port <= 0) {
		error = "could not bind a loopback port for the login redirect";
		return false;
	}
	state.thread = std::thread([&state] { state.server.listen_after_bind(); });
	state.server.wait_until_ready();
	return true;
}

std::string LoopbackRedirect::RedirectUri() const {
	return "http://127.0.0.1:" + std::to_string(impl->port) + "/callback";
}

void LoopbackRedirect::Expect(const std::string &state) {
	std::lock_guard<std::mutex> guard(impl->mutex);
	impl->expected_state = state;
}

LoopbackRedirect::Result LoopbackRedirect::Wait(int64_t deadline_epoch_seconds,
                                                const std::function<bool()> &cancelled) {
	Result out;
	if (!impl->started || impl->port <= 0) {
		out.error = "the login redirect receiver is not running";
		out.error_code = "invalid_request";
		return out;
	}
	while (true) {
		{
			std::unique_lock<std::mutex> lock(impl->mutex);
			if (impl->done) {
				out = impl->result;
				if (!out.Ok() && out.error.empty()) {
					out.error = "the login redirect receiver was already used";
					out.error_code = "invalid_request";
				}
				break;
			}
			if (NowSeconds() >= deadline_epoch_seconds) {
				out.error = "the login timed out before the browser returned";
				out.error_code = "expired_token";
				impl->done = true;  // late callbacks are refused from here on
				impl->result = out; // and a second Wait reports this end
				break;
			}
			impl->arrived.wait_for(lock, std::chrono::milliseconds(200));
			if (impl->done) {
				continue;
			}
		}
		// the caller's check runs outside the lock the callback handler takes
		if (cancelled && cancelled()) {
			std::lock_guard<std::mutex> guard(impl->mutex);
			if (!impl->done) {
				out.error = "login cancelled";
				out.error_code = "cancelled";
				impl->done = true;
				impl->result = out;
				break;
			}
		}
	}
	impl->Stop();
	return out;
}

TokenSet AuthorizationCodeLogin(const Endpoints &ep, const std::string &client_id, const std::string &scope,
                                const std::function<void(const std::string &url)> &present,
                                int64_t deadline_epoch_seconds, const std::function<bool()> &cancelled) {
	TokenSet out;
	// the endpoints first: no port is bound for an issuer that has no browser flow
	auto checked = BuildAuthorizationRequest(ep, client_id, "http://127.0.0.1/callback", scope);
	if (!checked.Ok()) {
		out.error = checked.error;
		return out;
	}
	LoopbackRedirect receiver;
	std::string error;
	if (!receiver.Start(error)) {
		out.error = error;
		return out;
	}
	auto request = BuildAuthorizationRequest(ep, client_id, receiver.RedirectUri(), scope);
	if (!request.Ok()) {
		out.error = request.error;
		return out;
	}
	receiver.Expect(request.state); // before the browser: the IdP may redirect back at once (SSO)
	if (present) {
		present(request.url);
	}
	auto redirect = receiver.Wait(deadline_epoch_seconds, cancelled);
	if (!redirect.Ok()) {
		out.error = redirect.error;
		out.error_code = redirect.error_code;
		return out;
	}
	return ExchangeAuthorizationCode(ep, client_id, redirect.code, request.verifier, request.redirect_uri);
}

TokenCache &TokenCache::Instance() {
	static TokenCache instance;
	return instance;
}

TokenSet TokenCache::Get(const void *owner, const std::string &key, int64_t margin_seconds) {
	std::lock_guard<std::mutex> guard(mutex);
	auto entry = cache.find({owner, key});
	if (entry == cache.end()) {
		return TokenSet();
	}
	// 0 = the response carried no expiry: cached until invalidated, the caller opted into that
	if (entry->second.expires_at != 0 && entry->second.expires_at - margin_seconds <= NowSeconds()) {
		cache.erase(entry); // stale rows must not pile up for the process lifetime
		return TokenSet();
	}
	return entry->second;
}

void TokenCache::Set(const void *owner, const std::string &key, TokenSet set) {
	std::lock_guard<std::mutex> guard(mutex);
	cache[{owner, key}] = std::move(set);
}

void TokenCache::Invalidate(const void *owner, const std::string &key) {
	std::lock_guard<std::mutex> guard(mutex);
	cache.erase({owner, key});
}

void TokenCache::Clear() {
	std::lock_guard<std::mutex> guard(mutex);
	cache.clear();
}

} // namespace oidc
} // namespace DUCKDB_EXT_COMMON_OIDC_NAMESPACE
} // namespace duckdb
