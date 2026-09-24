//===----------------------------------------------------------------------===//
// tresor_audit.hpp — tresor's audit and observability contract (spec 008 here; tresor spec 011)
//
// What tresor - the DuckDB client of a secrets service - did, as events a consumer (acl-otel) turns into
// OpenTelemetry: logins, secret lookups, refreshes, the management calls, and on a duckdb-acl node the life
// of each session's delegation grant. Built on hooks/ext_hooks.hpp:
//
//   string why;
//   auto hooks = TresorAuditHooks::Reach(db.GetObjectCache(), why);   // either side, any load order
//   if (hooks) { hooks->AddSink(my_sink); }                            // a consumer
//
// tresor composes an event only while a sink is registered (or its own log is on), and delivers it on its
// own thread (R8). An event never carries secret material, credentials, tokens, session handles or
// delegation grant ids, nor statement text (R7): a secret's NAME, type and service, the outcome and a
// bounded reason code, and on an acl node the session's ops id and the statement's trace context - so a
// consumer puts tresor's work in the trace of the statement that caused it.
//
// Owned by tresor (R6). Bump VERSION on any change to what this header lays out, the base included (R4).
//===----------------------------------------------------------------------===//

#pragma once

#include "ext_hooks.hpp"

namespace duckdb {
namespace tresor {

//! One occurrence. `kind` says which; the fields a kind does not use stay empty / -1.
//!
//! kinds (bounded): login, logout, lookup, refresh, write, drop, annotate, grant, revoke,
//!                  session_grant (a delegation grant for an acl session: detail = obtained / failed /
//!                  revoked / rejected / expired)
//! outcome (bounded): ok, none (a lookup found nothing here), denied, error
//! reason_code (bounded, on denied/error): no_verb, not_found, actor_not_allowed, mint_refused,
//!                  unauthenticated, service_unavailable, transport, invalid, no_grant, other
struct TresorAuditEvent {
	int64_t ts_us = 0; // when it ended (unix microseconds)
	int64_t seq = 0;   // per instance, increasing
	string kind;
	string outcome;
	string reason_code;
	string reason; // tresor's own text: never a value, a token or a grant id

	string service; // the attached catalog (`corp`)
	string host;    // the service it names (`secrets.corp:443/base`)
	string login;   // the login's flow: browser / device / client_credentials / token

	//! Who the service call was for: the attachment's own login (`subject:<issuer>|<sub>`), and on a
	//! duckdb-acl node under a session, the session's user (acl's principal subject) - never a handle.
	string principal;
	string user;
	string acl_session;    // acl's session ops id; empty off a session
	string correlation_id; // the statement's, as acl publishes it
	string traceparent;    // the statement's W3C trace context, as acl publishes it

	string secret;            // the secret's name (never its material)
	string secret_type;       // s3, http, quack, ...
	bool cached = false;      // lookup / refresh: served from tresor's cache, no service call
	bool dynamic = false;     // the secret is minted per request (a token for the caller included)
	string target;            // grant / revoke: the role: or group: principal
	int64_t duration_us = -1; // the service calls this took; -1 when none was made
	string detail;            // session_grant: obtained / failed / revoked / rejected / expired
};

//! The registry: sinks, counters (bounded attributes only: kind, outcome) and gauges.
class TresorAuditHooks : public ext_common::Registry<TresorAuditEvent, 0x54525341 /* "TRSA" */, 1> {
public:
	static string ObjectType() {
		return "tresor_audit_hooks";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	static shared_ptr<TresorAuditHooks> Reach(ObjectCache &cache, string &why) {
		return ReachAs<TresorAuditHooks>(cache, ObjectType(), why);
	}
};

using TresorAuditSink = ext_common::Sink<TresorAuditEvent>;

} // namespace tresor
} // namespace duckdb
