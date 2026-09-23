//===----------------------------------------------------------------------===//
// acl_connection.hpp — whose session a statement runs under, and when sessions open and close
//
// duckdb-acl turns a verified token into a session (its spec 040) and runs a session's statements
// on a connection under `ACL SESSION '<handle>'` - a door's own connection (its spec 050) or a
// gateway's shared one. An extension that acts on behalf of the session's user - tresor, resolving a
// secret through a delegation grant instead of the node's own identity - needs two things from acl:
//
//   1. AclConnection: on the connection, while a statement runs under a session, the session's
//      identity (never its handle). Reached per connection:
//
//        string why;
//        auto state = AclConnection::Reach(context, why);   // context.registered_state, by key
//        AclSessionView view;
//        if (state && state->Current(view)) { ... the session's statement ... }
//        else { ... the node's own work: no session, or between statements ... }
//
//      acl publishes it at the statement's QueryBegin and takes it away at its QueryEnd, the failed
//      and the interrupted statement included - on a gateway's shared connection the next statement
//      may be another principal's. Nothing is published between statements.
//
//   2. AclSessionHooks: per DatabaseInstance, in the ObjectCache (like acl_audit.hpp's AuditHooks),
//      the observers acl calls when a session opens and when it ends:
//
//        auto hooks = AclSessionHooks::Reach(db.GetObjectCache(), why);
//        if (hooks) { hooks->AddObserver(my_observer); }
//
//      OnSessionOpen is called on the opening thread, after verification and before the session is
//      usable, with the verified token by reference - valid ONLY for the call. acl never stores the
//      token nor hands it anywhere else. OnSessionClose follows exactly once for every session
//      OnSessionOpen was called for, whatever ended it.
//
// Everything is header-only, reached by name, and stamped (charter R1-R3): both objects carry
// AclConnectionContract::MAGIC ("ACLC") and ::VERSION as their first members, and only Reach() hands
// one out. Bump the version on any change to what this header lays out - AclSessionView, Principal
// (acl_principal.hpp: shared with acl_audit.hpp, so a field there bumps both), SessionOpenInfo, the
// observer interface, the two objects. Owned by duckdb-acl (R6).
//
// This is not an audit contract: R7 does not govern it, a stricter rule does - the token crosses
// only as a reference during OnSessionOpen, and the session's handle never crosses at all. Nor is it
// queued (R8): the open is synchronous by nature (the token must not outlive the call), so an
// observer must return promptly - copy what it needs and do the slow part on its own thread. acl
// cannot pre-empt an observer (a token reference must not outlive the call); it measures the calls,
// counts the slow and the failing ones, and never lets one fail an open.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_principal.hpp"

#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/storage/object_cache.hpp"

#include <cstdint>
#include <mutex>

namespace duckdb {
namespace acl {

//! The magic and version both objects of this contract are stamped with (R3).
struct AclConnectionContract {
	static constexpr int32_t MAGIC = 0x41434C43; // "ACLC"
	static constexpr int32_t VERSION = 1;        // 1: duckdb-ext-common spec 005, duckdb-acl spec 078
};

//! A session as a statement runs under it. Never its handle: the handle is a bearer credential.
struct AclSessionView {
	//! The session's ops id (acl spec 050) - what `acl_sessions()` lists; fresh per session, never
	//! reused, not a secret.
	string session_id;
	//! Who: subject, the issuer that vouched for it, roles, claims (acl_principal.hpp).
	Principal principal;
	//! The door it came through: "quack", "flight", or "session" for acl_session_open().
	string door;
	//! When it opened, and its token's `exp` (0 = none), in unix seconds.
	int64_t opened_at = 0;
	int64_t expires_at = 0;
	//! The statement's trace markers (acl spec 069), as the audit events carry them; may be empty.
	string correlation_id;
	string traceparent;
};

//! Per connection (`context.registered_state`, key StateKey()): the session the connection's
//! current statement runs under, or nothing. acl writes it; everyone else reads it.
class AclConnection : public ClientContextState {
public:
	int32_t contract_magic = AclConnectionContract::MAGIC;
	int32_t contract_version = AclConnectionContract::VERSION;

	static string StateKey() {
		return "acl_connection";
	}

	//! The state of a connection, created when absent (either side, any load order) and checked:
	//! null with `why` when the object under the key is stamped with another magic or version - an
	//! extension built from another revision of this header - and must not be used.
	static shared_ptr<AclConnection> Reach(ClientContext &context, string &why) {
		auto state = context.registered_state->GetOrCreate<AclConnection>(StateKey());
		if (!state) {
			why = "no connection state under '" + StateKey() + "'";
			return nullptr;
		}
		if (state->contract_magic != AclConnectionContract::MAGIC ||
		    state->contract_version != AclConnectionContract::VERSION) {
			why = "the connection state under '" + StateKey() + "' is stamped with another acl_connection contract (" +
			      std::to_string(state->contract_version) + "); this build speaks " +
			      std::to_string(AclConnectionContract::VERSION);
			return nullptr;
		}
		why.clear();
		return state;
	}

	//! The session of the statement running now: true and `out` filled, or false - no session, or
	//! nothing running under one.
	bool Current(AclSessionView &out) const {
		std::lock_guard<std::mutex> guard(lock);
		if (!active) {
			return false;
		}
		out = view;
		return true;
	}

	//! acl's, at the statement's QueryBegin.
	void Publish(AclSessionView session) {
		std::lock_guard<std::mutex> guard(lock);
		view = std::move(session);
		active = true;
	}

	//! acl's, at the statement's QueryEnd (and at any QueryBegin with no session).
	void Withdraw() {
		std::lock_guard<std::mutex> guard(lock);
		view = AclSessionView();
		active = false;
	}

private:
	mutable std::mutex lock;
	bool active = false;
	AclSessionView view;
};

//! What an observer learns when a session opens (the token comes beside it, by reference).
struct SessionOpenInfo {
	string session_id;
	Principal principal;
	string door;
	//! The `iss` of the token the session was opened with - the IdP to exchange it at. Empty for a
	//! session opened without a JWT (acl's development stub).
	string token_issuer;
	int64_t opened_at = 0;
	int64_t expires_at = 0;
};

//! Implemented by a consumer, registered in AclSessionHooks. acl calls it; an exception is caught,
//! counted and dropped - it never fails an open or a close.
class SessionObserver {
public:
	virtual ~SessionObserver() = default;
	//! On the opening thread, after verification, before the session is usable (its handle is not
	//! yet returned). `access_token` is the verified token, valid ONLY during this call: copy what
	//! you need. The client's connect waits on this call - return promptly.
	virtual void OnSessionOpen(const SessionOpenInfo &info, const string &access_token) = 0;
	//! Exactly once for every session OnSessionOpen was called for, and after it, whatever ended it:
	//! `reason` is acl's: client (closed, or replaced by the same connection re-authenticating), idle,
	//! expired, killed (an operator), door_stopped, shutdown (the instance went away). A session that
	//! opened before this observer registered may be announced here without an open - ignore an id
	//! you never saw. Called on whichever thread ended the session, never under acl's locks.
	virtual void OnSessionClose(const string &session_id, const string &reason) = 0;
};

//! Per DatabaseInstance (ObjectCache, key ObjectType()): the observers of session opens and closes.
class AclSessionHooks : public ObjectCacheEntry {
public:
	int32_t contract_magic = AclConnectionContract::MAGIC;
	int32_t contract_version = AclConnectionContract::VERSION;

	static string ObjectType() {
		return "acl_session_hooks";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	//! Never evicted: a registration must outlive any cache pressure.
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx();
	}

	//! The registry of an instance, created when absent and checked, as AclConnection::Reach.
	static shared_ptr<AclSessionHooks> Reach(ObjectCache &cache, string &why) {
		auto hooks = cache.GetOrCreate<AclSessionHooks>(ObjectType());
		if (!hooks) {
			why = "the object cache holds something else under '" + ObjectType() + "'";
			return nullptr;
		}
		if (hooks->contract_magic != AclConnectionContract::MAGIC ||
		    hooks->contract_version != AclConnectionContract::VERSION) {
			why = "the session hooks are stamped with another acl_connection contract (" +
			      std::to_string(hooks->contract_version) + "); this build speaks " +
			      std::to_string(AclConnectionContract::VERSION);
			return nullptr;
		}
		why.clear();
		return hooks;
	}

	void AddObserver(shared_ptr<SessionObserver> observer) {
		std::lock_guard<std::mutex> guard(lock);
		observers.push_back(std::move(observer));
	}
	void RemoveObserver(const shared_ptr<SessionObserver> &observer) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = observers.begin(); it != observers.end(); ++it) {
			if (*it == observer) {
				observers.erase(it);
				return;
			}
		}
	}
	//! A copy, so acl calls the observers without holding the registry.
	vector<shared_ptr<SessionObserver>> Observers() const {
		std::lock_guard<std::mutex> guard(lock);
		return observers;
	}

private:
	mutable std::mutex lock;
	vector<shared_ptr<SessionObserver>> observers;
};

} // namespace acl
} // namespace duckdb
