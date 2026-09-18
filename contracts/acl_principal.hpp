//===----------------------------------------------------------------------===//
// acl_principal.hpp - who a statement runs as, as the audit contract carries it
//
// Moved verbatim from duckdb-acl's acl_policy.hpp (duckdb-ext-common spec 002): `Principal` is a
// member of `AuditEvent` by value, so it is part of the audit contract's layout (charter R4) - a
// field added here is a CONTRACT_VERSION bump in acl_audit.hpp. Owned by duckdb-acl (R6).
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/vector.hpp"

namespace duckdb {
namespace acl {

struct Principal {
	//! The token's subject within its issuer (spec 050 F5): part of a principal's identity, so two
	//! users sharing roles+claims are not one session. Empty for the ROLE form and the dev stub.
	string subject;
	//! The issuer that vouched for the subject (spec 007): on every audit event about the principal
	//! (spec 069), so two IdPs' subjects never merge. Empty for the ROLE form and the dev stub.
	string issuer;
	vector<string> roles; // multi-role since spec 006 (union semantics); single-element until spec 007
	case_insensitive_map_t<string> claims;
	//! The one quack stream this principal is draining, when the statement being rewritten is the
	//! ingest INSERT the server generated for it (spec 042). Empty for every statement a client or a
	//! gateway wrote - which is what keeps the exemption it carries from reaching any of them.
	string ingest_stream;
	//! The statement is the Flight door's own composed ingest INSERT (spec 049): the function gate
	//! passes its arrow_scan source and nothing else. Set only by the ACL INGEST prefix, which only
	//! the door's C++ composes - never a client's or a gateway's text.
	bool arrow_ingest = false;
	//! The principal owns the connection the statement runs on (spec 068): set only by the
	//! ACL SESSION prefix - a door's client, whose session IS a connection (spec 050). A per-statement
	//! prefix a gateway writes runs on a connection the gateway shares between principals, so a
	//! setting left there would leak to the next one; only a session may SET anything.
	bool session_connection = false;
	//! The ops id of that session (never the handle), for what a statement records about it - the
	//! trace it SETs (spec 069). Empty off a session.
	string session;
};

} // namespace acl
} // namespace duckdb
