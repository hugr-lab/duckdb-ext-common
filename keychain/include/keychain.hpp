//===----------------------------------------------------------------------===//
// keychain.hpp — a credential in the operating system's own store (spec 010)
//
// macOS Keychain Services, Windows Credential Manager, the Linux Secret Service (libsecret, loaded at run
// time). No file, ever: where no store is reachable, KeychainAvailable says why and nothing is kept.
//
// duckdb-free (charter R10): compiled into each consumer, in the consumer's namespace (R13):
//
//   target_compile_definitions(<target> PRIVATE DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=<ns>)
//
// The secret is never logged or put in an error; the module wipes its own copies before freeing them.
//===----------------------------------------------------------------------===//

#pragma once

#include <string>

#ifndef DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE
#error "define DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=<your extension's namespace> on every TU that includes keychain.hpp"
#endif

namespace duckdb {
namespace DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE {
namespace keychain {

//! One call's outcome. `error` names the store and its status, never the secret.
struct KeychainResult {
	bool ok = false;
	bool found = false; // Load: an entry was there
	std::string error;
};

//! Is a store reachable in this process: false, with why, e.g. on a Linux without a Secret Service (a server,
//! a container) or where the platform has none.
bool KeychainAvailable(std::string &why);

//! Store `secret` under (service, account), replacing what was there.
KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret);

//! Load the secret under (service, account); found = false when there is none (not an error).
KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret);

//! Remove the entry under (service, account); ok when there was none.
KeychainResult KeychainRemove(const std::string &service, const std::string &account);

//! Overwrite a string's bytes, then empty it.
void KeychainWipe(std::string &text);

} // namespace keychain
} // namespace DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE
} // namespace duckdb
