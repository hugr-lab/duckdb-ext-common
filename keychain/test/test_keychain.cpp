// The keychain module against the real OS store (spec 010): store, load, replace, remove, not found - under a
// service name of this run's own, removed at the end. KEYCHAIN_EXPECT_UNAVAILABLE=1: the store must be absent.
#include "keychain.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

using namespace duckdb::ext_common::keychain;

static int failures = 0;
static void Check(bool ok, const std::string &what, const std::string &detail = std::string()) {
	std::printf("  %s: %s%s%s\n", ok ? "ok" : "FAIL", what.c_str(), detail.empty() ? "" : " - ", detail.c_str());
	failures += ok ? 0 : 1;
}

int main() {
	std::string why;
	auto available = KeychainAvailable(why);
	auto expect_absent = std::getenv("KEYCHAIN_EXPECT_UNAVAILABLE");
	if (expect_absent && std::string(expect_absent) == "1") {
		Check(!available && !why.empty(), "no store: not available, and why", why);
		auto stored = KeychainStore("duckdb-ext-common-test", "x", "y");
		Check(!stored.ok && !stored.error.empty(), "no store: a store fails, nothing kept elsewhere", stored.error);
		std::printf("%s test_keychain\n", failures ? "FAIL" : "PASS");
		return failures ? 1 : 0;
	}
	// the CI's locked-collection steps (spec 010): store, then - after the collection is locked outside - load
	auto step = std::getenv("KEYCHAIN_STEP");
	if (step && std::string(step) == "store") {
		auto stored = KeychainStore("duckdb-ext-common-locked", "acct", "locked-secret");
		Check(available && stored.ok, "stored for the locked-collection check", stored.error);
		std::printf("%s test_keychain\n", failures ? "FAIL" : "PASS");
		return failures ? 1 : 0;
	}
	if (step && std::string(step) == "load-locked") {
		std::string secret;
		auto started = std::chrono::steady_clock::now();
		auto loaded = KeychainLoad("duckdb-ext-common-locked", "acct", secret);
		auto seconds =
		    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started).count();
		Check(seconds < 30 && !(loaded.ok && loaded.found),
		      "a locked collection: nothing handed out, and no hang (" + std::to_string(seconds) + " s)", loaded.error);
		std::printf("%s test_keychain\n", failures ? "FAIL" : "PASS");
		return failures ? 1 : 0;
	}
	Check(available, "a store is available", why);
	auto service = "duckdb-ext-common-test-" + std::to_string(getpid());
	auto account = "https://idp.example/realms/r duckdb";
	std::string secret;
	auto loaded = KeychainLoad(service, account, secret);
	Check(loaded.ok && !loaded.found && secret.empty(), "nothing there yet: not found, not an error", loaded.error);
	auto stored = KeychainStore(service, account, "refresh-1");
	Check(stored.ok, "store", stored.error);
	loaded = KeychainLoad(service, account, secret);
	Check(loaded.ok && loaded.found && secret == "refresh-1", "load what was stored", loaded.error);
	stored = KeychainStore(service, account, std::string(1500, 'r'));
	loaded = KeychainLoad(service, account, secret);
	Check(stored.ok && loaded.found && secret == std::string(1500, 'r'), "store again: replaced (a long token)",
	      stored.error + loaded.error);
	std::string other;
	loaded = KeychainLoad(service, "another account", other);
	Check(loaded.ok && !loaded.found, "another account is another entry", loaded.error);
	auto removed = KeychainRemove(service, account);
	Check(removed.ok, "remove", removed.error);
	loaded = KeychainLoad(service, account, secret);
	Check(loaded.ok && !loaded.found && secret.empty(), "removed: not found", loaded.error);
	removed = KeychainRemove(service, account);
	Check(removed.ok, "removing what is not there is fine", removed.error);
	// what no store may take: names that are not UTF-8 (they would crash CF, or fold into U+FFFD on Windows),
	// a '/' in the service (Windows joins service and account with one), a NUL in the secret (C text on Linux)
	auto bad_account = KeychainLoad(service, "\xff\xfe", secret);
	Check(!bad_account.ok && !bad_account.error.empty(), "an account that is not UTF-8 is refused", bad_account.error);
	auto bad_store = KeychainStore(service, "\xc0\xaf", "x");
	Check(!bad_store.ok, "an overlong UTF-8 account is refused", bad_store.error);
	auto slash = KeychainStore("a/b", "c", "x");
	Check(!slash.ok, "a service with '/' is refused", slash.error);
	auto nul = KeychainStore(service, account, std::string("ab\0cd", 5));
	Check(!nul.ok, "a secret with a NUL is refused", nul.error);
	for (auto *error : {&bad_account.error, &bad_store.error, &slash.error, &nul.error}) {
		Check(error->find("refresh-1") == std::string::npos && error->find("ab\0cd") == std::string::npos,
		      "no secret in an error", *error);
	}
#ifdef _WIN32
	auto at_limit = KeychainStore(service, account, std::string(2560, 'w'));
	auto past_limit = KeychainStore(service, account, std::string(2561, 'w'));
	Check(at_limit.ok && !past_limit.ok, "Windows: 2560 bytes kept, 2561 refused",
	      at_limit.error + " / " + past_limit.error);
	KeychainRemove(service, account);
#endif
	std::string wiped = "abc";
	KeychainWipe(wiped);
	Check(wiped.empty(), "wipe empties");
	std::printf("%s test_keychain\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
