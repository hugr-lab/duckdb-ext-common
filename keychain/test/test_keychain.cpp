// The keychain module against the real OS store (spec 010): store, load, replace, remove, not found - under a
// service name of this run's own, removed at the end. KEYCHAIN_EXPECT_UNAVAILABLE=1: the store must be absent.
#include "keychain.hpp"

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
static void Check(bool ok, const char *what, const std::string &detail = std::string()) {
	std::printf("  %s: %s%s%s\n", ok ? "ok" : "FAIL", what, detail.empty() ? "" : " - ", detail.c_str());
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
	std::string wiped = "abc";
	KeychainWipe(wiped);
	Check(wiped.empty(), "wipe empties");
	std::printf("%s test_keychain\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
