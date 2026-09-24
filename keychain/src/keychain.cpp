// The keychain module (spec 010): one small secret per (service, account) in the OS credential store.
#include "keychain.hpp"

#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <vector>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincred.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <sys/stat.h>
#endif

namespace duckdb {
namespace DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE {
namespace keychain {

void KeychainWipe(std::string &text) {
	volatile char *bytes = text.empty() ? nullptr : &text[0];
	for (size_t i = 0; i < text.size(); i++) {
		bytes[i] = 0;
	}
	text.clear();
}

namespace {

KeychainResult Failed(std::string error) {
	KeychainResult result;
	result.error = std::move(error);
	return result;
}

KeychainResult Done(bool found = false) {
	KeychainResult result;
	result.ok = true;
	result.found = found;
	return result;
}

} // namespace

#if defined(__APPLE__)

namespace {

struct CF {
	CFTypeRef ref = nullptr;
	explicit CF(CFTypeRef ref_p) : ref(ref_p) {
	}
	~CF() {
		if (ref) {
			CFRelease(ref);
		}
	}
	CF(const CF &) = delete;
	CF &operator=(const CF &) = delete;
};

CFStringRef String(const std::string &text) {
	return CFStringCreateWithBytes(kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(text.data()),
	                               CFIndex(text.size()), kCFStringEncodingUTF8, false);
}

std::string Status(const char *what, OSStatus status) {
	std::string out = std::string("the macOS keychain: ") + what + " failed (" + std::to_string(int(status));
	CF message(SecCopyErrorMessageString(status, nullptr));
	if (message.ref) {
		char buffer[256];
		if (CFStringGetCString(static_cast<CFStringRef>(message.ref), buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
			out += ": " + std::string(buffer);
		}
	}
	return out + ")";
}

//! The item's identity: a generic password of (service, account).
CFMutableDictionaryRef Query(const std::string &service, const std::string &account) {
	auto query =
	    CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CF service_ref(String(service));
	CF account_ref(String(account));
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service_ref.ref);
	CFDictionarySetValue(query, kSecAttrAccount, account_ref.ref);
	return query;
}

} // namespace

bool KeychainAvailable(std::string &why) {
	why.clear();
	return true;
}

KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret) {
	CF query(Query(service, account));
	CF data(CFDataCreate(nullptr, reinterpret_cast<const UInt8 *>(secret.data()), CFIndex(secret.size())));
	CF update(CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
	auto changes = static_cast<CFMutableDictionaryRef>(const_cast<void *>(update.ref));
	CFDictionarySetValue(changes, kSecValueData, data.ref);
	auto status = SecItemUpdate(static_cast<CFDictionaryRef>(query.ref), changes);
	if (status == errSecItemNotFound) {
		auto add = static_cast<CFMutableDictionaryRef>(const_cast<void *>(query.ref));
		CFDictionarySetValue(add, kSecValueData, data.ref);
		// this device only: never synchronised, never restored onto another machine
		CFDictionarySetValue(add, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
		status = SecItemAdd(add, nullptr);
	}
	return status == errSecSuccess ? Done() : Failed(Status("storing", status));
}

KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret) {
	KeychainWipe(secret);
	CF query(Query(service, account));
	auto find = static_cast<CFMutableDictionaryRef>(const_cast<void *>(query.ref));
	CFDictionarySetValue(find, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(find, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef found = nullptr;
	auto status = SecItemCopyMatching(find, &found);
	if (status == errSecItemNotFound) {
		return Done(false);
	}
	if (status != errSecSuccess) {
		return Failed(Status("reading", status));
	}
	CF data(found);
	auto bytes = static_cast<CFDataRef>(data.ref);
	secret.assign(reinterpret_cast<const char *>(CFDataGetBytePtr(bytes)), size_t(CFDataGetLength(bytes)));
	return Done(true);
}

KeychainResult KeychainRemove(const std::string &service, const std::string &account) {
	CF query(Query(service, account));
	auto status = SecItemDelete(static_cast<CFDictionaryRef>(query.ref));
	return status == errSecSuccess || status == errSecItemNotFound ? Done() : Failed(Status("removing", status));
}

#elif defined(_WIN32)

namespace {

std::wstring Wide(const std::string &text) {
	if (text.empty()) {
		return std::wstring();
	}
	auto size = MultiByteToWideChar(CP_UTF8, 0, text.data(), int(text.size()), nullptr, 0);
	std::wstring out(size_t(size), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, text.data(), int(text.size()), &out[0], size);
	return out;
}

std::wstring Target(const std::string &service, const std::string &account) {
	return Wide(service + "/" + account);
}

std::string LastError(const char *what) {
	return std::string("the Windows Credential Manager: ") + what + " failed (" + std::to_string(GetLastError()) + ")";
}

} // namespace

bool KeychainAvailable(std::string &why) {
	why.clear();
	return true;
}

KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret) {
	if (secret.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
		return Failed("the Windows Credential Manager holds at most " + std::to_string(CRED_MAX_CREDENTIAL_BLOB_SIZE) +
		              " bytes per credential");
	}
	auto target = Target(service, account);
	auto user = Wide(account);
	std::vector<BYTE> blob(secret.begin(), secret.end());
	CREDENTIALW credential {};
	credential.Type = CRED_TYPE_GENERIC;
	credential.TargetName = &target[0];
	credential.UserName = user.empty() ? nullptr : &user[0];
	credential.CredentialBlobSize = DWORD(blob.size());
	credential.CredentialBlob = blob.empty() ? nullptr : blob.data();
	credential.Persist = CRED_PERSIST_LOCAL_MACHINE; // this machine's profile, never roaming
	auto written = CredWriteW(&credential, 0);
	SecureZeroMemory(blob.data(), blob.size());
	return written ? Done() : Failed(LastError("storing"));
}

KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret) {
	KeychainWipe(secret);
	auto target = Target(service, account);
	PCREDENTIALW credential = nullptr;
	if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
		if (GetLastError() == ERROR_NOT_FOUND) {
			return Done(false);
		}
		return Failed(LastError("reading"));
	}
	secret.assign(reinterpret_cast<const char *>(credential->CredentialBlob), credential->CredentialBlobSize);
	SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
	CredFree(credential);
	return Done(true);
}

KeychainResult KeychainRemove(const std::string &service, const std::string &account) {
	auto target = Target(service, account);
	if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND) {
		return Failed(LastError("removing"));
	}
	return Done();
}

#elif defined(__linux__)

namespace {

// libsecret's and GLib's declarations, as far as these calls need them (libsecret/secret-schema.h): the
// library is loaded at run time, so the extension needs no link-time dependency and loads where it is absent
enum SecretSchemaFlags { SECRET_SCHEMA_NONE = 0 };
enum SecretSchemaAttributeType { SECRET_SCHEMA_ATTRIBUTE_STRING = 0 };
struct SecretSchemaAttribute {
	const char *name;
	SecretSchemaAttributeType type;
};
struct SecretSchema {
	const char *name;
	SecretSchemaFlags flags;
	SecretSchemaAttribute attributes[32];
	int reserved;
	void *reserved1;
	void *reserved2;
	void *reserved3;
	void *reserved4;
	void *reserved5;
	void *reserved6;
	void *reserved7;
};
struct GError {
	uint32_t domain;
	int code;
	char *message;
};

using StoreFn = int (*)(const SecretSchema *, const char *, const char *, const char *, void *, GError **, ...);
using LookupFn = char *(*)(const SecretSchema *, void *, GError **, ...);
using ClearFn = int (*)(const SecretSchema *, void *, GError **, ...);
using FreeFn = void (*)(char *);
using ErrorFreeFn = void (*)(GError *);

struct Libsecret {
	bool loaded = false;
	std::string why;
	StoreFn store = nullptr;
	LookupFn lookup = nullptr;
	ClearFn clear = nullptr;
	FreeFn free_password = nullptr;
	ErrorFreeFn free_error = nullptr;
};

const Libsecret &Library() {
	static Libsecret library;
	static std::once_flag once;
	std::call_once(once, []() {
		auto handle = dlopen("libsecret-1.so.0", RTLD_NOW | RTLD_LOCAL);
		if (!handle) {
			library.why = "libsecret-1.so.0 is not installed (the Secret Service client library)";
			return;
		}
		library.store = reinterpret_cast<StoreFn>(dlsym(handle, "secret_password_store_sync"));
		library.lookup = reinterpret_cast<LookupFn>(dlsym(handle, "secret_password_lookup_sync"));
		library.clear = reinterpret_cast<ClearFn>(dlsym(handle, "secret_password_clear_sync"));
		library.free_password = reinterpret_cast<FreeFn>(dlsym(handle, "secret_password_free"));
		library.free_error = reinterpret_cast<ErrorFreeFn>(dlsym(handle, "g_error_free")); // from its GLib
		if (!library.store || !library.lookup || !library.clear || !library.free_password || !library.free_error) {
			library.why = "libsecret-1.so.0 lacks the calls this module uses";
			return;
		}
		library.loaded = true;
	});
	return library;
}

const SecretSchema &Schema() {
	static SecretSchema schema = [] {
		SecretSchema s {};
		s.name = "org.duckdb.ExtCommon.Keychain";
		s.flags = SECRET_SCHEMA_NONE;
		s.attributes[0] = {"service", SECRET_SCHEMA_ATTRIBUTE_STRING};
		s.attributes[1] = {"account", SECRET_SCHEMA_ATTRIBUTE_STRING};
		s.attributes[2] = {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING};
		return s;
	}();
	return schema;
}

//! A session bus to reach the Secret Service on: without one, libsecret would try to autolaunch D-Bus.
bool SessionBus(std::string &why) {
	auto address = std::getenv("DBUS_SESSION_BUS_ADDRESS");
	if (address && *address) {
		return true;
	}
	auto runtime = std::getenv("XDG_RUNTIME_DIR");
	struct stat info;
	if (runtime && *runtime && stat((std::string(runtime) + "/bus").c_str(), &info) == 0) {
		return true;
	}
	why = "no D-Bus session bus (DBUS_SESSION_BUS_ADDRESS) to reach a Secret Service on";
	return false;
}

KeychainResult GFailed(const char *what, GError *error) {
	std::string text = std::string("the Secret Service: ") + what + " failed";
	if (error) {
		text += " (" + std::string(error->message ? error->message : "") + ")";
		Library().free_error(error);
	}
	return Failed(text);
}

} // namespace

bool KeychainAvailable(std::string &why) {
	auto &library = Library();
	if (!library.loaded) {
		why = library.why;
		return false;
	}
	if (!SessionBus(why)) {
		return false;
	}
	// a lookup that finds nothing proves a Secret Service answers on the bus
	GError *error = nullptr;
	auto found =
	    library.lookup(&Schema(), nullptr, &error, "service", "org.duckdb.ext-common.probe", "account", "", nullptr);
	if (found) {
		library.free_password(found);
	}
	if (error) {
		why = "no Secret Service answers (" + std::string(error->message ? error->message : "") + ")";
		library.free_error(error);
		return false;
	}
	why.clear();
	return true;
}

KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret) {
	std::string why;
	if (!KeychainAvailable(why)) {
		return Failed(why);
	}
	auto label = service + " " + account;
	GError *error = nullptr;
	auto stored = Library().store(&Schema(), nullptr, label.c_str(), secret.c_str(), nullptr, &error, "service",
	                              service.c_str(), "account", account.c_str(), nullptr);
	return stored && !error ? Done() : GFailed("storing", error);
}

KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret) {
	KeychainWipe(secret);
	std::string why;
	if (!KeychainAvailable(why)) {
		return Failed(why);
	}
	GError *error = nullptr;
	auto found =
	    Library().lookup(&Schema(), nullptr, &error, "service", service.c_str(), "account", account.c_str(), nullptr);
	if (error) {
		return GFailed("reading", error);
	}
	if (!found) {
		return Done(false);
	}
	secret.assign(found);
	Library().free_password(found); // libsecret wipes it
	return Done(true);
}

KeychainResult KeychainRemove(const std::string &service, const std::string &account) {
	std::string why;
	if (!KeychainAvailable(why)) {
		return Failed(why);
	}
	GError *error = nullptr;
	Library().clear(&Schema(), nullptr, &error, "service", service.c_str(), "account", account.c_str(), nullptr);
	return error ? GFailed("removing", error) : Done();
}

#else

bool KeychainAvailable(std::string &why) {
	why = "this platform has no credential store this module knows";
	return false;
}

KeychainResult KeychainStore(const std::string &, const std::string &, const std::string &) {
	return Failed("no credential store on this platform");
}

KeychainResult KeychainLoad(const std::string &, const std::string &, std::string &secret) {
	KeychainWipe(secret);
	return Failed("no credential store on this platform");
}

KeychainResult KeychainRemove(const std::string &, const std::string &) {
	return Failed("no credential store on this platform");
}

#endif

} // namespace keychain
} // namespace DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE
} // namespace duckdb
