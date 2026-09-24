// The keychain module (spec 010): one small secret per (service, account) in the OS credential store.
#include "keychain.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <thread>
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

//! Well-formed UTF-8 (no overlongs, no surrogates): every store keys by text, and two byte strings that a
//! platform would read as one must never share an entry.
bool ValidUtf8(const std::string &text) {
	size_t i = 0;
	while (i < text.size()) {
		auto c = static_cast<unsigned char>(text[i]);
		size_t extra;
		uint32_t cp;
		if (c < 0x80) {
			i++;
			continue;
		} else if ((c & 0xE0) == 0xC0) {
			extra = 1;
			cp = c & 0x1F;
		} else if ((c & 0xF0) == 0xE0) {
			extra = 2;
			cp = c & 0x0F;
		} else if ((c & 0xF8) == 0xF0) {
			extra = 3;
			cp = c & 0x07;
		} else {
			return false;
		}
		if (i + extra >= text.size()) {
			return false; // truncated
		}
		for (size_t k = 1; k <= extra; k++) {
			auto next = static_cast<unsigned char>(text[i + k]);
			if ((next & 0xC0) != 0x80) {
				return false;
			}
			cp = (cp << 6) | (next & 0x3F);
		}
		if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
		    (cp >= 0xD800 && cp <= 0xDFFF)) {
			return false;
		}
		i += extra + 1;
	}
	return true;
}

//! The names every platform keys by: text, the service non-empty and without '/' (Windows joins the two by one).
bool NamesOk(const std::string &service, const std::string &account, std::string &why) {
	if (service.empty() || !ValidUtf8(service) || !ValidUtf8(account)) {
		why = "the keychain: the service and account must be UTF-8 text, the service non-empty";
		return false;
	}
	if (service.find('/') != std::string::npos) {
		why = "the keychain: a service name has no '/'";
		return false;
	}
	return true;
}

//! The secret every platform keeps the same way: text with no NUL (the Secret Service's password API is C text).
bool SecretOk(const std::string &secret, std::string &why) {
	if (secret.find('\0') != std::string::npos) {
		why = "the keychain holds text: the secret has a NUL byte";
		return false;
	}
	return true;
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
	if (status == errSecInteractionNotAllowed) {
		return std::string("the macOS keychain: ") + what +
		       " failed - the keychain is locked, or asks the user and cannot here (an SSH session)";
	}
	if (status == errSecUserCanceled || status == errSecAuthFailed) {
		return std::string("the macOS keychain: ") + what + " failed - access was denied";
	}
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

//! The item's identity: a generic password of (service, account); null when the names cannot be CF strings.
CFMutableDictionaryRef Query(const std::string &service, const std::string &account) {
	CF service_ref(String(service));
	CF account_ref(String(account));
	if (!service_ref.ref || !account_ref.ref) {
		return nullptr;
	}
	auto query =
	    CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!query) {
		return nullptr;
	}
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service_ref.ref);
	CFDictionarySetValue(query, kSecAttrAccount, account_ref.ref);
	return query;
}

} // namespace

bool KeychainAvailable(std::string &why) {
	// no default keychain (a daemon's session; a default that points at a deleted file): an add would have the
	// system ask the person, in a dialog, to create one - never from here. The call is deprecated, and the only
	// one that tells
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	SecKeychainRef keychain = nullptr;
	auto has_default = SecKeychainCopyDefault(&keychain);
	if (keychain) {
		CFRelease(keychain);
	}
#pragma clang diagnostic pop
	if (has_default != errSecSuccess) {
		why = "the macOS keychain: no default keychain in this session";
		return false;
	}
	// a lookup that finds nothing proves the keychain answers without asking anyone
	CF query(Query("org.duckdb.ext-common.probe", ""));
	if (!query.ref) {
		why = "the macOS keychain could not be queried";
		return false;
	}
	auto status = SecItemCopyMatching(static_cast<CFDictionaryRef>(query.ref), nullptr);
	if (status == errSecSuccess || status == errSecItemNotFound) {
		why.clear();
		return true;
	}
	why = status == errSecNoDefaultKeychain ? "the macOS keychain: no default keychain in this session"
	                                        : Status("probing", status);
	return false;
}

KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret) {
	std::string why;
	if (!NamesOk(service, account, why) || !SecretOk(secret, why) || !KeychainAvailable(why)) {
		return Failed(why);
	}
	CF query(Query(service, account));
	// no copy of the secret: the data refers to the caller's bytes for the duration of the call
	CF data(CFDataCreateWithBytesNoCopy(nullptr, reinterpret_cast<const UInt8 *>(secret.data()), CFIndex(secret.size()),
	                                    kCFAllocatorNull));
	CF update(CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
	if (!query.ref || !data.ref || !update.ref) {
		return Failed("the macOS keychain: the item could not be described");
	}
	auto changes = static_cast<CFMutableDictionaryRef>(const_cast<void *>(update.ref));
	CFDictionarySetValue(changes, kSecValueData, data.ref);
	auto status = SecItemUpdate(static_cast<CFDictionaryRef>(query.ref), changes);
	if (status == errSecItemNotFound) {
		// a file-based keychain item (what an unentitled process gets): kept in this user's keychain file, never
		// iCloud-synchronised (iCloud takes only data-protection items marked synchronizable)
		auto add = static_cast<CFMutableDictionaryRef>(const_cast<void *>(query.ref));
		CFDictionarySetValue(add, kSecValueData, data.ref);
		status = SecItemAdd(add, nullptr);
	}
	return status == errSecSuccess ? Done() : Failed(Status("storing", status));
}

KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret) {
	KeychainWipe(secret);
	std::string why;
	if (!NamesOk(service, account, why)) {
		return Failed(why);
	}
	CF query(Query(service, account));
	if (!query.ref) {
		return Failed("the macOS keychain: the item could not be described");
	}
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
	std::string why;
	if (!NamesOk(service, account, why)) {
		return Failed(why);
	}
	CF query(Query(service, account));
	if (!query.ref) {
		return Failed("the macOS keychain: the item could not be described");
	}
	auto status = SecItemDelete(static_cast<CFDictionaryRef>(query.ref));
	return status == errSecSuccess || status == errSecItemNotFound ? Done() : Failed(Status("removing", status));
}

#elif defined(_WIN32)

namespace {

//! UTF-8 to UTF-16, refusing what is not UTF-8 (never a U+FFFD that two inputs could share).
bool Wide(const std::string &text, std::wstring &out) {
	out.clear();
	if (text.empty()) {
		return true;
	}
	auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), int(text.size()), nullptr, 0);
	if (size <= 0) {
		return false;
	}
	out.assign(size_t(size), L'\0');
	return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), int(text.size()), &out[0], size) == size;
}

bool Target(const std::string &service, const std::string &account, std::wstring &target, std::string &why) {
	if (!NamesOk(service, account, why)) {
		return false;
	}
	if (!Wide(service + "/" + account, target)) {
		why = "the keychain: the service and account must be UTF-8 text";
		return false;
	}
	return true;
}

std::string LastError(const char *what) {
	auto code = GetLastError();
	if (code == ERROR_NO_SUCH_LOGON_SESSION) {
		return std::string("the Windows Credential Manager: ") + what +
		       " failed - this logon session keeps no credentials (a service, or an SSH key logon)";
	}
	return std::string("the Windows Credential Manager: ") + what + " failed (" + std::to_string(code) + ")";
}

} // namespace

bool KeychainAvailable(std::string &why) {
	// a service, a network or an SSH public-key logon has no credential set to persist into
	DWORD persist[CRED_TYPE_MAXIMUM] = {};
	if (!CredGetSessionTypes(CRED_TYPE_MAXIMUM, persist) || persist[CRED_TYPE_GENERIC] < CRED_PERSIST_LOCAL_MACHINE) {
		why = "the Windows Credential Manager keeps no credentials in this logon session";
		return false;
	}
	why.clear();
	return true;
}

KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret) {
	std::string why;
	std::wstring target;
	if (!Target(service, account, target, why) || !SecretOk(secret, why)) {
		return Failed(why);
	}
	if (secret.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
		return Failed("the Windows Credential Manager holds at most " + std::to_string(CRED_MAX_CREDENTIAL_BLOB_SIZE) +
		              " bytes per credential");
	}
	std::wstring user;
	Wide(account, user);
	if (user.size() > CRED_MAX_USERNAME_LENGTH) {
		return Failed("the Windows Credential Manager: the account name is too long");
	}
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
	std::string why;
	std::wstring target;
	if (!Target(service, account, target, why)) {
		return Failed(why);
	}
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
	std::string why;
	std::wstring target;
	if (!Target(service, account, target, why)) {
		return Failed(why);
	}
	if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND) {
		return Failed(LastError("removing"));
	}
	return Done();
}

#elif defined(__linux__)

namespace {

constexpr int CALL_TIMEOUT_SECONDS = 15; // an unlock prompt nobody answers must not hold an ATTACH forever

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
using CancellableNewFn = void *(*)();
using CancellableCancelFn = void (*)(void *);
using ObjectUnrefFn = void (*)(void *);

struct Libsecret {
	bool loaded = false;
	std::string why;
	StoreFn store = nullptr;
	LookupFn lookup = nullptr;
	ClearFn clear = nullptr;
	FreeFn free_password = nullptr;
	ErrorFreeFn free_error = nullptr;
	CancellableNewFn cancellable_new = nullptr;
	CancellableCancelFn cancellable_cancel = nullptr;
	ObjectUnrefFn object_unref = nullptr;
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
		// a handle's lookup searches its dependencies too: GLib's and GIO's calls come through it
		library.store = reinterpret_cast<StoreFn>(dlsym(handle, "secret_password_store_sync"));
		library.lookup = reinterpret_cast<LookupFn>(dlsym(handle, "secret_password_lookup_sync"));
		library.clear = reinterpret_cast<ClearFn>(dlsym(handle, "secret_password_clear_sync"));
		library.free_password = reinterpret_cast<FreeFn>(dlsym(handle, "secret_password_free"));
		library.free_error = reinterpret_cast<ErrorFreeFn>(dlsym(handle, "g_error_free"));
		library.cancellable_new = reinterpret_cast<CancellableNewFn>(dlsym(handle, "g_cancellable_new"));
		library.cancellable_cancel = reinterpret_cast<CancellableCancelFn>(dlsym(handle, "g_cancellable_cancel"));
		library.object_unref = reinterpret_cast<ObjectUnrefFn>(dlsym(handle, "g_object_unref"));
		if (!library.store || !library.lookup || !library.clear || !library.free_password || !library.free_error ||
		    !library.cancellable_new || !library.cancellable_cancel || !library.object_unref) {
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

//! A GCancellable a watchdog cancels after CALL_TIMEOUT_SECONDS: a prompt (an unlock dialog on a desktop the
//! person is not at) must not block forever.
class Deadline {
public:
	Deadline() : cancellable(Library().cancellable_new()) {
		watchdog = std::thread([this]() {
			std::unique_lock<std::mutex> guard(lock);
			if (!done.wait_for(guard, std::chrono::seconds(CALL_TIMEOUT_SECONDS), [this]() { return finished; })) {
				Library().cancellable_cancel(cancellable);
			}
		});
	}
	~Deadline() {
		{
			std::lock_guard<std::mutex> guard(lock);
			finished = true;
		}
		done.notify_all();
		watchdog.join();
		Library().object_unref(cancellable);
	}
	Deadline(const Deadline &) = delete;
	Deadline &operator=(const Deadline &) = delete;
	void *Get() {
		return cancellable;
	}

private:
	void *cancellable;
	std::mutex lock;
	std::condition_variable done;
	bool finished = false;
	std::thread watchdog;
};

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
	// probed once per process: every call would otherwise cost a round trip more (and activate a keyring daemon)
	static std::mutex lock;
	static bool probed = false;
	static bool available = false;
	static std::string reason;
	std::lock_guard<std::mutex> guard(lock);
	if (!probed) {
		probed = true;
		auto &library = Library();
		if (!library.loaded) {
			reason = library.why;
		} else if (SessionBus(reason)) {
			// a lookup that finds nothing proves a Secret Service answers on the bus
			GError *error = nullptr;
			Deadline deadline;
			auto found = library.lookup(&Schema(), deadline.Get(), &error, "service", "org.duckdb.ext-common.probe",
			                            "account", "", nullptr);
			if (found) {
				library.free_password(found);
			}
			if (error) {
				reason = "no Secret Service answers (" + std::string(error->message ? error->message : "") + ")";
				library.free_error(error);
			} else {
				available = true;
			}
		}
	}
	why = available ? std::string() : reason;
	return available;
}

KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret) {
	std::string why;
	if (!NamesOk(service, account, why) || !SecretOk(secret, why) || !KeychainAvailable(why)) {
		return Failed(why);
	}
	auto label = service + " " + account;
	GError *error = nullptr;
	Deadline deadline;
	auto stored = Library().store(&Schema(), nullptr, label.c_str(), secret.c_str(), deadline.Get(), &error, "service",
	                              service.c_str(), "account", account.c_str(), nullptr);
	return stored && !error ? Done() : GFailed("storing", error);
}

KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret) {
	KeychainWipe(secret);
	std::string why;
	if (!NamesOk(service, account, why) || !KeychainAvailable(why)) {
		return Failed(why);
	}
	GError *error = nullptr;
	Deadline deadline;
	// a locked collection with nobody to unlock it answers "nothing here", not an error: the consumer logs in
	auto found = Library().lookup(&Schema(), deadline.Get(), &error, "service", service.c_str(), "account",
	                              account.c_str(), nullptr);
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
	if (!NamesOk(service, account, why) || !KeychainAvailable(why)) {
		return Failed(why);
	}
	GError *error = nullptr;
	Deadline deadline;
	Library().clear(&Schema(), deadline.Get(), &error, "service", service.c_str(), "account", account.c_str(), nullptr);
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
