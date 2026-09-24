# Spec 010: the keychain module — a credential in the operating system's own store

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor specs/012-keychain-sso (the first); mssql-extension may follow

## Summary

A duckdb-free module, `keychain/`, beside `oidc/`. Each consumer compiles it into itself (charter
R10). It stores, loads and removes one small secret (a refresh token) in the operating system's
credential store:
- **macOS:** Keychain Services (Security framework);
- **Windows:** Credential Manager (`CredWriteW` / `CredReadW` / `CredDeleteW`);
- **Linux:** the Secret Service over D-Bus (GNOME Keyring, KWallet), through libsecret loaded at
  run time.

There is no file fallback, ever. Where no store is reachable the module says so, and the consumer
goes on without it.

## Problem

- **A person logs in again for every DuckDB process.** tresor keeps its tokens in memory only,
  so every new DuckDB process opens the browser again, even when the identity provider's session
  is still alive. The same is true for every service the person attaches through the same IdP.
- **Keeping the refresh token needs a store that is not a file.**
  - The refresh token is what would carry a login across processes.
  - The rule every consumer follows — "never write secret material to disk" — forbids a file.
  - The OS credential store is the one place a desktop application may keep a credential: it is
    encrypted at rest, bound to the user's login, and on macOS guarded per application.

## Design

### API (`keychain/include/keychain.hpp`, namespace set by the consumer as `oidc/` is)

```cpp
struct KeychainResult { bool ok = false; bool found = false; std::string error; };

//! Is a store reachable in this process: false, with why, on a headless Linux without a Secret Service.
bool KeychainAvailable(std::string &why);
//! Store `secret` under (service, account), replacing what was there.
KeychainResult KeychainStore(const std::string &service, const std::string &account, const std::string &secret);
//! Load it; found=false when there is none (not an error).
KeychainResult KeychainLoad(const std::string &service, const std::string &account, std::string &secret);
//! Remove it; ok when there was none.
KeychainResult KeychainRemove(const std::string &service, const std::string &account);
```

- **Names.**
  - `service` names the consumer and its purpose (`duckdb-tresor`).
  - `account` names the entry (for tresor, the issuer and client id).
  - Both are stored as the item's lookup attributes, never the secret.
- **The secret** is text with no NUL byte (the Secret Service's password API is C text): the same on
  every platform, and a NUL is refused. The module never logs it, and no error carries it.
- **The names are UTF-8 text:**
  - the service is non-empty and has no `/` (Windows joins service and account with one);
  - anything else is refused before any store is asked (CF would abort on it, Windows would fold it
    into U+FFFD).
- **Memory, best effort.** The module overwrites its own copies of the secret before freeing them.
  On macOS the stored data refers to the caller's bytes, with no copy; on Linux GLib's D-Bus buffers
  are not in its hands. The platform
  APIs' buffers are freed with their own functions: `CFRelease` on macOS, `CredFree` after
  `SecureZeroMemory` on Windows, `secret_password_free` (which wipes) on Linux.

### Platforms

- **macOS:** `SecItemAdd` / `SecItemCopyMatching` / `SecItemUpdate` / `SecItemDelete` on a
  generic-password item. `kSecAttrService` = service, `kSecAttrAccount` = account,
  no accessibility attribute.
  - The module does not ask for the data-protection keychain (`kSecUseDataProtectionKeychain`, which
    needs an entitlement), so items go to the file-based login keychain, where `kSecAttrAccessible`
    means nothing.
  - They are never iCloud-synchronised. But the login keychain is a file: a backup (Time Machine)
    or Migration Assistant carries it to another Mac, and it opens there with the login password.
  - The item's access list is the **host binary**: `duckdb`, `python3`, a JDBC tool's `java`. Any
    code in that host reads it without a prompt. Another binary, or the same one after an unsigned
    upgrade (a new cdhash), gets the system's "wants to use your confidential information" dialog.
    Over SSH that dialog cannot show, and the call fails with `errSecInteractionNotAllowed`, which
    the module reports as "locked, or asks the user and cannot here".
  - `KeychainAvailable` asks for the default keychain and then probes with a lookup. No default
    keychain (a launchd daemon, a default that names a deleted file) reads as unavailable. An add
    there would have the system ask the person, in a "Keychain Not Found" dialog, to create one.
    `KeychainStore` checks this first.
  - The consumer links `-framework Security -framework CoreFoundation`.
- **Windows:** a `CRED_TYPE_GENERIC` credential with target `service/account`,
  `CRED_PERSIST_LOCAL_MACHINE` (the user's profile on this machine, not roaming). Links `advapi32`.
  - A credential holds at most `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560) bytes; a longer secret is
    refused with that reason.
  - `KeychainAvailable` asks `CredGetSessionTypes`: a service logon, a network logon or an SSH
    public-key logon has no credential set, and reads as unavailable.
- **Linux:**
  - `dlopen("libsecret-1.so.0")` at the first call, then `secret_password_store_sync`,
    `secret_password_lookup_sync`, `secret_password_clear_sync` and `secret_password_free` with a
    schema of two string attributes (`service`, `account`), in the default collection.
  - No libsecret, or no Secret Service on the session bus: `KeychainAvailable` is false, with why.
    This is the normal case on a server or in a container.
  - No link-time dependency: the extension stays loadable everywhere.
  - The probe runs once per process.
  - Every call carries a `GCancellable` that a watchdog cancels after 15 s. An unlock prompt nobody
    answers (a desktop the person is not at, reached over SSH through `$XDG_RUNTIME_DIR/bus`) cannot
    hold an ATTACH.
  - A locked collection with nobody to unlock it answers "nothing here", not an error: the consumer
    logs in, and its store of the new token fails.
  - GDBus is not fork-safe: a process forked after the first call (Python multiprocessing) must not
    use the module in the child.
- **Anything else** (wasm and the like): not available.

### Build

`keychain/keychain.cmake` works as `oidc/oidc.cmake` does:
- sources plus an include directory, compiled per consumer, hidden visibility;
- `DUCKDB_EXT_COMMON_KEYCHAIN_LIBS` lists what to link on the platform;
- `DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE` sets the consumer's namespace.

## Enforcement & security

- **No file, no fallback.** A missing store is a reported absence, never a degraded mode that writes
  somewhere else.
- **What the OS store protects.** It protects against other users and against a copied disk. It does
  not protect against another process of the same user:
  - on Linux and Windows, any process of that user can read the item;
  - on macOS, the item's access list is the host binary (`duckdb`, `python3`), so another binary
    asks the user first;
  - on Linux, whoever owns `org.freedesktop.secrets` on the session bus receives what is stored.
    When nothing owns it, another process of the user could take the name first. The probe
    activates the real daemon, which narrows that window. It is the same boundary: same-user
    processes are not one.

  Consumers document this.
- **Where it lives:**
  - macOS: the file-based login keychain, never iCloud; a backup or a migration carries the file.
  - Windows: `CRED_PERSIST_LOCAL_MACHINE`, under the user's local (not roaming) profile.
  - Linux: the default collection of whichever provider owns the Secret Service. gnome-keyring keeps
    it under `~/.local/share/keyrings`, which may itself be on a network home. KeePassXC keeps it in
    a `.kdbx` file that people sync. The module cannot tell which.

## Testing

- `scripts/test_keychain.sh`: store, load, replace (with a 1500-byte token), another account apart,
  remove, load after remove (not found), and remove again (fine). It uses a service name of its own
  per run, removed at the end.
  - Linux CI: in `dbus-run-session` with `gnome-keyring-daemon --unlock` (an empty password piped in).
  - macOS CI: a temporary keychain made the default for the test (`security create-keychain`,
    `default-keychain`), deleted after.
  - Windows CI: the runner's Credential Manager.
- Linux without a Secret Service (`DBUS_SESSION_BUS_ADDRESS` unset): not available, with why, and
  no crash.
- A Linux locked collection (locked over D-Bus in CI): nothing handed out, in well under the watchdog.
- On every platform, the test also checks that these are refused, and that no error carries the
  secret:
  - names that are not UTF-8, overlongs included;
  - a `/` in the service;
  - a NUL in the secret.
- Windows: 2560 bytes are kept and 2561 refused. The module is also compiled with MSVC
  (`/W4 /WX`) and run.
- The test compiles the header with the module, under a namespace of its own (`ext_common`).
  `check_headers.sh` covers `hooks/` and `contracts/` only, as for `oidc/`.

## Compatibility

A new module, not a contract: no stamp, no version to bump. Tag `v0.8.0`.
