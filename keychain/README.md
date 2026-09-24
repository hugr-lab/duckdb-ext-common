# keychain/ — a credential in the operating system's own store

One small secret (a person's refresh token, for tresor) per `(service, account)`:

| Platform | Store | Links |
| --- | --- | --- |
| macOS | Keychain Services, generic password, the file-based login keychain | `-framework Security -framework CoreFoundation` |
| Windows | Credential Manager, generic credential, local machine | `advapi32` |
| Linux | the Secret Service over D-Bus, via `libsecret-1.so.0` loaded at run time | nothing (`dl`) |

No file, ever. Where no store answers (a server, a container, no session bus),
`KeychainAvailable(why)` is false and every call fails with the reason. The consumer then goes on without
a store.

```cmake
include(duckdb-ext-common/keychain/keychain.cmake)
include_directories(${DUCKDB_EXT_COMMON_KEYCHAIN_INCLUDE})
list(APPEND EXTENSION_SOURCES ${DUCKDB_EXT_COMMON_KEYCHAIN_SOURCES})
target_compile_definitions(<target> PRIVATE DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=<ns>)
target_link_libraries(<target> ${DUCKDB_EXT_COMMON_KEYCHAIN_LIBS})
```

`scripts/test_keychain.sh` runs the test against the real store (spec 010 says how CI provides one on
each platform). The secret is NUL-free text, and the names are UTF-8.

**What the store protects.** It keeps the secret from other OS users and off a copied disk. It does not
keep it from another process of the same user:
- on macOS, the item belongs to the host binary (`duckdb`, `python3`), and another binary asks first;
- the login keychain file travels with a backup or a migration;
- a Linux provider's collection may be a synced file.

Spec 010's "Enforcement & security" covers each platform.
