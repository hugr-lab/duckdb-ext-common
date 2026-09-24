# keychain/ — a credential in the operating system's own store

One small secret (a person's refresh token, for tresor) per `(service, account)`:

| Platform | Store | Links |
| --- | --- | --- |
| macOS | Keychain Services, generic password, this device only | `-framework Security -framework CoreFoundation` |
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

`scripts/test_keychain.sh` runs the test against the real store (spec 010: how CI provides one on each
platform). The store protects against other OS users and a copied disk, not against another process of
the same user (on macOS, another binary asks first).
