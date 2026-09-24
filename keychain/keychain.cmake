# keychain/keychain.cmake - how a consumer compiles the keychain module into itself (spec 010)
#
#   include(duckdb-ext-common/keychain/keychain.cmake)
#   include_directories(${DUCKDB_EXT_COMMON_KEYCHAIN_INCLUDE})
#   list(APPEND EXTENSION_SOURCES ${DUCKDB_EXT_COMMON_KEYCHAIN_SOURCES})
#   target_compile_definitions(<target> PRIVATE DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=<ns>)
#   target_link_libraries(<target> ${DUCKDB_EXT_COMMON_KEYCHAIN_LIBS})
#
# Sources, not a library (as oidc/): compiled per consumer, hidden visibility. Linux links nothing -
# libsecret is loaded at run time, so the extension loads where it is absent.
set(DUCKDB_EXT_COMMON_KEYCHAIN_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/include")
set(DUCKDB_EXT_COMMON_KEYCHAIN_SOURCES "${CMAKE_CURRENT_LIST_DIR}/src/keychain.cpp")
if(NOT MSVC)
  set_source_files_properties(${DUCKDB_EXT_COMMON_KEYCHAIN_SOURCES} PROPERTIES COMPILE_OPTIONS "-fvisibility=hidden")
endif()
if(APPLE)
  set(DUCKDB_EXT_COMMON_KEYCHAIN_LIBS "-framework Security" "-framework CoreFoundation")
elseif(WIN32)
  set(DUCKDB_EXT_COMMON_KEYCHAIN_LIBS advapi32)
elseif(UNIX)
  set(DUCKDB_EXT_COMMON_KEYCHAIN_LIBS ${CMAKE_DL_LIBS})
else()
  set(DUCKDB_EXT_COMMON_KEYCHAIN_LIBS "")
endif()
