# oidc/oidc.cmake - how a consumer compiles the OIDC core into itself (duckdb-ext-common spec 002)
#
#   include(duckdb-ext-common/oidc/oidc.cmake)
#   include_directories(${DUCKDB_EXT_COMMON_OIDC_INCLUDE} duckdb/third_party/httplib duckdb/third_party/yyjson/include)
#   list(APPEND EXTENSION_SOURCES ${DUCKDB_EXT_COMMON_OIDC_SOURCES})
#   target_compile_definitions(<target> PRIVATE DUCKDB_EXT_COMMON_OIDC_NAMESPACE=<ns> [DUCKDB_EXT_COMMON_OIDC_TLS=1])
#
# A list of sources, not a library target: duckdb's build_static_extension / build_loadable_extension
# take sources, the consumer's flags (its namespace, its TLS, its visibility) land on them naturally,
# and every consumer compiles its own copy (charter R10). The module's TU is compiled with hidden
# visibility where the compiler has it, so a statically linked consumer never exports the module's
# symbols for a co-loaded image to bind to (the lesson of duckdb-acl's embedded quack).
set(DUCKDB_EXT_COMMON_OIDC_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/include")
set(DUCKDB_EXT_COMMON_OIDC_SOURCES "${CMAKE_CURRENT_LIST_DIR}/src/oidc_core.cpp")
if(NOT MSVC)
  set_source_files_properties(${DUCKDB_EXT_COMMON_OIDC_SOURCES} PROPERTIES COMPILE_OPTIONS "-fvisibility=hidden")
endif()
