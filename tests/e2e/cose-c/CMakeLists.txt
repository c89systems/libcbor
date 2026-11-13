cmake_minimum_required(VERSION 3.21)
project(CoseCPeer LANGUAGES C CXX)

# This disposable fixture is independent of libcbor. Only the adapter is C89;
# upstream COSE-C and cn-cbor retain their own language requirements.
set(CMAKE_POLICY_VERSION_MINIMUM 3.10)
find_package(CpktCore 0.7.0 EXACT CONFIG REQUIRED)
list(APPEND CMAKE_FIND_ROOT_PATH "${CpktCore_PREFIX}")
list(APPEND CMAKE_PREFIX_PATH "${CpktCore_PREFIX}")
find_package(OpenSSL 3.6.5 EXACT CONFIG REQUIRED HINTS "${CpktCore_PREFIX}/lib/cmake/OpenSSL")
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
set(OPENSSL_LIBRARIES OpenSSL::Crypto)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(COSE_C_COVERALLS OFF CACHE BOOL "" FORCE)
set(COSE_C_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(COSE_C_BUILD_DUMPER OFF CACHE BOOL "" FORCE)
set(COSE_C_INCLUDE_MAC OFF CACHE BOOL "" FORCE)
set(COSE_C_INCLUDE_MAC0 OFF CACHE BOOL "" FORCE)
set(COSE_C_INCLUDE_SIGN OFF CACHE BOOL "" FORCE)
set(COSE_C_INCLUDE_SIGN1 OFF CACHE BOOL "" FORCE)
set(FETCHCONTENT_FULLY_DISCONNECTED ON)
add_subdirectory("${COSE_C_SOURCE_DIR}" cose-c)
# OpenSSL 3 made EVP_PKEY_get0_EC_KEY return const. Upstream only reads
# that pointer but declares it mutable; keep this compatibility flag confined
# to its backend source, leaving our adapter and product warnings strict.
set_property(SOURCE "${COSE_C_SOURCE_DIR}/src/openssl.cpp" TARGET_DIRECTORY cose-c
  APPEND PROPERTY COMPILE_OPTIONS -fpermissive)

add_executable(cose-c-peer peer.c)
target_compile_options(cose-c-peer PRIVATE -std=c89 -Wall -Wextra -Werror -Wpedantic
  -Wno-long-long -Wstrict-prototypes -Wmissing-prototypes -Wshadow
  -Wpointer-arith -Wcast-qual -Wwrite-strings -Wdeclaration-after-statement)
# The upstream C header uses inline, which GCC spells __inline__ in C89 mode.
target_compile_definitions(cose-c-peer PRIVATE USE_CBOR_CONTEXT inline=__inline__)
target_include_directories(cose-c-peer SYSTEM PRIVATE "${COSE_C_SOURCE_DIR}/include"
  "${CMAKE_BINARY_DIR}/include" "${FETCHCONTENT_SOURCE_DIR_PROJECT_CN_CBOR}/include")
target_link_libraries(cose-c-peer PRIVATE cose-c cn-cbor::cn-cbor OpenSSL::Crypto)
# A static musl fixture runs in the pinned Alpine image without host loader paths.
target_link_options(cose-c-peer PRIVATE -static)
