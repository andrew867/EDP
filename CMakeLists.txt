# CMakeLists.txt — EDP (Entropy Distribution Protocol)
# Hydrogenuine / Project DOCS
# MIT License
#
# Build targets:
#   edpd          — EDP daemon (main deliverable)
#   test_unit     — Unit tests
#   test_security — Security property tests
#   bench         — Performance benchmarks
#
# Cross-compile for RISC-V:
#   cmake -B build-riscv \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/riscv64-linux-musl.cmake \
#     -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-riscv
#
# Native build (for unit/security tests on x86):
#   cmake -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build
#   ctest --test-dir build -V

cmake_minimum_required(VERSION 3.16)
project(edp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Compiler flags ────────────────────────────────────────────────
set(EDP_COMMON_FLAGS
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Size optimisation for embedded targets
if(CMAKE_CROSSCOMPILING)
    list(APPEND EDP_COMMON_FLAGS -Os -ffunction-sections -fdata-sections)
    set(EDP_LINK_FLAGS "-Wl,--gc-sections")
else()
    list(APPEND EDP_COMMON_FLAGS -O2 -g)
    set(EDP_LINK_FLAGS "")
endif()

# ── Vendor dependencies ───────────────────────────────────────────
# BLAKE3 — https://github.com/BLAKE3-team/BLAKE3/tree/master/c
# Monocypher — https://monocypher.org/download
#
# Expected in vendor/:
#   vendor/blake3.h
#   vendor/blake3.c
#   vendor/blake3_portable.c  (BLAKE3 requires this)
#   vendor/monocypher.h
#   vendor/monocypher.c
#
# Fetch script: cmake/fetch_vendors.sh
set(VENDOR_SRCS
    vendor/blake3.c
    vendor/blake3_portable.c
    vendor/monocypher.c
)

# ── EDP core library ──────────────────────────────────────────────
set(EDP_CORE_SRCS
    src/edp_crypto.c
    src/edp_harvest.c
    src/edp_mix.c
    src/edp_protocol.c
    src/edp_peer.c
    ${VENDOR_SRCS}
)

add_library(edp_core STATIC ${EDP_CORE_SRCS})
target_include_directories(edp_core PUBLIC include src vendor)
# Note: include/ lives at repo root
target_compile_options(edp_core PRIVATE ${EDP_COMMON_FLAGS})

# ── edpd daemon ───────────────────────────────────────────────────
add_executable(edpd src/edp_daemon.c)
target_link_libraries(edpd PRIVATE edp_core)
target_compile_options(edpd PRIVATE ${EDP_COMMON_FLAGS})
if(EDP_LINK_FLAGS)
    target_link_options(edpd PRIVATE ${EDP_LINK_FLAGS})
endif()

# Static link for embedded targets
if(CMAKE_CROSSCOMPILING)
    target_link_options(edpd PRIVATE -static)
    target_link_libraries(edpd PRIVATE -lc)
endif()

# ── Tests ─────────────────────────────────────────────────────────
enable_testing()

add_executable(test_unit tests/test_unit.c)
target_link_libraries(test_unit PRIVATE edp_core)
target_compile_options(test_unit PRIVATE ${EDP_COMMON_FLAGS})
add_test(NAME unit COMMAND test_unit)

add_executable(test_security tests/test_security.c)
target_link_libraries(test_security PRIVATE edp_core)
target_compile_options(test_security PRIVATE ${EDP_COMMON_FLAGS})
add_test(NAME security COMMAND test_security)

# Integration test (shell script, Linux only)
if(UNIX AND NOT APPLE AND NOT CMAKE_CROSSCOMPILING)
    add_test(NAME integration
        COMMAND bash ${CMAKE_SOURCE_DIR}/tests/test_integration.sh --local
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(integration PROPERTIES TIMEOUT 120)
endif()

# ── Benchmarks ────────────────────────────────────────────────────
# bench: performance benchmark stub (not yet implemented)
add_executable(bench tests/bench.c)
target_link_libraries(bench PRIVATE edp_core)
target_compile_options(bench PRIVATE ${EDP_COMMON_FLAGS} -O2)

# ── Install ───────────────────────────────────────────────────────
install(TARGETS edpd DESTINATION bin)
install(FILES include/edp.h DESTINATION include)

# ── RISC-V toolchain info ─────────────────────────────────────────
# cmake/riscv64-linux-musl.cmake content (for reference):
#
# set(CMAKE_SYSTEM_NAME Linux)
# set(CMAKE_SYSTEM_PROCESSOR riscv64)
# set(TRIPLE riscv64-linux-musl)
# set(CMAKE_C_COMPILER   ${TRIPLE}-gcc)
# set(CMAKE_AR           ${TRIPLE}-ar)
# set(CMAKE_C_FLAGS_INIT "-march=rv64gc -mabi=lp64d")
# set(CMAKE_SYSROOT /opt/riscv64-musl)
# set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)

# ── Size report for embedded builds ──────────────────────────────
if(CMAKE_CROSSCOMPILING)
    add_custom_target(size
        COMMAND ${CMAKE_SIZE} -A edpd
        DEPENDS edpd
        COMMENT "Binary size breakdown"
    )
endif()

message(STATUS "EDP build configuration:")
message(STATUS "  Cross-compiling: ${CMAKE_CROSSCOMPILING}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
