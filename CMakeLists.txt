cmake_minimum_required(VERSION 3.10)
project(CarrierBridge)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM libsodium)

if(NOT LIBSODIUM_FOUND)
    message(FATAL_ERROR "libsodium not found. Install with: brew install libsodium (macOS) or apt install libsodium-dev (Linux)")
endif()

include_directories(src/libsecurecomm/include)
include_directories(${LIBSODIUM_INCLUDE_DIRS})
link_directories(${LIBSODIUM_LIBRARY_DIRS})

# Core library sources
set(LIBSECURECOMM_SOURCES
    src/libsecurecomm/src/ratchet.cpp
    src/libsecurecomm/src/crypto.cpp
    src/libsecurecomm/src/dispatcher.cpp
    src/libsecurecomm/src/envelope.cpp
    src/libsecurecomm/src/in_memory_transport.cpp
    src/libsecurecomm/src/mls_manager.cpp
)

# Desktop demo
add_executable(desktop_demo
    src/libsecurecomm/src/clients/desktop/main.cpp
    ${LIBSECURECOMM_SOURCES}
)
target_link_libraries(desktop_demo ${LIBSODIUM_LIBRARIES})

# Enable testing
enable_testing()

# Ratchet unit tests
add_executable(ratchet_test
    src/libsecurecomm/tests/ratchet_test.cpp
    ${LIBSECURECOMM_SOURCES}
)
target_link_libraries(ratchet_test ${LIBSODIUM_LIBRARIES})
add_test(NAME RatchetTest COMMAND ratchet_test)

# Crypto unit tests
add_executable(crypto_test
    src/libsecurecomm/tests/crypto_test.cpp
    src/libsecurecomm/src/crypto.cpp
)
target_link_libraries(crypto_test ${LIBSODIUM_LIBRARIES})
add_test(NAME CryptoTest COMMAND crypto_test)


message(STATUS "Build Configuration:")
message(STATUS "  CMAKE_CXX_STANDARD: ${CMAKE_CXX_STANDARD}")
message(STATUS "  libsodium: ${LIBSODIUM_LIBRARIES}")
message(STATUS "  Tests enabled: ratchet_test, crypto_test")
