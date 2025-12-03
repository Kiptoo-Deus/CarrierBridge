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

# Find SQLite3
find_package(SQLite3 REQUIRED)

# Find libcurl
find_package(CURL REQUIRED)

include_directories(src/libsecurecomm/include)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

# Core library sources
set(LIBSECURECOMM_SOURCES
    src/libsecurecomm/src/ratchet.cpp
    src/libsecurecomm/src/crypto.cpp
    src/libsecurecomm/src/dispatcher.cpp
    src/libsecurecomm/src/envelope.cpp
    src/libsecurecomm/src/in_memory_transport.cpp
    src/libsecurecomm/src/mls_manager.cpp
    src/libsecurecomm/src/websocket_transport.cpp
)

# Offline queue library
set(OFFLINE_QUEUE_SOURCES
    src/libsecurecomm/src/modules/offline/queue_manager.cpp
)

# Mesh network library
set(MESH_NETWORK_SOURCES
    src/libsecurecomm/src/modules/mesh/mesh_network.cpp
)

# Enhanced dispatcher
set(ENHANCED_DISPATCHER_SOURCES
    src/libsecurecomm/src/enhanced_dispatcher.cpp
)

# Create standalone libraries
add_library(offline ${OFFLINE_QUEUE_SOURCES})
target_link_libraries(offline ${SQLite3_LIBRARIES})

add_library(mesh ${MESH_NETWORK_SOURCES})
target_link_libraries(mesh ${LIBSODIUM_LIBRARIES})

add_library(enhanced ${ENHANCED_DISPATCHER_SOURCES})
target_link_libraries(enhanced offline mesh)

# Desktop demo
add_executable(desktop_demo
    src/libsecurecomm/src/clients/desktop/main.cpp
    ${LIBSECURECOMM_SOURCES}
)
target_link_libraries(desktop_demo 
    ${LIBSODIUM_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${CURL_LIBRARIES}
    offline
    mesh
)

# Enable testing
enable_testing()

# Ratchet unit tests
add_executable(ratchet_test
    src/libsecurecomm/tests/ratchet_test.cpp
    ${LIBSECURECOMM_SOURCES}
)
target_link_libraries(ratchet_test 
    ${LIBSODIUM_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${CURL_LIBRARIES}
    offline
    mesh
)
add_test(NAME RatchetTest COMMAND ratchet_test)

# Crypto unit tests
add_executable(crypto_test
    src/libsecurecomm/tests/crypto_test.cpp
    src/libsecurecomm/src/crypto.cpp
)
target_link_libraries(crypto_test ${LIBSODIUM_LIBRARIES})
add_test(NAME CryptoTest COMMAND crypto_test)

# Two-party messaging test
add_executable(two_party_test
    src/libsecurecomm/tests/ratchet_two_party_test.cpp
    ${LIBSECURECOMM_SOURCES}
)
target_link_libraries(two_party_test 
    ${LIBSODIUM_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${CURL_LIBRARIES}
    offline
    mesh
)
add_test(NAME TwoPartyTest COMMAND two_party_test)


message(STATUS "Build Configuration:")
message(STATUS "  CMAKE_CXX_STANDARD: ${CMAKE_CXX_STANDARD}")
message(STATUS "  libsodium: ${LIBSODIUM_LIBRARIES}")
message(STATUS "  SQLite3: ${SQLite3_LIBRARIES}")
message(STATUS "  libcurl: ${CURL_LIBRARIES}")
message(STATUS "  Tests enabled: ratchet_test, crypto_test, two_party_test")

