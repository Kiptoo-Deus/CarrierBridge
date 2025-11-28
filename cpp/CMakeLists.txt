cmake_minimum_required(VERSION 3.16)
project(CarrierBridge VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_SHARED_LIB "Build CarrierBridge as shared library" ON)


# ASIO
if(EXISTS "${CMAKE_SOURCE_DIR}/external/asio/CMakeLists.txt")
    add_subdirectory(${CMAKE_SOURCE_DIR}/external/asio EXCLUDE_FROM_ALL)
    add_library(asio::asio INTERFACE IMPORTED)
    target_include_directories(asio::asio INTERFACE "${CMAKE_SOURCE_DIR}/external/asio/asio/include")
else()
    include(FetchContent)
    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG        asio-1-30-2
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(asio)
    add_library(asio::asio INTERFACE IMPORTED)
    target_include_directories(asio::asio INTERFACE "${asio_SOURCE_DIR}/asio/include")
endif()

target_compile_definitions(asio::asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)

# Protobuf (from root)
find_package(Protobuf REQUIRED)

# ------------------------------------------------------------------
# Enhanced libcarb with protocol support
# ------------------------------------------------------------------
set(LIBCARB_SOURCES
    src/libcarb/core.cpp
    src/libcarb/broker.cpp
    src/libcarb/client.cpp
  
    src/libcarb/protocol_handler.cpp
    src/libcarb/crypto_bridge.cpp
)

if(BUILD_SHARED_LIB)
    add_library(libcarb SHARED ${LIBCARB_SOURCES})
else()
    add_library(libcarb STATIC ${LIBCARB_SOURCES})
endif()

# Link dependencies
target_link_libraries(libcarb 
    PUBLIC 
        asio::asio
        securecomm_protos
)

target_include_directories(libcarb
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>  # For generated protos
)

if (MSVC)
    target_compile_definitions(libcarb PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(libcarb PROPERTIES OUTPUT_NAME carrierbridge)

# ------------------------------------------------------------------
# Enhanced broker with protocol support
# ------------------------------------------------------------------
add_executable(broker_app src/broker/broker_main.cpp)
target_link_libraries(broker_app PRIVATE libcarb)

# ------------------------------------------------------------------
# Enhanced client with protocol support  
# ------------------------------------------------------------------
add_executable(client_app src/client/client_main.cpp)
target_link_libraries(client_app PRIVATE libcarb)

# ------------------------------------------------------------------
# New VPN engine (I will create this)
# ------------------------------------------------------------------
add_library(vpn_engine 
    vpn_engine/vpn_client.cpp
    vpn_engine/vpn_server.cpp
)
target_link_libraries(vpn_engine PRIVATE libcarb securecomm_protos)

# ------------------------------------------------------------------
# Crypto engine (bridge to Rust)
# ------------------------------------------------------------------
add_library(crypto_engine
    crypto_engine/rust_bridge.cpp
    crypto_engine/crypto_utils.cpp
)
target_link_libraries(crypto_engine PRIVATE libcarb)

# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)

# ------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------
install(TARGETS libcarb broker_app client_app vpn_engine crypto_engine
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")