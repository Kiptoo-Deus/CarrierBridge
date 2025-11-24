cmake_minimum_required(VERSION 3.20)
project(CarrierBridge VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Library
add_library(carrierbridge SHARED
    src/carrierbridge/core.cpp
)

target_include_directories(carrierbridge PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/carrierbridge/include>
)

# CLI app
add_executable(carrierbridgectl src/app/main.cpp)
target_link_libraries(carrierbridgectl PRIVATE carrierbridge)

# Enable testing
enable_testing()
add_subdirectory(tests)
