cmake_minimum_required(VERSION 3.10.2)
project(carrierbridge_jni)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(ANDROID)
    message(STATUS "Building carrierbridge_jni for Android ABI ${ANDROID_ABI}")
endif()

# Build a self-contained JNI library using only the local `native-lib.cpp` stub.
add_library(carrierbridge_jni SHARED native-lib.cpp)

find_library(log-lib log)

target_include_directories(carrierbridge_jni PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(carrierbridge_jni PRIVATE -fPIC)

if(log-lib)
    target_link_libraries(carrierbridge_jni PRIVATE ${log-lib})
endif()

message(STATUS "Configured self-contained JNI library: carrierbridge_jni (stub)")
