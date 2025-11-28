cmake_minimum_required(VERSION 3.16)
project(SecureCommPlatform LANGUAGES C CXX)

# Multi-language project
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Protocol Buffers setup
find_package(Protobuf REQUIRED)

# Generate protos for all languages
set(PROTO_FILES 
    core/proto/securecomm.proto
    core/proto/payment.proto
    core/proto/vpn.proto
)

# Create proto generation targets
protobuf_generate_cpp(PROTO_CPP_SRCS PROTO_CPP_HDRS ${PROTO_FILES})

# Create a library for generated protos
add_library(securecomm_protos ${PROTO_CPP_SRCS} ${PROTO_CPP_HDRS})
target_link_libraries(securecomm_protos PUBLIC protobuf::libprotobuf)
target_include_directories(securecomm_protos PUBLIC 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${Protobuf_INCLUDE_DIRS}
)

# Include C++ subproject (will be updated to use protos)
add_subdirectory(cpp)

# Create convenience targets for other languages
add_custom_target(build-go
    COMMENT "Building Go components..."
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/go
    COMMAND go build ./...
)

add_custom_target(build-rust
    COMMENT "Building Rust components..."
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
    COMMAND cargo build --release
)

add_custom_target(build-all
    DEPENDS securecomm_protos build-go build-rust
    COMMENT "Building all components..."
)

# Generate Go protobufs
find_program(PROTOC_GEN_GO protoc-gen-go)
if(PROTOC_GEN_GO)
    add_custom_target(generate-go-protos
        COMMAND protoc --go_out=${CMAKE_SOURCE_DIR}/go --go_opt=paths=source_relative 
                -I=${CMAKE_SOURCE_DIR}/core/proto ${PROTO_FILES}
        COMMENT "Generating Go protobuf files"
    )
endif()

# Installation
install(TARGETS securecomm_protos
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY core/proto/
    DESTINATION include/securecomm/proto
    FILES_MATCHING PATTERN "*.proto"
)