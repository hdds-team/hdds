# IDL Code Generation for HDDS Samples
#
# Usage:
#   cmake -B build
#   cmake --build build
#
# This generates types for C, C++, Python, and Rust from all IDL files.

cmake_minimum_required(VERSION 3.16)
project(hdds_samples_idl)

# Find hdds_gen
find_program(HDDS_GEN hdds_gen
    HINTS
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../target/release
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../target/debug
        $ENV{HDDS_HOME}/bin
)

if(NOT HDDS_GEN)
    message(STATUS "hdds_gen not found, trying cargo build...")
    set(HDDS_GEN_CMD cargo run --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../hdds_gen/Cargo.toml --)
else()
    set(HDDS_GEN_CMD ${HDDS_GEN})
endif()

# IDL files to process
set(IDL_FILES
    HelloWorld.idl
    KeyedData.idl
    Primitives.idl
    Strings.idl
    Sequences.idl
    Arrays.idl
    Maps.idl
    Enums.idl
    Unions.idl
    Nested.idl
    Bits.idl
    Optional.idl
    RequestReply.idl
    Benchmark.idl
)

# Output directories
set(GEN_C_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../01_basics/c/generated)
set(GEN_CPP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../01_basics/cpp/generated)
set(GEN_PY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../01_basics/python/generated)
set(GEN_RS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../01_basics/rust/src/generated)

# Create output directories
file(MAKE_DIRECTORY ${GEN_C_DIR})
file(MAKE_DIRECTORY ${GEN_CPP_DIR})
file(MAKE_DIRECTORY ${GEN_PY_DIR})
file(MAKE_DIRECTORY ${GEN_RS_DIR})

# Generate code for each IDL
foreach(IDL_FILE ${IDL_FILES})
    get_filename_component(IDL_NAME ${IDL_FILE} NAME_WE)

    # C generation
    add_custom_command(
        OUTPUT ${GEN_C_DIR}/${IDL_NAME}.h ${GEN_C_DIR}/${IDL_NAME}.c
        COMMAND ${HDDS_GEN_CMD} --lang c --output ${GEN_C_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        COMMENT "Generating C code from ${IDL_FILE}"
    )

    # C++ generation
    add_custom_command(
        OUTPUT ${GEN_CPP_DIR}/${IDL_NAME}.hpp ${GEN_CPP_DIR}/${IDL_NAME}.cpp
        COMMAND ${HDDS_GEN_CMD} --lang cpp --output ${GEN_CPP_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        COMMENT "Generating C++ code from ${IDL_FILE}"
    )

    # Python generation
    add_custom_command(
        OUTPUT ${GEN_PY_DIR}/${IDL_NAME}.py
        COMMAND ${HDDS_GEN_CMD} --lang python --output ${GEN_PY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        COMMENT "Generating Python code from ${IDL_FILE}"
    )

    # Rust generation
    add_custom_command(
        OUTPUT ${GEN_RS_DIR}/${IDL_NAME}.rs
        COMMAND ${HDDS_GEN_CMD} --lang rust --output ${GEN_RS_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${IDL_FILE}
        COMMENT "Generating Rust code from ${IDL_FILE}"
    )

    list(APPEND GEN_C_FILES ${GEN_C_DIR}/${IDL_NAME}.h ${GEN_C_DIR}/${IDL_NAME}.c)
    list(APPEND GEN_CPP_FILES ${GEN_CPP_DIR}/${IDL_NAME}.hpp ${GEN_CPP_DIR}/${IDL_NAME}.cpp)
    list(APPEND GEN_PY_FILES ${GEN_PY_DIR}/${IDL_NAME}.py)
    list(APPEND GEN_RS_FILES ${GEN_RS_DIR}/${IDL_NAME}.rs)
endforeach()

# Create targets
add_custom_target(generate_c ALL DEPENDS ${GEN_C_FILES})
add_custom_target(generate_cpp ALL DEPENDS ${GEN_CPP_FILES})
add_custom_target(generate_python ALL DEPENDS ${GEN_PY_FILES})
add_custom_target(generate_rust ALL DEPENDS ${GEN_RS_FILES})

add_custom_target(generate_all ALL
    DEPENDS generate_c generate_cpp generate_python generate_rust
)
