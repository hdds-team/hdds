cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

set(HDDS_PROJECT_VERSION "")

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml")
  message(WARNING "Unable to find 'Cargo.toml' in current directory: project version UNKNOWN")
else()
  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml" HDDS_CARGO_TOML)
  set(HDDS_SEARCHING_FOR_VERSION OFF)
  foreach(line IN LISTS HDDS_CARGO_TOML)
    # Search in Cargo.toml for the pattern 'major[.minor][.patch][.tweak]'
    if(HDDS_SEARCHING_FOR_VERSION AND "${line}" MATCHES "version[\r\n\t ]*=[\r\n\t ]*\"?([0-9]+([\.][0-9]+)?([\.][0-9]+)?([\.][0-9]+)?)\"?$")
      set(HDDS_PROJECT_VERSION ${CMAKE_MATCH_1})
      break()
    endif()

    if(${line} MATCHES "workspace.package")
      set(HDDS_SEARCHING_FOR_VERSION ON)
    endif()
  endforeach()
endif()

if(NOT HDDS_PROJECT_VERSION)
  message(WARNING "Unable to read rust library version")
endif()

project(hdds
    VERSION ${HDDS_PROJECT_VERSION}
    DESCRIPTION "High-performance DDS"
    LANGUAGES C CXX
)

option(BUILD_SHARED_LIBS "Build static or shared library" OFF)
option(BUILD_HDDS_CXX "Enable building hdds_cxx library" ON)

# Set CMAKE_BUILD_TYPE if neither parent nor project set it or if we are using
# a multi-config generator
get_property(HDDS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT HDDS_MULTI_CONFIG AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type for the library")
endif()

# Ensure cargo is installed
set(CARGO_EXECUTABLE)
find_program(CARGO_EXECUTABLE NAMES cargo)
if("${CARGO_EXECUTABLE}" STREQUAL "CARGO_EXECUTABLE-NOTFOUND")
  message(FATAL_ERROR "Cargo not found. Look at: https://rust-lang.org/learn/get-started")
endif()

# Determine library extensions and suffixes for the current OS
if(WIN32)
  set(HDDS_SHARED_LIBRARY_EXTENSION "dll")
  set(HDDS_STATIC_LIBRARY_EXTENSION "lib")
  set(HDDS_LIBRARY_PREFIX "")
else()
  set(HDDS_SHARED_LIBRARY_EXTENSION "so")
  set(HDDS_STATIC_LIBRARY_EXTENSION "a")
  set(HDDS_LIBRARY_PREFIX "lib")
endif()
set(HDDS_C_LIBRARY_NAME ${HDDS_LIBRARY_PREFIX}hdds_c)

# Use the build type to know the folder in which the library will be built
if("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    string(TOLOWER "${CMAKE_BUILD_TYPE}" HDDS_BUILD_TYPE)
else()
    set(HDDS_BUILD_TYPE "release")
endif()

set(HDDS_CMAKE_LIBRARY_TYPE "STATIC")
if(BUILD_SHARED_LIBS)
  set(HDDS_CMAKE_LIBRARY_TYPE "SHARED")
endif()

# Set the path to the library binary file depending on the build type
set(HDDS_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/${HDDS_BUILD_TYPE}")
if(BUILD_SHARED_LIBS)
  set(HDDS_LIBRARY_OUTPUT ${HDDS_OUTPUT_DIR}/${HDDS_C_LIBRARY_NAME}.${HDDS_SHARED_LIBRARY_EXTENSION})
else()
  set(HDDS_LIBRARY_OUTPUT ${HDDS_OUTPUT_DIR}/${HDDS_C_LIBRARY_NAME}.${HDDS_STATIC_LIBRARY_EXTENSION})
endif()

# Set location of library headers
set(HDDS_C_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/sdk/c/include")
set(HDDS_C_HEADERS "${HDDS_C_INCLUDE_DIR}/hdds.h")

# Set build flag for cargo only if building in Release
if(${HDDS_BUILD_TYPE} STREQUAL "release")
    set(HDDS_CARGO_RELEASE_BUILD_FLAG "--${HDDS_BUILD_TYPE}")
endif()

# Add a custom command to build the library and a custom target that depends on the output of the command
# that will triger the cargo build task
add_custom_target(${PROJECT_NAME}_rust ALL
  ${CARGO_EXECUTABLE} "rustc" "--manifest-path" "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
                      "--package" "hdds-c" "${HDDS_CARGO_RELEASE_BUILD_FLAG}"
                      "--crate-type" $<IF:$<BOOL:${BUILD_SHARED_LIBS}>,cdylib,staticlib>
                      "--target-dir" "${CMAKE_CURRENT_BINARY_DIR}"
  DEPENDS ${HDDS_C_HEADERS} # CMake will re-run the command whenever the files change
  BYPRODUCTS ${HDDS_LIBRARY_OUTPUT}
  VERBATIM
)

# Generate the imported library for HDDS and link it to the custom target to ensure the custom command to be called
add_library(${PROJECT_NAME}_c ${HDDS_CMAKE_LIBRARY_TYPE} IMPORTED GLOBAL ${HDDS_C_HEADERS})
add_library(${PROJECT_NAME}::${PROJECT_NAME}_c ALIAS ${PROJECT_NAME}_c)

if (WIN32)
  # Link Windows libraries
  target_link_libraries(${PROJECT_NAME}_c INTERFACE ntdll kernel32 ws2_32 userenv iphlpapi bcrypt)
endif()

# Manually specify the dependency between HDDS target and the fake one to ensure compiler will not invert the order
add_dependencies(${PROJECT_NAME}_c ${PROJECT_NAME}_rust)

# Change imported library location to the built one
set(HDDS_LIBRARY_IMPORTED_LOCATION ${HDDS_LIBRARY_OUTPUT})

# Set imported target library location and implib.
# On Windows if the library is static then both properties
# must be the same .lib file. On Linux the 'IMPORTED_IMPLIB' will be ignored
set_target_properties(
  ${PROJECT_NAME}_c
  PROPERTIES IMPORTED_LOCATION ${HDDS_LIBRARY_IMPORTED_LOCATION}
             IMPORTED_IMPLIB ${HDDS_LIBRARY_OUTPUT}.${HDDS_STATIC_LIBRARY_EXTENSION}
)

target_include_directories(${PROJECT_NAME}_c INTERFACE 
  "${HDDS_C_INCLUDE_DIR}" # Allows inclusion as '#include <hdds.h>'
)

# Expose also hdds_cxx target
if(BUILD_HDDS_CXX)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/sdk/cxx")
endif()
