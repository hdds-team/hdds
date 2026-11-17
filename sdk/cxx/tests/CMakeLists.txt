# sdk/cxx/tests/CMakeLists.txt
# C++ SDK tests, registered with CTest. Run with the hdds-c library on the
# loader path (LD_LIBRARY_PATH=${HDDS_C_LIB}).

find_package(Threads REQUIRED)

add_executable(test_listener test_listener.cpp)
target_link_directories(test_listener PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_listener PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_listener COMMAND test_listener)
set_tests_properties(test_listener PROPERTIES TIMEOUT 60)

add_executable(test_qos test_qos.cpp)
target_include_directories(test_qos PRIVATE ${HDDS_C_INCLUDE})
target_link_directories(test_qos PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_qos PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_qos COMMAND test_qos)
set_tests_properties(test_qos PROPERTIES TIMEOUT 60)

add_executable(test_access test_access.cpp)
target_link_directories(test_access PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_access PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_access COMMAND test_access)
set_tests_properties(test_access PROPERTIES TIMEOUT 60)

add_executable(test_datarep test_datarep.cpp)
target_include_directories(test_datarep PRIVATE ${HDDS_C_INCLUDE})
target_link_directories(test_datarep PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_datarep PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_datarep COMMAND test_datarep)
set_tests_properties(test_datarep PROPERTIES TIMEOUT 60)

add_executable(test_extensibility test_extensibility.cpp)
target_link_directories(test_extensibility PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_extensibility PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_extensibility COMMAND test_extensibility)
set_tests_properties(test_extensibility PROPERTIES TIMEOUT 60)

add_executable(test_status_timestamp test_status_timestamp.cpp)
target_include_directories(test_status_timestamp PRIVATE ${HDDS_C_INCLUDE})
target_link_directories(test_status_timestamp PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_status_timestamp PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_status_timestamp COMMAND test_status_timestamp)
set_tests_properties(test_status_timestamp PROPERTIES TIMEOUT 60 ENVIRONMENT "HDDS_INTERFACE=lo")

add_executable(test_type_name test_type_name.cpp)
target_include_directories(test_type_name PRIVATE ${HDDS_C_INCLUDE})
target_link_directories(test_type_name PRIVATE ${HDDS_C_LIB})
target_link_libraries(test_type_name PRIVATE hdds_cxx hdds_c Threads::Threads dl m)
add_test(NAME test_type_name COMMAND test_type_name)
set_tests_properties(test_type_name PROPERTIES TIMEOUT 60)
