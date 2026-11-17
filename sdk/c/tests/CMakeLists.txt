# sdk/c/tests/CMakeLists.txt
# Builds and registers HDDS C SDK tests with CTest.

set(TESTS
    test_api_stability
    test_condition
    test_conditions
    test_datarep
    test_dynamic_filter
    test_participant
    test_qos
    test_waitset
)

foreach(test ${TESTS})
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} PRIVATE hdds::c)
    add_test(NAME ${test} COMMAND ${test})
endforeach()

# Unified test runner - invokes all test suites as subprocesses
add_executable(test_runner test_runner.c)
add_test(NAME test_runner COMMAND test_runner)

if(UNIX)
    # Listener callbacks run on HDDS threads; the test drives a writer from
    # a thread of its own (pthreads).
    add_executable(test_status_timestamp test_status_timestamp.c)
    target_link_libraries(test_status_timestamp PRIVATE hdds::c)
    add_test(NAME test_status_timestamp COMMAND test_status_timestamp)
    set_tests_properties(test_status_timestamp PROPERTIES TIMEOUT 60 ENVIRONMENT "HDDS_INTERFACE=lo")
    find_package(Threads REQUIRED)
    add_executable(test_listener test_listener.c)
    target_link_libraries(test_listener PRIVATE hdds::c Threads::Threads)
    add_test(NAME test_listener COMMAND test_listener)
    set_tests_properties(test_listener PROPERTIES TIMEOUT 60)
    target_compile_definitions(test_runner PRIVATE HDDS_WITH_LISTENER_TEST)
endif()

if(HDDS_WITH_RPC AND UNIX)
    find_package(Threads REQUIRED)
    add_executable(test_rpc test_rpc.c)
    target_link_libraries(test_rpc PRIVATE hdds::c Threads::Threads)
    add_test(NAME test_rpc COMMAND test_rpc)
    set_tests_properties(test_rpc PROPERTIES TIMEOUT 30)
    target_compile_definitions(test_runner PRIVATE HDDS_WITH_RPC)
endif()
