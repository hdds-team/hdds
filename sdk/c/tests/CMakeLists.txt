# sdk/c/tests/CMakeLists.txt
# Builds and registers HDDS C SDK tests with CTest.

set(TESTS
    test_participant
    test_qos
    test_waitset
)

foreach(test ${TESTS})
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} PRIVATE hdds::c)
    add_test(NAME ${test} COMMAND ${test})
endforeach()

# Unified test runner — invokes all test suites as subprocesses
add_executable(test_runner test_runner.c)
add_test(NAME test_runner COMMAND test_runner)
