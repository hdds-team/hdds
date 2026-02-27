add_executable(basic_pubsub basic_pubsub.cpp)
target_link_directories(basic_pubsub PRIVATE ${HDDS_C_LIB})
target_link_libraries(basic_pubsub hdds_cxx hdds_c pthread dl m)
