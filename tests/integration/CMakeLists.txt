add_executable(integration_tests
    test_loopback_capture.cpp
    test_real_capture.cpp
)

target_link_libraries(integration_tests
    PRIVATE
        traffic_capture_lib
        GTest::gtest
        GTest::gtest_main
)

target_include_directories(integration_tests 
    PRIVATE 
        ${CMAKE_SOURCE_DIR}/h
        ${CMAKE_CURRENT_SOURCE_DIR}/helpers
)

# Register tests
include(GoogleTest)
gtest_discover_tests(integration_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    PROPERTIES
        TIMEOUT 30
        LABELS "integration"
)
