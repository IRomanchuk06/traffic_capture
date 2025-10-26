file(GLOB UNIT_TEST_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(unit_tests ${UNIT_TEST_FILES})

target_link_libraries(unit_tests PRIVATE
    traffic_capture_lib
    GTest::GTest
    GTest::Main
)

target_include_directories(unit_tests PRIVATE ${CMAKE_SOURCE_DIR}/h)

gtest_discover_tests(unit_tests)
