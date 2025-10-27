include(GoogleTest)

add_executable(unit_tests
  test_frame_parser.cpp
  test_arp_parser.cpp
  test_ipv4_parser.cpp
  test_pcap_writer.cpp
  test_cli.cpp
)

target_link_libraries(unit_tests
  PRIVATE
    traffic_capture_lib
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(unit_tests 
  PRIVATE 
    ${CMAKE_SOURCE_DIR}/h
)

gtest_discover_tests(unit_tests
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)
