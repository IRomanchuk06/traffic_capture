file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
list(FILTER SRC_FILES EXCLUDE REGEX ".*/main\\.cpp$")

add_library(traffic_capture_lib ${SRC_FILES})
target_include_directories(traffic_capture_lib PUBLIC ${CMAKE_SOURCE_DIR}/h)

find_package(Threads REQUIRED)
target_link_libraries(traffic_capture_lib PUBLIC Threads::Threads)

add_executable(traffic_capture main.cpp)
target_link_libraries(traffic_capture PRIVATE traffic_capture_lib)
