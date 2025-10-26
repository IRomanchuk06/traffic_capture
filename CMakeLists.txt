cmake_minimum_required(VERSION 3.20)
project(traffic_capture LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

file(GLOB_RECURSE SRC_FILES
  ${CMAKE_SOURCE_DIR}/src/*.cpp
  ${CMAKE_SOURCE_DIR}/src/**/*.cpp
)

add_executable(traffic_capture ${SRC_FILES})
target_include_directories(traffic_capture PRIVATE ${CMAKE_SOURCE_DIR}/h)

target_compile_options(traffic_capture PRIVATE -Wall -Wextra -Wpedantic)

find_package(Threads REQUIRED)
target_link_libraries(traffic_capture PRIVATE Threads::Threads)