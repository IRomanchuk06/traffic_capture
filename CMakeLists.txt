cmake_minimum_required(VERSION 3.20)
project(traffic_capture LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

option(BUILD_TESTS "Build tests" ON)

add_subdirectory(src)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

find_program(CLANG_FORMAT_PROGRAM clang-format)

if(CLANG_FORMAT_PROGRAM)
    file(GLOB_RECURSE ALL_SOURCE_FILES 
        CONFIGURE_DEPENDS
        ${CMAKE_SOURCE_DIR}/src/*.[ch]pp
        ${CMAKE_SOURCE_DIR}/h/*.[ch]pp
        ${CMAKE_SOURCE_DIR}/h/*.h
        ${CMAKE_SOURCE_DIR}/tests/unit/*.[ch]pp
    )

    add_custom_target(format
        COMMAND ${CLANG_FORMAT_PROGRAM} -i ${ALL_SOURCE_FILES}
        COMMENT "Formatting code with clang-format"
        VERBATIM
    )

    message(STATUS "Added 'format' target with ${CMAKE_LISTFILE_NUMBER_OF_ELEMENTS} files")
endif()
