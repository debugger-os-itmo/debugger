cmake_minimum_required(VERSION 3.0)
project(debugger)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -Werror -O2")

set(SOURCE_FILES debugger.cpp
        debug_info.cpp debug_info.h)

add_executable(dbg ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(dbg dwarf elf)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -g")

set(TEST_FILES hello.c)

add_executable(hello ${TEST_FILES})


