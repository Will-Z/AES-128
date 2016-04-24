cmake_minimum_required(VERSION 3.3)
project(tiny_AES128)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES aes.cpp aes.h test.cpp)
add_executable(tiny_AES128 ${SOURCE_FILES})