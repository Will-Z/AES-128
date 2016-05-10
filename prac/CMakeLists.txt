cmake_minimum_required(VERSION 3.3)
project(prac)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES    R.cpp)
add_executable(prac ${SOURCE_FILES})