cmake_minimum_required(VERSION 3.29)
project(talk)

set(CMAKE_CXX_STANDARD 23)

file(GLOB_RECURSE TALK_SOURCES src/impl/*.cpp)

add_library(talk STATIC ${TALK_SOURCES})
target_include_directories(talk PUBLIC src/include)
target_include_directories(talk PRIVATE src/headers)
