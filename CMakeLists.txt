cmake_minimum_required(VERSION 3.29)
project(talk)

set(CMAKE_CXX_STANDARD 23)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB_RECURSE TALK_SOURCES src/impl/*.cpp)

add_library(talk STATIC ${TALK_SOURCES})
target_include_directories(talk PUBLIC src/include)
target_include_directories(talk PRIVATE src/headers)

target_link_libraries(talk OpenSSL)
