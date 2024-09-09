cmake_minimum_required(VERSION 3.29)
project(talk)

set(CMAKE_CXX_STANDARD 23)

file(GLOB_RECURSE TALK_SOURCES src/generic-impl/*.cpp)

option(USE_OPENSSL "Use OpenSSL" ON)

# Platform specific

# if CMAKE_SYSTEM_NAME is Linux
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(GLOB_RECURSE TALK_SOURCES_LINUX src/linux-impl/*.cpp)
    list(APPEND TALK_SOURCES ${TALK_SOURCES_LINUX})
endif()

if(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    file(GLOB_RECURSE TALK_SOURCES_OPENSSL src/openssl-impl/*.cpp)
    list(APPEND TALK_SOURCES ${TALK_SOURCES_OPENSSL})
endif()

add_library(talk SHARED ${TALK_SOURCES})
target_include_directories(talk PUBLIC include/talk)
target_include_directories(talk PRIVATE src/headers)

add_library(talk_static STATIC ${TALK_SOURCES})
target_include_directories(talk_static PUBLIC include/talk)
target_include_directories(talk_static PRIVATE src/headers)

if (USE_OPENSSL)
    target_include_directories(talk_static PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(talk_static OpenSSL::Crypto)

    target_include_directories(talk PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(talk OpenSSL::Crypto)
endif()

    # Add the testing option
option(BUILD_TESTS "Build the tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

