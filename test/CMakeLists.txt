file(GLOB_RECURSE TALK_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

# Test with dynamic library
foreach (test_file ${TALK_TESTS})
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name} ${test_file})
    target_link_libraries(${test_name} talk)
    target_include_directories(${test_name} PRIVATE ../include)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Test with static library

foreach (test_file ${TALK_TESTS})
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name}_static ${test_file})
    target_link_libraries(${test_name}_static talk_static)
    target_include_directories(${test_name}_static PRIVATE ../include)
    add_test(NAME ${test_name}_static COMMAND ${test_name}_static)
endforeach()


