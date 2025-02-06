enable_testing()
cmake_minimum_required(VERSION 3.10)
project(Seva)

set(CMAKE_C_STANDARD 11)

set(MURMURHASH_INCLUDE_DIR lib/murmurhash)
set(MURMURHASH_SOURCES lib/murmurhash/murmurhash.c)

set(APP_SOURCES
    src/htable.c
    src/http.c
    src/ring_buffer.c
)

add_executable(seva src/main.c ${APP_SOURCES} ${MURMURHASH_SOURCES})
target_include_directories(seva PUBLIC ${MURMURHASH_INCLUDE_DIR})

# Tests
file(GLOB_RECURSE TEST_SOURCES "tests/*.c")

foreach(TEST_FILE ${TEST_SOURCES})
    get_filename_component(TEST_NAME "${TEST_FILE}" NAME_WE)
    add_executable(${TEST_NAME} ${TEST_FILE} ${APP_SOURCES} ${MURMURHASH_SOURCES})
    target_include_directories(${TEST_NAME} PUBLIC ${MURMURHASH_INCLUDE_DIR})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()

set_target_properties(seva PROPERTIES
    COMPILE_COMMANDS_JSON_DIR "${CMAKE_BINARY_DIR}"
)

foreach(TEST_NAME)
    set_target_properties(${TEST_NAME} PROPERTIES
        COMPILE_COMMANDS_JSON_DIR "${CMAKE_BINARY_DIR}"
    )
endforeach()
