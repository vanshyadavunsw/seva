enable_testing()
cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Seva)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
endif()

set(CMAKE_C_STANDARD 23)

set(MURMURHASH_INCLUDE_DIR vendor/murmurhash)
set(MURMURHASH_SOURCES vendor/murmurhash.c)

set(APP_SOURCES
    src/htable.c
    src/http.c
    src/ring_buffer.c
    src/utils.c
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
