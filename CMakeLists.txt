cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_COMPILER clang)
project(Seva)

option(ASAN "Enable AddressSanitizer" OFF)
option(LSAN "Enable LeakSanitizer" OFF)
option(USAN "Enable UndefinedBehaviorSanitizer" OFF)
option(TSAN "Enable ThreadSanitizer" OFF)
option(MSAN "Enable MemorySanitizer" OFF)

option(ENABLE_CLANG_TIDY "Enable clang-tidy checks during build" OFF)
if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
    if(CLANG_TIDY_EXE)
        set(CMAKE_C_CLANG_TIDY ${CLANG_TIDY_EXE})
        message(STATUS "clang-tidy enabled: ${CLANG_TIDY_EXE}")
    else()
        message(WARNING "clang-tidy requested but executable not found")
    endif()
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wformat-security -Wunused -Wconversion -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes")

    if(NOT (ASAN OR MSAN OR USAN))
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
    endif()

    if(ASAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    endif()

    if(LSAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=leak")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=leak")
    endif()

    if(USAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
    endif()

    if(TSAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    endif()

    if(MSAN)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=memory -fsanitize-memory-track-origins")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=memory")
    endif()
endif()

set(CMAKE_C_STANDARD 23)

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Find all source files recursively
file(GLOB_RECURSE ALL_SOURCES "src/*.c")
file(GLOB_RECURSE HEADERS "src/*.h")

# Find the main.c file
file(GLOB MAIN_SOURCE "src/main.c" "src/*/main.c")

# Create a list of sources without main.c
set(LIB_SOURCES ${ALL_SOURCES})
list(REMOVE_ITEM LIB_SOURCES ${MAIN_SOURCE})

# Include directories for headers
include_directories(src)

# Create a library with all code except main.c
add_library(seva_lib STATIC ${LIB_SOURCES})

# Create main executable with main.c and link to the library
add_executable(seva ${MAIN_SOURCE})
target_link_libraries(seva seva_lib)

# Enable testing
enable_testing()

# Find all test files
file(GLOB_RECURSE TEST_SOURCES "tests/*.c")

# Create a test executable for each test file and link to the library
foreach(TEST_SOURCE ${TEST_SOURCES})
    # Get the filename without extension
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)

    # Create an executable for this test
    add_executable(${TEST_NAME} ${TEST_SOURCE})

    # Link with the library
    target_link_libraries(${TEST_NAME} seva_lib)

    # Add the test to CTest
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()
