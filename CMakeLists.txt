cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Seva)

option(USE_SANITIZER_ADDRESS "Enable AddressSanitizer" OFF)
option(USE_SANITIZER_LEAK "Enable LeakSanitizer" OFF)
option(USE_SANITIZER_UNDEFINED "Enable UndefinedBehaviorSanitizer" OFF)
option(USE_SANITIZER_THREAD "Enable ThreadSanitizer" OFF)
option(USE_SANITIZER_MEMORY "Enable MemorySanitizer" OFF)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wformat-security -Wunused -Wconversion -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

    if(USE_SANITIZER_ADDRESS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    endif()

    if(USE_SANITIZER_LEAK)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=leak")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=leak")
    endif()

    if(USE_SANITIZER_UNDEFINED)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
    endif()

    if(USE_SANITIZER_THREAD)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
    endif()

    if(USE_SANITIZER_MEMORY)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=memory -fsanitize-memory-track-origins")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=memory")
    endif()
endif()

set(CMAKE_C_STANDARD 23)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Find all source files recursively
file(GLOB_RECURSE SOURCES "src/*.c")
file(GLOB_RECURSE HEADERS "src/*.h")

# Include directories for headers
include_directories(src)

# Create executable with ALL source files
add_executable(seva ${SOURCES})

# enable_testing()
