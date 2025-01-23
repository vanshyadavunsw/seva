#!/bin/sh

gcc -Wall -Wextra -fsanitize=address -g -o program_asan \
    src/*.c \
    lib/murmurhash/murmurhash.c \
    -I./lib/murmurhash

gcc -Wall -Wextra -g -o program_leaks \
    src/*.c \
    lib/murmurhash/murmurhash.c \
    -I./lib/murmurhash
