#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

struct ByteSlice {
    uint8_t *ptr;
    size_t len;
};

static inline struct ByteSlice
byte_slice(uint8_t *ptr, size_t len)
{
    return (struct ByteSlice) { .ptr = ptr, .len = len };
}

#endif
