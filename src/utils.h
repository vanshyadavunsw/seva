#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

#include "allocators/allocator.h"

struct ByteSlice {
    uint8_t *ptr;
    size_t len;
};

static inline struct ByteSlice
byte_slice(uint8_t *ptr, size_t len)
{
    return (struct ByteSlice) { .ptr = ptr, .len = len };
}

void *
memdup(struct Allocator *allocator, const void *src, size_t n);

int
mem_hex_to_u32(uint8_t *buf, size_t n, uint32_t *dst);

int
memncmp(const void *buf1, size_t n1, const void *buf2, size_t n2);

#endif
