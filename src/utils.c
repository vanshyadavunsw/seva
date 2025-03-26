#include <string.h>
#include <stdint.h>
#include "allocators/allocator.h"
#include "utils.h"
#include "abnf.h"

static const uint8_t hex_dig_to_dec[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
    ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15
};

int
mem_hex_to_u32(uint8_t *buf, size_t n, uint32_t *dst)
{
    if (n == 0) {
        return -1;
    }

    uint32_t value = 0;

    for (size_t i = 0; i < n; i++) {
        if (!is_hex_dig(buf[i])) {
            return -1;
        }

        uint8_t digit = hex_dig_to_dec[buf[i]];

        if (value > (UINT32_MAX - digit) / 16) {
            return -1;
        }

        value = value * 16 + hex_dig_to_dec[buf[i]];
    }

    *dst = value;

    return 0;
}

void *
memdup(struct Allocator *allocator, const void *src, size_t n)
{
    void *p = ALLOC(allocator, n);

    if (p == NULL) {
        return NULL;
    }

    memcpy(p, src, n);
    return p;
}

int
memncmp(const void *buf1, size_t n1, const void *buf2, size_t n2)
{
    if (n1 != n2) {
        return -1;
    }

    if (n1 == 0) {
        return 0;
    }

    return memcmp(buf1, buf2, n1);
}
