#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t rbsize_t;

struct RingBuffer {
    rbsize_t size;
    rbsize_t write_index;
    rbsize_t read_index;
    rbsize_t count;
    uint8_t *buffer;
};

struct RingBuffer *rb_init(rbsize_t size);

void rb_free(struct RingBuffer *rb);

int rb_write(struct RingBuffer *rb, const uint8_t *byte);

int rb_read(struct RingBuffer *rb, uint8_t *dst);

int rb_match(
    struct RingBuffer *rb,
    const uint8_t *pattern,
    const rbsize_t patlen
);

void rb_print(const struct RingBuffer *rb);

#endif
