#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct RingBuffer {
    uint8_t *buffer; size_t buffer_size;
    size_t write_index;
    size_t read_index;
};

struct RingBuffer *rb_init(size_t size);

void rb_destroy(struct RingBuffer *rb);

bool rb_write(struct RingBuffer *rb, const uint8_t *src, size_t size);

bool rb_read(struct RingBuffer *rb, uint8_t *dst, size_t size);bool rb_read(struct RingBuffer *rb, uint8_t *dst, size_t size);

static inline size_t rb_count(struct RingBuffer *rb) {
    return rb->write_index - rb->read_index;
}

static inline uint8_t *rb_read_ptr(struct RingBuffer *rb, size_t *n) {
    *n = rb_count(rb);
    return &rb->buffer[rb->read_index];
}

static inline uint8_t *rb_write_ptr(struct RingBuffer *rb, size_t *n) {
    *n = rb->buffer_size - rb_count(rb);    /* bytes available */
    return &rb->buffer[rb->write_index];
}

#endif
