#include "ring_buffer.h"
#include <stdio.h>
#include <stdlib.h>

struct RingBuffer *rb_init(rbsize_t size) {
    struct RingBuffer *rb = malloc(sizeof(struct RingBuffer));
    if (rb == NULL) return NULL;

    rb->buffer = malloc(size);
    if (rb->buffer == NULL) {
        free(rb);
        return NULL;
    }

    rb->size = size;
    rb->write_index = 0;
    rb->read_index = 0;
    rb->count = 0;

    return rb;
}

void rb_free(struct RingBuffer *rb) {
    free(rb->buffer);
    free(rb);
}

int rb_write(struct RingBuffer *rb, const uint8_t *byte) {
    if (rb->count == rb->size) return 0;
    rb->buffer[rb->write_index] = *byte;
    rb->write_index = (rb->write_index + 1) % rb->size;
    rb->count++;
    return 1;
}

int rb_read(struct RingBuffer *rb, uint8_t *dst) {
    if (rb->count == 0) return 0;
    *dst = rb->buffer[rb->read_index];
    rb->read_index = (rb->read_index + 1) % rb->size;
    rb->count--;
    return 1;
}

int rb_match(
    struct RingBuffer *rb,
    const uint8_t *pattern,
    const rbsize_t patlen
) {
    if (patlen > rb->count) return 0;
    rbsize_t read_index = rb->read_index;
    for (int i = 0; i < patlen; i++) {
        if (pattern[i] != rb->buffer[read_index]) return 0; 
        read_index = (read_index + 1) % rb->size;
    }
    return 1;
}

void rb_print(const struct RingBuffer *rb) {
    printf(
        "size = %u, count = %u, write index = %u, read_index = %u\n\n",
        rb->size, rb->count, rb->write_index, rb->read_index
    );

    for (int i = 0; i < rb->size; i++) {
        if (i == rb->read_index) putchar('r');
        if (i == rb->write_index) putchar('w');
        putchar('\t');
    }
    printf("\n");

    for (int i = 0; i < rb->size; i++) {
        printf("%d\t", i);
    }
    printf("\n");

    for (int i = 0; i < rb->size; i++) {
        printf("%c\t", (char) rb->buffer[i]);
    }
    printf("\n\n");
}

