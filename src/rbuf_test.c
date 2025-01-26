#include <stdio.h>
#include <assert.h>
#include "ring_buffer.h"

int main() {
    printf("page size is %ld bytes\n", sysconf(_SC_PAGESIZE));
    struct RingBuffer *rb = rb_init(sysconf(_SC_PAGESIZE));

    for (int i = 0; i < rb->buffer_size; i++) {
        uint8_t byte = randchar();
        assert(rb_write(rb, &byte, 1));
    }

    char buffer[16384];

    assert(count(rb) == 4096);

    assert(rb_read(rb, (uint8_t *) buffer, 4090));

    char *lol = "Hello world my name is Vansh";

    assert(rb_write(rb, (uint8_t *) lol, strlen(lol)));

    /* assert(rb_read(rb, (uint8_t *) buffer, 28)); */

    for (int i = 0; i < rb->buffer_size; i++) {
        char c = rb->buffer[i];
        printf("[0x%x] = %c", i, c);
        if (i == rb->read_index)    printf(" (r)");
        if (i == rb->write_index)   printf(" (w)");
        putchar('\n');
    }

    printf("\n---------\n\n");

    for (int i = rb->buffer_size; i < 2 * rb->buffer_size; i++) {
        char c = rb->buffer[i];
        printf("[0x%x] = %c", i, c);
        if (i == rb->read_index)    printf(" (r)");
        if (i == rb->write_index)   printf(" (w)");
        putchar('\n');
    }

    rb_destroy(rb);

    return 0;
}

