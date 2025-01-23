#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "ring_buffer.h"

int main() {
    struct RingBuffer *rb = rb_init(4);
    memset(rb->buffer, '0', rb->size);

    for (;;) {
        rb_print(rb);
        char line[10];
        printf("Enter cmd (r/w): ");
        fgets(line, 10, stdin);
        char cmd = line[0];
        if (cmd == '\n') continue;
        if (cmd == 'r') {
            int res = rb_read(rb, (uint8_t *) &cmd);
            if (res == 0) printf("Buffer is empty\n");
        } else if (cmd == 'w') {
            char towrite = line[2];
            int res = rb_write(rb, (uint8_t *) &towrite);
            if (res == 0) printf("Buffer is full\n");
        } else if (cmd == 'm') {
            if (rb_match(rb, (uint8_t *) "WOW", 3)) {
                printf("Found pattern \"WOW\" at current read index\n");
            } else {
                printf("Pattern \"WOW\" not found\n");
            }
        }
        printf("\n");
    }
    return 0;
}
