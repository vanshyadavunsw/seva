#include "allocators/gpa.h"
#include "http.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int
main(void)
{
    printf("Hello, world.\n");

    char *test = "///abc/def/h/g/%48%65%6c%6C%6f%20%57%6F%72%6C%64//?himynameis=?";

    printf("Testing \"%s\"\n", test);

    struct HttpRequestTarget *t;

    int res = parse_request_target(
        get_gpalloc(),
        byte_slice((uint8_t *) test, strlen(test)),
        &t
    );

    assert(res == SEVA_OK);

    printf("n segments = %zu\n", t->segments->count);

    for (size_t i = 0; i < t->segments->count; i++) {
        printf("[%zu] ", i);
        struct ByteSlice slice = t->segments->array[i].slice;

        for (size_t j = 0; j < slice.len; j++) {
            putchar(slice.ptr[j]);
        }

        putchar('\n');
    }

    printf("Query: ");

    for (size_t i = 0; i < t->query.len; i++) {
        putchar(t->query.ptr[i]);
    }

    putchar('\n');

    free_request_target(t);

    return EXIT_SUCCESS;
}
