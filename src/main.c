#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "utils.h"
#include "./collections/vector.h"
#include "./allocators/gpa.h"

#define UNUSED [[maybe_unused]]

int
main(UNUSED int argc, UNUSED char *argv[])
{
    struct IntegerVector *v = integer_vec_init(get_gpalloc(), 5);

    assert(integer_vec_push(v, 1));
    assert(integer_vec_push(v, 2));
    assert(integer_vec_push(v, 3));
    assert(integer_vec_push(v, 4));
    assert(integer_vec_push(v, 5));
    assert(integer_vec_push(v, 6));

    printf("size: %zu\n", v->size);
    printf("count: %zu\n", v->count);

    for (size_t i = 0; i < v->count; i++) {
        printf("%d ", v->array[i]);
    }

    putchar('\n');

    integer_vec_free(v);

    struct BazVector *b = baz_vec_init(get_gpalloc(), 5);

    assert(baz_vec_push(b, (struct Baz) { 1, 2 }));
    assert(baz_vec_push(b, (struct Baz) { 3, 4 }));
    assert(baz_vec_push(b, (struct Baz) { 5, 6 }));
    assert(baz_vec_push(b, (struct Baz) { 7, 8 }));
    assert(baz_vec_push(b, (struct Baz) { 9, 10 }));
    assert(baz_vec_push(b, (struct Baz) { 11, 12 }));
    assert(baz_vec_push(b, (struct Baz) { 14, 14 }));

    printf("size: %zu\n", b->size);
    printf("count: %zu\n", b->count);

    for (size_t i = 0; i < b->count; i++) {
        struct Baz baz = b->array[i];
        printf("(%d, %d) ", baz.foo, baz.bar);
    }

    baz_vec_free(b);

    return EXIT_SUCCESS;
}
