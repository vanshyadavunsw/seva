#include "../allocators/allocator.h"

/* Proof of concept for collections using the custom allocator
   interface. I've used arbitrary names for the type of the 
   vector (struct Baz) and its fields, because I want generic
   code-generating macros to be able to parameterize those
   tokens. For example, a macro could take a type T, e.g.
   "struct Baz", a prefix_1 for the vector "Baz", and a
   prefix_2 for the functions "baz" */

struct Baz {
    int foo;
    int bar;
};

struct BazVector {
    struct Allocator *allocator;
    struct Baz *array;
    size_t size;
    size_t count;
};

struct BazVector *
baz_vec_init(struct Allocator *a, size_t initial_size);

bool
baz_vec_push(struct BazVector *v, struct Baz i);

bool
baz_vec_free(struct BazVector *v);

struct BazVector *
baz_vec_init(struct Allocator *a, size_t initial_size)
{
    struct BazVector *v = ALLOC(a, sizeof(*v));

    if (v == nullptr) {
        return nullptr;
    }

    struct Baz *array = ALLOC(a, sizeof(struct Baz) * initial_size);

    if (array == nullptr) {
        SAFE_FREE(a, v);
        return nullptr;
    }

    *v = (struct BazVector) {
        .allocator = a,
        .array = array,
        .size = initial_size,
        .count = 0,
    };

    return v;
}

/**
 * Assumptions:
 *   - v is a valid struct BazVector.
 *   - v has a nonzero size.
 */
bool
baz_vec_push(struct BazVector *v, struct Baz i)
{
    if (v->count == v->size) {
        if (!HAS_REALLOC(v->allocator)) {
            return false;
        }

        struct Baz *new_array = REALLOC(v->allocator, v->array,
                                        2 * v->size * sizeof(struct Baz));

        if (new_array == NULL) {
            return false;
        }

        v->array = new_array;
        v->size *= 2;
    }

    v->array[v->count++] = i;

    return true;
}

/**
 * Assumptions:
 *   - v is a valid struct BazVector.
 *   - the pointers are to valid and freeable
 *     memory.
 */
bool
baz_vec_free(struct BazVector *v)
{
    if (!HAS_FREE(v->allocator)) {
        return false;
    }

    FREE(v->allocator, v->array);
    FREE(v->allocator, v);

    return true;
}

