#ifndef VECTOR_H
#define VECTOR_H

#include <stddef.h>
#include <stdbool.h>
#include "../allocators/allocator.h"

#define DEFINE_VECTOR_TYPE(type, prefix_1, prefix_2)                            \
                                                                                \
struct prefix_1##Vector {                                                       \
    struct Allocator *allocator;                                                \
    type *array;                                                                \
    size_t size;                                                                \
    size_t count;                                                               \
};                                                                              \
                                                                                \
static inline struct prefix_1##Vector *                                         \
prefix_2##_vec_init(struct Allocator *allocator, size_t initial_size)           \
{                                                                               \
    struct prefix_1##Vector *v = ALLOC(allocator, sizeof(*v));                  \
                                                                                \
    if (v == nullptr) {                                                         \
        return nullptr;                                                         \
    }                                                                           \
                                                                                \
    type *array = ALLOC(allocator, sizeof(type) * initial_size);                \
                                                                                \
    if (array == nullptr) {                                                     \
        SAFE_FREE(allocator, v);                                                \
        return nullptr;                                                         \
    }                                                                           \
                                                                                \
    *v = (struct prefix_1##Vector) {                                            \
        .allocator = allocator,                                                 \
        .array = array,                                                         \
        .size = initial_size,                                                   \
        .count = 0,                                                             \
    };                                                                          \
                                                                                \
    return v;                                                                   \
}                                                                               \
                                                                                \
static inline bool                                                              \
prefix_2##_vec_push(struct prefix_1##Vector *v, type i)                         \
{                                                                               \
    if (v->count == v->size) {                                                  \
        if (!HAS_REALLOC(v->allocator)) {                                       \
            return false;                                                       \
        }                                                                       \
                                                                                \
        type *new_array = REALLOC(v->allocator, v->array,                       \
                                  2 * v->size * sizeof(type));                  \
                                                                                \
        if (new_array == nullptr) {                                             \
            return false;                                                       \
        }                                                                       \
                                                                                \
        v->array = new_array;                                                   \
        v->size *= 2;                                                           \
    }                                                                           \
                                                                                \
    v->array[v->count++] = i;                                                   \
                                                                                \
    return true;                                                                \
}                                                                               \
                                                                                \
static inline bool                                                              \
prefix_2##_vec_free(struct prefix_1##Vector *v)                                 \
{                                                                               \
    if (!HAS_FREE(v->allocator)) {                                              \
        return false;                                                           \
    }                                                                           \
                                                                                \
    FREE(v->allocator, v->array);                                               \
    FREE(v->allocator, v);                                                      \
                                                                                \
    return true;                                                                \
}

DEFINE_VECTOR_TYPE(int, Integer, integer)

struct Baz {
    int foo;
    int bar;
};

DEFINE_VECTOR_TYPE(struct Baz, Baz, baz)

#endif
