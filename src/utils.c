#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "abnf.h"

int
memncmp(const void *buf1, size_t n1, const void *buf2, size_t n2)
{
    if (n1 != n2) {
        return -1;
    }

    return memcmp(buf1, buf2, n1);
}

void *
memdup(const void *src, size_t n)
{
    void *p = malloc(n);

    if (p == NULL) {
        return NULL;
    }

    memcpy(p, src, n);
    return p;
}

int
parse_bytes_to_i32(uint8_t *buf, size_t n, int32_t *dst)
{
    if (n == 0) {
        return -1;
    }

    size_t i = 0;
    int32_t sign = 1;
    int64_t magnitude = 0;

    if (buf[0] == '-') {
        sign = -1;
        i++;

        if (i == n) {
            return -1;
        }
    }

    for (; i < n; i++) {
        if (!is_digit(buf[i])) {
            return -1;
        }

        magnitude = magnitude * 10 + (buf[i] - '0'); 

        if (sign == 1 && magnitude > INT32_MAX) {
            return -1;
        }

        if (sign == -1 && -magnitude < INT32_MIN) {
            return -1;
        }
    }

    *dst = sign * (int32_t) magnitude;

    return 0;
}

struct PtrList *
ptr_list_create(size_t initial_size)
{
    void **array = malloc(initial_size * sizeof(void *));

    if (array == NULL) {
        return NULL;
    }

    struct PtrList *list = malloc(sizeof(struct PtrList));

    if (list == NULL) {
        free(array);
        return NULL;
    }

    *list = (struct PtrList) {
        .array = array,
        .count = 0,
        .capacity = initial_size
    };

    return list;
}

void
ptr_list_free(struct PtrList *list)
{
    free(list->array);
    free(list);
}

int
ptr_list_push(struct PtrList *list, void *item)
{
    if (list->count == list->capacity) {
        void **new_array = realloc(
            list->array,
            sizeof(void *) * list->capacity * 2
        );

        if (new_array == NULL) {
            return -1;
        }

        list->array = new_array;
        list->capacity *= 2;
    }

    list->array[list->count++] = item;

    return 0;
}

struct ByteSliceVector *
bslice_vec_init(size_t initial_size)
{
    struct ByteSlice **array = malloc(initial_size * sizeof(struct ByteSlice *));

    if (array == NULL) {
        return NULL;
    }

    struct ByteSliceVector *list = malloc(sizeof(struct ByteSliceVector));

    if (list == NULL) {
        free(array);
        return NULL;
    }

    *list = (struct ByteSliceVector) {
        .array = array,
        .count = 0,
        .capacity = initial_size
    };

    return list;
}

void
bslice_vec_free(struct ByteSliceVector *list)
{
    free(list->array);
    free(list);
}

int
bslice_vec_push(struct ByteSliceVector *list, struct ByteSlice *item)
{
    if (list->count == list->capacity) {
        struct ByteSlice **new_array = realloc(
            list->array,
            sizeof(void *) * list->capacity * 2
        );

        if (new_array == NULL) {
            return -1;
        }

        list->array = new_array;
        list->capacity *= 2;
    }

    list->array[list->count++] = item;

    return 0;
}
