#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "abnf.h"

static const uint8_t hex_to_dec[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
    ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15
};

// TODO: needs unit testing
int
memncmp(const void *buf1, size_t n1, const void *buf2, size_t n2)
{
    if (n1 != n2) {
        return -1;
    }

    return memcmp(buf1, buf2, n1);
}

int
memncasecmp(const void *buf1, size_t n1, const void *buf2, size_t n2)
{
    if (n1 != n2) {
        return -1;
    }

    for (size_t i = 0; i < n1; i++) {
        if (tolower(((uint8_t *) buf1)[i]) != tolower(((uint8_t *) buf2)[i])) {
            return -1;
        }
    }

    return 0;
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
mem_dec_to_i32(uint8_t *buf, size_t n, int32_t *dst)
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

// simple enough for our use case. just need to know _if_ an
// error occurred.
int
mem_hex_to_u32(uint8_t *buf, size_t n, uint32_t *dst)
{
    if (n == 0) {
        return -1;
    }

    uint32_t value = 0;

    for (size_t i = 0; i < n; i++) {
        if (!is_hex_dig(buf[i])) {
            return -1;
        }

        uint8_t digit = hex_to_dec[buf[i]];

        if (value > (UINT32_MAX - digit) / 16) {
            return -1;
        }

        value = value * 16 + hex_to_dec[buf[i]];
    }

    *dst = value;

    return 0;
}

ssize_t
find_crlf(uint8_t *data, size_t length)
{
    for (ssize_t i = 0; i < (ssize_t) length - 1; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return i;
        }
    }
    return -1;
}

/* pointer list (legacy) needs to be removed */
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

// TODO: need unit testing
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
    for (size_t i = 0; i < list->count; i++) {
        free(list->array[i]);
    }
    free(list->array);
    free(list);
}

// TODO: need unit testing
// TODO: change the semantics of this.
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

// TODO: needs unit testing
int
bslice_vec_contains(
    struct ByteSliceVector *list,
    uint8_t *data, 
    size_t length
) {
    struct ByteSlice *slice;
    for (size_t i = 0; i < list->count; i++) {
        slice = list->array[i];
        if (memncmp(data, length, slice->data, slice->length) == 0) {
            return 1;
        }
    }
    return 0;
}

// TODO: needs unit testing
int
bslice_vec_remove_all(
    struct ByteSliceVector *list,
    uint8_t *data,
    size_t length
) {
    struct ByteSlice *slice;
    int removed = 0;
    for (size_t i = 0; i < list->count; i++) {
        slice = list->array[i];
        if (memncmp(data, length, slice->data, slice->length) == 0) {
            free(slice->data);
            free(slice);
            memmove(
                &list->array[i],
                &list->array[i + 1],
                (list->count - i - 1) * sizeof(struct ByteSlice *)
            );
            list->count--;
            i--;
            removed++;
        }
    }
    return removed;
}
