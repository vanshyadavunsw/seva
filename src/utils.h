#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

void *
memdup(const void *src, size_t n);

int
parse_bytes_to_i32(uint8_t *buf, size_t n, int32_t *dst);

int
memncmp(const void *buf1, size_t n1, const void *buf2, size_t n2);

/* PtrList (old */

struct PtrList {
    void **array;
    size_t count;
    size_t capacity;
};

struct PtrList *
ptr_list_create(size_t initial_size);

void
ptr_list_free(struct PtrList *list);

int
ptr_list_push(struct PtrList *list, void *item);

/* ByteSlice */

struct ByteSlice {
    size_t length;
    uint8_t *data;
};

struct ByteSlice
bslice_create(uint8_t *data, size_t length);

void
bslice_free(struct ByteSlice);

/* ByteSliceList */

struct ByteSliceVector {
    struct ByteSlice **array;
    size_t count;
    size_t capacity;
};

struct ByteSliceVector *
bslice_vec_init(size_t initial_size);

void
bslice_vec_free(struct ByteSliceVector *list);

int
bslice_vec_push(struct ByteSliceVector *list, struct ByteSlice *item);

#endif
