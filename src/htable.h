#ifndef HTABLE_H
#define HTABLE_H

#include <stdint.h>
#include <stddef.h>

#define HTABLE_INIT_SIZE 20
#define HTABLE_LF_MAX 0.75f

struct Header {
    char *name;
    char *value;
    struct Header *next;
};

struct HeaderTable {
    struct Header **hlist;
    size_t size;
    size_t nheaders;
};

struct HeaderTable *htable_init(size_t size);

int htable_insert(struct HeaderTable *ht, char *name, char *value);

int htable_resize(struct HeaderTable *ht);

void htable_free(struct HeaderTable *htable);

void htable_print(struct HeaderTable *ht);

#endif



