#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "../lib/murmurhash/murmurhash.h"
#include "htable.h"

unsigned long djb2_hash(unsigned char *str);
unsigned long murmur_hash_wrapper(unsigned char *str);

unsigned long (*hashfunc)(unsigned char *str) = murmur_hash_wrapper;

struct HeaderTable *htable_init(size_t size) {
    struct HeaderTable *htable = malloc(sizeof(struct HeaderTable));
    if (htable == NULL) return NULL;

    htable->hlist = malloc(sizeof(struct Header *) * size);
    if (htable->hlist == NULL) {
        free(htable);
        return NULL;
    }

    for (size_t i = 0; i < size; i++) {
        htable->hlist[i] = NULL;
    }

    htable->size = size;
    htable->nheaders = 0;

    return htable;
}

void htable_free(struct HeaderTable *htable) {
    struct Header *current, *next;
    for (size_t i = 0; i < htable->size; i++) {
        current = htable->hlist[i];
        while (current != NULL) {
            next = current->next;
            free(current->name);
            free(current->value);
            free(current);
            current = next;
        }
    }
    free(htable->hlist);
    free(htable);
    return;
}

int htable_insert(struct HeaderTable *ht, char *name, char *value) {
    struct Header *new_header = malloc(sizeof(struct Header));
    if (new_header == NULL) return -1;

    char *namecpy, *valuecpy;
    if ((namecpy = strdup(name)) == NULL) {
        free(new_header);
        return -1;
    }

    if ((valuecpy = strdup(value)) == NULL) {
        free(new_header);
        free(namecpy);
        return -1;
    }

    new_header->name = namecpy;
    new_header->value = valuecpy;
    new_header->next = NULL;

    size_t i = hashfunc((unsigned char *) name) % ht->size;

    if (ht->hlist[i] == NULL) {
        ht->hlist[i] = new_header;
        ht->nheaders++;
    } else {
        struct Header *current = ht->hlist[i];
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_header;
        ht->nheaders++;
    }

    float lf = ((float) ht->nheaders) / ht->size;
    if (lf > HTABLE_LF_MAX) {
        if (htable_resize(ht) == -1) {
            fprintf(stderr, "htable resize failed\n");
            return -1;
        }
    }

    return 0;
}

int htable_resize(struct HeaderTable *ht) {
    struct HeaderTable *newht = htable_init(ht->size * 2);
    if (newht == NULL) return -1;

    for (size_t i = 0; i < ht->size; i++) {
        struct Header *current = ht->hlist[i];
        while (current != NULL) {
            if (htable_insert(newht, current->name, current->value) == -1) {
                htable_free(newht);
                return -1;
            }
            current = current->next;
        }
    }
    /* swap newht fields with old ht */
    struct HeaderTable temp = *ht;
    ht->hlist = newht->hlist;
    ht->size = newht->size;

    newht->hlist = temp.hlist;
    newht->size = temp.size;
    htable_free(newht);
    return 0;
}

void htable_print(struct HeaderTable *ht) {
    printf("-----------struct HeaderTable-----------\n");
    printf("size = %zu\n", ht->size);
    printf("num headers = %zu\n", ht->nheaders);
    printf("----------------Elements----------------\n");

    for (size_t i = 0; i < ht->size; i++) {
        printf("[%zu]: ", i);
        struct Header *current = ht->hlist[i];
        while (current != NULL) {
            printf("(K: %s, V: %s) -> ", current->name, current->value);
            current = current->next;
        }
        printf("NULL\n");
    }

    printf("----------------------------------------\n");
}

/*
* djb2 hash function
*/
unsigned long djb2_hash(unsigned char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

unsigned long murmur_hash_wrapper(unsigned char *str) {
    return (unsigned long) murmurhash((char *) str, strlen((char *) str), 0);
}

