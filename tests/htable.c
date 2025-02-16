#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "../src/htable.h"

#define TEST_MODULE_NAME "htable"

static bool key_val_exists_in_ht(struct HeaderTable *ht, char *key, char *val);

void test_successful_init(void);
void test_add_item_and_single_query(void);
void test_multiple_add_and_resize(void);
void test_unique_id_invariant(void);
void test_delete(void);

void log_test_start(void) {
    printf("Testing module %s\n", TEST_MODULE_NAME);
}

void log_success(char *name) {
    printf("[PASS] test \"%s\" succeeded.\n", name);
}

int main(void) {
    log_test_start();

    test_successful_init();
    test_add_item_and_single_query();
    test_multiple_add_and_resize();
    test_unique_id_invariant();
    test_delete();

    printf("ALL OK\n");

    return 0;
}

void test_successful_init(void) {
    struct HeaderTable *ht = htable_init(5);
    assert(ht != NULL);
    assert(ht->size == 5);
    assert(ht->nheaders == 0);
    htable_free(ht);
    log_success("htable successful init");
}

void test_add_item_and_single_query(void) {
    struct HeaderTable *ht = htable_init(5);
    assert(htable_insert(ht, "Content-Length", "ABC") >= 0);
    assert(ht->nheaders == 1);
    assert(ht->size == 5);

    struct Header *query = htable_query(ht, "Content-Length");

    assert(query != NULL);
    assert(strcmp(query->name, "Content-Length") == 0);
    assert(strcmp(query->value, "ABC") == 0);
    assert(query->next == NULL);

    htable_query_free(query);
    htable_free(ht);

    log_success("htable successful add and query single");
}

void test_multiple_add_and_resize(void) {
    struct HeaderTable *ht = htable_init(5);

    assert(htable_insert(ht, "abc", "def") >= 0);
    assert(key_val_exists_in_ht(ht, "abc", "def"));
    assert(ht->nheaders == 1);
    assert(ht->size == 5);

    assert(htable_insert(ht, "lorem", "ipsum") >= 0);
    assert(key_val_exists_in_ht(ht, "lorem", "ipsum"));
    assert(ht->nheaders == 2);
    assert(ht->size == 5);

    assert(htable_insert(ht, "dolor", "Sit") >= 0);
    assert(key_val_exists_in_ht(ht, "dolor", "Sit"));
    assert(ht->nheaders == 3);
    assert(ht->size == 5);

    assert(htable_insert(ht, "this will increase", "the load factor") >= 0);
    assert(key_val_exists_in_ht(ht, "this will increase", "the load factor"));
    assert(ht->nheaders == 4);
    assert(ht->size == 10);

    assert(htable_insert(ht, "another one", "test") >= 0);
    assert(key_val_exists_in_ht(ht, "another one", "test"));
    assert(ht->nheaders == 5);
    assert(ht->size == 10);

    assert(htable_insert(ht, "def", "efg") >= 0);
    assert(key_val_exists_in_ht(ht, "def", "efg"));
    assert(ht->nheaders == 6);
    assert(ht->size == 10);

    assert(htable_insert(ht, "hij", "klm") >= 0);
    assert(key_val_exists_in_ht(ht, "hij", "klm"));
    assert(ht->nheaders == 7);
    assert(ht->size == 10);

    assert(htable_insert(ht, "will cause another resize", "test") >= 0);
    assert(key_val_exists_in_ht(ht, "will cause another resize", "test"));
    assert(ht->nheaders == 8);
    assert(ht->size == 20);

    htable_free(ht);

    log_success("test multiple adds and resizes");
}

void test_unique_id_invariant(void) {
    struct HeaderTable *ht = htable_init(5);

    assert(htable_insert(ht, "a", "b") >= 0);

    struct Header *query = htable_query(ht, "a");
    const int id = query->id;
    htable_query_free(query);

    assert(htable_insert(ht, "ab", "cd") >= 0);
    assert(htable_insert(ht, "1241w", "wowza") >= 0);
    assert(htable_insert(ht, "haha", "lorem") >= 0);
    assert(ht->size == 10);

    query = htable_query(ht, "a");
    assert(query->id == id);

    htable_query_free(query);
    htable_free(ht);

    log_success("ids maintained between resizes");
}

void test_delete(void) {
    struct HeaderTable *ht = htable_init(5);

    assert(htable_insert(ht, "Content-Length", "32") >= 0);
    assert(htable_insert(ht, "Transfer-Encoding", "21") >= 0);
    assert(ht->nheaders == 2);
    assert(key_val_exists_in_ht(ht, "Content-Length", "32"));
    assert(key_val_exists_in_ht(ht, "Transfer-Encoding", "21"));

    struct Header *query = htable_query(ht, "Transfer-Encoding");
    assert(query != NULL);
    uint8_t id = query->id;
    htable_query_free(query);

    assert(htable_delete(ht, "Transfer-Encoding", id) == 1);
    assert(!key_val_exists_in_ht(ht, "Transfer-Encoding", "21"));
    assert(ht->nheaders == 1);

    query = htable_query(ht, "Content-Length");
    assert(query != NULL);
    id = query->id;
    htable_query_free(query);

    assert(htable_delete(ht, "Content-Length", id) == 1);
    assert(!key_val_exists_in_ht(ht, "Content-Length", "32"));
    assert(ht->nheaders == 0);

    assert(htable_delete(ht, "Doesn't exist", 23) == 0);
    assert(ht->nheaders == 0);

    htable_free(ht);

    log_success("test header table deletion");
}

static bool key_val_exists_in_ht(struct HeaderTable *ht, char *key, char *val) {
    struct Header *query = htable_query(ht, key);
    struct Header *current = query;
    bool found = false;
    while (current != NULL) {
        if (strcmp(current->name, key) == 0 && strcmp(query->value, val) == 0) {
            found = true;
            break;
        }
        current = current->next;
    }
    htable_query_free(query);
    return found;
}
