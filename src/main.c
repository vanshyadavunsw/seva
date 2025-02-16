#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "http.h"
#include "utils.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>

void print_bsv(struct ByteSliceVector *v) {
    printf("count = %zu, capacity = %zu\n", v->count, v->capacity);
    printf("\"");
    for (size_t i = 0; i < v->count; i++) {
        struct ByteSlice *slice = v->array[i];
        for (size_t j = 0; j < slice->length; j++) {
            putchar(slice->data[j]);
        }
        putchar(',');
    }
    printf("\"\n");
}

int main(void) {
    char *data = "  \t, , hiya ,, ,    ,some   , insane   , list  , wow! ,,,, boo, hiya";
    struct ByteSliceVector *v = tokenize_cslist((uint8_t *) data, strlen(data));
    assert(v != NULL);
    print_bsv(v);
    return 0;
}
