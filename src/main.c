#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "htable.h"
#include "http.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>

int main() {
    struct HttpRequest *req = http_request_init();

    char *header = "Content-Length:\t\t\t \t hi!!!!!  \t\t";
    printf("%s\n", header);

    int res = parse_header(req, (uint8_t *) header, strlen(header));

    header = "Accept:application/json";
    res = parse_header(req, (uint8_t *) header, strlen(header));

    assert(res >= 0);

    htable_print(req->headers);

    return 0;
}

void print_segments(struct HttpRequestTarget *targ) {
    for (int i = 0; i < targ->num_segments; i++) {
        struct UriSegment *seg = targ->segments[i];
        printf("Segment num = %d, num bytes = %zu\n", i, seg->length);
        for (int j = 0; j < seg->length; j++) {
            uint8_t byte = seg->bytes[j];
            printf("\t[Byte %d]:\t", j);
            printf("%02x ", byte);
            if (isprint(byte)) {
                putchar(byte);
            }
            putchar('\n');
        }
    }

    printf("Query exists = %d, query len = %zu\n", targ->query != NULL, targ->query_length);
    for (int i = 0; i < targ->query_length; i++) {
            uint8_t byte = targ->query[i];
            printf("\t[Byte %d]:\t", i);
            printf("%02x ", byte);
            if (isprint(byte)) {
                putchar(byte);
            }
            putchar('\n');
    }
}

