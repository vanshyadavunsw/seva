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
    struct HTTPRequest *req = http_request_init();

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

/**
int main() {
    char *rqline = "/help/index.html?somedata%02%33%AA%cf%00m&y-/:@?";
    // rqline = "/";
    // rqline = "*";
    int len = strlen(rqline);

    struct HttpRequestTarget *targ = parse_request_target((uint8_t *) rqline, len);

    assert(targ != NULL);

    printf("targ is NOT null!!\n");

    printf("num segments = %zu\n", targ->num_segments);
    printf("is asterisk = %d\n", targ->is_asterisk);
    printf("address of segments = %p\n", targ->segments);

    printf("\n\n\n");

    print_segments(targ);

    printf("test str: %s\n", rqline);

    return 0;
}
*/

/**
int main() {
    char *rqline = "GET /help.php?foo=bar&bin=%00%cf%fc%ec HTTP/1.1";
    int len = strlen(rqline);

    struct HTTPRequest *req = http_request_init();

    int res = parse_request_line(req, (uint8_t *) rqline, len);

    printf("%d\n", res);

    printf("http ver: %d %d\n", req->version.major, req->version.minor);
    printf("method: %d\n", req->method);

    print_segments(req->target);

    return 0;
}
*/

/**
int main() {
    struct HeaderTable *ht = htable_init(10);
    htable_insert(ht, "Keep-Alive", "a");
    htable_insert(ht, "Transfer-Encoding", "b");
    htable_insert(ht, "Content-Length", "c");
    htable_insert(ht, "Multi-Cast", "d");
    htable_insert(ht, "Protocol-Version", "e");
    htable_insert(ht, "Mutliplex-Stream", "f");
    htable_insert(ht, "Authorization", "g");

    htable_print(ht);
    // 8th element insert -> kickstart resize
    htable_insert(ht, "Language", "h");
    // should have resized
    htable_print(ht);

    htable_insert(ht, "Proxy-Flags", "h");    // 9
    htable_insert(ht, "Network-Topo", "h");    // 10
    htable_insert(ht, "Never-Forget", "h");    // 11
    htable_insert(ht, "User-Agent", "h");    // 12
    htable_insert(ht, "Token", "h");    // 13
    htable_insert(ht, "Token", "a");    // 14
    htable_insert(ht, "Chunking", "h");    // 15

    htable_print(ht);
    // 16th element insert (16/20 = 0.8 > 0.75) -> kickstart resize
    htable_insert(ht, "Final", "h");
    // should have resized
    htable_print(ht);

    htable_free(ht);

    return 0;
}
*/
