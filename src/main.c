#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "htable.h"
#include "ring_buffer.h"
#include <stddef.h>

void htable_print_2(struct HeaderTable *ht);

void rb_print(struct RingBuffer *rb) {
    
}

int main() {
    
}

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
