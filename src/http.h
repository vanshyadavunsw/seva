#ifndef HTTP_H
#define HTTP_H

#include "allocators/allocator.h"
#include "utils.h"
#include "./collections/vector.h"

#define MAX_LINE_LEN 8192

enum SevaStatus {
    SEVA_OK = 0,
    SEVA_BAD = -1,
    SEVA_NOMEM = -2,
    SEVA_PARSE_ERR = -3,
    SEVA_PARSE_FATAL = -4,
};

struct UriSegment {
    struct ByteSlice slice;
};

DEFINE_VECTOR_TYPE(struct UriSegment, UriSegment, uri_seg)

static inline void
uri_seg_cleanup(struct UriSegment seg, struct Allocator *allocator)
{
    if (seg.slice.ptr != NULL) {
        SAFE_FREE(allocator, seg.slice.ptr);
    }
}

struct HttpRequestTarget {
    struct UriSegmentVector *segments;
    struct ByteSlice query;
    bool is_asterisk_type;
};

int
parse_request_target(
    struct Allocator *allocator,
    struct ByteSlice input,
    struct HttpRequestTarget **out
);

#endif
