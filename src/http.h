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
    struct Allocator *allocator;
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

int
free_request_target(
    struct HttpRequestTarget *t
);

enum HttpMethod {
    HTTP_METHOD_UNKNOWN = -1,
    HTTP_GET            = 0,
    HTTP_POST           = 1,
    HTTP_PUT            = 2,
    HTTP_DELETE         = 3,
    HTTP_HEAD           = 4,
    HTTP_OPTIONS        = 5,
    HTTP_PATCH          = 6,
    HTTP_TRACE          = 7,
    HTTP_CONNECT        = 8,
    HTTP_METHODS_COUNT  = 9,
};

enum HttpVersion {
    HTTP_VERSION_UNKNOWN,
    HTTP_1_0,
    HTTP_1_1,
};

struct HttpRequest {
    struct Allocator *allocator;
    enum HttpMethod method;
    enum HttpVersion version;
    struct HttpRequestTarget *target;
};

int request_init(
    struct Allocator *allocator,
    struct HttpRequest **out
);

int request_free(struct HttpRequest *req);

int
parse_request_line(
    struct HttpRequest *req,
    struct ByteSlice input
);

#endif
