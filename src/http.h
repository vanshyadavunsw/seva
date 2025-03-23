#ifndef HTTP_H
#define HTTP_H

#include "utils.h"
#include "./collections/vector.h"

struct UriSegment {
    struct ByteSlice slice;
};

DEFINE_VECTOR_TYPE(struct UriSegment, UriSegment, uri_seg)

struct HttpRequestTarget {
    struct UriSegmentVector *segments;
    struct ByteSlice *query;
    bool is_asterisk_type;
};

#endif
