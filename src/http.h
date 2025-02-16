#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <stdbool.h>
#include "htable.h"

#define MAX_LINE_SIZE 8192

struct HttpVersion {
    uint8_t major;
    uint8_t minor;
};

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
    HTTP_METHODS_COUNT  = 9,      /* num of methods */ 
};

struct HttpRequest {
    enum HttpMethod method;
    struct HttpVersion version;
    struct HttpRequestTarget *target;
    struct HeaderTable *headers;
};

struct HttpRequest *http_request_init(void);

void http_request_free(struct HttpRequest *req);

typedef enum SevaStatus {
    SEVA_OK = 0,
    SEVA_PARSE_BAD = -1,
    SEVA_PARSE_BAD_METHOD = -2,
    SEVA_PARSE_BAD_TARGET = -3,
    SEVA_PARSE_BAD_VERSION = -4,
    SEVA_PARSE_BAD_REQUEST = -5,
    SEVA_NOMEM = -6,
    SEVA_ERROR_GENERIC = -7,
} seva_status_t;

struct UriSegment {
    uint8_t *bytes;
    size_t length;
};

struct HttpRequestTarget {
    struct UriSegment **segments;
    size_t num_segments;
    uint8_t *query;
    size_t query_length;
    bool is_asterisk;
};

enum SevaStatus parse_request_line(
    struct HttpRequest *req,
    uint8_t *data,
    size_t length
);

struct HttpRequestTarget
*parse_request_target(
    uint8_t *target_data,
    size_t target_length
);

enum SevaStatus parse_header(
    struct HttpRequest *req,
    const uint8_t *data,
    size_t length
);

/* exposed for testing only */

struct ByteSliceVector *
tokenize_cslist(uint8_t *data, size_t length);

#endif
