#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <stdbool.h>
#include "htable.h"

#define MAX_LINE_SIZE 8192
#define INIT_SEGMENT_ARR_SIZE 20
#define INIT_HTABLE_BUCKETS 20
#define INIT_CSTOKENS_ARR_SIZE 5
#define CONTENT_LENGTH_MAX 16384
#define MESSAGE_BODY_MAX 1024 * 1024

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

struct HttpBody {
    size_t length;
    uint8_t *data;
};

struct HttpRequest {
    enum HttpMethod method;
    struct HttpVersion version;
    struct HttpRequestTarget *target;
    struct HeaderTable *headers;
    struct HttpBody *body;
};

struct HttpRequest *
http_request_init(void);

void
http_request_free(struct HttpRequest *req);

typedef enum SevaStatus {
    SEVA_OK = 0,
    SEVA_PARSE_BAD = -1,
    SEVA_PARSE_BAD_METHOD = -2,
    SEVA_PARSE_BAD_TARGET = -3,
    SEVA_PARSE_BAD_VERSION = -4,
    SEVA_PARSE_BAD_REQ = -5,
    SEVA_PARSE_FATAL = -6,
    SEVA_NOMEM = -7,
    SEVA_ERROR_GENERIC = -8,
    SEVA_AGAIN = -9,
    SEVA_HEADER_IGNORED = -10,
    SEVA_BODY_TOO_LARGE = -11,
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

struct HttpRequestTarget *
parse_request_target(
    uint8_t *target_data,
    size_t target_length
);

typedef bool (*header_validator_fn)(uint8_t *field_name, size_t length, void *ctx);

static inline bool
accept_all_headers(uint8_t *field_name, size_t length, void *ctx)
{
    (void) field_name;
    (void) length;
    (void) ctx;
    return true;
}

seva_status_t
parse_header_ex(
    struct HttpRequest *req,
    uint8_t *data,
    size_t length,
    header_validator_fn validator,
    void *validator_ctx
);

static inline seva_status_t
parse_header(
    struct HttpRequest *req,
    uint8_t *data,
    size_t length
) {
    return parse_header_ex(req, data, length, accept_all_headers, NULL);
}

/* exposed for testing only */

struct ByteSliceVector *
tokenize_cslist(uint8_t *data, size_t length);

struct ReqBodyInfo {
    bool is_chunked;
    size_t content_length;
};

seva_status_t get_req_body_info(
    const struct HttpRequest *req,
    struct ReqBodyInfo *rbinfo
);

seva_status_t
parse_body_fixed(struct HttpRequest *req, uint8_t *data, size_t length);

struct ChunkedParserState {
    enum {
        CHP_INIT,
        CHP_PARSING_CHUNK_SIZE,
        CHP_PARSING_CHUNK_DATA,
        CHP_PARSING_TRAILERS,
        CHP_CLEANUP,
    } state, last_state;

    struct ByteSliceVector *allowed_trailers;

    uint8_t *buf; // size MESSAGE_BODY_MAX
    size_t size; // size MESSAGE_BODY_MAX
    size_t count;

    uint32_t curr_chunk_size;
};

#endif
