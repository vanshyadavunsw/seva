#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <stdbool.h>
#include "htable.h"

#define MAX_LINE_SIZE 8192

struct HTTPVersion {
    uint8_t major;
    uint8_t minor;
};

enum HTTPMethod {
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

struct HTTPRequest {
    enum HTTPMethod method;
    struct HTTPVersion version;
    struct HttpRequestTarget *target;
    struct HeaderTable *headers;
};

enum BufferStatus {
    BUF_STATUS_OK = 1,
    BUF_ERR_EOF = 0,
    BUF_ERR_WOULD_BLOCK = -1,
    BUF_ERR_FATAL = -2,
};

enum HTTPParserStatus {
    PARSE_STATUS_OK = 1,
    PARSE_ERR_NEED_DATA = -1,
    PARSE_ERR_BAD_REQ = -2,
};

enum HTTPParserState {
    P_METHOD,
    P_TARGET,
    P_VERSION,
    P_HEADERS,
    P_HEADER,
    P_DONE
};

struct ParserState {
    struct HTTPRequest *req;        /* caller allocated */
    struct BufferOps *bops;         /* called allocated */
    enum HTTPParserState state;
    uint8_t *cln;                      /* internally alocated */
    size_t clnsize;
    size_t cli;
};

/**
 * Function pointer type for reading a byte from a buffer.
 */
typedef enum BufferStatus (*BufferOpGetByteFn)(
    struct BufferOps *self,
    uint8_t *dst
);

/**
 * Function pointer type for matching a byte sequence in a buffer.
 */
typedef int (*BufferOpMatchFn)(
    struct BufferOps *self,
    uint8_t *pattern,
    const size_t patlen
);

struct BufferOps {
    /**
     * A pointer to the buffer's context.
     */
    void *buffer;

    /**
     * A method to read one byte from the buffer.
     * Should return the appropriate BufferStatus for each call.
     * 
     * Parameters:
     *   - struct BufferOps *self: a pointer to the self context.
     *   - uint8_t *dst: the destination address to store the byte.
     */
    BufferOpGetByteFn get_byte;

    /**
    * A method to match a byte sequence (pattern) of length (patlen)
    * from the current read pointer onwards. This method should NOT advance
    * the read pointer/stream position. A consequence of guaranteeing that
    * the match method works is that the buffer must always maintain at least
    * 4 bytes of data from and including the current read pointer, unless EOF
    * has been received.
    *
    * Parameters:
    *   - struct BufferOps *self: a pointer to the self context.
    *   - uint8_t *pattern: a pointer to a sequence of patlen bytes for the
    *       buffer's data to be matched against.
    *   - size_t *patlen: the size, in bytes, of the pattern.
    */

    BufferOpMatchFn match;
};

struct ParserState *http_parser_init(
    struct BufferOps *bops,
    struct HTTPRequest *req
);

void http_parser_free(struct ParserState *ps);

struct HTTPRequest *http_request_init();

void http_request_free(struct HTTPRequest *req);

typedef enum SevaStatus {
    PARSE_OK = 0,
    PARSE_BAD = -1,
    PARSE_BAD_METHOD = -2,
    PARSE_BAD_TARGET = -3,
    PARSE_BAD_VERSION = -4,
} SevaStatus;

struct UriSegment {
    uint8_t *bytes;
    size_t length;
};

struct HttpRequestTarget {
    struct UriSegment **segments;
    size_t num_segments;
    uint8_t *query;
    size_t query_length;
    bool is_asterisk;   // for a server-wide OPTIONS request
};

enum SevaStatus parse_request_line(
    struct HTTPRequest *req,
    uint8_t *data,
    size_t length
);

struct HttpRequestTarget
*parse_request_target(
    uint8_t *target_data,
    size_t target_length
);

enum SevaStatus parse_header(
    struct HTTPRequest *req,
    uint8_t *data,
    size_t length
);

#endif
