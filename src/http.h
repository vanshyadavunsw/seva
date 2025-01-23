#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include "htable.h"

#define MAX_LINE_SIZE 8192

struct HTTPVersion {
    uint8_t major;
    uint8_t minor;
};

enum HTTPMethod {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH,
    HTTP_TRACE,
    HTTP_CONNECT,
};

struct HTTPRequest {
    enum HTTPMethod method;
    struct HTTPVersion version;
    char *target;
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
    PARSE_BEGIN,
    PARSE_REQ_LINE,
    PARSE_HEADER,
    PARSE_CLN_WSP,
};

struct ParserState {
    struct HTTPRequest *req;        /* caller allocated */
    struct BufferOps *bops;         /* called allocated */
    enum HTTPParserState state;
    char *cln;                      /* internally alocated */
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
    size_t *patlen
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

#endif
