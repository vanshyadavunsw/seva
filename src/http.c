#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "http.h"
#include "htable.h"

enum ElementType {
    TOKEN_BYTE,
    TOKEN_CRLF,
    TOKEN_2CRLF,
};

struct Element {
    enum ElementType type;
    uint8_t data;
};

enum BufferStatus get_element(struct ParserState *ps, struct Element *e) {
    enum ElementType type;
    ps->bops->match("");
}

/**
 * Initialize a new HTTP Request structure.
 *
 * Parameters:
 *   - None
 *
 * Returns: a pointer to the new struct HTTPRequest.
 */
struct HTTPRequest *http_request_init() {
    struct HTTPRequest *req = malloc(sizeof(struct HTTPRequest));
    if (req == NULL) return NULL;

    char *target = malloc(MAX_LINE_SIZE);
    if (target == NULL) {
        free(req);
        return NULL;
    }

    struct HeaderTable *headers = htable_init(MAX_LINE_SIZE);
    if (headers == NULL) {
        free(req);
        free(target);
        return NULL;
    }

    memset(req, 0, sizeof(struct HTTPRequest));
    req->target = target;
    req->headers = headers;

    return req;
}

/**
 * Free/cleanup an HTTP Request structure.
 *
 * Parameters:
 *   - req: a pointer to an HTTP Request structure.
 *
 * Returns: void.
 */
void http_request_free(struct HTTPRequest *req) {
    free(req->target);
    htable_free(req->headers);
    free(req);
}

/**
 * Initialize an HTTP Parser's state structure.
 * 
 * Parameters:
 *   - bops: a pointer to a buffer operations structure that implements
 *           the necessary buffer operations.
 *   - req:  a pointer to an HTTP request structure.
 *
 *  The BufferOps and HTTPRequest structs must be freed by the caller.
 *
 * Returns: a pointer to the new struct ParserState.
 */
struct ParserState *http_parser_init(
    struct BufferOps *bops,
    struct HTTPRequest *req
) {
    struct ParserState *ps = malloc(sizeof(struct ParserState));
    if (ps == NULL) return NULL;

    ps->bops = bops;
    ps->req = req;
    ps->state = PARSE_BEGIN;

    char *cln = malloc(MAX_LINE_SIZE);
    if (cln == NULL) {
        free(ps);
        return NULL;
    }

    ps->rcvd_EOF = 0;
    ps->cln = cln;
    ps->clnsize = MAX_LINE_SIZE;
    ps->cli = 0;

    return ps;
}

/**
 * Cleanup and free a parser state struct. Only deallocates the internal parser 
 * buffers. The request and buffer operations structures are caller-managed.
 *
 * Parameters:
 *   - ps: a pointer to a struct ParserState.
 *
 * Returns: void.
 */
void http_parser_free(struct ParserState *ps) {
    free(ps->cln);
    free(ps);
}

enum HTTPParserStatus parse_request(struct ParserState *ps) {
    for (;;) {
        
    }
}

