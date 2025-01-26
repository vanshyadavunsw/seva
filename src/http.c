#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "http.h"
#include "htable.h"
#include "abnf.h"
#include <assert.h>

enum ElementType {
    ELEMENT_BYTE,
    ELEMENT_CRLF,
    ELEMENT_2CRLF,
    ELEMENT_ERROR,
};

uint8_t size[] = { 1, 2, 4 };

struct Element {
    enum ElementType type;
    uint8_t data;
};

enum EventType {
    EVENT_ELEMENT,
    EVENT_EOF,
    EVENT_INTERRUPT,
    EVENT_ERR_FATAL,
};

struct Event {
    enum EventType type;
    struct Element element;
};

enum StateHandlerStatus {
    HANDLER_BAD = 0,
    HANDLER_OK = 1,
};

typedef enum StateHandlerStatus (*StateHandler)(
    struct ParserState *ps,
    struct Event e
);

/**
 * Deduce a parsing event from the buffer.
 * e.g. received a byte, received a multi-byte seq, received EOF, etc.
 */
struct Event get_event(struct ParserState *ps) {
    BufferOpMatchFn match = ps->bops->match;
    enum ElementType element_type;
    struct Event event;

    if (match(ps->bops, (uint8_t *) "\r\n\r\n", 4))
        element_type = ELEMENT_2CRLF;
    else if (match(ps->bops, (uint8_t *) "\r\n", 2))
        element_type = ELEMENT_CRLF;
    else
        element_type = ELEMENT_BYTE;

    uint8_t byte;
    enum BufferStatus res;

    if (element_type != ELEMENT_BYTE) {
        for (int i = 0; i < size[element_type]; i++) {
            res = ps->bops->get_byte(ps->bops, &byte);
            assert(res != BUF_STATUS_OK);
        }
        event.element = (struct Element) { element_type, 0 };
        event.type = EVENT_ELEMENT;
        return event;
    }

    res = ps->bops->get_byte(ps->bops, &byte);

    if (res != BUF_STATUS_OK) {
        if (res == BUF_ERR_EOF)
            event.type = EVENT_EOF;
        else if (res == BUF_ERR_WOULD_BLOCK)
            event.type = EVENT_INTERRUPT;
        else
            event.type = EVENT_ERR_FATAL;
    } else {
        event.element = (struct Element) { ELEMENT_BYTE, byte };
        event.type = EVENT_ELEMENT;
    }

    return event;
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
    ps->state = P_METHOD;

    uint8_t *cln = malloc(MAX_LINE_SIZE);
    if (cln == NULL) {
        free(ps);
        return NULL;
    }

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

static inline int cln_write(struct ParserState *ps, uint8_t byte) {
    if (ps->cli == ps->clnsize) return 0;
    ps->cln[ps->cli] = byte;
    ps->cli++;
    return 1;
}

static inline void cln_clear(struct ParserState *ps) {
    ps->cli = 0;
}

static inline int cln_match()

static inline size_t cln_count(struct ParserState *ps) {
    return ps->cli;
}

enum StateHandlerStatus handle_method(
    struct ParserState *ps,
    struct Event *event
) {
    /* if not an element, bad req */
    if (event->type != EVENT_ELEMENT) return HANDLER_BAD;
    /* not expecting a multi-byte token like CRLF */
    if (event->element.type != ELEMENT_BYTE) return HANDLER_BAD;

    /* request method is case-sensitive so strncmp is valid */
    if (event->element.data == ' ') {
        // check if any matches
    }

    /* if not a tchar, bad */
    if (!is_tchar(event->element.data)) return HANDLER_BAD;
}

StateHandler handlers[] = {

};

enum HTTPParserStatus parse_request(struct ParserState *ps) {
    struct Event e;
    for (;;) {
        e = get_event(ps);

        if (e.type == EVENT_INTERRUPT)
            return PARSE_ERR_NEED_DATA;
        else if (e.type == EVENT_ERR_FATAL)
            return PARSE_ERR_BAD_REQ;

        // handle fatal errors and interrupt
        // get state handler
        // call
        // if PARSE_STATUS_OK, continue
        // if ERR_NEED_MORE_DATA, return
        // if ERR_BAD_REQ, return

        // pass event to state-based event handlers
        // via some kind of lookup matrix (1D or 2D Array).
        // 1D (e.g. get handler for state, e.g. PARSING_HEADERS), and pass event.
        // 2D if get event handler for PARSING_HEADERS and EVENT_ELEMENT;
        // 1D seems better atm
    }
}

