#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "abnf.h"
#include "http.h"
#include "htable.h"

#define INIT_SEGMENT_ARR_SIZE 20

static const int hex_to_dec[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3, ['4'] = 4,  ['5'] = 5,  ['6'] = 6,
    ['7'] = 7, ['8'] = 8,  ['9'] = 9,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15
};

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

    struct HttpRequestTarget *target = malloc(sizeof(struct HttpRequestTarget));
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

static inline const char *http_method_enum_to_str(enum HTTPMethod method) {
    static const char *HTTP_METHOD_STRINGS[] = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "TRACE",
        "CONNECT"
    };

    return HTTP_METHOD_STRINGS[method];
}

enum State {
    PARSING_METHOD,
    PARSING_TARGET,
    PARSING_VERSION,
};

static enum HTTPMethod
get_method_from_bytes(
    uint8_t *data,
    size_t datalen
) {
    for (enum HTTPMethod i = 0; i < HTTP_METHODS_COUNT; i++) {
        const char *mstr = http_method_enum_to_str(i);
        size_t mstrlen = strlen(mstr); 
        if (mstrlen == datalen && memcmp(data, mstr, mstrlen) == 0)
            return i;
    }
    return HTTP_METHOD_UNKNOWN;
}

static struct HttpRequestTarget
*parse_request_target(
    uint8_t *target_data,
    size_t target_length
) {
    if (target_length == 0) return NULL;

    /* handle asterisk-form target */
    if (target_data[0] == '*' && target_length == 1) {
        struct HttpRequestTarget *target = malloc(sizeof(struct HttpRequestTarget));
        if (target == NULL) {
            fprintf(stderr, "error allocating target structure for asterisk form\n");
            return NULL;
        }

        *target = (struct HttpRequestTarget) {
            .segments = NULL,
            .query = NULL,
            .num_segments = 0,
            .query_length = 0,
            .is_asterisk = true
        };

        return target;
    }

    /* invalid origin-form */
    if (target_data[0] != '/') return NULL;

    /* find query string if it exists */
    size_t query_dlim_index = -1;
    for (size_t i = 0; i < target_length; i++) {
        if (target_data[i] == '?') {
            query_dlim_index = i;
            break;
        }
    }

    /* the length of the absolute path */
    size_t abs_path_len = query_dlim_index;

    /* initialize (dynamic) segments array */
    struct UriSegment **segments = malloc(
        INIT_SEGMENT_ARR_SIZE * sizeof(struct UriSegment *)
    );

    if (segments == NULL) {
        fprintf(stderr, "error allocating UriSegment array\n");
        return NULL;
    }

    /* state variables for segments array */
    size_t segment_count = 0;
    size_t segment_arr_size = INIT_SEGMENT_ARR_SIZE;

    /**
    -- THIS IS PROBABLY REDUNDANT
    struct UriSegment *root_segment = malloc(sizeof(struct UriSegment));

    if (root_segment == NULL) {
        free(segments);
        fprintf(stderr, "error allocating UriSegment for root\n");
        return NULL;
    }

    *root_segment = (struct UriSegment) {.bytes = NULL, .length = 0};
    segments[0] = root_segment;
    segment_count++;

    assert(segment_count == 1);
    */

    uint8_t buffer[MAX_LINE_SIZE];  /* store the segment being decoded */
    size_t buf_write_index = 0;     /* where the write index is */
    size_t prev_delim_index = 0;    /* where in target_data the last delim was */

    /* already checked that target_data[0] == '/' */

    size_t i = 1;
    for (;;) {
        if (i > abs_path_len) break;
        if (i == abs_path_len || target_data[i] == '/') {
            /* found a new delim OR ran out of data */
            struct UriSegment *seg = malloc(sizeof(struct UriSegment));

            if (seg == NULL) {
                fprintf(stderr, "error while populating UriSegment array\n");
                goto cleanup_seg_list;
            }

            if (buf_write_index == 0) {
                /* buffer is empty, so segment is empty */
                *seg = (struct UriSegment) {.bytes = NULL, .length = 0};
            } else {
                /* non-zero segment size */
                uint8_t *bytes = malloc(buf_write_index);
                if (bytes == NULL) {
                    fprintf(stderr, "malloc error while alloc segment byte arr\n");
                    free(seg);
                    goto cleanup_seg_list;
                }
                memcpy(bytes, buffer, buf_write_index);
                *seg = (struct UriSegment) {.bytes = bytes, .length = buf_write_index};
            }

            /* store ptr to segment in the segments array */
            segments[segment_count] = seg;

            /* segment dynamic array book-keeping */
            segment_count++;

            if (segment_count == segment_arr_size) {
                /* segments array is full, needs resizing */
                struct UriSegment **new_segments = realloc(
                    segments,
                    2 * segment_arr_size * sizeof(struct UriSegment *)
                );

                if (new_segments == NULL) {
                    fprintf(stderr, "segment array realloc failed\n");
                    goto cleanup_seg_list;
                }

                segments = new_segments;
                segment_arr_size *= 2;
            }

            /* reset buffer for use with next segment to be built */
            buf_write_index = 0;
            prev_delim_index = i;

            /* continue */
            i++;
            continue;
        }

        /* deal with percent encoding */
        if (target_data[i] == '%') {
            if (i + 2 >= target_length) return NULL;
            if (!is_hex_dig(target_data[i + 1])) return NULL;
            if (!is_hex_dig(target_data[i + 2])) return NULL;

            uint8_t byte = hex_to_dec[target_data[i + 1]] * 16 
                                    + hex_to_dec[target_data[i + 2]];

            buffer[buf_write_index] = byte;
            buf_write_index++;
            i += 3;
            continue;
        }

        /* check if valid pchar */
        if (is_unreserved(target_data[i]) || is_sub_delim(target_data[i]) || 
                target_data[i] == ':' || target_data[i] == '@') {
            buffer[buf_write_index] = target_data[i];
            buf_write_index++;
            i++;
        } else {
            goto cleanup_seg_list;
        }
    }

    // if here, then everything was successful.
    // need to get the final segment
    // should just be everything that's in the buffer right now
    // pretend that code that properly fills in the HttpRequestTarget struct exists here

cleanup_seg_list:
    for (int j = 0; j < segment_count; j++) {
        free(segments[j]->bytes);
        free(segments[j]);
    }
    free(segments);

    return NULL;
}

// TODO: change prototype to include const on data
enum SevaStatus
parse_request_line(
    struct HTTPRequest *req,
    uint8_t *data,
    size_t length
) {
    enum State state = PARSING_METHOD;
    size_t i = 0;
    size_t target_start = 0;
    size_t version_start = 0;

    while (true) {
        if (i >= length)
            break;

        switch (state) {
            case PARSING_METHOD: {
                if (data[i] == ' ') {
                    if (i == 0)
                        return PARSE_BAD_METHOD;

                    enum HTTPMethod method = get_method_from_bytes(data, i);

                    if (method == HTTP_METHOD_UNKNOWN)
                        return PARSE_BAD_METHOD;

                    req->method = method;
                    state = PARSING_TARGET;
                    target_start = i + 1;
                    break;
                }

                if (!is_tchar(data[i]))
                    return PARSE_BAD_METHOD;

                break;
            }

            case PARSING_TARGET: {
                /* entering here mean's we're on target_start */
                assert(i == target_start);

                /* need to find the next space */
                int sp_index = -1;
                for (int j = i + 1; j < length; j++) {
                    if (data[j] == ' ') {
                        sp_index = j;
                        break;
                    }
                }

                /* no space found, target doesn't end */
                if (sp_index == -1) return PARSE_BAD_TARGET;

                struct HttpRequestTarget *target = parse_request_target(
                    &data[i], sp_index - i
                );

                if (target == NULL) return PARSE_BAD_TARGET;

                req->target = target;

                version_start = sp_index + 1;
                i = sp_index;
                state = PARSING_VERSION;

                /* pass pointer to where target starts + len to diff function */


                // if (data[i] == ' ') {
                //     if (i == target_start)
                //         return PARSE_BAD_TARGET;

                //     const size_t tlen = i - target_start;

                //     memcpy(req->target, data + target_start, tlen);
                //     req->target[tlen] = '\0';

                //     state = PARSING_VERSION;
                //     version_start = i + 1;

                //     break;
                // }

                break;
            }

            case PARSING_VERSION: {
                int major;
                int minor;

                char *rest = strndup((char *) &data[i], length - i);

                if (sscanf(rest, "HTTP/%d.%d", &major, &minor) != 2)
                    return PARSE_BAD_VERSION;

                free(rest);

                req->version.major = major;
                req->version.minor = minor;

                return PARSE_OK;
            }

            default: {
                return PARSE_BAD;
            }
        }
        i++;
    }
    return PARSE_BAD;
}

