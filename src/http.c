#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "abnf.h"
#include "http.h"
#include "htable.h"
#include "utils.h"

// TODO: use the utils version
static const unsigned int hex_to_dec[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
    ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15
};

static inline const char *http_method_enum_to_str(enum HttpMethod method) {
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

static enum HttpMethod
get_method_from_bytes(
    uint8_t *data,
    size_t datalen
) {
    for (enum HttpMethod i = 0; i < HTTP_METHODS_COUNT; i++) {
        const char *mstr = http_method_enum_to_str(i);
        size_t mstrlen = strlen(mstr); 
        if (mstrlen == datalen && memcmp(data, mstr, mstrlen) == 0)
            return i;
    }
    return HTTP_METHOD_UNKNOWN;
}

/**
 * Initialize a new HTTP Request structure.
 *
 * Parameters:
 *   - None
 *
 * Returns: a pointer to the new struct HTTPRequest.
 */
struct HttpRequest *http_request_init(void) {
    struct HttpRequest *req = malloc(sizeof(struct HttpRequest));
    if (req == NULL) return NULL;

    struct HeaderTable *headers = htable_init(INIT_HTABLE_BUCKETS);
    if (headers == NULL) {
        free(req);
        return NULL;
    }

    memset(req, 0, sizeof(struct HttpRequest));

    req->headers = headers;
    req->target = NULL;
    req->body = NULL;

    return req;
}

static void http_request_target_free(struct HttpRequestTarget *t) {
    assert(t != NULL);
    if (t->segments != NULL) {
        for (size_t i = 0; i < t->num_segments; i++) {
            free(t->segments[i]->bytes);
            free(t->segments[i]);
        }
        free(t->segments);
    }
    free(t->query);
    free(t);
}

/**
 * Free/cleanup an HTTP Request structure.
 *
 * Parameters:
 *   - req: a pointer to an HTTP Request structure.
 *
 * Returns: void.
 */
void http_request_free(struct HttpRequest *req) {
    if (req->target != NULL)
        http_request_target_free(req->target);
    htable_free(req->headers);
    free(req);
}


struct HttpRequestTarget *parse_request_target(
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
    ssize_t query_dlim_index = -1;
    for (size_t i = 0; i < target_length; i++) {
        if (target_data[i] == '?') {
            query_dlim_index = i;
            break;
        }
    }

    /* the length of the absolute path */
    size_t abs_path_len = query_dlim_index == -1 ? target_length: query_dlim_index;

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

    uint8_t buffer[MAX_LINE_SIZE];  /* store the segment being decoded */
    size_t buf_write_index = 0;     /* where the write index is */

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

            /* continue */
            i++;
            continue;
        }

        /* deal with percent encoding */
        if (target_data[i] == '%') {
            if (i + 2 >= target_length) goto cleanup_seg_list;
            if (!is_hex_dig(target_data[i + 1])) goto cleanup_seg_list;
            if (!is_hex_dig(target_data[i + 2])) goto cleanup_seg_list;

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

    struct UriSegment **resized = realloc(
        segments, segment_count * sizeof(struct UriSegment *)
    );

    if (resized == NULL) {
        fprintf(stderr, "error while downsizing UriSegment arr\n");
    } else {
        segments = resized;
    }

    /* query parsing */

    assert(buf_write_index == 0);

    uint8_t *query_bytes;
    size_t query_len;

    if (query_dlim_index != -1) {
        i = query_dlim_index + 1;
        for (;;) {
            if (i >= target_length) break;

            if (target_data[i] == '%') {
                if (i + 2 >= target_length) goto cleanup_seg_list;
                if (!is_hex_dig(target_data[i + 1])) goto cleanup_seg_list;
                if (!is_hex_dig(target_data[i + 2])) goto cleanup_seg_list;

                uint8_t byte = hex_to_dec[target_data[i + 1]] * 16 
                                        + hex_to_dec[target_data[i + 2]];

                buffer[buf_write_index] = byte;
                buf_write_index++;
                i += 3;
                continue;
            }

            /* check if valid query character */
            if (is_unreserved(target_data[i]) || is_sub_delim(target_data[i]) || 
                    target_data[i] == ':' || target_data[i] == '@' ||
                    target_data[i] == '/' || target_data[i] == '?') {
                buffer[buf_write_index] = target_data[i];
                buf_write_index++;
                i++;
            } else {
                goto cleanup_seg_list;
            }
        }

        if (buf_write_index == 0) {
            query_bytes = NULL;
        } else {
            query_bytes = malloc(buf_write_index);
            memcpy(query_bytes, buffer, buf_write_index);
        }
        query_len = buf_write_index;

    } else {
        query_bytes = NULL;
        query_len = 0;
    }

    struct HttpRequestTarget *target = malloc(sizeof(struct HttpRequestTarget));

    if (target == NULL) {
        fprintf(stderr, "error while allocating nz target struct\n");
        free(query_bytes);
        goto cleanup_seg_list;
    }

    *target = (struct HttpRequestTarget) {
        .is_asterisk = false,
        .segments = segments,
        .num_segments = segment_count,
        .query = query_bytes,
        .query_length = query_len,
    };

    return target;

cleanup_seg_list:

    for (size_t j = 0; j < segment_count; j++) {
        free(segments[j]->bytes);
        free(segments[j]);
    }
    free(segments);

    return NULL;
}

// TODO: apply filter to turn repeated headers into lists
seva_status_t parse_header_ex(
    struct HttpRequest *req,
    uint8_t *data,
    size_t length,
    header_validator_fn validator,
    void *validator_ctx
) {
    enum State { PARSING_FNAME, PARSING_WS, PARSING_FVAL };
    enum State state = PARSING_FNAME;

    size_t fname_end;
    ssize_t fval_start;  /* inclusive */
    ssize_t fval_end;    /* inclusive */

    for (fval_end = length - 1; fval_end >= 0 && is_ows(data[fval_end]); fval_end--);

    bool eof = false;
    uint8_t byte;
    size_t i = 0;

    for (;;) {
        if (i > fval_end) {
            eof = true;
        } else {
            byte = data[i];
        }

        switch (state) {
            case PARSING_FNAME: {
                if (eof) return SEVA_PARSE_BAD;

                if (byte == ':') {
                    if (i == 0) return SEVA_PARSE_BAD;

                    fname_end = i - 1;

                    /* ignore if field name is not allowed */
                    if (!validator(data, fname_end + 1, validator_ctx)) {
                        return SEVA_HEADER_IGNORED;
                    }

                    state = PARSING_WS;
                    break;
                }

                if (!is_tchar(byte)) return SEVA_PARSE_BAD;

                break;
            }

            case PARSING_WS: {
                if (eof) {
                    fval_start = -1;
                    break;
                }

                if (!is_ows(byte)) {
                    fval_start = i;
                    state = PARSING_FVAL;
                    continue;
                }

                break;
            }

            case PARSING_FVAL: {
                if (eof) break;

                int is_valid = is_vchar(byte) || is_obs_text(byte) || is_ows(byte);
                if (!is_valid) return SEVA_PARSE_BAD;

                break;
            }

            default: {
                return SEVA_PARSE_BAD;
            }
        }

        if (eof) break;

        i++;
    }

    const size_t name_len = fname_end + 1;
    char *name_str = malloc(name_len + 1);
    if (name_str == NULL) return SEVA_PARSE_BAD;
    memcpy(name_str, data, name_len);
    name_str[name_len] = '\0';

    char *val_str;
    if (fval_start == -1) {
        val_str = malloc(1);
        if (val_str == NULL) {
            free(name_str);
            return SEVA_PARSE_BAD;
        }
        val_str[0] = '\0';
    } else {
        const size_t val_len = (fval_end - fval_start + 1);
        val_str = malloc(val_len + 1);
        if (val_str == NULL) {
            free(name_str);
            return SEVA_PARSE_BAD;
        }
        memcpy(val_str, &data[fval_start], val_len);
        val_str[val_len] = '\0';
    }

    if (htable_insert(req->headers, name_str, val_str) < 0) {
        free(name_str);
        free(val_str);
        return SEVA_PARSE_BAD;
    }

    free(name_str);
    free(val_str);

    return SEVA_OK;
}

// Tokenize comma separated list
// TODO: needs unit testing
[[nodiscard]] struct ByteSliceVector *
tokenize_cslist(uint8_t *data, size_t length)
{
    enum State {
        PARSING_ITEM
    };

    enum State state = PARSING_ITEM;
    bool eof = false;
    ssize_t last_comma = -1;
    uint8_t *item_bytes = nullptr;
    struct ByteSlice *item_slice = nullptr;
    struct ByteSliceVector *items_vec = bslice_vec_init(INIT_CSTOKENS_ARR_SIZE);

    if (items_vec == NULL) {
        return NULL;
    }

    ssize_t i = 0;
    uint8_t byte;

    for (;;) {
        if (eof) { break; }

        if (i == (ssize_t) length) {
            eof = true;
        } else {
            byte = data[i];
        }

        switch (state) {
            case PARSING_ITEM: {
                if (byte == ',' || eof) {
                    ssize_t p, q;
                    for (p = last_comma + 1; p < i && is_ows(data[p]); p++);
                    for (q = i - 1; q > last_comma && is_ows(data[q]); q--);

                    if (p == i) {
                        /* element is empty, ignore */
                        last_comma = i;
                        i++;
                        continue;
                    }

                    const size_t trimmed_len = q - p + 1;

                    item_bytes = memdup(&data[p], trimmed_len);

                    if (item_bytes == NULL) {
                        goto cleanup_2;
                    }

                    item_slice = malloc(sizeof(struct ByteSlice));

                    if (item_slice == NULL) {
                        goto cleanup_3;
                    }

                    *item_slice = (struct ByteSlice) {
                        .data = item_bytes,
                        .length = trimmed_len
                    };

                    if (bslice_vec_push(items_vec, item_slice) == -1) {
                        goto cleanup_3;
                    }

                    last_comma = i;
                    i++;
                    continue;
                }

                i++;
                continue;
            }
        }
    }

    return items_vec;

cleanup_3:
    free(item_slice);

cleanup_2:
    free(item_bytes);
// cleanup_1:
    bslice_vec_free(items_vec);
    return nullptr;

}

// TODO: needs unit testing
seva_status_t get_req_body_info(
    const struct HttpRequest *req,
    struct ReqBodyInfo *rbinfo
) {
    if (req->method == HTTP_HEAD) {
        *rbinfo = (struct ReqBodyInfo) {
            .is_chunked = false, .content_length = 0
        };
        return SEVA_OK;
    }

    seva_status_t status = SEVA_PARSE_BAD_REQ;

    struct Header *te_query = htable_query(req->headers, "Transfer-Encoding");
    struct Header *cl_query = htable_query(req->headers, "Content-Length");

    struct ByteSliceVector *v;
    struct ByteSlice *last;

    if (te_query != NULL && cl_query != NULL) {
        return SEVA_PARSE_BAD_REQ; 
    }

    if (te_query != NULL) {
        /* check for only one field */ 
        if (te_query->next != NULL) {
            goto cleanup_1;
        }

        v = tokenize_cslist((uint8_t *) te_query->value, strlen(te_query->value));

        if (v == NULL) {
            goto cleanup_1;
        }

        if (v->count == 0) {
            goto cleanup_2;
        }

        last = v->array[v->count - 1];
        char *ch_str = "chunked";

        if (
            last->length != strlen(ch_str) ||
            memcmp(last->data, ch_str, last->length) != 0
        ) {
            /* IRRECOVERABLE. connection must be closed. */
            status = SEVA_PARSE_FATAL;
            goto cleanup_2;
        }

        *rbinfo = (struct ReqBodyInfo) { .is_chunked = true, .content_length = 0 };

        htable_query_free(te_query);
        bslice_vec_free(v);

        return SEVA_OK;
    }

    if (cl_query != NULL) {
        /* there is a Content-Length header */
        int32_t content_length;

        /* parse the field value to an integer */
        const int res = mem_dec_to_i32(
            (uint8_t *) cl_query->value,
            strlen(cl_query->value),
            &content_length
        );

        /* malformed Content-Length field value */
        if (res == -1) {
            status = SEVA_PARSE_FATAL;
            goto cleanup_1;
        }

        /* TODO: maybe consider 413 Payload Too Large */
        /* Content-Length cannot be negative or too large */
        if (content_length < 0 || content_length > CONTENT_LENGTH_MAX) {
            status = SEVA_PARSE_FATAL;
            goto cleanup_1;
        }

        *rbinfo = (struct ReqBodyInfo) {
            .is_chunked = false,
            .content_length = content_length
        };

        /* if there are multiple Content-Length headers, check that they're
         * all identical */
        if (cl_query->next != NULL) {
            const char *first_val = cl_query->value;
            struct Header *current = cl_query->next;

            while (current != NULL) {
                if (strcmp(first_val, current->value) != 0) {
                    status = SEVA_PARSE_FATAL;
                    goto cleanup_1;
                }
                current = current->next;
            }
        }

        htable_query_free(cl_query);

        return SEVA_OK;
    }


    *rbinfo = (struct ReqBodyInfo) { .is_chunked = false, .content_length = 0 };

    return SEVA_OK;

// cleanup_3:

cleanup_2:
    bslice_vec_free(v);

cleanup_1:
    htable_query_free(te_query);
    htable_query_free(cl_query);

    return status;
}

seva_status_t parse_request_line(
    struct HttpRequest *req,
    uint8_t *data,
    size_t length
) {
    enum State {
        PARSING_METHOD,
        PARSING_TARGET,
        PARSING_VERSION,
    };

    enum State state = PARSING_METHOD;
    size_t i = 0;
    size_t target_start = 0;

    while (true) {
        if (i >= length)
            break;

        switch (state) {
            case PARSING_METHOD: {
                if (data[i] == ' ') {
                    if (i == 0)
                        return SEVA_PARSE_BAD_METHOD;

                    enum HttpMethod method = get_method_from_bytes(data, i);

                    if (method == HTTP_METHOD_UNKNOWN)
                        return SEVA_PARSE_BAD_METHOD;

                    req->method = method;
                    state = PARSING_TARGET;
                    target_start = i + 1;
                    break;
                }

                if (!is_tchar(data[i]))
                    return SEVA_PARSE_BAD_METHOD;

                break;
            }

            case PARSING_TARGET: {
                /* entering here mean's we're on target_start */
                assert(i == target_start);

                /* need to find the next space */
                ssize_t sp_index = -1;
                for (size_t j = i + 1; j < length; j++) {
                    if (data[j] == ' ') {
                        sp_index = j;
                        break;
                    }
                }

                /* no space found, target doesn't end */
                if (sp_index == -1) return SEVA_PARSE_BAD_TARGET;

                struct HttpRequestTarget *target = parse_request_target(
                    &data[i], sp_index - i
                );

                if (target == NULL) return SEVA_PARSE_BAD_TARGET;

                req->target = target;

                i = sp_index;
                state = PARSING_VERSION;

                break;
            }

            case PARSING_VERSION: {
                int major;
                int minor;

                char *rest = strndup((char *) &data[i], length - i);

                if (sscanf(rest, "HTTP/%d.%d", &major, &minor) != 2) {
                    free(rest);
                    return SEVA_PARSE_BAD_VERSION;
                }

                free(rest);

                req->version.major = major;
                req->version.minor = minor;

                return SEVA_OK;
            }

            default: {
                return SEVA_PARSE_BAD;
            }
        }
        i++;
    }
    return SEVA_PARSE_BAD;
}

seva_status_t
sanitize_req_headers(struct HttpRequest *req)
{
    (void) req;
    return SEVA_ERROR_GENERIC;

    /**
     * Function to run important checks on the headers
     * e.g. coalesce those headers which are repeated into comma separated lists if applicable
     * other stuff
     *
     */
}

/** 
 * this function does NOT check whether the body is valid according to HTTP semantics. 
 * the caller (me) MUST determine if it is valid to read a fixed, `length` number of bytes from
 * the buffer `data` through a call to `get_req_body_info` or equivalent.
 */
seva_status_t
parse_body_fixed(struct HttpRequest *req, uint8_t *data, size_t length)
{
    uint8_t *datacpy = memdup(data, length);

    if (datacpy == NULL) {
        return SEVA_NOMEM;
    }

    req->body->length = length;
    req->body->data = datacpy;

    return SEVA_OK;
}

static int
remove_invalid_trailers(struct ByteSliceVector *trailers)
{
    // TODO: keep adding new invalid trailers as i get through the RFCs
    static const char *invalid_trailers[] = {
        "Content-Length",
        "Transfer-Encoding",
        "Host",
        "Content-Encoding",
        "Content-Type",
        "Content-Range",
        "Trailer",
    };

    size_t num_invalids = sizeof(invalid_trailers) / sizeof(char *);

    int count = 0;
    for (size_t i = 0; i < num_invalids; i++) {
        count += bslice_vec_remove_all(
            trailers,
            (uint8_t *) invalid_trailers[i], strlen(invalid_trailers[i])
        );
    }

    return count;
}


struct ChunkedParserState *
chunked_parser_state_init()
{
    struct ChunkedParserState *state = malloc(sizeof(*state));

    if (state == NULL) {
        return NULL;
    }

    *state = (struct ChunkedParserState) {
        .state = CHP_INIT,
        .last_state = CHP_PARSING_CHUNK_SIZE,
    };

    return state;
}

void
chunked_parser_state_free(struct ChunkedParserState *state)
{
    (void) state;
    return;
}

static bool
is_allowed_trailer(uint8_t *field_name, size_t length, void *ctx)
{
    return bslice_vec_contains(ctx, field_name, length);
}

static inline int
remove_chunked_str(struct HeaderTable *ht)
{
    struct Header *hdr = htable_query_first(ht, "Transfer-Encoding");

    if (hdr == NULL) {
        return -1;
    }

    struct ByteSliceVector *v = tokenize_cslist(hdr->value, strlen(hdr->value));

    memncasecmp(const void *buf1, size_t n1, const void *buf2, size_t n2)
    if (
    
    if (v->count == 1 && 
        memncmp(v->array[0]->data, v->array[0]->length, "chunked", 7)) {
        
    }

}

/**
 * ChunkedParserState's lifetime is managed by the caller.
 */
seva_status_t
parse_body_chunked(
    struct HttpRequest *req,
    struct ChunkedParserState *ps,
    uint8_t *data, 
    size_t length,
    size_t *bytes_read
) {
    size_t i = 0;
    bool eof = false;
    uint8_t byte;
    size_t crlf;


    struct Header *trailer_query;
    struct ByteSliceVector *trailers;

    for (;;) {
        if (eof) { break; }

        if (i >= length){
            eof = true;
        } else {
            byte = data[i];
        }

        switch (ps->state) {
            case CHP_INIT: {
                trailer_query = htable_query(req->headers, "Trailer");
                if (trailer_query != NULL) { // no trailer, dont accept
                    trailers = tokenize_cslist(
                        (uint8_t *) trailer_query->value,
                        strlen(trailer_query->value)
                    );

                    // TODO: deal with empty trailer
                    remove_invalid_trailers(trailers);
                    ps->allowed_trailers = trailers;

                    free(trailer_query);
                    trailer_query = NULL;

                    ps->state = CHP_PARSING_CHUNK_SIZE;

                    break;
                }
            }

            case CHP_PARSING_CHUNK_SIZE: {
                ssize_t res;

                if (eof || (res = find_crlf(data, length)) == -1) {
                    *bytes_read = i;
                    return SEVA_AGAIN;
                }

                crlf = res;

                const uint8_t *ext = memchr(&data[i], ';', crlf - i);
                size_t hex_seq_length;

                if (ext != NULL) {
                    hex_seq_length = ext - &data[i];
                } else {
                    hex_seq_length = crlf - i;
                } int err = mem_hex_to_u32(
                    &data[i],
                    hex_seq_length,
                    &ps->curr_chunk_size
                );

                if (err == -1) {
                    return SEVA_PARSE_FATAL;
                }

                if (ext != NULL) {
                    /* handle chunk-extensions here one day */
                }

                i = crlf + 2;

                if (ps->curr_chunk_size == 0) {
                    ps->state = CHP_PARSING_TRAILERS;
                } else {
                    ps->state = CHP_PARSING_CHUNK_DATA;
                }

                continue;
            }

            case CHP_PARSING_CHUNK_DATA: {
                if (eof || i + ps->curr_chunk_size + 1 >= length) {
                    *bytes_read = i;
                    return SEVA_AGAIN;
                }

                if (find_crlf(&data[i + ps->curr_chunk_size], 2) == -1) {
                    return SEVA_PARSE_FATAL;
                }

                ps->count += ps->curr_chunk_size;

                if (ps->count > (size_t) MESSAGE_BODY_MAX) {
                    return SEVA_BODY_TOO_LARGE;
                }

                memcpy(&ps->buf[ps->count], &data[i], ps->curr_chunk_size);

                i += ps->curr_chunk_size + 2;
                ps->state = CHP_PARSING_CHUNK_SIZE;

                continue;
            }

            case CHP_PARSING_TRAILERS: {
                if (eof) {
                    *bytes_read = i;
                    return SEVA_AGAIN;
                }

                ssize_t res = find_crlf(&data[i], length - i);

                if (res == -1) {
                    *bytes_read = i;
                    return SEVA_AGAIN;
                }

                /* no trailers. we're done */
                if (res == 0) {
                    *bytes_read = i;
                    return SEVA_OK;

                    // TODO: write a function to modify an htable entry
                    // removed chunked by setting '\0' som
                    // and delete trailer. maybe put this in a different state.
                    /**
                     * Content-Length := length
                     * Remove "chunked" from Transfer-Encoding
                     * Remove Trailer from existing header fields.
                     *
                     */
                }

                /* if we're here, that means there's some header field to process
                 * from here to the CRLF */

                const seva_status_t tr_res = parse_header_ex(
                    req,
                    &data[i],
                    res - i,
                    is_allowed_trailer,
                    ps->allowed_trailers
                );

                if (tr_res < 0 && tr_res != SEVA_HEADER_IGNORED) {
                    return SEVA_PARSE_FATAL;
                }

                i = res + 2;
                ps->state = CHP_PARSING_TRAILERS;
                continue;
            }
        }
    }

    return SEVA_OK;
}
/**
*  NOTE:: figure out what to do with no trailer
*  figure out how to make parse_header_ex accept allowed headers
*/

/**
*  NOTE: some pointers about this function
*  each state handler can verify that it has enough data to do what it needs to do
*  it will verify before changing any state. so it can easily be re-entered.
*  if don't have enough data, return bytes read (0 or whatever). state enum stays unchanged
*  in state struct, so when it's called again it enters right there.
*  get rid of CHP_READING, and handle extensions within parsing chunk size. for most state
*  cases, the check at the front will just be if we have a CRLF (we have complete data),
*  but for reading the actual chunked data, we want to buffer the entire chunk's data. for
*  that the check will be to see if we have chunk-size to read all together + the two CRLF. can easily check if malformed by checking if CRLF is missing.
*/

/**
*  TODO: Document every error a function can return like man pages do.
*/
