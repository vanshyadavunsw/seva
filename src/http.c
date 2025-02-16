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

#define INIT_SEGMENT_ARR_SIZE 20
#define INIT_HTABLE_BUCKETS 20
#define INIT_CSTOKENS_ARR_SIZE 5
#define CONTENT_LENGTH_MAX 16384

static const int hex_to_dec[256] = {
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
seva_status_t parse_header(
    struct HttpRequest *req,
    const uint8_t *data,
    size_t length
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
struct ByteSliceVector *
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
                    for (p = last_comma + 1; is_ows(data[p]) && p < i; p++);
                    for (q = i - 1; is_ows(data[q]) && q > last_comma; q--);

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

struct ReqBodyInfo {
    bool is_chunked;
    size_t content_length;
};

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

    struct Header *te_query = htable_query(req->headers, "Transfer-Encoding");
    struct Header *cl_query = htable_query(req->headers, "Content-Length");

    struct ByteSliceVector *v;
    struct ByteSlice *last;

    if (te_query != NULL && cl_query != NULL) {
        return SEVA_PARSE_BAD_REQUEST; 
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
            goto cleanup_2;
        }

        *rbinfo = (struct ReqBodyInfo) { .is_chunked = true, .content_length = 0 };

        htable_query_free(te_query);
        bslice_vec_free(v);

        return SEVA_OK;
    }

    if (cl_query != NULL) {
        if (cl_query->next != NULL) {
            const char *first_val = cl_query->value;
            struct Header *current = cl_query->next;

            while (current != NULL) {
                if (strcmp(first_val, current->value) != 0) {
                    goto cleanup_1;
                }
                current = current->next;
            }
        }

        int32_t content_length;

        const int res = parse_bytes_to_i32(
            (uint8_t *) cl_query->value,
            strlen(cl_query->value),
            &content_length
        );

        if (res == -1) {
            goto cleanup_1;
        }

        if (content_length < 0 || content_length > CONTENT_LENGTH_MAX) {
            goto cleanup_1;
        }

        *rbinfo = (struct ReqBodyInfo) {
            .is_chunked = false,
            .content_length = content_length
        };

        htable_query_free(cl_query);

        return SEVA_OK;
    }

    return SEVA_PARSE_BAD_REQUEST;

    // TODO: differentiate bad request vs irrecoverable

    // check if transfer-encoding AND content-length present. return 400 if both
    // check if transfer-encoding is present
    // get the field value from htable, tokenize into list, and get last
    // if chunked is last, set is_chunked true and content_length unspec.
    // if chunked not last, return 400
    // if no transfer encoding but content-length (multiple headers diff val) or single with diffval 
       // IRRECOVERABLE ERROR, so 400 and CLOSE connection
    // else default is_chunked = false and content_length = 0;

// cleanup_3:

cleanup_2:
    bslice_vec_free(v);

cleanup_1:
    htable_query_free(te_query);
    htable_query_free(cl_query);

    return SEVA_PARSE_BAD_REQUEST;
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

