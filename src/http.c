#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "allocators/allocator.h"
#include "utils.h"
#include "http.h"
#include "abnf.h"

static const struct {
    const char *method_str;
    enum HttpMethod method_int;
} method_table[] = {
    { "GET", HTTP_GET },
    { "POST", HTTP_POST },
    { "PUT", HTTP_PUT },
    { "DELETE", HTTP_DELETE },
    { "HEAD", HTTP_HEAD },
    { "OPTIONS", HTTP_OPTIONS },
    { "PATCH", HTTP_PATCH },
    { "TRACE", HTTP_TRACE },
    { "CONNECT", HTTP_CONNECT },
};

int
request_init(
    struct Allocator *allocator,
    struct HttpRequest **out
) {
    struct HttpRequest *r = ALLOC(allocator, sizeof(*r));

    if (r == nullptr) {
        return SEVA_NOMEM;
    }

    *r = (struct HttpRequest) {
        .allocator = allocator, .target = nullptr,
        .method = HTTP_METHOD_UNKNOWN,
        .version = HTTP_VERSION_UNKNOWN,
    //  .headers = ...
    //  .body = ...
    };

    *out = r;

    return SEVA_OK;
}

int
request_free(struct HttpRequest *req)
{
    if (req == nullptr || !HAS_FREE(req->allocator)) {
        return -1;
    }

    free_request_target(req->target);

    FREE(req->allocator, req);

    return 0;
}

/**
 * (WIP comment)
 * Function to parse a request line into a request structure.
 *
 * Unknown versions and unknown methods are NOT treated as errors.
 * The caller MUST check that req->method and req->version are NOT
 * HTTP_METHOD_UNKNOWN or HTTP_VERSION_UNKNOWN.
 *
 * If the parse is successful, SEVA_OK will be returned.
 *
 * This function can return the following error codes:
 *     - SEVA_PARSE_ERR: the request line referenced by input was 
 *       malformed. SEVA_PARSE_ERR should be treated as a fatal
 *       error by a server implementation as framing is ambiguous
 *       in this case.
 *
 *     - SEVA_NOMEM: the function was unable to successfully
 *       allocate memory for the parsed target structure via the
 *       HttpRequest's internal allocator.
 *
 * The concents of *req are undefined in case of an error.
 */
int
parse_request_line(
    struct HttpRequest *req,
    struct ByteSlice input
) {
    struct StateData {
        enum State {
            INIT,
            PARSING_METHOD,
            PARSING_TARGET,
            PARSING_VERSION,
            DEINIT,
        } state;

        uint8_t *buf;
        size_t len;
        size_t i;

        enum HttpMethod method;
        enum HttpVersion version;

        size_t target_start;
        size_t target_end;

        bool eol;

        int err;
    } ctx = {
        .state = INIT,
        .buf = input.ptr,
        .len = input.len,
        .i = 0,
        .eol = false,
        .err = SEVA_OK,
    };

    for (;;) {

        if (ctx.i >= ctx.len) {
            ctx.eol = true;
        }

        switch (ctx.state) {

            case INIT: {

                if (ctx.eol) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                ctx.state = PARSING_METHOD;
                break;

            }

            case PARSING_METHOD: {

                if (ctx.eol) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.buf[ctx.i] == ' ') {
                    if (ctx.i == 0) {
                        ctx.err = SEVA_PARSE_ERR;
                        ctx.state = DEINIT;
                        break;
                    }

                    enum HttpMethod method = HTTP_METHOD_UNKNOWN;
                    const size_t num_methods = sizeof(method_table) / sizeof(method_table[0]);

                    for (size_t j = 0; j < num_methods; j++) {
                        if (memncmp(
                            ctx.buf,
                            ctx.i,
                            method_table[j].method_str,
                            strlen(method_table[j].method_str)
                        ) == 0) {
                            method = method_table[j].method_int;
                            break;
                        }
                    }

                    ctx.method = method;
                    ctx.target_start = ctx.i + 1;

                    ctx.state = PARSING_TARGET;
                    ctx.i++;
                    break;
                }

                if (!is_tchar(ctx.buf[ctx.i])) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                ctx.i++;
                break;

            }

            case PARSING_TARGET: {

                if (ctx.eol) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.buf[ctx.i] == ' ') {
                    if (ctx.i == ctx.target_start) {
                        ctx.err = SEVA_PARSE_ERR;
                        ctx.state = DEINIT;
                        break;
                    }

                    ctx.target_end = ctx.i - 1;
                    ctx.state = PARSING_VERSION;
                    ctx.i++;
                    break;
                }

                ctx.i++;
                break;

            }

            case PARSING_VERSION: {
                //  H  T  T  P  /  M  .  m
                //  i +1 +2 +3 +4 +5 +6 +7
                if (ctx.eol) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.i + 7 >= ctx.len
                    || memcmp(&ctx.buf[ctx.i], "HTTP/", 5) != 0
                    || ctx.buf[ctx.i + 6] != '.'
                    || ctx.i + 8 != ctx.len
                ) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                const uint8_t major = ctx.buf[ctx.i + 5];
                const uint8_t minor = ctx.buf[ctx.i + 7];

                if (!is_digit(major) || !is_digit(minor)) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (major != '1') {
                    ctx.version = HTTP_VERSION_UNKNOWN;
                } else {
                    if (minor == '1') {
                        ctx.version = HTTP_1_1;
                    } else if (minor == '0') {
                        ctx.version = HTTP_1_0;
                    } else {
                        ctx.version = HTTP_VERSION_UNKNOWN;
                    }
                }

                ctx.state = DEINIT;
                break;

            }

            case DEINIT: {

                if (ctx.err != SEVA_OK) {
                    return ctx.err;
                }

                struct HttpRequestTarget *t;

                const int res = parse_request_target(
                    req->allocator,
                    byte_slice(
                        &ctx.buf[ctx.target_start],
                        ctx.target_end - ctx.target_start + 1
                    ),
                    &t
                );

                if (res != SEVA_OK) {
                    return res;
                }

                req->target = t;
                req->version = ctx.version;
                req->method = ctx.method;

                return SEVA_OK;
            }

        }

    }

}

/**
 * (WIP comment)
 * Function to parse a request target URI and store it in a
 * a dynamically allocated (using the passed allocator) struct
 * HttpRequest. This parser only handles origin-form and
 * origin-form targets (which are the only targets that an 
 * HTTP/1.1 server can expect. This implementation WILL reject
 * any URIs with fragments and exercises so leniency to that end.
 *
 * This parser will reject any URIs with segments that decode to
 * a length > MAX_LINE_LEN. This should not be an issue in practice
 * as MAX_LINE_LEN is also a bound on any line (including the request
 * line).
 *
 * Successful parsing will result in a return value of SEVA_OK.
 *
 * Errors:
 *     - SEVA_PARSE_ERR: a fatal parse error.
 *     - SEVA_NOMEM: was unable to allocate memory via the
 *       passed allocator. or a segment decoded to a length >
 *       MAX_LINE_LEN.
 */
int
parse_request_target(
    struct Allocator *allocator,
    struct ByteSlice input,
    struct HttpRequestTarget **out
) {
    struct StateData {
        enum State {
            INIT,
            PARSING_ABS_PATH,
            PARSING_HEX_SEQ,
            PARSING_QUERY,
            BUILDING_NEW_SEG,
            DEINIT,
        } state;

        uint8_t *buf;
        size_t len;

        size_t i;

        uint8_t curr_seg_buf[MAX_LINE_LEN];
        size_t curr_seg_count;

        struct UriSegmentVector *vec;
        struct ByteSlice query;

        bool eol;
        bool parsing_query;

        bool is_asterisk_form;

        int err;
    } ctx = {
        .state = INIT,
        .buf = input.ptr,
        .len = input.len,
        .err = SEVA_OK,
        .eol = false,
        .parsing_query = false,
        .is_asterisk_form = false,
    };

    for (;;) {

        if (ctx.i >= ctx.len) {
            ctx.eol = true;
        }

        switch (ctx.state) {

            case INIT: {

                if (ctx.eol) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.buf[0] == '*') {
                    if (ctx.len != 1) {
                        ctx.err = SEVA_PARSE_ERR;
                        ctx.state = DEINIT;
                        break;
                    }

                    ctx.is_asterisk_form = true;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.buf[0] != '/') {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                size_t num_segs = 0;

                for (size_t j = 0; j < ctx.len && ctx.buf[j] != '?'; j++) {
                    if (ctx.buf[j] == '/') {
                        num_segs++;
                    }
                }

                ctx.vec = uri_seg_vec_init(allocator, num_segs);

                if (ctx.vec == nullptr) {
                    ctx.err = SEVA_NOMEM;
                    ctx.state = DEINIT;
                    break;
                }

                ctx.i = 1;
                ctx.state = PARSING_ABS_PATH;
                break;

            }

            case PARSING_ABS_PATH: {

                if (ctx.eol || ctx.buf[ctx.i] == '/' || ctx.buf[ctx.i] == '?') {
                    // set current_seg_end correctly
                    ctx.state = BUILDING_NEW_SEG;
                    break;
                }

                if (ctx.buf[ctx.i] == '%') {
                    ctx.state = PARSING_HEX_SEQ;
                    break;
                }

                const bool is_valid_byte = is_unreserved(ctx.buf[ctx.i])
                                        || is_sub_delim(ctx.buf[ctx.i])
                                        || ctx.buf[ctx.i] == ':'
                                        || ctx.buf[ctx.i] == '@';

                if (!is_valid_byte) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                /* check buffer overflow */
                if (ctx.curr_seg_count >= MAX_LINE_LEN) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                ctx.curr_seg_buf[ctx.curr_seg_count] = ctx.buf[ctx.i];
                ctx.curr_seg_count++;
                ctx.i++;

                break;
            }

            case PARSING_HEX_SEQ: {

                if (ctx.i + 2 >= ctx.len) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (!is_hex_dig(ctx.buf[ctx.i + 1])
                    || !is_hex_dig(ctx.buf[ctx.i + 2])) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.curr_seg_count >= MAX_LINE_LEN) {
                    ctx.err = SEVA_NOMEM;
                    ctx.state = DEINIT;
                    break;
                }

                uint32_t byte;
                mem_hex_to_u32(&ctx.buf[ctx.i + 1], 2, &byte);

                ctx.curr_seg_buf[ctx.curr_seg_count] = (uint8_t) byte;

                ctx.curr_seg_count++;
                ctx.i += 3;
                ctx.state = ctx.parsing_query ? PARSING_QUERY : PARSING_ABS_PATH;

                break;
            }

            case BUILDING_NEW_SEG: {

                struct UriSegment segment;

                if (ctx.curr_seg_count == 0) {
                    segment.slice = byte_slice(nullptr, 0);
                } else {
                    uint8_t *segcpy = memdup(allocator, ctx.curr_seg_buf, ctx.curr_seg_count);

                    if (segcpy == nullptr) {
                        ctx.err = SEVA_NOMEM;
                        ctx.state = DEINIT;
                        break;
                    }

                    segment.slice = byte_slice(segcpy, ctx.curr_seg_count);
                }

                if(!uri_seg_vec_push(ctx.vec, segment)) {
                    ctx.err = SEVA_NOMEM;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.eol) {
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.buf[ctx.i] == '?') {
                    ctx.curr_seg_count = 0;
                    ctx.state = PARSING_QUERY;
                    ctx.parsing_query = true;
                    ctx.i++;
                    break;
                }

                ctx.curr_seg_count = 0;
                ctx.i++;
                ctx.state = PARSING_ABS_PATH;

                break;

            }

            case PARSING_QUERY: {

                if (ctx.eol) {
                    if (ctx.curr_seg_count == 0) {
                        ctx.query.len = 0;
                        ctx.query.ptr = nullptr;

                        ctx.state = DEINIT;
                        break;
                    }

                    uint8_t *qcpy = memdup(allocator, ctx.curr_seg_buf, ctx.curr_seg_count);

                    if (qcpy == nullptr) {
                        ctx.err = SEVA_NOMEM;
                        ctx.state = DEINIT;
                        break;
                    }

                    ctx.query.len = ctx.curr_seg_count;
                    ctx.query.ptr = qcpy;

                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.buf[ctx.i] == '%') {
                    ctx.state = PARSING_HEX_SEQ;
                    break;
                }

                const bool is_valid_byte = is_unreserved(ctx.buf[ctx.i])
                                        || is_sub_delim(ctx.buf[ctx.i])
                                        || ctx.buf[ctx.i] == ':'
                                        || ctx.buf[ctx.i] == '@'
                                        || ctx.buf[ctx.i] == '/'
                                        || ctx.buf[ctx.i] == '?';

                if (!is_valid_byte) {
                    ctx.err = SEVA_PARSE_ERR;
                    ctx.state = DEINIT;
                    break;
                }

                if (ctx.curr_seg_count >= MAX_LINE_LEN) {
                    ctx.err = SEVA_NOMEM;
                    ctx.state = DEINIT;
                    break;
                }

                ctx.curr_seg_buf[ctx.curr_seg_count] = ctx.buf[ctx.i];
                ctx.curr_seg_count++;
                ctx.i++;

                break;

            }

            case DEINIT: {

                if (ctx.err != SEVA_OK) {
                    if (ctx.vec != nullptr) {
                        uri_seg_vec_free(ctx.vec, uri_seg_cleanup);
                    }

                    if (ctx.query.ptr != nullptr) {
                        SAFE_FREE(allocator, ctx.query.ptr);
                    }

                    return ctx.err;
                }

                struct HttpRequestTarget *t = ALLOC(allocator, sizeof(*t));

                if (t == nullptr) {
                    if (ctx.vec != nullptr) {
                        uri_seg_vec_free(ctx.vec, uri_seg_cleanup);
                    }

                    if (ctx.query.ptr != nullptr) {
                        SAFE_FREE(allocator, ctx.query.ptr);
                    }

                    return SEVA_NOMEM;
                }

                if (ctx.is_asterisk_form) {
                    *t = (struct HttpRequestTarget) {
                        .allocator = allocator,
                        .is_asterisk_type = true,
                        .segments = nullptr,
                        .query = byte_slice(nullptr, 0),
                    };
                } else {
                    *t = (struct HttpRequestTarget) {
                        .allocator = allocator,
                        .segments = ctx.vec,
                        .query = ctx.query,
                        .is_asterisk_type = false,
                    };
                }

                *out = t;

                return SEVA_OK;

            }

        }

    }

    return SEVA_OK;

}

int
free_request_target(
    struct HttpRequestTarget *t
) {
    if (t == nullptr || !HAS_FREE(t->allocator)) {
        return -1;
    }

    if (t->query.ptr != nullptr) {
        FREE(t->allocator, t->query.ptr);
    }

    if (t->segments != nullptr) {
        uri_seg_vec_free(t->segments, uri_seg_cleanup);
    }

    FREE(t->allocator, t);

    return 0;
}
