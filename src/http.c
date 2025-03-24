#include <assert.h>

#include "allocators/allocator.h"
#include "utils.h"
#include "http.h"
#include "abnf.h"

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

        int err;
    } ctx = { .state = INIT, .buf = input.ptr,
        .len = input.len,
        .err = SEVA_OK,
        .eol = false,
        .parsing_query = false,
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
                    struct HttpRequestTarget *t = ALLOC(allocator, sizeof(*t));

                    if (t == nullptr) {
                        ctx.err = SEVA_NOMEM;
                        ctx.state = DEINIT;
                        break;
                    }

                    *t = (struct HttpRequestTarget) {
                        .is_asterisk_type = true
                    };

                    *out = t;

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
                const int res = mem_hex_to_u32(&ctx.buf[ctx.i + 1], 2, &byte);

                /* tmp */
                assert(res == 0 && byte < UINT8_MAX);

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
                    return ctx.err;
                }

                struct HttpRequestTarget *t = ALLOC(allocator, sizeof(*t));

                if (t == nullptr) {
                    uri_seg_vec_free(ctx.vec, uri_seg_cleanup);
                    return SEVA_NOMEM;
                }

                *t = (struct HttpRequestTarget) {
                    .segments = ctx.vec,
                    .query = ctx.query,
                    .is_asterisk_type = false,
                };

                *out = t;

                return SEVA_OK;

            }

        }

    }

    return SEVA_OK;

}
