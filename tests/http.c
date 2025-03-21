#include "../src/http.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/utils.h"
#include <stdlib.h>

#define TEST_MODULE_NAME "http"

void log_test_start(void) {
    printf("Testing module %s\n", TEST_MODULE_NAME);
}

void log_success(char *name) {
    printf("[PASS] test \"%s\" succeeded.\n", name);
}

void test_parse_rqline_simple(void);
void test_parse_rqline_root(void);
void test_parse_rqline_double_seg(void);
void test_parse_target_asterisk(void);
void test_parse_target_invalid(void);
void test_target_complicated(void);
void test_parse_target_invalid_percent(void);
void test_invalid_methods(void);
void test_complex_paths(void);
void test_query_parameters(void);
void test_percent_encoding(void);
void test_basic_header(void);
void test_basic_header_2(void);
void test_header_whitespace(void);
void test_invalid_headers(void);
void test_header_edge_cases(void);
void test_header_case_nonsensitive(void);
void test_header_duplicate_key_diff_val(void);
void test_header_dup_key_dup_val(void);

void test_tokenize_cslist_basic(void);
void test_tokenize_cslist_whitespace(void);
void test_tokenize_cslist_empty_elements(void);
void test_tokenize_cslist_http_headers(void);
void test_tokenize_cslist_special_chars(void);
void test_tokenize_cslist_edge_cases(void);

void test_get_req_body_info_basic(void);
void test_get_req_body_info_transfer_encoding(void);
void test_get_req_body_info_content_length(void);
void test_get_req_body_info_header_conflicts(void);
void test_get_req_body_info_methods(void);
void test_get_req_body_info_whitespace(void);

int main(void) {
    log_test_start();

    test_parse_rqline_simple();
    test_parse_rqline_root();
    test_parse_rqline_double_seg();
    test_parse_target_asterisk();
    test_parse_target_invalid();
    test_target_complicated();
    test_parse_target_invalid_percent();
    test_invalid_methods();
    test_complex_paths();
    test_query_parameters();
    test_percent_encoding();

    test_basic_header();
    test_basic_header_2();
    test_header_whitespace();
    test_invalid_headers();
    test_header_edge_cases();
    test_header_case_nonsensitive();
    test_header_duplicate_key_diff_val();
    test_header_dup_key_dup_val();

    test_tokenize_cslist_basic();
    test_tokenize_cslist_whitespace();
    test_tokenize_cslist_empty_elements();
    test_tokenize_cslist_http_headers();
    test_tokenize_cslist_special_chars();
    test_tokenize_cslist_edge_cases();

    test_get_req_body_info_basic();
    test_get_req_body_info_transfer_encoding();
    test_get_req_body_info_content_length();
    test_get_req_body_info_header_conflicts();
    test_get_req_body_info_methods();
    test_get_req_body_info_whitespace();

    printf("ALL OK\n");

    return 0;
}

// Request-line and target parsing test suite

void test_parse_rqline_simple(void) {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST /lorem/ipsum/dol HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 3);

    assert(memcmp(r->target->segments[0]->bytes, "lorem", 5) == 0);
    assert(memcmp(r->target->segments[1]->bytes, "ipsum", 5) == 0);
    assert(memcmp(r->target->segments[2]->bytes, "dol", 3) == 0);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("parse request line simple");
}

void test_parse_rqline_double_seg(void) {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST // HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 2);

    assert(r->target->segments[0]->bytes == NULL);
    assert(r->target->segments[0]->length == 0);

    assert(r->target->segments[1]->bytes == NULL);
    assert(r->target->segments[1]->length == 0);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("target is '//'");
}

void test_parse_rqline_root(void) {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST / HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 1);

    assert(r->target->segments[0]->bytes == NULL);
    assert(r->target->segments[0]->length == 0);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("parse request line with target as root");
}

void test_parse_target_asterisk(void) {
    struct HttpRequest *r = http_request_init();
    char *rqline = "CONNECT * HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 1);

    assert(r->target->segments == NULL);

    assert(r->target->query == NULL);
    assert(r->target->query_length == 0);

    http_request_free(r);

    log_success("parse asterisk form target");
}

void test_parse_target_invalid(void) {
    struct HttpRequest *r;
    char *lines[] = {
        "CONNECT ../something HTTP/1.1",
        "CONNECT . HTTP/1.1",
        "CONNECT  HTTP/1.1",
        "CONNECT HTTP/1.1",
        "CONNECT HTTP/1.1",
        "CONNECT HTTP/1.1",
    };

    for (size_t i = 0; i < (sizeof(lines) / sizeof(char *)); i++) {
        r = http_request_init();
        int res = parse_request_line(r, (uint8_t *) lines[i], strlen(lines[i]));
        assert (res < 0);
        http_request_free(r);
    }

    log_success("invalid targets");
}

void test_target_complicated(void) {
    struct HttpRequest *r = http_request_init();
    char *rqline = "POST /abc/def//help.php/h%65%6c%6C%6Fworld?foo=%00%FF&bar=lorem HTTP/1.1";

    parse_request_line(r, (uint8_t *) rqline, strlen(rqline));

    assert(r->method != -1);
    assert(r->version.major == 1);
    assert(r->version.minor == 1);

    assert(r->target != NULL);
    assert(r->target->is_asterisk == 0);

    assert(r->target->segments != NULL);
    assert(r->target->num_segments == 5);

    assert(r->target->segments[0]->length == 3);
    assert(memcmp(r->target->segments[0]->bytes, "abc", 3) == 0);

    assert(r->target->segments[1]->length == 3);
    assert(memcmp(r->target->segments[1]->bytes, "def", 3) == 0);

    assert(r->target->segments[2]->length == 0);
    assert(r->target->segments[2]->bytes == NULL);

    assert(r->target->segments[3]->length == 8);
    assert(memcmp(r->target->segments[3]->bytes, "help.php", 8) == 0);

    assert(r->target->segments[4]->length == 10);
    assert(memcmp(r->target->segments[4]->bytes, "helloworld", 10) == 0);

    assert(r->target->query != NULL);
    assert(r->target->query_length == 16);

    uint8_t test[] = { 'f', 'o', 'o', '=', 0, 255, '&', 'b', 'a', 'r', '=', 'l', 'o', 'r', 'e', 'm' };
    assert(memcmp(r->target->query, test, 16) == 0);

    http_request_free(r);

    log_success("test target complicated with hex decoding");
}

void test_parse_target_invalid_percent(void) {
    struct HttpRequest *r;
    char *lines[] = {
        "CONNECT /% HTTP/1.1",
        "CONNECT //% HTTP/1.1",
        "CONNECT /%AZ HTTP/1.1",
        "CONNECT /%A/%ab HTTP/1.1",
        "CONNECT /%z3 HTTP/1.1",
        "CONNECT /%% HTTP/1.1",
        "CONNECT /%%% HTTP/1.1",
    };

    for (size_t i = 0; i < (sizeof(lines) / sizeof(char *)); i++) {
        r = http_request_init();
        int res = parse_request_line(r, (uint8_t *) lines[i], strlen(lines[i]));
        assert (res < 0);
        http_request_free(r);
    }

    log_success("invalid hex encodings");
}

void test_invalid_methods(void) {
    const char *invalid_methods[] = {
        "INVALID / HTTP/1.1",
        "Get / HTTP/1.1",
        "POST_BAD / HTTP/1.1",
        "G#T / HTTP/1.1",
        "GET@ / HTTP/1.1",
        " GET / HTTP/1.1",
        "GET  / HTTP/1.1"
    };

    for (size_t i = 0; i < sizeof(invalid_methods)/sizeof(char*); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)invalid_methods[i],
                                        strlen(invalid_methods[i]));
        assert(result < 0);
        http_request_free(r);
    }
    log_success("invalid HTTP methods");
}

void test_complex_paths(void) {
    const char *test_cases[] = {
        "GET /a/bb/ccc/dddd HTTP/1.1",
        "GET /segment//between/empty HTTP/1.1",
        "GET /multiple///slashes HTTP/1.1",
        "GET /Upper/lower/12345/-._~!$&'()*+,;=:@ HTTP/1.1",
        "GET /really/really/really/really/really/really/long/path HTTP/1.1",
        "GET /path/with./dots/../in.it HTTP/1.1"
    };

    for (size_t i = 0; i < sizeof(test_cases)/sizeof(char*); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)test_cases[i], 
                                        strlen(test_cases[i]));
        assert(result >= 0);
        assert(r->target != NULL);
        assert(r->target->is_asterisk == false);
        http_request_free(r);
    }
    log_success("complex request paths");
}

void test_query_parameters(void) {
    struct {
        const char *request;
        const uint8_t *expected_query;
        size_t expected_query_len;
    } test_cases[] = {
        { "GET /path?key=value HTTP/1.1", (uint8_t *) "key=value", 9 },
        { "GET /path?k1=v1&k2=v2 HTTP/1.1", (uint8_t *) "k1=v1&k2=v2", 11 },
        { "GET /path?empty= HTTP/1.1", (uint8_t *) "empty=", 6 },
        { "GET /path?=value HTTP/1.1", (uint8_t *) "=value", 6 },
        { "GET /path?&&& HTTP/1.1", (uint8_t *) "&&&", 3 },
        { "GET /path?q=a+b HTTP/1.1", (uint8_t *) "q=a+b", 5 },
    };

    for (size_t i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)test_cases[i].request, 
                                        strlen(test_cases[i].request));

        assert(result >= 0);
        assert(r->target != NULL);
        assert(r->target->query != NULL);
        assert(r->target->query_length == test_cases[i].expected_query_len);
        assert(memcmp(r->target->query, test_cases[i].expected_query,
                      test_cases[i].expected_query_len) == 0);

        http_request_free(r);
    }
    log_success("query parameter parsing");
}

void test_percent_encoding(void) {
    struct {
        const char* request;
        bool should_succeed;
    } test_cases[] = {
        { "GET /path%20with%20spaces HTTP/1.1", true },
        { "GET /path%2F%2E%2E%2Ftraversal HTTP/1.1", true },
        { "GET /all%ff%Fe%Fa%FB%fc%FD%00 HTTP/1.1", true },
        { "GET /invalid%2 HTTP/1.1", false },
        { "GET /invalid%2g HTTP/1.1", false },
        { "GET /invalid%g2 HTTP/1.1", false },
        { "GET /truncated% HTTP/1.1", false },
        { "GET /%2 HTTP/1.1", false },
        { "GET /%2G HTTP/1.1", false },
        { "GET /%G2 HTTP/1.1", false },
    };

    for (size_t i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        struct HttpRequest *r = http_request_init();
        int result = parse_request_line(r, (uint8_t *)test_cases[i].request, 
                                      strlen(test_cases[i].request));
        assert((result >= 0) == test_cases[i].should_succeed);
        http_request_free(r);
    }
    log_success("percent encoding edge cases");
}

// Header parsing test suite

void test_basic_header(void) {
    struct HttpRequest *r = http_request_init();

    char *headers[] = {
        "Host: example.com",
        "Content-Length: 42",
        "Accept: text/html, application/json",
        "X-Custom-Header: some-value",
        "Connection: keep-alive"
    };

    for (size_t i = 0; i < sizeof(headers) / sizeof(char*); i++) {
        int result = parse_header(r, (uint8_t *) headers[i], strlen(headers[i]));
        assert(result >= 0);
    }

    assert(r->headers->nheaders == 5);

    http_request_free(r);
    log_success("basic header parsing");
}

void test_basic_header_2(void) {
    struct HttpRequest *r = http_request_init();

    struct {
        char *header;
        char *expected_name;
        char *expected_value;
    } cases[] = {
        { "Host: example.com", "Host", "example.com" },
        { "Content-Length: 42", "Content-Length", "42" },
        { "Accept: text/html, application/json", "Accept", "text/html, application/json" },
        { "X-Custom-Header: some-value", "X-Custom-Header", "some-value" },
        { "Connection: keep-alive", "Connection", "keep-alive" },
        { "Contains-High-Bytes: Some \x80\x81\xFF value", 
            "Contains-High-Bytes", "Some \x80\x81\xFF value" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int result = parse_header(r, (uint8_t *) cases[i].header, strlen(cases[i].header));
        assert(result >= 0);

        struct Header *query = htable_query(r->headers, cases[i].expected_name);

        assert(query != NULL);
        assert(query->next == NULL);
        assert(strcmp(cases[i].expected_value, query->value) == 0);

        htable_query_free(query);
    }

    assert(r->headers->nheaders == sizeof(cases) / sizeof(cases[0]));

    http_request_free(r);
    log_success("more rigorous basic header case testing");
}

// test duplicates, high bytes, duplicates should come up in same search

void test_header_whitespace(void) {
    struct HttpRequest *r = http_request_init();

    struct {
        char *header;
        char *expected_name;
        char *expected_value;
    } cases[] = {
        { "Host:   example.com   ", "Host", "example.com" },
        { "Content-Length:42", "Content-Length", "42" },
        { "Accept:     text/html", "Accept", "text/html" },
        { "X-Header:\tvalue    ", "X-Header", "value" },
        { "Server:     seva    ", "Server", "seva" },
        { "Random-Header: \t\t  \x81wowza \t   ", "Random-Header", "\x81wowza" }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int result = parse_header(r, (uint8_t *) cases[i].header, strlen(cases[i].header));
        assert(result >= 0);

        struct Header *query = htable_query(r->headers, cases[i].expected_name);

        assert(query != NULL);
        assert(query->next == NULL);
        assert(strcmp(cases[i].expected_value, query->value) == 0);

        htable_query_free(query);
    }

    assert(r->headers->nheaders == sizeof(cases) / sizeof(cases[0]));

    http_request_free(r);
    log_success("test header whitespace parsing");
}

void test_invalid_headers(void) {
    struct HttpRequest *r;

    char *invalid_headers[] = {
        ":no-header-name",
        "Invalid Header: value",
        ": missing-header-name",
        "Header\tName: value",
        "@Invalid-Char: value",
        "Header: value\n",
        "Some-Header: va\rl",
        "HeaderWithoutColon",
        " WhiteSpaceInBeginning: Hi"
    };

    for (size_t i = 0; i < sizeof(invalid_headers) / sizeof(char *); i++) {
        r = http_request_init();
        int result = parse_header(
            r, (uint8_t *) invalid_headers[i], strlen(invalid_headers[i])
        );
        assert(result < 0);
        http_request_free(r);
    }

    log_success("invalid header detection");
}

void test_header_edge_cases(void) {
    struct HttpRequest *r = http_request_init();

    char *edge_headers[] = {
        "X-Empty-Value: ",
        "a: b",
        "Long-Header-Name-123456789: value",
        "Header: !\"#$%&'()*+,-./",
        "Header: 0123456789",
        "X-Header: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };

    for (size_t i = 0; i < sizeof(edge_headers) / sizeof(char *); i++) {
        int result = parse_header(
            r, (uint8_t *) edge_headers[i], strlen(edge_headers[i])
        );
        assert(result >= 0);
    }

    assert(r->headers->nheaders == 6);

    http_request_free(r);
    log_success("header edge cases");
}

static int count_query_result_count(struct Header *query) {
    int i = 0;
    while (query != NULL) {
        i++;
        query = query->next;
    }
    return i;
}

static bool name_exists_in_query_cs(struct Header *query, char *name) {
    while (query != NULL) {
        if (strcmp(query->name, name) == 0) return true;
        query = query->next;
    }
    return false;
}

static bool name_val_in_query_cs(struct Header *query, char *name, char *val) {
    while (query != NULL) {
        if (strcmp(query->name, name) == 0 && strcmp(query->value, val) == 0) return true;
        query = query->next;
    }
    return false;
}

void test_header_case_nonsensitive(void) {
    struct HttpRequest *r = http_request_init();

    char *dup1 = "Content-Length: 147\t\t  ";
    char *dup2 = "content-length: \t\t 148\t\t";
    char *dup3 = "cOnTeNt-LeNgTh:      149   ";

    int res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup2, strlen(dup2));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup3, strlen(dup3));
    assert(res >= 0);

    struct Header *query = htable_query(r->headers, "Content-Length");

    assert(count_query_result_count(query) == 3);

    assert(name_exists_in_query_cs(query, "Content-Length"));
    assert(name_exists_in_query_cs(query, "content-length"));
    assert(name_exists_in_query_cs(query, "cOnTeNt-LeNgTh"));

    assert(name_val_in_query_cs(query, "Content-Length", "147"));
    assert(name_val_in_query_cs(query, "content-length", "148"));
    assert(name_val_in_query_cs(query, "cOnTeNt-LeNgTh", "149"));

    htable_query_free(query);
    http_request_free(r);
    log_success("duplicate non-case-sensitive");
}

void test_header_duplicate_key_diff_val(void) {
    struct HttpRequest *r = http_request_init();

    char *dup1 = "Content-Length: 147";
    char *dup2 = "Content-Length: 148";

    int res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup2, strlen(dup2));
    assert(res >= 0);

    struct Header *query = htable_query(r->headers, "Content-Length");
    struct Header *current = query;

    assert(count_query_result_count(query) == 2);

    while (current != NULL) {
        assert(strcmp(current->name, "Content-Length") == 0);
        current = current->next;
    }

    assert(name_val_in_query_cs(query, "Content-Length", "147"));
    assert(name_val_in_query_cs(query, "Content-Length", "148"));

    htable_query_free(query);
    http_request_free(r);
    log_success("header duplicate same key different value");
}

void test_header_dup_key_dup_val(void) {
    struct HttpRequest *r = http_request_init();

    char *dup1 = "Content-Length: 147";

    int res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    res = parse_header(r, (uint8_t *) dup1, strlen(dup1));
    assert(res >= 0);

    struct Header *query = htable_query(r->headers, "Content-Length");
    struct Header *current = query;

    assert(count_query_result_count(query) == 2);

    while (current != NULL) {
        assert(strcmp(current->name, "Content-Length") == 0);
        current = current->next;
    }

    assert(name_val_in_query_cs(query, "Content-Length", "147"));

    htable_query_free(query);
    http_request_free(r);
    log_success("header duplicate key and duplicate val");
}

/* tokenize cslist */
void test_tokenize_cslist_basic(void) {
    // Simple case, no whitespace
    const char *input1 = "a,b,c";
    struct ByteSliceVector *v = tokenize_cslist((uint8_t *) input1, strlen(input1));
    assert(v != NULL);
    assert(v->count == 3);
    assert(v->array[0]->length == 1);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    assert(v->array[1]->length == 1);
    assert(memcmp(v->array[1]->data, "b", 1) == 0);
    assert(v->array[2]->length == 1);
    assert(memcmp(v->array[2]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Single element
    const char *input2 = "single";
    v = tokenize_cslist((uint8_t *) input2, strlen(input2));
    assert(v != NULL);
    assert(v->count == 1);
    assert(v->array[0]->length == 6);
    assert(memcmp(v->array[0]->data, "single", 6) == 0);
    bslice_vec_free(v);

    // Empty string
    const char *input3 = "";
    v = tokenize_cslist((uint8_t *) input3, strlen(input3));
    assert(v != NULL);
    assert(v->count == 0);
    bslice_vec_free(v);

    log_success("tokenize_cslist basic cases");
}

void test_tokenize_cslist_whitespace(void) {
    // Leading whitespace
    const char *input1 = "  a,b,c";
    struct ByteSliceVector *v = tokenize_cslist((uint8_t*)input1, strlen(input1));
    assert(v != NULL);
    assert(v->count == 3);
    assert(v->array[0]->length == 1);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    bslice_vec_free(v);

    // Trailing whitespace
    const char *input2 = "a,b,c  ";
    v = tokenize_cslist((uint8_t*)input2, strlen(input2));
    assert(v != NULL);
    assert(v->count == 3);
    assert(v->array[2]->length == 1);
    assert(memcmp(v->array[2]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Mixed whitespace types
    const char *input3 = " a \t,\t b  ,  c\t";
    v = tokenize_cslist((uint8_t*)input3, strlen(input3));
    assert(v != NULL);
    assert(v->count == 3);
    assert(v->array[0]->length == 1);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    assert(v->array[1]->length == 1);
    assert(memcmp(v->array[1]->data, "b", 1) == 0);
    assert(v->array[2]->length == 1);
    assert(memcmp(v->array[2]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Only whitespace
    const char *input4 = "   \t  ";
    v = tokenize_cslist((uint8_t*)input4, strlen(input4));
    assert(v != NULL);
    assert(v->count == 0);
    bslice_vec_free(v);

    log_success("tokenize_cslist whitespace handling");
}

void test_tokenize_cslist_empty_elements(void) {
    // Empty elements in middle
    const char *input1 = "a,,c";
    struct ByteSliceVector *v = tokenize_cslist((uint8_t*)input1, strlen(input1));
    assert(v != NULL);
    assert(v->count == 2);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    assert(memcmp(v->array[1]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Multiple empty elements
    const char *input2 = "a,,,,,c";
    v = tokenize_cslist((uint8_t*)input2, strlen(input2));
    assert(v != NULL);
    assert(v->count == 2);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    assert(memcmp(v->array[1]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Empty elements with whitespace
    const char *input3 = "a, ,  ,\t,c";
    v = tokenize_cslist((uint8_t*)input3, strlen(input3));
    assert(v != NULL);
    assert(v->count == 2);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    assert(memcmp(v->array[1]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Leading/trailing empty elements
    const char *input4 = ",,,a,b,c,,,";
    v = tokenize_cslist((uint8_t*)input4, strlen(input4));
    assert(v != NULL);
    assert(v->count == 3);
    assert(memcmp(v->array[0]->data, "a", 1) == 0);
    assert(memcmp(v->array[1]->data, "b", 1) == 0);
    assert(memcmp(v->array[2]->data, "c", 1) == 0);
    bslice_vec_free(v);

    // Just commas
    const char *input5 = ",,,,,";
    v = tokenize_cslist((uint8_t*)input5, strlen(input5));
    assert(v != NULL);
    assert(v->count == 0);
    bslice_vec_free(v);

    log_success("tokenize_cslist empty elements");
}

void test_tokenize_cslist_http_headers(void) {
    // Test with actual HTTP header values
    const char *input1 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
    struct ByteSliceVector *v = tokenize_cslist((uint8_t*)input1, strlen(input1));
    assert(v != NULL);
    assert(v->count == 4);
    assert(memcmp(v->array[0]->data, "text/html", 9) == 0);
    assert(memcmp(v->array[1]->data, "application/xhtml+xml", 20) == 0);
    assert(memcmp(v->array[2]->data, "application/xml;q=0.9", 20) == 0);
    assert(memcmp(v->array[3]->data, "*/*;q=0.8", 9) == 0);
    bslice_vec_free(v);

    // Test with Keep-Alive header
    const char *input2 = "timeout=5, max=1000";
    v = tokenize_cslist((uint8_t*)input2, strlen(input2));
    assert(v != NULL);
    assert(v->count == 2);
    assert(memcmp(v->array[0]->data, "timeout=5", 9) == 0);
    assert(memcmp(v->array[1]->data, "max=1000", 8) == 0);
    bslice_vec_free(v);

    // Test with Transfer-Encoding header
    const char *input3 = "gzip, chunked";
    v = tokenize_cslist((uint8_t*)input3, strlen(input3));
    assert(v != NULL);
    assert(v->count == 2);
    assert(memcmp(v->array[0]->data, "gzip", 4) == 0);
    assert(memcmp(v->array[1]->data, "chunked", 7) == 0);
    bslice_vec_free(v);

    log_success("tokenize_cslist HTTP header values");
}

void test_tokenize_cslist_special_chars(void) {
    // Test with UTF-8 characters
    const char *input1 = "résumé,façade,über";
    struct ByteSliceVector *v = tokenize_cslist((uint8_t*)input1, strlen(input1));
    assert(v != NULL);
    assert(v->count == 3);
    assert(v->array[0]->length == 8);  // résumé in UTF-8
    assert(v->array[1]->length == 7);  // façade in UTF-8
    assert(v->array[2]->length == 5);  // über in UTF-8
    bslice_vec_free(v);

    // Test with various special characters
    const char *input2 = "!@#$,=%^&*, ()[]{}";
    v = tokenize_cslist((uint8_t*)input2, strlen(input2));
    assert(v != NULL);
    assert(v->count == 3);
    assert(memcmp(v->array[0]->data, "!@#$", 4) == 0);
    assert(memcmp(v->array[1]->data, "=%^&*", 5) == 0);
    assert(memcmp(v->array[2]->data, "()[]{}", 6) == 0);
    bslice_vec_free(v);

    // Test with escaped commas in quotes (should not split)
    // const char *input3 = "\"hello,world\",simple,\"a,b,c\"";
    // v = tokenize_cslist((uint8_t*)input3, strlen(input3));
    // assert(v != NULL);
    // assert(v->count == 3);
    // assert(memcmp(v->array[0]->data, "\"hello,world\"", 13) == 0);
    // assert(memcmp(v->array[1]->data, "simple", 6) == 0);
    // assert(memcmp(v->array[2]->data, "\"a,b,c\"", 7) == 0);
    // bslice_vec_free(v);

    log_success("tokenize_cslist special characters");
}

void test_tokenize_cslist_edge_cases(void) {
    // Test with very long elements
    char *long_str = malloc(1000);
    memset(long_str, 'a', 999);
    long_str[999] = '\0';
    struct ByteSliceVector *v = tokenize_cslist((uint8_t*)long_str, strlen(long_str));
    assert(v != NULL);
    assert(v->count == 1);
    assert(v->array[0]->length == 999);
    assert(memcmp(v->array[0]->data, long_str, 999) == 0);
    bslice_vec_free(v);
    free(long_str);

    // Test with many elements
    char *many_elements = malloc(1000);
    for(int i = 0; i < 998; i++) {
        many_elements[i] = (i % 2 == 0) ? 'a' : ',';
    }
    many_elements[998] = 'a';
    many_elements[999] = '\0';
    v = tokenize_cslist((uint8_t*)many_elements, strlen(many_elements));
    assert(v != NULL);
    assert(v->count == 500);  // 500 'a's separated by commas
    for(size_t i = 0; i < v->count; i++) {
        assert(v->array[i]->length == 1);
        assert(v->array[i]->data[0] == 'a');
    }
    bslice_vec_free(v);
    free(many_elements);

    // Test with null bytes in middle (should handle up to null byte)
    const char input[] = "hello\0,world";
    v = tokenize_cslist((uint8_t*)input, sizeof(input)-1);  // include null byte
    assert(v != NULL);
    assert(v->count == 2);
    assert(memcmp(v->array[0]->data, "hello", 5) == 0);
    assert(memcmp(v->array[1]->data, "world", 5) == 0);
    bslice_vec_free(v);

    log_success("tokenize_cslist edge cases");
}

void test_get_req_body_info_basic(void) {
    struct HttpRequest *req = http_request_init();
    struct ReqBodyInfo rbinfo;

    // Test no headers (should have zero-length body)
    req->method = HTTP_POST;
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 0);
    
    // Test basic Content-Length
    const char *header = "Content-Length: 42";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 42);

    http_request_free(req);
    log_success("get_req_body_info basic tests");
}

void test_get_req_body_info_transfer_encoding(void) {
    struct HttpRequest *req = http_request_init();
    struct ReqBodyInfo rbinfo;
    req->method = HTTP_POST;

    // Test chunked transfer encoding
    const char *header = "Transfer-Encoding: chunked";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == true);
    assert(rbinfo.content_length == 0);

    // Test invalid transfer encoding (not ending in chunked) - FATAL error
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Transfer-Encoding: gzip";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);

    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Transfer-Encoding: gzip, chunked";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == true);

    // Test duplicate Transfer-Encoding headers
    // http_request_free(req);
    // req = http_request_init();
    // req->method = HTTP_POST;
    // header = "Transfer-Encoding: chunked";
    // assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    // assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    // assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_BAD_REQ);

    http_request_free(req);
    log_success("get_req_body_info transfer encoding tests");
}

void test_get_req_body_info_content_length(void) {
    struct HttpRequest *req = http_request_init();
    struct ReqBodyInfo rbinfo;
    req->method = HTTP_POST;

    // Test zero content length (explicit)
    const char *header = "Content-Length: 0";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 0);

    // Test maximum allowed content length
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Content-Length: 16384";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 16384);

    // Test content length too large - now FATAL
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Content-Length: 16385";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);

    // Test negative content length - now FATAL
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Content-Length: -1";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);

    // Test invalid content length format - now FATAL
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Content-Length: abc";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);

    // Test multiple identical Content-Length values
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Content-Length: 42";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.content_length == 42);

    // Test multiple different Content-Length values - now FATAL
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    const char *header1 = "Content-Length: 42";
    const char *header2 = "Content-Length: 43";
    assert(parse_header(req, (uint8_t *) header1, strlen(header1)) == SEVA_OK);
    assert(parse_header(req, (uint8_t *) header2, strlen(header2)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);

    http_request_free(req);
    log_success("get_req_body_info content length tests");
}

void test_get_req_body_info_header_conflicts(void) {
    struct HttpRequest *req = http_request_init();
    struct ReqBodyInfo rbinfo;
    req->method = HTTP_POST;

    // Test both Transfer-Encoding and Content-Length
    const char *te_header = "Transfer-Encoding: chunked";
    const char *cl_header = "Content-Length: 42";
    assert(parse_header(req, (uint8_t *) te_header, strlen(te_header)) == SEVA_OK);
    assert(parse_header(req, (uint8_t *) cl_header, strlen(cl_header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_BAD_REQ);

    http_request_free(req);
    log_success("get_req_body_info header conflict tests");
}

void test_get_req_body_info_methods(void) {
    struct HttpRequest *req;
    struct ReqBodyInfo rbinfo;
    const char *cl_header = "Content-Length: 42";
    const char *te_header = "Transfer-Encoding: chunked";
    const char *invalid_cl = "Content-Length: abc";

    // Test HEAD request (should never have body regardless of headers)
    req = http_request_init();
    req->method = HTTP_HEAD;
    // No headers - should be zero length
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 0);
    // With Content-Length - should still be zero length
    assert(parse_header(req, (uint8_t *) cl_header, strlen(cl_header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 0);
    http_request_free(req);

    // Test HEAD with Transfer-Encoding - should still be zero length
    req = http_request_init();
    req->method = HTTP_HEAD;
    assert(parse_header(req, (uint8_t *) te_header, strlen(te_header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 0);
    http_request_free(req);

    // Test various methods that can have a body
    enum HttpMethod methods[] = {HTTP_POST, HTTP_PUT, HTTP_PATCH};
    for (size_t i = 0; i < sizeof(methods)/sizeof(methods[0]); i++) {
        // Test with no headers
        req = http_request_init();
        req->method = methods[i];
        assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
        assert(rbinfo.is_chunked == false);
        assert(rbinfo.content_length == 0);
        http_request_free(req);

        // Test with Content-Length
        req = http_request_init();
        req->method = methods[i];
        assert(parse_header(req, (uint8_t *) cl_header, strlen(cl_header)) == SEVA_OK);
        assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
        assert(rbinfo.is_chunked == false);
        assert(rbinfo.content_length == 42);
        http_request_free(req);

        // Test with invalid Content-Length - should be FATAL
        req = http_request_init();
        req->method = methods[i];
        assert(parse_header(req, (uint8_t *) invalid_cl, strlen(invalid_cl)) == SEVA_OK);
        assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);
        http_request_free(req);
    }

    log_success("get_req_body_info method specific tests");
}

void test_get_req_body_info_whitespace(void) {
    struct HttpRequest *req = http_request_init();
    struct ReqBodyInfo rbinfo;
    req->method = HTTP_POST;

    // Test Content-Length with whitespace
    const char *header = "Content-Length:  42  ";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == false);
    assert(rbinfo.content_length == 42);

    // Test Content-Length with tabs and spaces
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Content-Length:\t42\t";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.content_length == 42);

    // Test Transfer-Encoding with whitespace
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Transfer-Encoding:  chunked  ";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_OK);
    assert(rbinfo.is_chunked == true);

    // Test Transfer-Encoding with whitespace but invalid - should be FATAL
    http_request_free(req);
    req = http_request_init();
    req->method = HTTP_POST;
    header = "Transfer-Encoding:  gzip  ";
    assert(parse_header(req, (uint8_t *) header, strlen(header)) == SEVA_OK);
    assert(get_req_body_info(req, &rbinfo) == SEVA_PARSE_FATAL);

    http_request_free(req);
    log_success("get_req_body_info whitespace handling tests");
}

